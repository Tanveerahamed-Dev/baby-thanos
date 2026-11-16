"""Own one static Linux entry worker and validate its terminal control frame; never open command output files.

Single-reaper/default-SIGCHLD and trusted no-session-escape callers are premises, not authentication.
A separate public adapter must invoke this controller itself before any bounded output read.
"""
from __future__ import annotations

import os
import select
import secrets
import signal
import subprocess
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from tools import p4_linux_entry as entry
from tools import p4_process_state as metadata

ROOT = Path(__file__).resolve().parents[1]
BOOT = r"""
import os,sys
status,entry=1,None
try:
    sys.path.insert(0,sys.argv[1])
    from tools import p4_linux_entry as entry
    entry.main(int(sys.argv[2]))
    sys.stderr.flush()
    status=0
finally:
    try:
        if status:
            if entry is None: os.write(2,b"P4_LINUX_BOOTSTRAP_FAILURE\n")
            else: entry.diagnose(sys.exception())
            sys.stderr.flush()
    finally:
        os._exit(status)
"""


class ControlError(metadata.ProcessError):
    def __init__(self, reason, cleanup=()):
        RuntimeError.__init__(self, "p4_linux_control_" + reason)
        self.reason, self.quiescent, self.cleanup = reason, False, cleanup


@dataclass(frozen=True, slots=True)
class Controlled:
    status: str
    returncode: int | None
    reason: str
    stop_by: float


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise ControlError("deadline")
    return left


def run_control(command, *, env, cwd, stdout_path, stderr_path, deadline, timeout=90):
    if sys.platform != "linux":
        raise ControlError("linux_only")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL or len(tuple(islice(Path("/proc/self/task").iterdir(), 2))) != 1:
        raise ControlError("parent_context")
    if type(env) is not dict or any(type(key) is not str or not key or "=" in key or "\0" in key or type(value) is not str or "\0" in value for key, value in env.items()):
        raise ControlError("environment")
    if type(command) not in (list, tuple) or not command or any(type(part) is not str or not part or "\0" in part for part in command):
        raise ControlError("command")
    if type(timeout) not in (int, float) or type(deadline) not in (int, float) or not 11 < timeout < float("inf") or not time.monotonic() < deadline < float("inf"):
        raise ControlError("deadline")
    stop_by = min(deadline, time.monotonic()+timeout)
    monitor_by = stop_by-4
    request = entry.encode({"schema":entry.REQUEST_SCHEMA,"nonce":secrets.token_hex(16),"command":list(command),
        "cwd":str(Path(cwd).absolute()),"stdout":str(Path(stdout_path).absolute()),"stderr":str(Path(stderr_path).absolute()),"stop_by":stop_by-5})
    entry.request(request)
    process = reader = writer = None
    anchor = reaped = eof = False
    code, primary, issues = None, None, []
    received = bytearray()

    def close_reader():
        if reader is not None:
            os.close(reader)

    def close_writer():
        nonlocal writer
        if writer is not None:
            fd, writer = writer, None
            os.close(fd)

    def close_input():
        if process is not None and not process.stdin.closed:
            process.stdin.close()

    def observe():
        nonlocal anchor
        try:
            return os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError:
            anchor = False
            process._child_created = False  # Lost custody: suppress numeric-PID destructor polling; no exit status invented.
            raise ControlError("worker_custody") from None

    def stop_group():
        if process is not None and anchor:
            observe()
            try:
                os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass

    def reap():
        nonlocal anchor, reaped, code
        if process is not None and anchor:
            observe()
            code = process.wait(timeout=remaining(stop_by))
            try:
                os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            except ChildProcessError:
                anchor, reaped = False, True
            else:
                raise ControlError("worker_reap_unconfirmed")

    def drain():
        nonlocal eof
        if reader is not None:
            while len(received) <= entry.RECEIPT_LIMIT:
                try:
                    block = os.read(reader,entry.RECEIPT_LIMIT+1-len(received))
                except BlockingIOError:
                    return
                if not block:
                    eof = True
                    return
                received.extend(block)
            raise ControlError("receipt_limit")

    cleanup = ExitStack()
    for label,operation in (("reader_close",close_reader),("writer_close",close_writer),("input_close",close_input),
        ("final_drain",drain),("worker_wait",reap),("group_stop",stop_group)):
        cleanup.callback(metadata.attempt,issues,label,operation)
    try:
        with cleanup:
            try:
                remaining(monitor_by)
                reader,writer = os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
                process = subprocess.Popen([sys.executable,"-I","-S","-c",BOOT,str(ROOT),str(writer)],cwd=cwd,env=env,
                    stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=None,start_new_session=True,close_fds=True,pass_fds=(writer,))
                anchor = True
                close_writer()
                os.set_blocking(process.stdin.fileno(),False)
                sent = 0
                while True:
                    remaining(monitor_by)
                    if sent < len(request):
                        try:
                            count = os.write(process.stdin.fileno(),request[sent:sent+4096])
                            if count <= 0:
                                raise ControlError("request_write")
                            sent += count
                        except BlockingIOError:
                            pass
                    if sent == len(request):
                        close_input()
                    drain()
                    if observe() is not None:
                        break
                    select.select([] if eof else [reader],[] if process.stdin.closed else [process.stdin.fileno()],[],min(.01,remaining(monitor_by)))
            except metadata.FAILURES as error:
                primary = error
    finally:
        metadata.retain_pending(primary,issues)
    if primary is not None or issues or not reaped or code != 0 or not eof:
        raise ControlError("worker_or_channel",tuple(issues)) from primary
    while True:
        remaining(stop_by)
        try:
            os.killpg(process.pid,0)  # Never a nonzero group signal after the original worker has been reaped.
        except ProcessLookupError:
            break
        time.sleep(min(.01,remaining(stop_by)))
    value = entry.read_terminal(bytes(received),request,process.pid)
    result = Controlled(value["status"],value["returncode"],value["reason"],stop_by)
    remaining(stop_by)
    return result
