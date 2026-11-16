"""Dedicated Linux worker backend only; not a production wrapper, sandbox or origin proof.

All mutations require the reviewed fresh isolated single-thread/session-leader role.
Outcome concerns this owned command tree; callers must still supervise the worker.
"""
from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from tools import p4_linux_process_api as api
from tools import p4_process_state as metadata

GATE = "import os,sys\nif sys.stdin.buffer.read(1)!=b'R': raise SystemExit(125)\nos.dup2(os.open(os.devnull,os.O_RDONLY),0)\nos.execv(sys.argv[1],sys.argv[1:])\n"


class LinuxError(metadata.ProcessError):
    def __init__(self, reason, quiescent, cleanup=()):
        RuntimeError.__init__(self, "p4_linux_worker_" + reason + (" cleanup=" + repr(cleanup) if cleanup else ""))
        self.reason, self.quiescent, self.cleanup = reason, quiescent, cleanup


@dataclass(frozen=True, slots=True)
class Outcome:
    returncode: int
    quiescent: bool


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise LinuxError("deadline", False)
    return left


def context():
    if sys.platform != "linux":
        raise LinuxError("linux_only", True)
    if not sys.flags.isolated or not sys.flags.no_site or os.getsid(0) != os.getpid() or os.getpgrp() != os.getpid() or len(tuple(islice(Path("/proc/self/task").iterdir(), 2))) != 1:
        raise LinuxError("worker_context", True)
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | api.WALL)
    except ChildProcessError as error:
        if error.errno != errno.ECHILD:
            raise
    else:
        raise LinuxError("preexisting_children", False)


def census(deadline):
    """Drain adopted exits only AFTER Popen has exclusively reaped the original."""
    while True:
        remaining(deadline)
        try:
            state = api.reap_any()
        except ChildProcessError as error:
            if error.errno != errno.ECHILD:
                raise
            return True
        if state is None:
            return False


def candidates():
    """Positive candidates only; an empty proc listing never proves population closure."""
    with Path(f"/proc/self/task/{os.getpid()}/children").open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096 or any(not token.isdigit() for token in raw.split()):
        raise LinuxError("population_query", False)
    return tuple(map(int, raw.split()))


def run_backend(command, *, env, cwd, stdout_path, stderr_path, deadline, timeout=90):
    """Return metadata only after kernel child closure and checked resource closes; never read streams."""
    context()
    if type(command) not in (list, tuple) or not command or any(type(part) is not str or not part or "\0" in part for part in command) or Path(command[0]).resolve() != Path(sys.executable).resolve() or type(env) is not dict:
        raise LinuxError("arguments", True)
    if type(timeout) not in (int, float) or type(deadline) not in (int, float) or not 5 < timeout < float("inf") or not time.monotonic() < deadline < float("inf"):
        raise LinuxError("deadline", True)
    out_path, err_path = Path(stdout_path), Path(stderr_path)
    if out_path.resolve() == err_path.resolve():
        raise LinuxError("streams", True)
    stop_by = min(deadline, time.monotonic() + timeout)
    run_by = stop_by - 5
    remaining(run_by)
    process = fd = out = err = None
    done = zero = attempted = False
    primary, stage, code, issues = None, "capability", None, []

    def gate():
        if process is not None and not process.stdin.closed:
            process.stdin.close()

    def stop_original():
        if process is not None and not done and fd is not None:
            api.signal_child(fd, signal.SIGKILL)

    def reap_original():
        nonlocal done, code
        if process is not None and not done:
            code = process.wait(timeout=remaining(stop_by))
            done = True

    def close_original():
        if fd is not None:
            os.close(fd)

    def kill_one(pid):
        with ExitStack() as cleanup:
            descriptor = None
            cleanup.callback(lambda: os.close(descriptor) if descriptor is not None else None)
            descriptor = api.open_child(pid)
            api.signal_child(descriptor, signal.SIGKILL)

    def settle():
        nonlocal zero
        if process is None:
            zero = True
            return
        if not done:
            raise LinuxError("original_unreaped", False)
        while not census(stop_by):
            with ExitStack() as kills:
                for pid in candidates():
                    kills.callback(metadata.attempt, issues, "descendant", lambda pid=pid: kill_one(pid))
            time.sleep(min(0.005, remaining(stop_by)))
        zero = True

    cleanup = ExitStack()
    for label, operation in (("stdout_close", lambda: out.close() if out is not None else None),
        ("stderr_close", lambda: err.close() if err is not None else None), ("population", settle),
        ("pidfd_close", close_original), ("original_wait", reap_original), ("original_stop", stop_original), ("gate_close", gate)):
        cleanup.callback(metadata.attempt, issues, label, operation)
    try:
        with cleanup:
            try:
                api.reset_sigchld()
                api.set_subreaper(True)
                if api.get_subreaper() is not True:
                    raise LinuxError("capability", False)
                remaining(run_by)
                stage = "streams"
                out = out_path.open("xb")
                err = err_path.open("xb")
                remaining(run_by)
                stage, attempted = "spawn", True
                process = subprocess.Popen([sys.executable, "-I", "-S", "-c", GATE, *command], env=env, cwd=cwd,
                    stdin=subprocess.PIPE, stdout=out, stderr=err, close_fds=True)
                stage = "ownership"
                fd = api.open_child(process.pid)
                remaining(run_by)
                stage = "release"
                process.stdin.write(b"R")
                process.stdin.flush()
                process.stdin.close()
                stage = "wait"
                code = process.wait(timeout=remaining(run_by))
                done = True
                if not census(run_by):
                    primary = LinuxError("descendants", False)
            except metadata.FAILURES as error:
                primary = error
                if isinstance(error, metadata.ProcessError):
                    issues.extend(error.cleanup)
    finally:
        metadata.retain_pending(primary, issues)
    quiescent = zero and not issues and (done or not attempted and process is None)
    if primary is not None or issues:
        reason = primary.reason if isinstance(primary, LinuxError) else "timeout" if isinstance(primary, subprocess.TimeoutExpired) else stage if primary is not None else "cleanup"
        raise LinuxError(reason, quiescent, tuple(issues)) from primary
    if not quiescent:
        raise LinuxError("quiescence", False)
    result = Outcome(code, True)
    remaining(stop_by)
    return result
