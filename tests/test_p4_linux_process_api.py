"""Hosted Linux capability experiments only; other platforms prove refusal, never Linux semantics."""
import errno
import importlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tools import p4_linux_process_api as api

REPO = Path(__file__).resolve().parents[1]
CASES = ("subreaper", "owned_signal", "not_child", "double_fork", "invalid", "missing")
CHILD = r"""
import errno, os, select, signal, sys, time
from contextlib import ExitStack
sys.path.insert(0, sys.argv[1])
from tools import p4_linux_process_api as api

def expect(kind, number, operation):
    try:
        operation()
    except kind as error:
        assert error.errno == number
        return
    raise AssertionError("required native refusal missing")

def live_child():
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(writer)
        os.read(reader, 1)
        os._exit(0)
    os.close(reader)
    return pid, writer

def exited(fd):
    end = time.monotonic() + 3
    while time.monotonic() < end:
        result = api.child_state(fd)
        if result is not None:
            return result
        time.sleep(0.005)
    raise AssertionError("native child exit not observed")

case = sys.argv[2]
assert api.get_subreaper() is False
api.reset_sigchld()
if case == "subreaper":
    api.set_subreaper(True)
    assert api.get_subreaper() is True
    api.set_subreaper(False)
    assert api.get_subreaper() is False
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    api.reset_sigchld()
    assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
    pid = os.fork()
    if pid == 0:
        os._exit(7)
    assert os.waitpid(pid, 0) == (pid, 7 << 8)
    expect(ChildProcessError, errno.ECHILD, api.reap_any)
    expect(OSError, errno.EINVAL, lambda: api._prctl(-1, 0))
elif case == "owned_signal":
    pid, gate = live_child()
    with ExitStack() as cleanup:
        cleanup.callback(os.close, gate)
        fd = api.open_child(pid)
        cleanup.callback(os.close, fd)
        assert os.get_inheritable(fd) is False and api.child_state(fd) is None
        api.signal_child(fd, 0)
        assert api.child_state(fd) is None
        api.signal_child(fd, signal.SIGKILL)
        first, second = exited(fd), api.child_state(fd)
        assert first == second and first.si_pid == pid
        assert first.si_code == os.CLD_KILLED and first.si_status == signal.SIGKILL
        assert os.waitpid(pid, 0) == (pid, signal.SIGKILL)
        expect(ChildProcessError, errno.ECHILD, lambda: api.child_state(fd))
        expect(ChildProcessError, errno.ECHILD, lambda: api.signal_child(fd, signal.SIGKILL))
        expect(ProcessLookupError, errno.ESRCH, lambda: signal.pidfd_send_signal(fd, 0))
    expect(ChildProcessError, errno.ECHILD, api.reap_any)
elif case == "not_child":
    observed, calls = [], []
    real_open, real_send = os.pidfd_open, signal.pidfd_send_signal
    def capture(pid, flags):
        fd = real_open(pid, flags)
        observed.append(fd)
        return fd
    def forbidden(*args):
        calls.append(args)
        raise AssertionError("nonchild must never reach signal syscall")
    os.pidfd_open = capture
    expect(ChildProcessError, errno.ECHILD, lambda: api.open_child(os.getppid()))
    os.pidfd_open = real_open
    assert len(observed) == 1
    expect(OSError, errno.EBADF, lambda: os.fstat(observed[0]))
    with ExitStack() as cleanup:
        fd = real_open(os.getppid(), 0)
        cleanup.callback(os.close, fd)
        signal.pidfd_send_signal = forbidden
        expect(ChildProcessError, errno.ECHILD, lambda: api.signal_child(fd, signal.SIGKILL))
        assert calls == []
        signal.pidfd_send_signal = real_send
elif case == "double_fork":
    api.set_subreaper(True)
    reader, writer = os.pipe()
    middle = os.fork()
    if middle == 0:
        os.close(reader)
        grand = os.fork()
        if grand == 0:
            os.close(writer)
            while True:
                signal.pause()
        os.write(writer, str(grand).encode() + b"\n")
        os._exit(0)
    os.close(writer)
    assert select.select([reader], [], [], 3)[0] == [reader]
    raw = os.read(reader, 64)
    os.close(reader)
    assert raw.endswith(b"\n") and raw[:-1].isdigit() and len(raw) < 64
    grand = int(raw)
    assert os.waitpid(middle, 0) == (middle, 0)
    with ExitStack() as cleanup:
        fd = api.open_child(grand)
        cleanup.callback(os.close, fd)
        assert api.child_state(fd) is None and api.reap_any() is None
        api.signal_child(fd, signal.SIGKILL)
        state = exited(fd)
        assert state.si_pid == grand and state.si_code == os.CLD_KILLED and state.si_status == signal.SIGKILL
        reaped = api.reap_any()
        assert reaped == state
        expect(ChildProcessError, errno.ECHILD, api.reap_any)
    api.set_subreaper(False)
    assert api.get_subreaper() is False
elif case == "invalid":
    for value in (0, 1, None):
        try:
            api.set_subreaper(value)
        except TypeError:
            pass
        else:
            raise AssertionError("bool-only subreaper input")
    for operation in (lambda: api.open_child(0), lambda: api.open_child(True),
                      lambda: api.child_state(-1), lambda: api.child_state(True), lambda: api.signal_child(0, signal.SIGTERM)):
        try:
            operation()
        except ValueError:
            pass
        else:
            raise AssertionError("invalid native input accepted")
    assert api.get_subreaper() is False
elif case == "missing":
    pid, gate = live_child()
    observed = []
    real_wait, real_open = os.waitid, os.pidfd_open
    def unavailable(*args):
        raise OSError(errno.ENOSYS, "planted unavailable waitid")
    def capture(pid, flags):
        fd = real_open(pid, flags)
        observed.append(fd)
        return fd
    os.waitid, os.pidfd_open = unavailable, capture
    expect(OSError, errno.ENOSYS, lambda: api.open_child(pid))
    os.waitid, os.pidfd_open = real_wait, real_open
    assert len(observed) == 1
    expect(OSError, errno.EBADF, lambda: os.fstat(observed[0]))
    os.close(gate)
    assert os.waitpid(pid, 0) == (pid, 0)
else:
    raise AssertionError("unknown closed capability scenario")
import json
print(json.dumps({"case": case, "status": "capability-only"}, sort_keys=True))
"""


def snapshot():
    return api.get_subreaper(), signal.getsignal(signal.SIGCHLD)


def run_case(root, case):
    before = snapshot()
    assert before[1] == signal.SIG_DFL
    end, anchor, process = time.monotonic() + 20, True, None
    out, err = root / "stdout.bin", root / "stderr.bin"
    try:
        with out.open("xb") as stdout, err.open("xb") as stderr:
            process = subprocess.Popen([sys.executable, "-I", "-S", "-c", CHILD, str(REPO), case],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, close_fds=True)
            try:
                while time.monotonic() < end - 3:
                    try:
                        state = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError:
                        anchor = False
                        raise
                    if state is not None:
                        break
                    time.sleep(0.01)
                else:
                    raise AssertionError("isolated capability child deadline")
            finally:
                try:
                    if anchor:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)  # Original child remains unreaped: owned PGID only.
                        except ProcessLookupError:
                            pass
                finally:
                    process.wait(timeout=max(0.001, end - time.monotonic()))
        while time.monotonic() < end:
            try:
                os.killpg(process.pid, 0)  # Never send a nonzero group signal after reaping.
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("isolated capability group not confirmed gone")
        output, errors = out.read_bytes(), err.read_bytes()
        assert process.returncode == 0, (output, errors)
        assert errors == b""
        assert json.loads(output) == {"case": case, "status": "capability-only"}
    finally:
        assert snapshot() == before


@pytest.mark.parametrize("case", CASES)
def test_actual_capabilities_only_in_fresh_child_with_parent_unchanged(tmp_path, case):
    if sys.platform != "linux":
        for operation in (api.get_subreaper, lambda: api.set_subreaper(True), api.reset_sigchld,
                          lambda: api.open_child(1), lambda: api.child_state(0), lambda: api.signal_child(0), api.reap_any):
            with pytest.raises(OSError, match="^p4_linux_process_api_linux_lp64_only$"):
                operation()
        assert list(tmp_path.iterdir()) == []
        return
    run_case(tmp_path, case)


def test_import_is_inert_and_native_queries_are_read_only(monkeypatch):
    before = snapshot() if sys.platform == "linux" else None
    calls = []
    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("module import must not load a native library")
    with monkeypatch.context() as guard:
        guard.setattr(api.c, "CDLL", forbidden)
        importlib.reload(api)
    assert calls == []
    if before is not None:
        assert snapshot() == before


def test_lost_kill_ack_still_reaps_original_child_without_reading(tmp_path, monkeypatch):
    if sys.platform != "linux":
        with pytest.raises(OSError, match="^p4_linux_process_api_linux_lp64_only$"):
            api.get_subreaper()
        assert list(tmp_path.iterdir()) == []
        return
    before = snapshot()
    real_spawn, real_waitid, real_kill = subprocess.Popen, os.waitid, os.killpg
    real_wait = real_spawn.wait
    processes, waits, kills, reads = [], [], [], []
    body, lost = RuntimeError("planted body interruption"), PermissionError(errno.EPERM, "planted lost kill acknowledgement")
    def spawn(*args, **kwargs):
        process = real_spawn(*args, **kwargs)
        processes.append(process)
        return process
    def interrupt(kind, pid, flags):
        assert processes and pid == processes[0].pid and kind == os.P_PID
        assert real_waitid(kind, pid, flags) is None  # Actual original child is still alive and unreaped.
        raise body
    def kill(pgid, number):
        assert pgid == processes[0].pid and number == signal.SIGKILL
        real_kill(pgid, number)
        kills.append(pgid)
        raise lost
    def bounded_wait(process, timeout=None):
        assert process is processes[0] and kills == [process.pid] and 0 < timeout <= 20
        waits.append((process, timeout))
        return real_wait(process, timeout=timeout)
    def forbidden(path):
        reads.append(path)
        raise AssertionError("failed containment must not read parent streams")
    with monkeypatch.context() as guard:
        guard.setattr(subprocess, "Popen", spawn)
        guard.setattr(real_spawn, "wait", bounded_wait)
        guard.setattr(os, "waitid", interrupt)
        guard.setattr(os, "killpg", kill)
        guard.setattr(Path, "read_bytes", forbidden)
        guard.setitem(globals(), "CHILD", "import signal\nwhile True: signal.pause()\n")
        with pytest.raises(PermissionError) as error:
            run_case(tmp_path, "lost_ack")
    assert error.value is lost and lost.__context__ is body
    assert len(processes) == len(waits) == len(kills) == 1 and reads == []
    assert processes[0].returncode == -signal.SIGKILL
    with pytest.raises(ChildProcessError) as reaped:
        real_waitid(os.P_PID, processes[0].pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    assert reaped.value.errno == errno.ECHILD and snapshot() == before
