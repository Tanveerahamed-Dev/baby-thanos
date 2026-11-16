"""Linux capabilities and isolated worker experiments; other platforms prove refusal only."""
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
from tools import p4_linux_worker as worker

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


def run_case(root, case, *, expected_status="capability-only"):
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
        assert json.loads(output) == {"case": case, "status": expected_status}
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


WORKER_CASES = ("success0", "success7", "orphan", "double_fork", "timeout", "deadline", "ownership_failure", "timeout_cleanup", "timeout_note_memory", "timeout_attribute_memory", "body_cleanup", "close_unknown", "late_outcome")
WORKER_CHILD = r"""
import errno, json, os, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
from tools import p4_linux_process_api as api, p4_linux_worker as worker
case, root = sys.argv[2], Path(os.environ["P4_WORKER_CASE_ROOT"])
marker, beat = root/"started", root/"heartbeat"
spawned, validated, files, reads, timeouts, native_errors = [], [], [], [], [], []
real_spawn, real_owned = subprocess.Popen, api.open_child
real_wait, real_open, real_read = real_spawn.wait, Path.open, Path.read_bytes
nominal_outcome, real_clock, built, returned = worker.Outcome, time.monotonic, [], []
body = TypeError("planted body")
class CleanupFault(TypeError):
    def __setattr__(self, name, value):
        if name == "owned_process_primary" and case == "timeout_attribute_memory":
            raise MemoryError("planted attachment allocation")
        super().__setattr__(name, value)
    def add_note(self, note):
        if case == "timeout_note_memory":
            raise MemoryError("planted note allocation")
        super().add_note(note)
cleanup_error = CleanupFault("planted close")
class Wrapped:
    def __init__(self, stream, role):
        self.stream, self.role = stream, role
    @property
    def closed(self):
        return self.stream.closed
    def fileno(self):
        return self.stream.fileno()
    def write(self, value):
        assert self.role == "gate" and any(pid == spawned[0].pid for pid, fd in validated)
        return self.stream.write(value)
    def flush(self):
        return self.stream.flush()
    def close(self):
        self.stream.close()
        if self.role == "err" and case in ("timeout_cleanup", "timeout_note_memory", "timeout_attribute_memory", "body_cleanup"):
            try:
                raise KeyError("retained close context")
            except KeyError:
                raise cleanup_error
        if self.role == "err" and case == "close_unknown":
            raise OSError(errno.EIO, "planted lost close acknowledgement")
def spawn(*args, **kwargs):
    process = real_spawn(*args, **kwargs)
    spawned.append(process)
    process.stdin = Wrapped(process.stdin, "gate")
    return process
def owned(pid):
    if case == "body_cleanup":
        raise body
    try:
        descriptor = real_owned(os.getpid() if case == "ownership_failure" else pid)
    except OSError as error:
        native_errors.append(error)
        raise
    validated.append((pid, descriptor))
    return descriptor
def wait(process, timeout=None):
    try:
        return real_wait(process, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timeouts.append(error)
        raise
def opening(path, *args, **kwargs):
    stream = real_open(path, *args, **kwargs)
    if args and args[0] == "xb":
        files.append(stream)
        return Wrapped(stream, "err" if path.name == "command.err" else "out")
    return stream
def forbidden(path):
    reads.append(path)
    raise AssertionError("backend must never read command streams")
subprocess.Popen, real_spawn.wait, api.open_child = spawn, wait, owned
Path.open, Path.read_bytes = opening, forbidden
if case == "late_outcome":
    def late_outcome(*args, **kwargs):
        result = nominal_outcome(*args, **kwargs)
        built.append(result)
        worker.time = SimpleNamespace(monotonic=lambda: real_clock()+40, sleep=time.sleep)
        return result
    worker.Outcome = late_outcome
code = "import os,sys;from pathlib import Path;Path(sys.argv[1]).write_bytes(b'started');os.write(1,str(os.getpid()).encode());os.write(2,b'err');raise SystemExit(" + ("7" if case == "success7" else "0") + ")"
if case in ("orphan", "double_fork"):
    code = ("import os,sys,time\nfrom pathlib import Path\npid=os.fork()\nif pid==0:\n" +
        (" if os.fork(): os._exit(0)\n" if case == "double_fork" else "") +
        " f=open(sys.argv[2],'ab',buffering=0)\n f.write(b'x');os.write(1,b'writer');os.write(2,b'writer-error')\n"
        " Path(sys.argv[1]).write_bytes(b'ready')\n while True: f.write(b'x');os.write(1,b'x');time.sleep(0.01)\n"
        "end=time.monotonic()+2\nwhile not Path(sys.argv[1]).exists() and time.monotonic()<end: time.sleep(0.005)\n"
        "assert Path(sys.argv[1]).exists()\nos._exit(0)\n")
elif case in ("timeout", "deadline", "timeout_cleanup", "timeout_note_memory", "timeout_attribute_memory"):
    code = "import time;print('real-partial',flush=True);time.sleep(60)"
start = time.monotonic()
try:
    value = worker.run_backend([sys.executable, "-c", code, str(marker), str(beat)], env=dict(os.environ), cwd=root,
        stdout_path=root/"command.out", stderr_path=root/"command.err", deadline=start+(6 if case=="deadline" else 20),
        timeout=15 if case=="deadline" else 8)
    returned.append(value)
except worker.LinuxError as error:
    assert str(error).startswith("p4_linux_worker_")
    if case in ("orphan", "double_fork"):
        assert error.reason == "descendants" and error.quiescent is True and spawned[0].returncode == 0
        assert marker.exists() and beat.stat().st_size > 0
        size = beat.stat().st_size
        time.sleep(0.1)
        assert beat.stat().st_size == size and b"writer" in real_read(root/"command.out")
    elif case == "ownership_failure":
        assert error.reason == "ownership" and error.quiescent is True and error.__cause__ is native_errors[0]
        assert native_errors[0].errno == errno.ECHILD and not marker.exists() and spawned[0].returncode == 125
    elif case in ("timeout", "deadline"):
        assert error.reason in ("timeout", "deadline") and error.quiescent is True
        if timeouts:
            assert error.__cause__ is timeouts[0]
        if case == "deadline":
            assert time.monotonic()-start < 6
        else:
            assert timeouts and b"real-partial" in real_read(root/"command.out")
    elif case == "late_outcome":
        assert error.reason == "deadline" and error.quiescent is False and returned == []
        assert len(built) == 1 and type(built[0]) is nominal_outcome and built[0].returncode == 0
    else:
        assert case == "close_unknown" and error.reason == "cleanup" and error.quiescent is False and error.cleanup
except CleanupFault as error:
    assert error is cleanup_error and isinstance(error.__context__, KeyError) and error.__cause__ is None
    assert getattr(error, "quiescent", False) is False
    if case == "body_cleanup":
        assert error.__context__.__context__ is body and not hasattr(error, "owned_process_primary") and not marker.exists()
    elif case == "timeout_attribute_memory":
        assert timeouts and not hasattr(error, "owned_process_primary")
    else:
        assert timeouts and error.owned_process_primary is timeouts[0]
        assert bool(getattr(error, "__notes__", [])) == (case == "timeout_cleanup")
else:
    assert case in ("success0", "success7") and type(value) is nominal_outcome and value.quiescent is True
    assert value.returncode == spawned[0].returncode == (7 if case=="success7" else 0)
    assert int(real_read(root/"command.out")) == spawned[0].pid and real_read(root/"command.err") == b"err"
assert reads == [] and len(files) == 2 and all(stream.closed for stream in files)
assert len(spawned) == 1 and spawned[0].returncode is not None
try:
    api.reap_any()
except ChildProcessError as error:
    assert error.errno == errno.ECHILD
else:
    raise AssertionError("worker did not close its kernel-owned child population")
for pid, descriptor in validated:
    try:
        os.fstat(descriptor)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("owned pidfd not closed")
print(json.dumps({"case":case,"status":"backend-only"},sort_keys=True))
"""


@pytest.mark.parametrize("case", WORKER_CASES)
def test_actual_backend_only_in_isolated_worker_with_parent_state_unchanged(tmp_path, monkeypatch, case):
    if sys.platform != "linux":
        with pytest.raises(worker.LinuxError, match="^p4_linux_worker_linux_only$"):
            worker.run_backend([], env={}, cwd=tmp_path, stdout_path=tmp_path/"out", stderr_path=tmp_path/"err", deadline=1)
        assert list(tmp_path.iterdir()) == []
        return
    with monkeypatch.context() as guard:
        guard.setitem(globals(), "CHILD", WORKER_CHILD)
        guard.setenv("P4_WORKER_CASE_ROOT", str(tmp_path))
        run_case(tmp_path, case, expected_status="backend-only")


def test_backend_import_is_inert_and_parent_role_is_refused(tmp_path, monkeypatch):
    before = snapshot() if sys.platform == "linux" else None
    calls = []
    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("parent must not mutate native state")
    with monkeypatch.context() as guard:
        guard.setattr(api.c, "CDLL", forbidden)
        importlib.reload(worker)
        guard.setattr(api, "reset_sigchld", forbidden)
        guard.setattr(api, "set_subreaper", forbidden)
        with pytest.raises(worker.LinuxError, match="^p4_linux_worker_(worker_context|linux_only)$"):
            worker.run_backend([], env={}, cwd=tmp_path, stdout_path=tmp_path/"out", stderr_path=tmp_path/"err", deadline=1)
    assert calls == [] and list(tmp_path.iterdir()) == []
    if before is not None:
        assert snapshot() == before
