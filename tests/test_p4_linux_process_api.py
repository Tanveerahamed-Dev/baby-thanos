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

from tools import p4_linux_control as control
from tools import p4_linux_entry as entry
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


def entry_request(root):
    return {"schema": entry.REQUEST_SCHEMA, "nonce": "a"*32, "command": [sys.executable, "-c", "pass"],
            "cwd": str(root), "stdout": str(root/"command.out"), "stderr": str(root/"command.err"), "stop_by": time.monotonic()+20}


@pytest.mark.parametrize("plant", ["extra_env", "schema", "duplicate", "space", "nonce", "command", "nul", "path", "deadline_bool", "nonfinite", "missing", "oversize"])
def test_entry_request_is_closed_canonical_and_never_echoes_environment(tmp_path, plant):
    value = entry_request(tmp_path)
    assert entry.request(entry.encode(value)) == value
    if plant == "extra_env":
        value["env"] = "fixture_environment_private"
    elif plant == "schema":
        value["schema"] = "other"
    elif plant == "nonce":
        value["nonce"] = "A"*32
    elif plant == "command":
        value["command"] = []
    elif plant == "nul":
        value["command"].append("\0")
    elif plant == "path":
        value["stdout"] = "relative"
    elif plant == "deadline_bool":
        value["stop_by"] = True
    elif plant == "missing":
        value.pop("cwd")
    raw = entry.encode(value)
    if plant == "duplicate":
        raw = raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    elif plant == "space":
        raw += b" "
    elif plant == "nonfinite":
        raw = raw.replace(str(value["stop_by"]).encode(), b"NaN", 1)
    elif plant == "oversize":
        raw = b"x"*(entry.REQUEST_LIMIT+1)
    with pytest.raises(ValueError) as error:
        entry.request(raw)
    assert "fixture_environment_private" not in str(error.value)


@pytest.mark.parametrize("plant", ["schema", "nonce", "hash", "pid", "bool_pid", "unknown", "bool_code", "reason", "extra", "false_quiet", "newline", "oversize", "duplicate", "noncanonical"])
def test_entry_terminal_requires_exact_request_worker_fields_and_frame(tmp_path, plant):
    request = entry.encode(entry_request(tmp_path))
    raw = entry.terminal(request, 1234, worker.Outcome(0, True))
    assert entry.read_terminal(raw, request, 1234)["status"] == "ok"
    value = json.loads(raw)
    if plant == "schema":
        value["schema"] = "other"
    elif plant == "nonce":
        value["nonce"] = "b"*32
    elif plant == "hash":
        value["request_sha256"] = "b"*64
    elif plant == "pid":
        value["worker_pid"] = 1235
    elif plant == "bool_pid":
        value["worker_pid"] = True
    elif plant == "unknown":
        value["status"] = "unknown"
    elif plant == "bool_code":
        value["returncode"] = False
    elif plant == "reason":
        value["reason"] = "unexpected"
    elif plant == "extra":
        value["env"] = "fixture_environment_private"
    elif plant == "false_quiet":
        value["quiescent"] = False
    raw = entry.encode(value)+b"\n"
    if plant == "newline":
        raw = raw[:-1]
    elif plant == "oversize":
        raw = b"x"*(entry.RECEIPT_LIMIT+1)
    elif plant == "duplicate":
        raw = raw.replace(b'"status":', b'"status":"ok","status":', 1)
    elif plant == "noncanonical":
        raw = b" "+raw
    with pytest.raises(ValueError):
        entry.read_terminal(raw, request, 1234)


ENTRY_CASES = ("ok", "known_error", "timeout", "unknown", "short_write", "close_failure", "bad_writer", "bad_request")
ENTRY_CHILD = r"""
import errno, io, json, os, sys, time
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
from tools import p4_linux_entry as entry,p4_linux_worker as worker,p4_linux_process_api as api
case,root=sys.argv[2],Path(os.environ["P4_ENTRY_CASE_ROOT"])
read_fd,write_fd=os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
os.set_inheritable(write_fd,True)  # Model the descriptor made inheritable by Popen pass_fds.
identity=os.fstat(write_fd)
sentinel="entry_environment_"+str(os.getpid())
argument="entry_argument_"+str(os.getpid())
os.environ["P4_ENTRY_SENTINEL"]=sentinel
probe=("import errno,os,sys\ntry: s=os.fstat(int(sys.argv[1]))\n"
       "except OSError as e: assert e.errno==errno.EBADF\n"
       "else: assert (s.st_dev,s.st_ino)!=(int(sys.argv[2]),int(sys.argv[3]))\n"
       "os.write(1,os.environ['P4_ENTRY_SENTINEL'].encode())\n")
if case=="timeout": probe="import time;time.sleep(60)"
if case in ("known_error","short_write","close_failure"):
    probe=("import os,sys,time\nfrom pathlib import Path\np=os.fork()\n"
           "if p==0:\n Path(sys.argv[4]).write_bytes(b'ready')\n while True: time.sleep(.01)\n"
           "end=time.monotonic()+2\nwhile not Path(sys.argv[4]).exists() and time.monotonic()<end: time.sleep(.005)\n"
           "assert Path(sys.argv[4]).exists()\nos._exit(0)\n")
value={"schema":entry.REQUEST_SCHEMA,"nonce":"a"*32,"command":[sys.executable,"-c",probe,str(write_fd),str(identity.st_dev),str(identity.st_ino),str(root/"ready"),argument],
       "cwd":str(root),"stdout":str(root/"command.out"),"stderr":str(root/"command.err"),"stop_by":time.monotonic()+(8 if case=="timeout" else 20)}
if case=="bad_request": value["env"]=sentinel
raw=entry.encode(value)
assert sentinel.encode() not in raw or case=="bad_request"
request_read,request_write=os.pipe()
assert os.write(request_write,raw)==len(raw)
os.close(request_write)
real_stdin,real_write,real_close,real_open,real_read=sys.stdin,os.write,os.close,Path.open,Path.read_bytes
actual_errors,causes,terminals,reads,writes=[],[],[],[],[]
real_run,real_terminal=worker.run_backend,entry.terminal
def observed(*args,**kwargs):
    assert os.get_inheritable(write_fd) is False  # Entry must seal the passed writer BEFORE calling A.
    try: return real_run(*args,**kwargs)
    except worker.LinuxError as error:
        actual_errors.append(error)
        causes.append(error.__cause__)
        raise
def terminal(*args):
    terminals.append(args[2]);return real_terminal(*args)
def forbidden(path):
    reads.append(path);raise AssertionError("entry must never read command files")
def write(fd,data):
    if fd==write_fd:
        writes.append(data)
        return real_write(fd,data[:-1] if case=="short_write" else data)
    return real_write(fd,data)
def close(fd):
    real_close(fd)
    if fd==write_fd and case=="close_failure":
        try: raise KeyError("existing channel context")
        except KeyError: raise TypeError("planted close acknowledgement")
class Output:
    def __init__(self,stream): self.stream=stream
    def fileno(self): return self.stream.fileno()
    def close(self):
        self.stream.close()
        raise OSError(errno.EIO,"planted lost stream acknowledgement")
def opening(path,*args,**kwargs):
    stream=real_open(path,*args,**kwargs)
    return Output(stream) if case=="unknown" and args and args[0]=="xb" else stream
worker.run_backend,entry.terminal,Path.read_bytes,Path.open=observed,terminal,forbidden,opening
os.write,os.close=write,close
log=io.StringIO()
raised=None
with os.fdopen(request_read,"rb") as request_stream:
    sys.stdin=SimpleNamespace(buffer=request_stream)
    try:
        with redirect_stderr(log): entry.main(read_fd if case=="bad_writer" else write_fd)
    except (entry.ProtocolError,worker.LinuxError,TypeError) as error: raised=error
    finally: sys.stdin=real_stdin
os.write,os.close=real_write,real_close
if case=="bad_writer":
    assert isinstance(raised,entry.ProtocolError) and not (root/"command.out").exists()
    real_close(write_fd)
    try: os.fstat(read_fd)
    except OSError as error: assert error.errno==errno.EBADF
    else: raise AssertionError("rejected owned read descriptor not closed")
else:
    payload=os.read(read_fd,entry.RECEIPT_LIMIT+1)
    real_close(read_fd)
    if case in ("ok","known_error","timeout"):
        assert raised is None and len(writes)==1
        result=entry.read_terminal(payload,raw,os.getpid())
        assert sentinel.encode() not in payload and sentinel not in log.getvalue()
        assert argument.encode() not in payload and argument not in log.getvalue()
        if case=="ok":
            assert result["status"]=="ok" and real_read(root/"command.out")==sentinel.encode()
        else:
            reason="timeout" if case=="timeout" else "descendants"
            assert result["status"]=="error" and result["reason"]==reason
            assert actual_errors[0] is terminals[0] and actual_errors[0].__traceback__ is not None
            assert '"reason":"'+reason+'"' in log.getvalue()
            if case=="timeout":
                import subprocess
                assert isinstance(actual_errors[0].__cause__,subprocess.TimeoutExpired)
                assert argument in actual_errors[0].__cause__.cmd
    elif case=="close_failure":
        assert isinstance(raised,TypeError) and isinstance(raised.__context__,KeyError)
        assert raised.owned_process_primary is actual_errors[0] and terminals[0] is actual_errors[0]
        assert actual_errors[0].__cause__ is causes[0]
        assert entry.read_terminal(payload,raw,os.getpid())["status"]=="error"  # Payload alone cannot establish worker-exit success.
    elif case=="short_write":
        assert isinstance(raised,entry.ProtocolError) and len(writes)==1 and not payload.endswith(b"\n")
        assert raised.owned_process_primary is actual_errors[0] is terminals[0] and actual_errors[0].__cause__ is causes[0]
    elif case=="unknown":
        assert raised is actual_errors[0] and raised.quiescent is False and payload==b"" and terminals==[]
    else:
        assert case=="bad_request" and isinstance(raised,entry.ProtocolError) and payload==b""
        assert sentinel not in str(raised) and not (root/"command.out").exists()
    try: os.fstat(write_fd)
    except OSError as error: assert error.errno==errno.EBADF
    else: raise AssertionError("private writer not closed")
assert reads==[]
try: api.reap_any()
except ChildProcessError as error: assert error.errno==errno.ECHILD
else: raise AssertionError("entry fixture left owned children")
print(json.dumps({"case":case,"status":"entry-only"},sort_keys=True))
"""


@pytest.mark.parametrize("case", ENTRY_CASES)
def test_entry_actual_anonymous_pipes_in_fresh_worker_preserve_parent_state(tmp_path, monkeypatch, case):
    if sys.platform != "linux":
        with pytest.raises(worker.LinuxError, match="^p4_linux_worker_linux_only$"):
            entry.main(3)
        return
    with monkeypatch.context() as guard:
        guard.setitem(globals(),"CHILD",ENTRY_CHILD)
        guard.setenv("P4_ENTRY_CASE_ROOT",str(tmp_path))
        run_case(tmp_path,case,expected_status="entry-only")


def test_entry_import_and_refused_parent_role_do_not_mutate_native_state(monkeypatch):
    before = snapshot() if sys.platform == "linux" else None
    calls = []
    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("parent role cannot mutate native state or descriptor ownership")
    with monkeypatch.context() as guard:
        guard.setattr(api.c,"CDLL",forbidden)
        importlib.reload(entry)
        guard.setattr(os,"set_inheritable",forbidden)
        guard.setattr(os,"close",forbidden)
        guard.setattr(api,"reset_sigchld",forbidden)
        guard.setattr(api,"set_subreaper",forbidden)
        with pytest.raises(worker.LinuxError,match="^p4_linux_worker_(worker_context|linux_only)$"):
            entry.main(3)
    assert calls==[]
    if before is not None:
        assert snapshot()==before


@pytest.mark.parametrize("kind,args", [("outcome",(0,False)), ("outcome",(False,True)),
    ("error",("timeout",False)), ("error",("timeout",True,("lost acknowledgement",))),
    ("error",("request_argument_canary",True))])
def test_entry_never_promotes_unknown_or_unclosed_reason_labels_to_terminal(tmp_path,kind,args):
    raw=entry.encode(entry_request(tmp_path))
    constructor=worker.Outcome if kind=="outcome" else worker.LinuxError
    valid=constructor(0,True) if kind=="outcome" else constructor("timeout",True)
    assert entry.read_terminal(entry.terminal(raw,1234,valid),raw,1234)["quiescent"] is True
    result=constructor(*args)
    with pytest.raises(entry.ProtocolError):
        entry.terminal(raw,1234,result)


CONTROL_CASES = ("ok0","ok7","orphan","timeout","system_exit","import_error","hang","malformed","oversize","wrong_context","frame_before_failure","reader_close","late_metadata","parent_signal","crash_writer","missing_eof","flush_failure","backpressure","oversize_request","stop_ack","custody_loss")
CONTROL_CHILD = r"""
import errno,io,json,os,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1])
from tools import p4_linux_control as control,p4_linux_entry as entry,p4_linux_process_api as api
case,root=sys.argv[2],Path(os.environ["P4_CONTROL_CASE_ROOT"])
api.reset_sigchld();api.set_subreaper(True)
real_clock,real_spawn,real_kill,real_waitid,real_close,real_read,real_write,real_pipe=time.monotonic,subprocess.Popen,os.killpg,os.waitid,os.close,os.read,os.write,os.pipe2
real_wait,real_open,nominal=real_spawn.wait,Path.open,control.Controlled
workers,events,pipes,wire,frames,reads,built,returned,duplicates,stolen=[],[],[],[],[],[],[],[],[],[]
log=tempfile.TemporaryFile()
environment_secret="environment_"+str(os.getpid())
argument_secret="argument_"+str(os.getpid())
env={**os.environ,"P4_ENV_SECRET":environment_secret,"P4_ARG_SECRET":argument_secret,"P4_CASE_ROOT":str(root)}
code="import os,sys;os.write(1,os.environ['P4_ENV_SECRET'].encode());raise SystemExit("+("7" if case=="ok7" else "0")+")"
if case in ("orphan","frame_before_failure"):
    code=("import os,sys,time\nfrom pathlib import Path\np=os.fork()\nif p==0:\n"
          " f=open(sys.argv[1],'ab',buffering=0);f.write(b'x')\n Path(sys.argv[2]).write_bytes(b'ready')\n"
          " while True: f.write(b'x');time.sleep(.01)\n"
          "end=time.monotonic()+2\nwhile not Path(sys.argv[2]).exists() and time.monotonic()<end: time.sleep(.005)\n"
          "assert Path(sys.argv[2]).exists()\nos._exit(0)\n")
elif case=="timeout":code="import time;time.sleep(60)"
faults={
 "system_exit":'\ndef main(fd): raise SystemExit(os.environ["P4_ARG_SECRET"])\n',
 "import_error":'\nraise RuntimeError(os.environ["P4_ENV_SECRET"])\n',
 "hang":'\ndef main(fd):\n import time\n while True: time.sleep(1)\n',
 "stop_ack":'\ndef main(fd):\n import time\n while True: time.sleep(1)\n',
 "backpressure":'\ndef main(fd):\n import time\n time.sleep(5);os._exit(7)\n',
 "malformed":'\ndef main(fd): os.write(fd,b"invalid\\n");os.close(fd)\n',
 "oversize":'\ndef main(fd): os.write(fd,b"x"*(RECEIPT_LIMIT+1));os.close(fd)\n',
 "wrong_context":'\n_real_main=main\ndef main(fd):\n original=os.write\n def write(target,data):\n  if target==fd:\n   item=json.loads(data);item["nonce"]="b"*32;data=encode(item)+b"\\n"\n  return original(target,data)\n os.write=write\n _real_main(fd)\n',
 "frame_before_failure":'\n_real_main=main\ndef main(fd):\n original=os.close\n def close(target):\n  original(target)\n  if target==fd: raise TypeError(os.environ["P4_ENV_SECRET"])\n os.close=close\n _real_main(fd)\n',
 "crash_writer":'\ndef main(fd):\n import time\n from pathlib import Path\n root=Path(os.environ["P4_CASE_ROOT"])\n p=os.fork()\n if p==0:\n  f=open(root/"heartbeat","ab",buffering=0);f.write(b"x")\n  (root/"ready").write_text(str(os.getpid()))\n  while True: f.write(b"x");time.sleep(.01)\n end=time.monotonic()+2\n while not (root/"ready").exists() and time.monotonic()<end: time.sleep(.005)\n assert (root/"ready").exists()\n os._exit(7)\n',
 "flush_failure":'\n_real_main=main\ndef main(fd):\n _real_main(fd)\n class Bad:\n  def write(self,value): return len(value)\n  def flush(self): raise SystemExit(os.environ["P4_ENV_SECRET"])\n sys.stderr=Bad()\n',
}
if case in faults:
    fake=root/"fake";(fake/"tools").mkdir(parents=True)
    for name in ("p4_linux_entry","p4_linux_worker","p4_linux_process_api","p4_process_state"):
        shutil.copyfile(Path(sys.argv[1])/"tools"/(name+".py"),fake/"tools"/(name+".py"))
    path=fake/"tools"/"p4_linux_entry.py"
    with path.open("a") as stream:stream.write(faults[case])
    control.ROOT=fake
def spawn(*args,**kwargs):
    kwargs["stderr"]=log
    value=real_spawn(*args,**kwargs);workers.append(value)
    if case=="backpressure":
        import fcntl
        fcntl.fcntl(value.stdin.fileno(),fcntl.F_SETPIPE_SZ,4096)
    return value
def group(pid,number):
    if number:assert not stolen  # Any attempted nonzero group signal after external reap must fail the fixture itself.
    assert workers and pid==workers[0].pid
    if number:
        assert number==signal.SIGKILL and workers[0].returncode is None
        real_waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        events.append("stop")
    else:assert workers[0].returncode is not None
    result=real_kill(pid,number)
    if number and case=="stop_ack":raise OSError(errno.EIO,"planted lost group-stop acknowledgement")
    return result
def wait(value,timeout=None):
    assert value is workers[0] and "stop" in events and 0<timeout<=12
    result=real_wait(value,timeout=timeout);events.append("reap");return result
def waitid(kind,pid,flags):
    state=real_waitid(kind,pid,flags)
    if case=="custody_loss" and state is not None and not stolen:
        assert state.si_pid==workers[0].pid and state.si_code==os.CLD_EXITED and state.si_status==0
        stolen.append(os.waitpid(pid,0))
        return real_waitid(kind,pid,flags)  # Genuine ECHILD after an actual external reap.
    return state
def pipe(flags):
    value=real_pipe(flags);pipes.append(value)
    if case=="missing_eof":duplicates.append(os.dup(value[1]))
    return value
def read(fd,count):
    result=real_read(fd,count)
    if pipes and fd==pipes[0][0]:frames.append(result)
    return result
def write(fd,data):
    if workers and fd==workers[0].stdin.fileno():assert os.get_blocking(fd) is False
    count=real_write(fd,data)
    if workers and fd==workers[0].stdin.fileno():wire.append(data[:count])
    return count
def close(fd):
    real_close(fd)
    if pipes and fd==pipes[0][0] and case=="reader_close":raise OSError(errno.EIO,"planted lost reader close acknowledgement")
def opening(path,*args,**kwargs):
    mode=args[0] if args else kwargs.get("mode","r")
    if path.name in ("command.out","command.err") and "r" in mode:
        reads.append(path);raise AssertionError("controller must not read command outputs")
    return real_open(path,*args,**kwargs)
def late(*args):
    result=nominal(*args);built.append(result)
    control.time=SimpleNamespace(monotonic=lambda:real_clock()+1000,sleep=time.sleep)
    return result
subprocess.Popen,real_spawn.wait,os.killpg,os.waitid,os.pipe2,os.read,os.write,os.close,Path.open=spawn,wait,group,waitid,pipe,read,write,close,opening
if case=="late_metadata":control.Controlled=late
if case=="parent_signal":signal.signal(signal.SIGCHLD,signal.SIG_IGN)
before=(api.get_subreaper(),signal.getsignal(signal.SIGCHLD),os.getsid(0),os.getpgrp())
start=real_clock()
try:
    try:
        value=control.run_control([sys.executable,"-c",code,str(root/"heartbeat"),str(root/"ready"),argument_secret]+(["x"*(entry.REQUEST_LIMIT+1)] if case=="oversize_request" else ["x"*10000] if case=="backpressure" else []),
            env=env,cwd=root,stdout_path=root/"command.out",stderr_path=root/"command.err",deadline=start+(6 if case=="backpressure" else 20),timeout=12)
        returned.append(value)
    except (control.ControlError,ValueError) as error:
        assert case not in ("ok0","ok7","orphan","timeout")
        if case=="stop_ack":assert isinstance(error,control.ControlError) and any(label=="group_stop" for label,detail in error.cleanup)
    else:
        assert type(value) is nominal and case in ("ok0","ok7","orphan","timeout")
        assert value.status==("error" if case in ("orphan","timeout") else "ok")
        if value.status=="ok":assert value.returncode==(7 if case=="ok7" else 0)
        else:assert value.reason==("descendants" if case=="orphan" else "timeout")
    assert before==(api.get_subreaper(),signal.getsignal(signal.SIGCHLD),os.getsid(0),os.getpgrp()) and reads==[]
    for value in workers:
        assert environment_secret not in "".join(value.args) and argument_secret not in "".join(value.args)
    log.seek(0);diagnostics=log.read(65536)
    assert environment_secret.encode() not in diagnostics and argument_secret.encode() not in diagnostics
    if case=="frame_before_failure":
        assert workers[0].returncode==1 and returned==[]
        assert entry.read_terminal(b"".join(frames),b"".join(wire),workers[0].pid)["status"]=="error"
    if case=="late_metadata":assert len(built)==1 and returned==[]
    if case=="backpressure":assert real_clock()-start<6 and len(b"".join(wire))>=4096
    if case=="crash_writer":
        pid=int((root/"ready").read_text())
        fd=api.open_child(pid)
        try:
            end=real_clock()+2
            state=api.child_state(fd)
            while state is None and real_clock()<end:
                time.sleep(.005);state=api.child_state(fd)
            assert state is not None and state.si_code==os.CLD_KILLED and state.si_status==signal.SIGKILL
        finally:real_close(fd)
    if case in ("parent_signal","oversize_request"):assert workers==[]
    if case in ("missing_eof","reader_close"):
        assert workers[0].returncode==0 and returned==[]
        assert entry.read_terminal(b"".join(frames),b"".join(wire),workers[0].pid)["status"]=="ok"
    if case not in ("parent_signal","oversize_request","custody_loss"):assert len(workers)==1 and "stop" in events and "reap" in events
    if case=="custody_loss":
        assert stolen==[(workers[0].pid,0)] and workers[0].returncode is None and workers[0]._child_created is False
        assert returned==[] and events==[]
        def forbidden_poll(*args,**kwargs):raise AssertionError("lost PID must never be polled")
        workers[0]._internal_poll=forbidden_poll
        real_spawn.__del__(workers[0])
    if case in ("system_exit","import_error","flush_failure","frame_before_failure"):assert workers[0].returncode==1
    if case in ("hang","stop_ack"):assert workers[0].returncode==-signal.SIGKILL
finally:
    for value in workers:
        if value.pid in {pid for pid,status in stolen}:value._child_created=False
    os.close,os.killpg,os.waitid,os.read,os.write,os.pipe2=real_close,real_kill,real_waitid,real_read,real_write,real_pipe
    signal.signal(signal.SIGCHLD,signal.SIG_DFL)
    for fd in duplicates:real_close(fd)
    for value in workers:
        if value.returncode is None and value.pid not in {pid for pid,status in stolen}:
            try:fd=api.open_child(value.pid)
            except ChildProcessError:value._child_created=False
            else:
                try:api.signal_child(fd,signal.SIGKILL);real_wait(value,timeout=3)
                finally:real_close(fd)
    end=real_clock()+3
    while True:
        assert real_clock()<end
        try:item=api.reap_any()
        except ChildProcessError:break
        if item is None:
            raw=(Path("/proc/self/task")/str(os.getpid())/"children").read_text()
            for pid in map(int,raw.split()):
                fd=api.open_child(pid)
                try:api.signal_child(fd,signal.SIGKILL)
                finally:real_close(fd)
            time.sleep(.005)
    log.close()
print(json.dumps({"case":case,"status":"control-only"},sort_keys=True))
"""


@pytest.mark.parametrize("case", CONTROL_CASES)
def test_control_real_worker_failures_keep_parent_state_and_never_read_command_files(tmp_path,monkeypatch,case):
    if sys.platform!="linux":
        with pytest.raises(control.ControlError,match="^p4_linux_control_linux_only$"):
            control.run_control([],env={},cwd=tmp_path,stdout_path=tmp_path/"out",stderr_path=tmp_path/"err",deadline=1)
        return
    with monkeypatch.context() as guard:
        guard.setitem(globals(),"CHILD",CONTROL_CHILD)
        guard.setenv("P4_CONTROL_CASE_ROOT",str(tmp_path))
        run_case(tmp_path,case,expected_status="control-only")


def test_control_import_is_inert_and_nonlinux_refusal_has_no_side_effects(monkeypatch):
    before=snapshot() if sys.platform=="linux" else None
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append((args,kwargs))
        raise AssertionError("import/refusal cannot mutate native state or spawn")
    with monkeypatch.context() as guard:
        guard.setattr(api.c,"CDLL",forbidden)
        importlib.reload(control)
        if sys.platform!="linux":
            guard.setattr(subprocess,"Popen",forbidden)
            with pytest.raises(control.ControlError,match="^p4_linux_control_linux_only$"):
                control.run_control([],env={},cwd=".",stdout_path="out",stderr_path="err",deadline=1)
    assert calls==[]
    if before is not None:assert snapshot()==before
