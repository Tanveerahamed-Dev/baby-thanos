"""Owned Windows Python process trees; not a hostile-code sandbox or cryptographic origin proof."""
import ctypes as c
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

HANDLE, DWORD, SIZE = c.c_void_p, c.c_uint32, c.c_size_t
GATE = ("import subprocess,sys\n"
    "if sys.stdin.buffer.read(1)!=b'R': raise SystemExit(125)\n"
    "raise SystemExit(subprocess.call(sys.argv[1:],stdin=subprocess.DEVNULL))\n")


class ProcessError(RuntimeError):
    def __init__(self, reason, quiescent, cleanup=()):
        super().__init__("p4_windows_job_" + reason + (" cleanup=" + repr(cleanup) if cleanup else ""))
        self.reason, self.quiescent, self.cleanup = reason, quiescent, cleanup


@dataclass(frozen=True, slots=True)
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes
    quiescent: bool


class BasicLimit(c.Structure):
    _fields_ = [("process_time", c.c_int64), ("job_time", c.c_int64), ("flags", DWORD),
        ("minimum", SIZE), ("maximum", SIZE), ("active_limit", DWORD), ("affinity", SIZE),
        ("priority", DWORD), ("scheduling", DWORD)]


class Counters(c.Structure):
    _fields_ = [(name, c.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class ExtendedLimit(c.Structure):
    _fields_ = [("basic", BasicLimit), ("io", Counters), ("process_memory", SIZE),
        ("job_memory", SIZE), ("peak_process", SIZE), ("peak_job", SIZE)]


class Accounting(c.Structure):
    _fields_ = [(name, c.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")] + [
        ("faults", DWORD), ("total", DWORD), ("active", DWORD), ("terminated", DWORD)]


def _kernel():
    if c.sizeof(HANDLE) != 8 or (c.sizeof(BasicLimit), c.sizeof(ExtendedLimit), c.sizeof(Accounting)) != (64, 144, 48):
        raise ProcessError("abi", True)
    api = c.WinDLL("kernel32", use_last_error=True)
    api.CreateJobObjectW.argtypes, api.CreateJobObjectW.restype = (HANDLE, c.c_wchar_p), HANDLE
    api.SetInformationJobObject.argtypes, api.SetInformationJobObject.restype = (HANDLE, c.c_int, HANDLE, DWORD), c.c_int
    api.AssignProcessToJobObject.argtypes, api.AssignProcessToJobObject.restype = (HANDLE, HANDLE), c.c_int
    api.QueryInformationJobObject.argtypes, api.QueryInformationJobObject.restype = (HANDLE, c.c_int, HANDLE, DWORD, c.POINTER(DWORD)), c.c_int
    api.TerminateJobObject.argtypes, api.TerminateJobObject.restype = (HANDLE, DWORD), c.c_int
    api.CloseHandle.argtypes, api.CloseHandle.restype = (HANDLE,), c.c_int
    return api


def _check(value):
    if not value:
        raise c.WinError(c.get_last_error())


class Job:
    def __init__(self):
        self.api = _kernel()
        self.handle = self.api.CreateJobObjectW(None, None)
        _check(self.handle)
        limits = ExtendedLimit()
        limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE only: no breakaway or UI restrictions.
        try:
            _check(self.api.SetInformationJobObject(self.handle, 9, c.byref(limits), c.sizeof(limits)))
        except BaseException as primary:
            try:
                _check(self.api.CloseHandle(self.handle))
                self.handle = None
            except BaseException as cleanup:
                raise ProcessError("job_setup", False, (("setup_close", repr(cleanup)),)) from primary
            raise

    def assign(self, original_handle):
        _check(self.api.AssignProcessToJobObject(self.handle, int(original_handle)))

    def active(self):
        state = Accounting()
        _check(self.api.QueryInformationJobObject(self.handle, 1, c.byref(state), c.sizeof(state), None))
        return state.active

    def terminate(self):
        _check(self.api.TerminateJobObject(self.handle, 1))

    def close(self):
        _check(self.api.CloseHandle(self.handle))
        self.handle = None


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise ProcessError("deadline", False)
    return left


def run_windows(command, *, env, cwd, stdout_path, stderr_path, deadline, timeout=90):
    """Return/read streams only after original launcher and owned job are verified stopped."""
    if sys.platform != "win32":
        raise ProcessError("windows_only", True)
    if (type(command) not in (list, tuple) or not command or any(type(part) is not str or not part or "\0" in part for part in command)
            or Path(command[0]).resolve() != Path(sys.executable).resolve() or type(env) is not dict):
        raise ProcessError("arguments", True)
    if type(timeout) not in (int, float) or type(deadline) not in (int, float) or not 5 < timeout < float("inf") or not time.monotonic() < deadline < float("inf"):
        raise ProcessError("deadline", True)
    out_path, err_path = Path(stdout_path), Path(stderr_path)
    if out_path.resolve() == err_path.resolve():
        raise ProcessError("streams", True)
    stop_by = min(deadline, time.monotonic() + timeout)
    run_by = stop_by - 5  # Cleanup is reserved INSIDE both deadlines.
    if run_by <= time.monotonic():
        raise ProcessError("deadline", True)
    job = process = None
    streams, issues = [], []
    attempted = assigned = done = zero = closed = False
    primary, stage, code = None, "job", None
    try:
        job = Job()
        _remaining(run_by)
        stage = "streams"
        out = out_path.open("xb")
        streams.append(out)
        err = err_path.open("xb")
        streams.append(err)
        _remaining(run_by)
        stage, attempted = "spawn", True
        process = subprocess.Popen([sys.executable, "-I", "-S", "-c", GATE, *command], env=env, cwd=cwd,
            stdin=subprocess.PIPE, stdout=out, stderr=err, close_fds=True)
        _remaining(run_by)
        stage = "assign"
        job.assign(process._handle)  # CPython Windows original HANDLE; never reopen a PID.
        assigned = True
        _remaining(run_by)
        stage = "release"
        process.stdin.write(b"R")
        process.stdin.flush()
        process.stdin.close()
        _remaining(run_by)
        stage = "wait"
        code = process.wait(timeout=_remaining(run_by))
        done = True
    except BaseException as error:
        primary = error
        if isinstance(error, ProcessError):
            issues.extend(error.cleanup)
    if process is not None:
        try:
            if not process.stdin.closed:
                process.stdin.close()
        except BaseException as error:
            issues.append(("gate_close", repr(error)))
        if not assigned:
            try:
                process.kill()  # Only the original, still-blocked launcher HANDLE.
            except BaseException as error:
                issues.append(("launcher_kill", repr(error)))
    if done:
        try:
            process._handle.Close()
            closed = True
        except BaseException as error:
            issues.append(("launcher_close", repr(error)))
    if assigned:
        try:
            if done and job.active() > 0:
                primary = primary or ProcessError("descendants", False)
        except BaseException as error:
            issues.append(("query", repr(error)))
        try:
            job.terminate()
        except BaseException as error:
            issues.append(("terminate", repr(error)))
    if process is not None:
        try:
            if not done:
                code = process.wait(timeout=_remaining(stop_by))
                done = True
            if not closed:
                process._handle.Close()  # Checked native close; CPython records the closed state.
                closed = True
        except BaseException as error:
            issues.append(("launcher_wait_close", repr(error)))
    if job is not None:
        try:
            while job.active() != 0:
                time.sleep(min(0.01, _remaining(stop_by)))
            zero = True
        except BaseException as error:
            issues.append(("quiescence", repr(error)))
        try:
            job.close()  # KILL_ON_JOB_CLOSE is a fallback, never a substitute for observed zero.
        except BaseException as error:
            issues.append(("job_close", repr(error)))
    for stream in streams:
        try:
            stream.close()
        except BaseException as error:
            issues.append(("stream_close", repr(error)))
    quiescent = not issues and ((not attempted and process is None) or done and zero)
    if primary is not None or issues:
        reason = primary.reason if isinstance(primary, ProcessError) else "timeout" if isinstance(primary, subprocess.TimeoutExpired) else stage if primary is not None else "cleanup"
        raise ProcessError(reason, quiescent, tuple(issues)) from primary
    if not quiescent:
        raise ProcessError("quiescence", False)
    try:
        _remaining(stop_by)
        if out_path.stat().st_size > 1024 * 1024 or err_path.stat().st_size > 1024 * 1024:
            raise ProcessError("output_limit", True)
        stdout, stderr = out_path.read_bytes(), err_path.read_bytes()
        _remaining(stop_by)
    except ProcessError as error:
        raise ProcessError(error.reason, True) from error
    except OSError as error:
        raise ProcessError("read", True) from error
    return Result(code, stdout, stderr, True)
