"""Owned Windows Python process trees; not a hostile-code sandbox or cryptographic origin proof."""
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from tools import p4_process_state as process_state
from tools import p4_windows_job_api as abi

c, BasicLimit, ExtendedLimit, Accounting = abi.c, abi.BasicLimit, abi.ExtendedLimit, abi.Accounting
GATE = ("import subprocess,sys\n" "if sys.stdin.buffer.read(1)!=b'R': raise SystemExit(125)\n" "raise SystemExit(subprocess.call(sys.argv[1:],stdin=subprocess.DEVNULL))\n")

ProcessError, Result, FAILURES = process_state.ProcessError, process_state.Result, process_state.FAILURES
_attempt, _remaining, _retain_pending = process_state.attempt, process_state.remaining, process_state.retain_pending


class Job:
    def __init__(self):
        self.api = abi.kernel()
        ready, primary, issues = False, None, []
        self.handle = self.api.CreateJobObjectW(None, None)
        try:
            try:
                abi.check(self.handle)
                limits = ExtendedLimit()
                limits.basic.flags = abi.KILL_ON_JOB_CLOSE  # No breakaway or UI restrictions.
                abi.check(self.api.SetInformationJobObject(self.handle, abi.EXTENDED_LIMIT, c.byref(limits), c.sizeof(limits)))
                ready = True
            except FAILURES as error:
                primary = error
        finally:
            try:
                if not ready and self.handle:
                    _attempt(issues, "setup_close", self.close)
            finally:
                _retain_pending(primary, issues)
        if primary is not None:
            raise ProcessError("job_setup", not issues, tuple(issues)) from primary

    def assign(self, original_handle):
        abi.check(self.api.AssignProcessToJobObject(self.handle, int(original_handle)))

    def active(self):
        state = Accounting()
        abi.check(self.api.QueryInformationJobObject(self.handle, abi.BASIC_ACCOUNTING, c.byref(state), c.sizeof(state), None))
        return state.active

    def terminate(self):
        abi.check(self.api.TerminateJobObject(self.handle, 1))

    def close(self):
        abi.check(self.api.CloseHandle(self.handle))
        self.handle = None


def run_windows(command, *, env, cwd, stdout_path, stderr_path, deadline, timeout=90):
    """Return/read streams only after original launcher and owned job are verified stopped."""
    if sys.platform != "win32":
        raise ProcessError("windows_only", True)
    if (type(command) not in (list, tuple) or not command or any(type(part) is not str or not part or "\0" in part for part in command) or Path(command[0]).resolve() != Path(sys.executable).resolve() or type(env) is not dict):
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
    issues = []
    out = err = None
    attempted = assigned = done = zero = False
    primary, stage, code = None, "job", None

    def close_handle():
        if process is not None and done and not process._handle.closed:
            process._handle.Close()

    def detect_descendants():
        nonlocal primary
        if process is not None and assigned and done:
            _attempt(issues, "launcher_close", close_handle)
            active = _attempt(issues, "query", job.active)
            if active is not None and active > 0:
                primary = primary or ProcessError("descendants", False)

    def stop():
        if process is not None:
            if assigned:
                job.terminate()
            else:
                process.kill()  # Original blocked launcher HANDLE only, never a reopened PID.

    def reap():
        nonlocal done, code
        if process is not None and not done:
            code = process.wait(timeout=_remaining(stop_by))
            done = True

    def quiet():
        nonlocal zero
        if job is not None:
            while job.active() != 0:
                time.sleep(min(0.01, _remaining(stop_by)))
            zero = True

    cleanup = ExitStack()
    for label, operation in (("stream_close", lambda: out.close() if out is not None else None), ("stream_close", lambda: err.close() if err is not None else None),
        ("job_close", lambda: job.close() if job is not None else None), ("quiescence", quiet),
        ("launcher_close", close_handle), ("launcher_wait", reap), ("stop", stop), ("detect", detect_descendants), ("gate_close", lambda: process.stdin.close() if process is not None and not process.stdin.closed else None)):
        cleanup.callback(_attempt, issues, label, operation)
    try:
        with cleanup:
            try:
                job = Job()
                _remaining(run_by)
                stage = "streams"
                out = out_path.open("xb")
                err = err_path.open("xb")
                _remaining(run_by)
                stage, attempted = "spawn", True
                process = subprocess.Popen([sys.executable, "-I", "-S", "-c", GATE, *command], env=env, cwd=cwd, stdin=subprocess.PIPE, stdout=out, stderr=err, close_fds=True)
                _remaining(run_by)
                stage = "assign"
                job.assign(process._handle)  # CPython original HANDLE before the command release byte.
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
            except FAILURES as error:
                primary = error
                if isinstance(error, ProcessError):
                    issues.extend(error.cleanup)
    finally:
        _retain_pending(primary, issues)
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
