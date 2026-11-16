"""Read stable Linux command streams only after this adapter's own fresh controller completes.

Trusted artifact directories with no external writers are premises; leaf refusal is not ancestor/hardlink authentication.
Result/ProcessError metadata never provides independent origin, health, file ownership or upload authority.
"""
import os
import stat
import sys
from pathlib import Path

from tools import p4_linux_control as control
from tools import p4_process_state as metadata

Result = metadata.Result
LIMIT = 1024 * 1024


class ProcessError(metadata.ProcessError):
    def __init__(self, reason, quiescent, cleanup=()):
        RuntimeError.__init__(self, "p4_linux_process_" + reason)
        self.reason, self.quiescent, self.cleanup = reason, quiescent, cleanup


def _opener(path, flags):
    return os.open(path, flags | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)


def _read(path):
    with open(path, "rb", opener=_opener) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ProcessError("regular_stream", True)
        data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ProcessError("output_limit", True)
    return data


def run_linux(command, *, env, cwd, stdout_path, stderr_path, deadline, timeout=90):
    """Own the complete control call; reject errors before opening either captured stream."""
    if sys.platform != "linux":
        raise ProcessError("linux_only", True)
    try:
        value = control.run_control(command, env=env, cwd=cwd, stdout_path=stdout_path, stderr_path=stderr_path,
            deadline=deadline, timeout=timeout)
    except metadata.FAILURES as error:
        cleanup = error.cleanup if isinstance(error, metadata.ProcessError) else ()
        raise ProcessError("control", False, cleanup) from error
    if type(value) is not control.Controlled:
        raise ProcessError("invalid_control", False)
    if value.status == "error":
        if value.returncode is not None or type(value.reason) is not str or value.reason not in control.entry.REASONS:
            raise ProcessError("invalid_control", False)
        raise ProcessError("worker_" + value.reason, True)
    if value.status != "ok" or value.reason != "" or type(value.returncode) is not int:
        raise ProcessError("invalid_control", False)
    try:
        control.remaining(value.stop_by)
        stdout = _read(Path(stdout_path))
        control.remaining(value.stop_by)
        stderr = _read(Path(stderr_path))
        control.remaining(value.stop_by)
        result = Result(value.returncode, stdout, stderr, True)
        control.remaining(value.stop_by)  # AFTER real reads, checked closes and immutable Result construction.
    except control.ControlError as error:
        raise ProcessError("deadline", True) from error
    except (OSError, ValueError) as error:
        raise ProcessError("read", True) from error
    return result
