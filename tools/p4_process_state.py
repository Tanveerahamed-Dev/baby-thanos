"""Process result/error/deadline metadata only; never proves ownership, quiescence, execution or qualification."""
import ctypes
import subprocess
import sys
import time
from dataclasses import dataclass


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


FAILURES = (OSError, ValueError, ctypes.ArgumentError, subprocess.SubprocessError, ProcessError, KeyboardInterrupt, SystemExit)


def attempt(issues, label, operation):
    """Collect only declared OS/stream/ctypes/Popen/deadline/cancellation failures."""
    try:
        return operation()
    except FAILURES as error:
        issues.append((label, repr(error)))
        return None


def remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise ProcessError("deadline", False)
    return left


def retain_pending(primary, issues):
    """Retain an actual stored primary without changing cause/context or suppressing the pending exception.

    False means structured primary attachment failed or conflicted; True only describes metadata,
    never process quiescence or permission to emit success. A note can fail while
    the actual primary object remains attached. The contract covers reviewed
    parent-side builtin/native errors plus MemoryError in annotation. Custom
    exception hooks raising other errors are outside scope. Within this scope,
    the helper does not consume the pending exception.
    """
    pending = sys.exception()
    if pending is None:
        return True
    retained = True
    if primary is not None:
        try:
            previous = getattr(pending, "owned_process_primary", None)
            if previous is None:
                pending.owned_process_primary = primary
            elif previous is not primary:
                retained = False  # Keep the earlier actual object; conflict is explicitly unknown.
        except MemoryError:
            retained = False
    if primary is not None or issues:
        try:
            pending.add_note("stored primary: " + repr(primary) + "; cleanup: " + repr(issues))
        except MemoryError:
            pass  # Annotation failure must not replace the exception already propagating.
    return retained
