"""Linux LP64 capability primitives for dedicated child supervisors; no tree/quiescence qualification.

Mutating calls belong only in an isolated single-reaper child. Import performs no native call.
The caller owns returned pidfds. Proc listings never establish child ownership or absence.
"""
from __future__ import annotations

import ctypes as c
import errno
import os
import signal
import sys
from contextlib import ExitStack

SET_SUBREAPER, GET_SUBREAPER, WALL = 36, 37, 0x40000000


def _linux() -> None:
    if sys.platform != "linux" or (c.sizeof(c.c_void_p), c.sizeof(c.c_ulong), c.sizeof(c.c_int)) != (8, 8, 4):
        raise OSError("p4_linux_process_api_linux_lp64_only")


def _prctl(option: int, value: int) -> None:
    _linux()
    libc = c.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (c.c_int, c.c_ulong, c.c_ulong, c.c_ulong, c.c_ulong)
    libc.prctl.restype = c.c_int
    c.set_errno(0)
    result = libc.prctl(option, value, 0, 0, 0)
    if result != 0:
        number = (c.get_errno() or errno.EIO) if result < 0 else errno.EPROTO
        raise OSError(number, os.strerror(number))


def get_subreaper() -> bool:
    """Read-only native query; never changes the caller's reaper setting."""
    value = c.c_int(-1)
    _prctl(GET_SUBREAPER, c.addressof(value))
    if value.value not in (0, 1):
        raise OSError(errno.EPROTO, "invalid child-subreaper query")
    return bool(value.value)


def set_subreaper(enabled: bool) -> None:
    _linux()
    if type(enabled) is not bool:
        raise TypeError("subreaper requires bool")
    _prctl(SET_SUBREAPER, int(enabled))


def reset_sigchld() -> None:
    _linux()
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def child_state(fd: int) -> os.waitid_result | None:
    """P_PIDFD validates CURRENT child ownership; WNOWAIT never reaps the target."""
    _linux()
    if type(fd) is not int or fd < 0:
        raise ValueError("invalid pidfd")
    return os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT | WALL)


def open_child(pid: int) -> int:
    """Return a held descriptor only after native child-ownership validation."""
    _linux()
    if type(pid) is not int or pid <= 0:
        raise ValueError("invalid child pid")
    fd = None
    with ExitStack() as cleanup:
        cleanup.callback(lambda: os.close(fd) if fd is not None else None)
        fd = os.pidfd_open(pid, 0)
        child_state(fd)
        cleanup.pop_all()
        return fd


def signal_child(fd: int, number: int = 0) -> None:
    """Signal a validated held child descriptor; never a numeric PID from proc."""
    _linux()
    if type(number) not in (int, signal.Signals) or number not in (0, signal.SIGKILL):
        raise ValueError("unsupported child signal")
    child_state(fd)  # ECHILD/permission/availability uncertainty propagates BEFORE signalling.
    signal.pidfd_send_signal(fd, number, None, 0)


def reap_any() -> os.waitid_result | None:
    """Dedicated sole-reaper primitive; use after the original command is reaped.

    None means an eligible child still exists; only ECHILD closes that population.
    This primitive alone establishes neither descendant ownership nor quiescence.
    """
    _linux()
    return os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | WALL)
