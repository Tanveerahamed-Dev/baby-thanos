"""Win64 Job Object ABI foundation only; no process-tree supervision, origin or qualification claim."""
import ctypes as c
import sys

HANDLE, DWORD, BOOL, SIZE = c.c_void_p, c.c_uint32, c.c_int32, c.c_size_t
BASIC_ACCOUNTING, EXTENDED_LIMIT, KILL_ON_JOB_CLOSE = 1, 9, 0x2000


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


def _windows():
    if sys.platform != "win32":
        raise OSError("p4_windows_job_api_windows_only")


def check(value):
    """Check a native BOOL/HANDLE result before consuming output or claiming success."""
    _windows()
    if not value:
        raise c.WinError(c.get_last_error())


def kernel():
    """Load explicit standard-library bindings only on the supported native Win64 ABI."""
    _windows()
    if (c.sizeof(HANDLE), c.sizeof(DWORD), c.sizeof(BOOL), c.sizeof(SIZE),
            c.sizeof(BasicLimit), c.sizeof(Counters), c.sizeof(ExtendedLimit), c.sizeof(Accounting)) != (8, 4, 4, 8, 64, 48, 144, 48):
        raise OSError("p4_windows_job_api_abi")
    api = c.WinDLL("kernel32", use_last_error=True)
    api.CreateJobObjectW.argtypes, api.CreateJobObjectW.restype = (HANDLE, c.c_wchar_p), HANDLE
    api.SetInformationJobObject.argtypes, api.SetInformationJobObject.restype = (HANDLE, c.c_int, HANDLE, DWORD), BOOL
    api.AssignProcessToJobObject.argtypes, api.AssignProcessToJobObject.restype = (HANDLE, HANDLE), BOOL
    api.QueryInformationJobObject.argtypes, api.QueryInformationJobObject.restype = (HANDLE, c.c_int, HANDLE, DWORD, c.POINTER(DWORD)), BOOL
    api.TerminateJobObject.argtypes, api.TerminateJobObject.restype = (HANDLE, DWORD), BOOL
    api.CloseHandle.argtypes, api.CloseHandle.restype = (HANDLE,), BOOL
    return api
