"""Native Win64 ABI and gated disposable-handle tests; Linux refusal is not Windows emulation."""
import subprocess
import sys
import time
from contextlib import ExitStack

import pytest

from tools import p4_windows_job_api as api


def checked(function, *args):
    api.check(function(*args))


def unsupported(tmp_path):
    if sys.platform == "win32":
        return False
    with pytest.raises(OSError, match="^p4_windows_job_api_windows_only$"):
        api.kernel()
    with pytest.raises(OSError, match="^p4_windows_job_api_windows_only$"):
        api.check(True)
    assert list(tmp_path.iterdir()) == []
    return True


def new_job(native, stack):
    handle = native.CreateJobObjectW(None, None)
    api.check(handle)
    stack.callback(checked, native.CloseHandle, handle)
    limits = api.ExtendedLimit()
    limits.basic.flags = api.KILL_ON_JOB_CLOSE
    api.check(native.SetInformationJobObject(handle, api.EXTENDED_LIMIT, api.c.byref(limits), api.c.sizeof(limits)))
    return handle


def active(native, handle):
    state = api.Accounting()
    api.check(native.QueryInformationJobObject(handle, api.BASIC_ACCOUNTING, api.c.byref(state), api.c.sizeof(state), None))
    return state.active


def wait_zero(native, handles):
    deadline = time.monotonic() + 3
    while any(active(native, handle) != 0 for handle in handles):
        assert time.monotonic() < deadline, "owned disposable jobs did not reach zero"
        time.sleep(0.01)
    assert all(active(native, handle) == 0 for handle in handles)


def finish(native, handles, process):
    def close_original():
        if process.returncode is not None:
            process._handle.Close()  # Checked CPython native handle close, only after bounded wait/status.
    with ExitStack() as cleanup:
        cleanup.callback(close_original)
        cleanup.callback(process.wait, timeout=5)
        cleanup.callback(process.kill)  # Original disposable HANDLE; never OpenProcess/PID lookup.
        for handle in handles:
            cleanup.callback(checked, native.TerminateJobObject, handle, 1)
        cleanup.callback(process.stdin.close)


def test_explicit_native_layout_offsets_limit_bits_and_six_function_signatures(tmp_path):
    if unsupported(tmp_path):
        return
    native = api.kernel()
    assert tuple(api.c.sizeof(kind) for kind in (api.HANDLE, api.DWORD, api.BOOL, api.SIZE,
        api.BasicLimit, api.Counters, api.ExtendedLimit, api.Accounting)) == (8, 4, 4, 8, 64, 48, 144, 48)
    assert [getattr(api.BasicLimit, name).offset for name in ("process_time", "job_time", "flags", "minimum", "maximum",
        "active_limit", "affinity", "priority", "scheduling")] == [0, 8, 16, 24, 32, 40, 48, 56, 60]
    assert [getattr(api.ExtendedLimit, name).offset for name in ("basic", "io", "process_memory", "job_memory", "peak_process", "peak_job")] == [0, 64, 112, 120, 128, 136]
    assert [getattr(api.Accounting, name).offset for name in ("user", "kernel", "period_user", "period_kernel",
        "faults", "total", "active", "terminated")] == [0, 8, 16, 24, 32, 36, 40, 44]
    assert api.BasicLimit._fields_[:2] == [("process_time", api.c.c_int64), ("job_time", api.c.c_int64)]
    assert api.Accounting._fields_[:4] == [(name, api.c.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")]
    assert api.Counters._fields_ == [(name, api.c.c_uint64) for name in
        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
    signatures = {
        "CreateJobObjectW": ((api.HANDLE, api.c.c_wchar_p), api.HANDLE),
        "SetInformationJobObject": ((api.HANDLE, api.c.c_int, api.HANDLE, api.DWORD), api.BOOL),
        "AssignProcessToJobObject": ((api.HANDLE, api.HANDLE), api.BOOL),
        "QueryInformationJobObject": ((api.HANDLE, api.c.c_int, api.HANDLE, api.DWORD, api.c.POINTER(api.DWORD)), api.BOOL),
        "TerminateJobObject": ((api.HANDLE, api.DWORD), api.BOOL),
        "CloseHandle": ((api.HANDLE,), api.BOOL)}
    assert all((getattr(native, name).argtypes, getattr(native, name).restype) == wanted for name, wanted in signatures.items())
    with ExitStack() as cleanup:
        handle = new_job(native, cleanup)
        limits = api.ExtendedLimit()
        api.check(native.QueryInformationJobObject(handle, api.EXTENDED_LIMIT, api.c.byref(limits), api.c.sizeof(limits), None))
        assert (api.BASIC_ACCOUNTING, api.EXTENDED_LIMIT, api.KILL_ON_JOB_CLOSE) == (1, 9, 0x2000)
        assert limits.basic.flags == 0x2000 and active(native, handle) == 0


@pytest.mark.parametrize("levels", (1, 2))
def test_original_disposable_handle_is_assigned_and_nested_before_release_byte(tmp_path, levels):
    if unsupported(tmp_path):
        return
    native = api.kernel()
    marker = tmp_path / "released"
    code = ("import os,sys\n"
        "if sys.stdin.buffer.read(1)!=b'R': raise SystemExit(125)\n"
        "with open(sys.argv[1],'xb') as f: f.write(b'owned')\n"
        "os.write(1,b'owned-out');os.write(2,b'owned-err')\n")
    with ExitStack() as cleanup:
        out = cleanup.enter_context((tmp_path / "stdout.bin").open("xb"))
        err = cleanup.enter_context((tmp_path / "stderr.bin").open("xb"))
        handles = [new_job(native, cleanup) for _ in range(levels)]
        process = subprocess.Popen([sys.executable, "-I", "-S", "-c", code, str(marker)], stdin=subprocess.PIPE,
            stdout=out, stderr=err, close_fds=True)
        cleanup.callback(finish, native, handles, process)
        assert not marker.exists()
        for handle in handles:
            api.check(native.AssignProcessToJobObject(handle, int(process._handle)))
            assert active(native, handle) == 1 and not marker.exists()
        process.stdin.write(b"R")
        process.stdin.flush()
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        process._handle.Close()
        wait_zero(native, handles)
    assert marker.read_bytes() == b"owned"
    assert (tmp_path / "stdout.bin").read_bytes() == b"owned-out"
    assert (tmp_path / "stderr.bin").read_bytes() == b"owned-err"


@pytest.mark.parametrize("fault", ("query", "close", "assign", "set"))
def test_failed_native_bool_is_checked_before_zero_or_success_is_consumed(tmp_path, fault):
    if unsupported(tmp_path):
        return
    native = api.kernel()
    with ExitStack() as cleanup:
        handle = new_job(native, cleanup)
        state = api.Accounting()
        assert state.active == 0  # A zero-initialized buffer is not a successful query.
        with pytest.raises(OSError) as error:
            if fault == "query":
                api.check(native.QueryInformationJobObject(handle, -1, api.c.byref(state), api.c.sizeof(state), None))
            elif fault == "close":
                api.check(native.CloseHandle(None))
            elif fault == "assign":
                api.check(native.AssignProcessToJobObject(handle, None))
            else:
                api.check(native.SetInformationJobObject(handle, -1, api.c.byref(state), api.c.sizeof(state)))
        assert error.value.winerror != 0
        assert active(native, handle) == 0  # Only this separate checked query can establish zero.


def test_failed_configuration_closes_only_new_job_and_preserves_native_primary_error(tmp_path):
    if unsupported(tmp_path):
        return
    native = api.kernel()
    closed = []
    def close(handle):
        api.check(native.CloseHandle(handle))
        closed.append(handle)
    with ExitStack() as outer:
        existing = new_job(native, outer)
        created = None
        with pytest.raises(OSError) as error, ExitStack() as rollback:
            created = native.CreateJobObjectW(None, None)
            api.check(created)
            rollback.callback(close, created)
            limits = api.ExtendedLimit()
            api.check(native.SetInformationJobObject(created, -1, api.c.byref(limits), api.c.sizeof(limits)))
        assert error.value.winerror != 0 and closed == [created] and created != existing
        assert active(native, existing) == 0


def test_close_acknowledgement_failure_retains_original_configuration_error_chain(tmp_path):
    if unsupported(tmp_path):
        return
    native = api.kernel()
    with ExitStack() as outer:
        existing = new_job(native, outer)
        created = native.CreateJobObjectW(None, None)
        api.check(created)
        def close_then_refuse():
            api.check(native.CloseHandle(created))
            raise OSError("planted close acknowledgement")
        with pytest.raises(OSError, match="planted close acknowledgement") as error, ExitStack() as rollback:
            rollback.callback(close_then_refuse)
            limits = api.ExtendedLimit()
            api.check(native.SetInformationJobObject(created, -1, api.c.byref(limits), api.c.sizeof(limits)))
        assert isinstance(error.value.__context__, OSError) and error.value.__context__.winerror != 0
        assert active(native, existing) == 0
