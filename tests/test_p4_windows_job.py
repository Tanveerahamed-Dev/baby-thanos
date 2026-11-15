"""Native owned-job controls on Windows; Linux proves refusal, never emulates native job evidence."""
import os
import sys
import time
from pathlib import Path

import pytest

from tools import p4_windows_job as job

REPO = Path(__file__).resolve().parents[1]


def run(root, code, *args, timeout=10):
    return job.run_windows([sys.executable, "-c", code, *map(str, args)], env={**os.environ, "PYTHONPATH": str(REPO)},
        cwd=root, stdout_path=root / "stdout.bin", stderr_path=root / "stderr.bin", deadline=time.monotonic() + 30, timeout=timeout)


def unsupported(root):
    if sys.platform == "win32":
        return False
    with pytest.raises(job.ProcessError, match="^p4_windows_job_windows_only$") as error:
        run(root, "raise SystemExit(0)")
    assert error.value.quiescent is True and list(root.iterdir()) == []
    return True


@pytest.mark.parametrize("exitcode", (0, 7))
def test_native_result_abi_full_handle_assignment_and_stable_streams(tmp_path, exitcode):
    if unsupported(tmp_path):
        return
    assert (job.c.sizeof(job.BasicLimit), job.c.sizeof(job.ExtendedLimit), job.c.sizeof(job.Accounting)) == (64, 144, 48)
    assert [getattr(job.BasicLimit, name).offset for name in ("process_time", "job_time", "flags", "minimum", "maximum", "active_limit", "affinity", "priority", "scheduling")] == [0, 8, 16, 24, 32, 40, 48, 56, 60]
    assert [getattr(job.ExtendedLimit, name).offset for name in ("basic", "io", "process_memory", "job_memory", "peak_process", "peak_job")] == [0, 64, 112, 120, 128, 136]
    assert [getattr(job.Accounting, name).offset for name in ("user", "kernel", "period_user", "period_kernel", "faults", "total", "active", "terminated")] == [0, 8, 16, 24, 32, 36, 40, 44]
    owned = job.Job()
    try:
        limits = job.ExtendedLimit()
        assert owned.api.QueryInformationJobObject(owned.handle, 9, job.c.byref(limits), job.c.sizeof(limits), None)
        assert limits.basic.flags == 0x2000
    finally:
        owned.close()
    result = run(tmp_path, f"import os;os.write(1,b'out');os.write(2,b'err');raise SystemExit({exitcode})")
    assert result.returncode == exitcode and result.quiescent is True
    assert result.stdout == (tmp_path / "stdout.bin").read_bytes() == b"out"
    assert result.stderr == (tmp_path / "stderr.bin").read_bytes() == b"err"


@pytest.mark.parametrize("mode", ("timeout", "early_exit"))
def test_real_grandchild_holds_inherited_streams_and_stops_all_writes_before_refusal(tmp_path, mode):
    if unsupported(tmp_path):
        return
    writer = ("import os,sys,time\n"
        "f=open(sys.argv[1],'ab',buffering=0)\n"
        "os.write(1,b'grand-ready\\n');os.write(2,b'grand-error\\n')\n"
        "while True: f.write(b'x');time.sleep(0.01)\n")
    parent = ("import subprocess,sys,time\nfrom pathlib import Path\n"
        "p=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL)\n"
        "end=time.monotonic()+3\n"
        "while not Path(sys.argv[2]).exists() and time.monotonic()<end: time.sleep(0.01)\n"
        "assert Path(sys.argv[2]).exists()\n" + ("time.sleep(60)\n" if mode == "timeout" else "raise SystemExit(0)\n"))
    before = time.monotonic()
    with pytest.raises(job.ProcessError, match="^p4_windows_job_" + ("timeout" if mode == "timeout" else "descendants") + "$") as error:
        run(tmp_path, parent, writer, tmp_path / "heartbeat")
    assert error.value.quiescent is True and time.monotonic() - before < 10
    out, err, beat = ((tmp_path / name).read_bytes() for name in ("stdout.bin", "stderr.bin", "heartbeat"))
    assert b"grand-ready\n" in out and b"grand-error\n" in err and beat
    time.sleep(0.2)
    assert [(tmp_path / name).read_bytes() for name in ("stdout.bin", "stderr.bin", "heartbeat")] == [out, err, beat]


def test_actual_nested_job_assignment_under_outer_owned_job(tmp_path):
    if unsupported(tmp_path):
        return
    inner = ("import os,sys,time\nfrom pathlib import Path\nfrom tools.p4_windows_job import run_windows\n"
        "r=Path(sys.argv[1])\n"
        "p=run_windows([sys.executable,'-c',\"import os;os.write(1,b'nested-ok')\"],env=dict(os.environ),cwd=r,"
        "stdout_path=r/'inner.out',stderr_path=r/'inner.err',deadline=time.monotonic()+15,timeout=10)\n"
        "assert p.returncode==0 and p.quiescent and p.stdout==b'nested-ok' and p.stderr==b''\n"
        "os.write(1,p.stdout)\n")
    result = run(tmp_path, inner, tmp_path, timeout=20)
    assert result.quiescent is True and result.returncode == 0 and result.stdout == b"nested-ok"
    assert (tmp_path / "inner.out").read_bytes() == b"nested-ok" and (tmp_path / "inner.err").read_bytes() == b""


@pytest.mark.parametrize("stage", ("assign", "release"))
def test_pre_release_failure_reaps_blocked_original_launcher_and_never_starts_command(tmp_path, monkeypatch, stage):
    if unsupported(tmp_path):
        return
    if stage == "assign":
        monkeypatch.setattr(job.Job, "assign", lambda *args: (_ for _ in ()).throw(OSError("planted assignment")))
    else:
        original = job.subprocess.Popen
        class Broken:
            closed = False
            def __init__(self, stream):
                self.stream = stream
            def write(self, value):
                raise BrokenPipeError("planted release")
            def flush(self):
                raise AssertionError("write must refuse first")
            def close(self):
                self.stream.close()
                self.closed = True
        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            process.stdin = Broken(process.stdin)
            return process
        monkeypatch.setattr(job.subprocess, "Popen", spawn)
    with pytest.raises(job.ProcessError, match="^p4_windows_job_" + stage + "$") as error:
        run(tmp_path, "from pathlib import Path;Path('command-started').write_bytes(b'bad')")
    assert error.value.quiescent is True and not (tmp_path / "command-started").exists()
    assert isinstance(error.value.__cause__, OSError)


@pytest.mark.parametrize("fault", ("query", "terminate", "close", "poll_deadline", "popen", "query_after_timeout"))
def test_native_cleanup_uncertainty_never_reads_streams_or_labels_quiescent(tmp_path, monkeypatch, fault):
    if unsupported(tmp_path):
        return
    read_calls = []
    monkeypatch.setattr(job.Path, "read_bytes", lambda path: read_calls.append(path) or b"FORBIDDEN")
    if fault == "popen":
        monkeypatch.setattr(job.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(OSError("planted spawn")))
    elif fault == "poll_deadline":
        real_time, count = time.monotonic, [0]
        def active(self):
            count[0] += 1
            return 1
        monkeypatch.setattr(job.Job, "active", active)
        monkeypatch.setattr(job.time, "monotonic", lambda: real_time() + (40 if count[0] > 1 else 0))
    else:
        method = {"query": "active", "query_after_timeout": "active", "terminate": "terminate", "close": "close"}[fault]
        original = getattr(job.Job, method)
        def fail(self):
            original(self)  # Actual native operation happens; only its acknowledgement is withheld.
            raise OSError("planted " + fault)
        monkeypatch.setattr(job.Job, method, fail)
    with pytest.raises(job.ProcessError) as error:
        run(tmp_path, "import time;print('partial-before-timeout',flush=True);time.sleep(60)" if fault == "query_after_timeout" else "print('retained',flush=True)")
    assert error.value.quiescent is False and read_calls == []
    assert (tmp_path / "stdout.bin").is_file() and (tmp_path / "stderr.bin").is_file()
    assert error.value.cleanup or fault == "popen"
    if fault == "query_after_timeout":
        assert error.value.reason == "timeout" and isinstance(error.value.__cause__, job.subprocess.TimeoutExpired)
        assert "quiescence" in {entry[0] for entry in error.value.cleanup}
        assert (tmp_path / "stdout.bin").stat().st_size > 0  # Retained partial bytes; helper did not read unverified streams.


@pytest.mark.parametrize("fault", ("same_stream", "existing_stdout", "existing_stderr", "expired", "nonpython"))
def test_preflight_and_exclusive_stream_creation_preserve_existing_evidence(tmp_path, fault):
    if unsupported(tmp_path):
        return
    out, err = tmp_path / "stdout.bin", tmp_path / "stderr.bin"
    if fault in ("existing_stdout", "existing_stderr"):
        (out if fault == "existing_stdout" else err).write_bytes(b"prior")
    with pytest.raises(job.ProcessError):
        job.run_windows(["not-python" if fault == "nonpython" else sys.executable, "-c", "raise SystemExit(0)"],
            env=dict(os.environ), cwd=tmp_path, stdout_path=out, stderr_path=out if fault == "same_stream" else err,
            deadline=time.monotonic() + (-1 if fault == "expired" else 30), timeout=10)
    if fault.startswith("existing_"):
        assert (out if fault == "existing_stdout" else err).read_bytes() == b"prior"
    else:
        assert list(tmp_path.iterdir()) == []
