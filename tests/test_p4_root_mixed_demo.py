"""Controlled orchestration faults; the dedicated workflow supplies genuine eighteen-parent-CLI evidence."""
import io
import json
import stat
import sys
from types import SimpleNamespace

import pytest

from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS
from atlas_brain.runner import p4_root_mixed_report, tripwire
from tools import p4_mixed_control as control
from tools import p4_root_mixed_demo as demo
from tools.p4_root_mixed_expected import expected_bundle

NATIVE=("Linux","ubuntu-latest") if sys.platform=="linux" else ("Windows","windows-latest")
CURRENT = {"reviewed_head": "a" * 40, "run_id": "123", "run_attempt": "1", "platform": sys.platform, "runner_os": NATIVE[0], "matrix_os": NATIVE[1]}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def read(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def frame(files):
    receipt = {"schema": "atlas-brain.p4-root-mixed-cli-witness/1", "format": "p4-root-mixed-observations",
        "report_schema": "atlas-brain.p4-root-mixed-observations/1", "manifest_sha256": demo.sha256(files["MANIFEST.sha256"]).hexdigest(),
        "execution": {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4}, "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
            "steps": [{"denied": 4, "id": f"witness/{i:02d}"} for i in range(8)]}, "scope": "runner_witness_only"}
    return b"P4_ROOT_MIXED_CLI_RECEIPT " + encoded(receipt) + b"\nrunner: ok egress_denied=40\n"


@pytest.fixture
def controlled(tmp_path, monkeypatch):
    state = SimpleNamespace(root=tmp_path / "retained", fault="", calls=[], events=[], contexts=0, checks=[], owners=[])
    registration = compile_packs(DECLARATIONS).registration_sha256
    monkeypatch.setattr(demo, "ROOT", state.root)
    monkeypatch.setattr(demo.sys, "argv", ["demo"])
    def current():
        state.contexts += 1
        return CURRENT
    monkeypatch.setattr(demo, "context", current)
    def checked(owner,head):
        state.owners.append(owner);state.checks.append(len(state.calls))
        assert head==CURRENT["reviewed_head"] and owner.retention_ready
        if len(state.checks)==1:assert list(owner.root.iterdir())==[]
        if state.fault=="late_head" and len(state.checks)==2:raise control.CaptureError("context_refused",True)
        if state.fault=="deadline":
            monkeypatch.setattr(control,"time",SimpleNamespace(monotonic=lambda:owner.deadline-1))
    monkeypatch.setattr(demo.MixedCapture,"check_context",checked)
    monkeypatch.setattr(tripwire, "install", lambda: state.fault != "installed")
    def probe():
        count = 3 if state.fault == "probe" else 4
        state.events.extend(["probe"] * count)
        return count
    monkeypatch.setattr(tripwire, "probe", probe)
    monkeypatch.setattr(tripwire, "violations", lambda: tuple(state.events))
    def report(root, budgets):
        if state.fault == "extra_egress":
            state.events.append("extra")
        assert (budgets.bundle_bytes, budgets.artifact_bytes, budgets.artifacts) == (16 * 1024 * 1024, 4 * 1024 * 1024, 128)
        return expected_bundle(root.parent.name, read(root), registration)
    monkeypatch.setattr(p4_root_mixed_report, "analyse_root_mixed_folder", report)
    module=control.linux if sys.platform=="linux" else control.windows
    def saved(command, *, env, cwd, stdout_path, stderr_path, deadline, timeout):
        root,label=stdout_path.parent,stdout_path.name.split(".")[0]
        assert deadline==state.owners[0].deadline and timeout==90 and cwd==control.REPO
        batch = int(label[-1])
        api = "tools.p4_root_mixed_demo" in command
        state.calls.append(("api" if api else root.name, batch, env["PYTHONHASHSEED"], None if api else int(command[-1])))
        try:
            if state.fault in ("exit","timeout","stderr","opaque","unknown"):
                stdout_path.write_bytes(b"partial-out");stderr_path.write_bytes(b"partial-error")
                if state.fault=="opaque":raise TypeError("opaque acknowledgement")
                if state.fault in ("timeout","unknown"):raise module.ProcessError("timeout",state.fault=="timeout")
                return module.Result(9 if state.fault=="exit" else 0,b"partial-out",b"partial-error",True)
            if api:
                state.events.clear()
                buffer = io.BytesIO()
                with monkeypatch.context() as patch:
                    patch.setenv("PYTHONHASHSEED", env["PYTHONHASHSEED"])
                    patch.setattr(demo.sys,"argv",["demo","--api-batch",str(batch)])
                    patch.setattr(demo.sys, "stdout", SimpleNamespace(buffer=buffer))
                    demo.api_batch(CURRENT, batch)
                stdout = buffer.getvalue()
                record = json.loads(stdout.removeprefix(b"P4_ROOT_MIXED_API_BATCH "))
                if state.fault in ("api_context", "api_count", "api_type", "api_case", "api_batch"):
                    if state.fault == "api_context":
                        record["context"]["run_attempt"] = "2"
                    elif state.fault == "api_case":
                        record["case_order"].pop()
                    else:
                        record[{"api_count": "api_runs", "api_type": "api_runs", "api_batch": "batch"}[state.fault]] = 8 if state.fault == "api_count" else 9.0 if state.fault == "api_type" else 1 - batch
                    stdout = b"P4_ROOT_MIXED_API_BATCH " + encoded(record) + b"\n"
                if state.fault == "missing_case":
                    (state.root / "zero_vrrp" / f"api{batch}" / "result.json").unlink()
            else:
                source, out = command[command.index("--evidence") + 1], command[command.index("--out") + 1]
                files = expected_bundle(root.name, read(demo.Path(source)), registration)
                if state.fault == "oracle":
                    header = json.loads(files["result.json"])
                    header["checks"] = "planted"
                    files["result.json"] = encoded(header)
                    files["MANIFEST.sha256"] = b"".join(demo.sha256(files[name]).hexdigest().encode() + b"  " + name.encode() + b"\n" for name in sorted(files) if name != "MANIFEST.sha256")
                demo.write_files(demo.Path(out), files)
                stdout = frame(files)
                if state.fault == "receipt":
                    stdout = stdout.replace(b'"denied":40', b'"denied":39')
                if state.fault == "input":
                    (state.root / "none/inputs1/p4.json").write_bytes(b"changed")
                if state.fault == "inventory" and len(state.calls) == 20:
                    (state.root / "normal/cli0.stderr.txt").rename(state.root / "normal/replayed.stderr.txt")
            (root / f"{label}.stdout.txt").write_bytes(stdout)
            (root / f"{label}.stderr.txt").write_bytes(b"")
            return module.Result(0,stdout,b"",True)
        except ValueError as error:
            (root / f"{label}.stdout.txt").write_bytes(b"partial")
            (root / f"{label}.stderr.txt").write_bytes(str(error).encode())
            raise
    monkeypatch.setattr(module,"run_linux" if sys.platform=="linux" else "run_windows",saved)
    return state


def test_complete_controlled_run_has_exact_twenty_child_calls_and_384_file_inventory(controlled, capsys,monkeypatch):
    clock=SimpleNamespace(monotonic=lambda:100.0)
    monkeypatch.setattr(demo,"time",clock);monkeypatch.setattr(control,"time",clock)
    current=demo.context
    def delayed():clock.monotonic=lambda:150.0;return current()
    monkeypatch.setattr(demo,"context",delayed)
    demo.main()
    assert controlled.owners[0].deadline==520.0
    value = json.loads((controlled.root / "DIGESTS.json").read_bytes())
    assert controlled.calls == [item for batch, (seed, workers) in enumerate(zip(("1", "83"), (1, 4), strict=True)) for item in [("api", batch, seed, None), *((case, batch, seed, workers) for case in demo.CASES)]]
    assert controlled.checks==[0,20] and controlled.owners[0] is controlled.owners[1]
    files = read(controlled.root)
    assert len(files) == 384 and set(value["inventory"]) == set(files) - {"DIGESTS.json"}
    assert value["inventory"] == {name: {"bytes": len(raw), "sha256": demo.sha256(raw).hexdigest()} for name, raw in files.items() if name != "DIGESTS.json"}
    assert value["context"] == CURRENT and (value["api_runs"], value["api_processes"], value["cli_runs"]) == (18, 2, 18)
    assert tuple(value["cases"]) == tuple(sorted(demo.CASES)) and value["case_order"] == list(demo.CASES)
    assert [value["cases"][case]["cells"] for case in demo.CASES] == [18, 18, 18, 2, 18, 18, 18, 18, 16]
    assert all(len(case["batches"]) == 2 for case in value["cases"].values())
    assert capsys.readouterr().out.encode() == b"P4_ROOT_MIXED_RECEIPT " + encoded(value) + b"\n"


@pytest.mark.parametrize("fault", ("api_context", "api_count", "api_type", "api_case", "api_batch", "missing_case", "oracle", "receipt", "input", "inventory", "installed", "probe", "extra_egress", "late_head"))
def test_partial_or_replayed_oracle_case_context_or_witness_never_emits_success(controlled, capsys, fault):
    controlled.fault = fault
    with pytest.raises((ValueError,control.CaptureError)):
        demo.main()
    assert not (controlled.root / "DIGESTS.json").exists()
    assert "P4_ROOT_MIXED_RECEIPT " not in capsys.readouterr().out
    assert (controlled.root / "normal/inputs0/p2.json").is_file() and list(controlled.root.glob("api0.*.txt"))


@pytest.mark.parametrize("fault", ("host", "reviewed", "checkout", "tree", "platform", "run", "attempt", "arguments", "replay"))
def test_exact_native_context_and_fresh_root_guard_before_writing(tmp_path, monkeypatch, fault):
    root = tmp_path / "retained"
    monkeypatch.setattr(demo, "ROOT", root)
    native = ("Linux", "ubuntu-latest") if sys.platform == "linux" else ("Windows", "windows-latest")
    for key, value in {"GITHUB_ACTIONS": "false" if fault == "host" else "true", "P4_ROOT_MIXED_REVIEWED_SHA": "bad" if fault == "reviewed" else "a" * 40,
        "RUNNER_OS": "other" if fault == "platform" else native[0], "P4_ROOT_MIXED_MATRIX_OS": native[1], "GITHUB_RUN_ID": "0123" if fault == "run" else "123", "GITHUB_RUN_ATTEMPT": "0" if fault == "attempt" else "1"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(demo.sys, "argv", ["demo", *(["extra"] if fault == "arguments" else [])])
    def checked(owner,head):
        assert head=="a"*40 and list(owner.root.iterdir())==[]
        raise control.CaptureError("context_refused",True)
    monkeypatch.setattr(demo.MixedCapture,"check_context",checked)
    if fault == "replay":
        root.mkdir()
        (root / "prior").write_bytes(b"preserved")
    with pytest.raises(FileExistsError if fault == "replay" else (ValueError,control.CaptureError)):
        demo.main()
    assert read(root) == ({"prior": b"preserved"} if fault == "replay" else {})


@pytest.mark.parametrize("fault", ("exit", "timeout", "stderr", "deadline", "opaque", "unknown"))
def test_failed_owned_capture_never_reads_or_finalizes_and_keeps_partial_bytes(controlled,monkeypatch,capfd,fault):
    controlled.fault=fault
    reads,finals=[],[]
    def forbidden(*args,**kwargs):reads.append(args);raise AssertionError("failed call cannot read")
    def finalize(*args,**kwargs):finals.append(args);raise AssertionError("failed call cannot finalize")
    monkeypatch.setattr(demo,"snapshot",forbidden)
    monkeypatch.setattr(demo.MixedCapture,"finalize",finalize)
    with pytest.raises(TypeError if fault=="opaque" else control.CaptureError):demo.main()
    assert reads==[] and finals==[] and controlled.checks==[0]
    owner=controlled.owners[0]
    assert owner.retention_ready is (fault not in ("opaque","unknown"))
    files={path.name:path.read_bytes() for path in controlled.root.glob("api0.*.txt")}
    assert files==({} if fault=="deadline" else {"api0.stdout.txt":b"partial-out","api0.stderr.txt":b"partial-error"})
    emitted=capfd.readouterr()
    assert emitted.out=="" and "partial-error" not in emitted.err


@pytest.mark.parametrize("fault", ("manifest", "float", "duplicate", "spacing", "status", "prefix", "newline"))
def test_cli_witness_frame_is_typed_manifest_bound_and_separate(tmp_path, fault):
    files = {"MANIFEST.sha256": b"fixture-manifest"}
    raw = frame(files)
    if fault in ("manifest", "float", "duplicate", "spacing"):
        payload = raw.splitlines()[0].removeprefix(b"P4_ROOT_MIXED_CLI_RECEIPT ")
        record = json.loads(payload)
        if fault == "manifest":
            record["manifest_sha256"] = "0" * 64
        elif fault == "float":
            record["execution"]["egress"]["parent_denied"] = 4.0
        payload = b'{"scope":"other",' + payload[1:] if fault == "duplicate" else json.dumps(record, sort_keys=True).encode() if fault == "spacing" else encoded(record)
        raw = b"P4_ROOT_MIXED_CLI_RECEIPT " + payload + b"\nrunner: ok egress_denied=40\n"
    else:
        raw = raw.replace(b"egress_denied=40", b"egress_denied=36") if fault == "status" else raw.replace(b"MIXED_CLI", b"CLI") if fault == "prefix" else raw.replace(b"\n", b"\v")
    assert demo.cli_receipt(frame(files), files)["scope"] == "runner_witness_only"
    assert demo.cli_receipt(frame(files).replace(b"\n", b"\r\n"), files)["execution"]["egress"]["denied"] == 40
    with pytest.raises(ValueError, match="^p4_root_mixed_demo_cli_receipt$"):
        demo.cli_receipt(raw, files)


@pytest.mark.parametrize("fault",("file","tree","unknown","late","nonregular"))
def test_snapshot_bounds_unknown_and_real_close_before_late_refusal(tmp_path,monkeypatch,fault):
    owner=demo.MixedCapture(tmp_path/"owned",deadline=demo.time.monotonic()+30)
    for index in range(5 if fault=="tree" else 1):
        (owner.root/str(index)).write_bytes(b"x"*(4*1024*1024 if fault=="tree" and index<4 else 4*1024*1024+1 if fault=="file" else 1))
    if fault=="unknown":owner._unknown=True
    real_open,real_lstat=demo.Path.open,demo.Path.lstat
    opened=[]
    def opening(path,*args,**kwargs):
        stream=real_open(path,*args,**kwargs);opened.append(stream)
        if fault=="late":monkeypatch.setattr(demo,"time",SimpleNamespace(monotonic=lambda:owner.deadline+1))
        return stream
    monkeypatch.setattr(demo.Path,"open",opening)
    if fault=="nonregular":monkeypatch.setattr(demo.Path,"lstat",lambda self:SimpleNamespace(st_mode=stat.S_IFIFO) if self==owner.root/"0" else real_lstat(self))
    reason="unknown" if fault=="unknown" else "deadline" if fault=="late" else "snapshot_population" if fault=="nonregular" else "snapshot_budget"
    with pytest.raises(ValueError,match="^p4_root_mixed_demo_"+reason+"$"):demo.snapshot(owner.root,owner)
    assert all(stream.closed for stream in opened)
    if fault in ("unknown","nonregular"):assert opened==[]
