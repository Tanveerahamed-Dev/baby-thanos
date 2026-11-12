"""Publish Root CLI bytes and bind separate witnesses only after verified publication."""
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from atlas_brain.runner import cli, coordinator, p4
from tools import p4_estate_cases as estate

FORMAT = "p4-root-observations"
LIMITS = p4.Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128)
RECEIPTS = tuple((f"witness/{index:02d}", 4) for index in range(8))


def fixture(root, *, roots=True):
    root.mkdir()
    inputs = estate.members(canonical, "baseline")
    if roots:
        old = b"   Root guard is disabled on the port\n"
        assert inputs["tree.txt"].count(old) == 2
        inputs["tree.txt"] = inputs["tree.txt"].replace(old, old + b"   Designated root has priority 0, address aBcD.EF01.2345\n")
        side = json.loads(inputs["p4.json"])
        next(row for row in side["captures"] if row["target"] == "tree")["sha256"] = sha256(inputs["tree.txt"]).hexdigest()
        inputs["p4.json"] = canonical(side)
    for name, raw in inputs.items():
        (root / name).write_bytes(raw)
    return inputs


def snapshot(root):
    return {str(path.relative_to(root)).replace("\\", "/"): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def stage(out):
    return out.with_name("." + out.name + ".p4-stage")


def prepared(tmp_path, monkeypatch, *, roots=True):
    evidence, out = tmp_path / "evidence", tmp_path / "out"
    inputs = fixture(evidence, roots=roots)
    monkeypatch.setattr(coordinator.tripwire, "probe", lambda: 4)
    monkeypatch.setattr(coordinator, "_spawn_workers", lambda workers: RECEIPTS)
    return evidence, out, inputs


def witness(files, parent):
    return {"schema": "atlas-brain.p4-root-cli-witness/1", "format": FORMAT,
        "report_schema": "atlas-brain.p4-root-observations/1", "scope": "runner_witness_only",
        "manifest_sha256": sha256(files["MANIFEST.sha256"]).hexdigest(),
        "execution": {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4},
            "egress": {"parent_denied": parent, "coordinator_denied": 4, "worker_denied": 32, "denied": parent + 36},
            "steps": [{"id": step, "denied": denied} for step, denied in RECEIPTS]}}


def child(arguments, *, seed="1"):
    return subprocess.run([sys.executable, "-B", "-m", "atlas_brain.runner", *arguments],
        env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=60, check=False)


def test_real_parent_workers_seeds_and_coordinator_publish_exact_api_bytes_and_manifest_witness(tmp_path):
    evidence = tmp_path / "evidence"
    before = fixture(evidence)
    pure = p4.analyse_root_observations_folder(evidence, LIMITS)
    assert len(pure) == 5 and pure["MANIFEST.sha256"] == manifest({n: raw for n, raw in pure.items() if n != "MANIFEST.sha256"})
    outputs = []
    for role, workers, seed, parent in (("parent", "1", "1", 4), ("parent", "4", "83", 4), ("coordinator", "2", "1", 0)):
        out = tmp_path / (role + workers)
        result = child(["--format", FORMAT, "--role", role, "--evidence", str(evidence), "--out", str(out), "--workers", workers], seed=seed)
        assert result.returncode == 0 and result.stderr == "", result.stderr
        files = snapshot(out)
        assert files == pure and snapshot(evidence) == before and not stage(out).exists()
        expected = "P4_ROOT_CLI_RECEIPT " + canonical(witness(files, parent)).decode() + "\n"
        assert result.stdout == expected + "runner: ok egress_denied=" + str(parent + 36) + "\n"
        assert "execution" not in json.loads(files["result.json"])
        facts = [json.loads(row) for row in files["facts/stp_port_vlan.jsonl"].splitlines()]
        assert len(facts) == 12 and any(row.get("value") == 0 and type(row.get("value")) is int for row in facts)
        assert any(row.get("value") == "aBcD.EF01.2345" for row in facts)
        outputs.append(files)
    assert outputs[0] == outputs[1] == outputs[2]


def test_direct_root_coordinator_calls_api_once_and_prints_receipt_after_real_atomic_publish(tmp_path, monkeypatch, capsys):
    evidence, out, inputs = prepared(tmp_path, monkeypatch)
    analyse, publish, calls = p4.analyse_root_observations_folder, coordinator._publish_p4, []
    pure = analyse(evidence, LIMITS)
    def analysed(root, budgets):
        assert root == evidence and budgets == LIMITS and not out.exists() and not stage(out).exists()
        calls.append("analysis")
        return analyse(root, budgets)
    def publishing(destination, staging, files):
        assert calls == ["analysis"] and capsys.readouterr().out == "" and files == pure
        publish(destination, staging, files)
        assert snapshot(destination) == pure
        calls.append("published")
    monkeypatch.setattr(p4, "analyse_root_observations_folder", analysed)
    monkeypatch.setattr(coordinator, "_publish_p4", publishing)
    assert coordinator.run_p4_root(evidence=evidence, out=out, workers=2, parent_denied=0) == 36
    assert calls == ["analysis", "published"] and snapshot(evidence) == inputs
    assert capsys.readouterr().out == "P4_ROOT_CLI_RECEIPT " + canonical(witness(pure, 0)).decode() + "\n"


@pytest.mark.parametrize("output_format", [None, "legacy", "p4-observations", FORMAT])
def test_parent_forwards_only_selected_nonlegacy_format_and_preserves_exit_status(tmp_path, monkeypatch, output_format):
    evidence, out, _ = prepared(tmp_path, monkeypatch)
    commands = []
    monkeypatch.setattr(cli.subprocess, "run", lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=3))
    arguments = ["--evidence", str(evidence), "--out", str(out), "--workers", "2"]
    assert cli._run(arguments + ([] if output_format is None else ["--format", output_format])) == 3
    expected = [sys.executable, "-m", "atlas_brain.runner", "--role", "coordinator", "--evidence", str(evidence),
        "--out", str(out), "--workers", "2", "--parent-denied", "4"]
    assert commands == [expected + (["--format", output_format] if output_format in ("p4-observations", FORMAT) else [])]
    assert not out.exists() and not stage(out).exists()


def test_worker_cannot_select_root_format_or_publish_any_receipt(tmp_path):
    out = tmp_path / "out"
    result = child(["--role", "worker", "--steps", "witness/00", "--format", FORMAT, "--out", str(out)])
    assert result.returncode == 2 and result.stderr == "runner refused: invalid_format\n" and result.stdout == ""
    assert not out.exists() and not stage(out).exists()


def test_existing_p4_publication_keeps_embedded_witness_and_no_root_receipt(tmp_path, monkeypatch, capsys):
    evidence, out, inputs = prepared(tmp_path, monkeypatch, roots=False)
    pure = p4.analyse_folder(evidence, LIMITS)
    assert coordinator.run_p4(evidence=evidence, out=out, workers=2, parent_denied=4) == 40
    files = snapshot(out)
    head, expected = json.loads(files["result.json"]), json.loads(pure["result.json"])
    assert head.pop("execution") == witness(pure, 4)["execution"] and head == expected
    assert all(files[name] == raw for name, raw in pure.items() if name not in ("result.json", "MANIFEST.sha256"))
    assert files["MANIFEST.sha256"] == manifest({n: raw for n, raw in files.items() if n != "MANIFEST.sha256"})
    assert capsys.readouterr().out == "" and snapshot(evidence) == inputs


@pytest.mark.parametrize("fault", ["analysis", "admission", "late_peer", "scope", "root_scope", "execution", "manifest",
    "missing", "extra", "rawtype", "probe", "missing_step", "float_denied", "duplicate_step", "worker_os",
    "workers_bool", "parent_bool", "parent_count"])
def test_root_profile_analysis_and_typed_witness_fail_before_staging_or_receipt(tmp_path, monkeypatch, capsys, fault):
    spawn = coordinator._spawn_workers
    evidence, out, _ = prepared(tmp_path, monkeypatch)
    analyse, calls = p4.analyse_root_observations_folder, []
    if fault == "admission":
        (evidence / "tree.txt").write_bytes((evidence / "tree.txt").read_bytes() + b"\n")
    before = snapshot(evidence)
    def analysed(*args):
        assert not out.exists() and not stage(out).exists() and calls == []
        calls.append("analysis")
        if fault == "analysis":
            raise coordinator.RunnerRefused("p4_projection_scope")
        files = analyse(*args)
        if fault in ("scope", "root_scope", "execution"):
            head = json.loads(files["result.json"])
            head[{"scope": "scope", "root_scope": "root_scope", "execution": "execution"}[fault]] = "forged"
            files["result.json"] = canonical(head)
        if fault == "manifest":
            files["MANIFEST.sha256"] = b"wrong"
        elif fault == "rawtype":
            files["result.json"] = "not bytes"
        else:
            if fault == "missing":
                files.pop("facts/fhrp_local.jsonl")
            if fault == "extra":
                files["facts/foreign.jsonl"] = b"extra"
            files["MANIFEST.sha256"] = manifest({n: raw for n, raw in files.items() if n != "MANIFEST.sha256"})
        return files
    def probe():
        assert calls == ["analysis"] and not stage(out).exists()
        calls.append("probe")
        return 4.0 if fault == "probe" else 4
    def workers(count):
        assert count == 2 and calls == ["analysis", "probe"] and not stage(out).exists()
        if fault not in ("missing_step", "float_denied", "duplicate_step", "worker_os"):
            return RECEIPTS
        def completed(command, **kwargs):
            assert "--format" not in command
            if fault == "worker_os":
                raise OSError("spawn failed")
            batch = command[command.index("--steps") + 1].split(",")
            selected = batch[:-1] if fault == "missing_step" else batch[:-1] + [batch[0]] if fault == "duplicate_step" else batch
            records = [{"step": step, "denied": 4.0 if fault == "float_denied" else 4} for step in selected]
            return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps(row) for row in records))
        monkeypatch.setattr(coordinator.subprocess, "run", completed)
        return spawn(count)
    monkeypatch.setattr(p4, "analyse_root_observations_folder", analysed)
    monkeypatch.setattr(coordinator.tripwire, "probe", probe)
    monkeypatch.setattr(coordinator, "_spawn_workers", workers)
    if fault == "late_peer":
        monkeypatch.setattr(p4.StandbyBriefPack, "finish", lambda *args: (_ for _ in ()).throw(ValueError("hsrp_test_finish")))
    code = ("invalid_workers" if fault == "workers_bool" else "invalid_parent_witness" if fault in ("parent_bool", "parent_count")
        else "p4_projection_scope" if fault == "analysis" else "p4_p4_capture_hash" if fault == "admission"
        else "p4_hsrp_test_finish" if fault == "late_peer" else "egress_witness_failed" if fault == "probe"
        else "worker_protocol_failed" if fault in ("missing_step", "float_denied", "duplicate_step", "worker_os") else "p4_output_invalid")
    with pytest.raises(coordinator.RunnerRefused, match="^" + code + "$"):
        coordinator.run_p4_root(evidence=evidence, out=out, workers=True if fault == "workers_bool" else 2,
            parent_denied=False if fault == "parent_bool" else 99 if fault == "parent_count" else 4)
    assert not out.exists() and not stage(out).exists() and capsys.readouterr().out == "" and snapshot(evidence) == before


@pytest.mark.parametrize("which", ["out", "stage"])
@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_root_route_refuses_preexisting_paths_without_touching_them(tmp_path, monkeypatch, capsys, which, kind):
    evidence, out, _ = prepared(tmp_path, monkeypatch)
    path = out if which == "out" else stage(out)
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "marker"
    marker.write_bytes(b"preserve")
    if kind == "file":
        path.write_bytes(b"preserve")
    elif kind == "directory":
        path.mkdir()
        (path / "marker").write_bytes(b"preserve")
    else:
        path.symlink_to(target, target_is_directory=True)
    original = path.lstat()[:3]
    monkeypatch.setattr(p4, "analyse_root_observations_folder", lambda *args: pytest.fail("unsafe output analysed"))
    with pytest.raises(coordinator.RunnerRefused, match="^" + ("output_exists" if which == "out" else "output_staging_exists") + "$"):
        coordinator.run_p4_root(evidence=evidence, out=out, workers=1, parent_denied=4)
    assert path.lstat()[:3] == original and marker.read_bytes() == b"preserve" and capsys.readouterr().out == ""
    preserved = path if kind == "file" else path / "marker"
    assert preserved.read_bytes() == b"preserve"


@pytest.mark.parametrize("overlap", ["same", "inside", "ancestor", "parent_link", "nameless"])
def test_root_route_reuses_overlap_and_parent_link_refusals_before_analysis(tmp_path, monkeypatch, capsys, overlap):
    evidence, normal, _ = prepared(tmp_path, monkeypatch)
    out = Path(".") if overlap == "nameless" else evidence if overlap == "same" else evidence / "out" if overlap == "inside" else tmp_path if overlap == "ancestor" else normal
    if overlap == "parent_link":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        linked = tmp_path / "link"
        linked.symlink_to(elsewhere, target_is_directory=True)
        out = linked / "out"
    monkeypatch.setattr(p4, "analyse_root_observations_folder", lambda *args: pytest.fail("overlap analysed"))
    code = "output_parent_invalid" if overlap == "parent_link" else "evidence_output_unreadable" if overlap == "nameless" else "evidence_output_overlap"
    with pytest.raises(coordinator.RunnerRefused, match="^" + code + "$"):
        coordinator.run_p4_root(evidence=evidence, out=out, workers=1, parent_denied=4)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("fault", ["open", "partial_write", "short_write", "readback", "rename", "replacement", "inventory", "cleanup"])
def test_root_publication_failure_cleanup_is_owned_and_cannot_print_success_receipt(tmp_path, monkeypatch, capsys, fault):
    evidence, out, before = prepared(tmp_path, monkeypatch)
    staging = stage(out)
    first, target = staging / "MANIFEST.sha256", staging / "facts/stp_port_vlan.jsonl"
    real_open, real_read, real_rename, real_unlink = Path.open, Path.read_bytes, Path.rename, Path.unlink
    @contextmanager
    def opened(path, *args, **kwargs):
        if path == target and args == ("xb",):
            if fault == "replacement":
                real_rename(first, tmp_path / "displaced")
                first.write_bytes(b"foreign")
            if fault == "inventory":
                (staging / "unknown").write_bytes(b"preserve")
            if fault in ("open", "replacement", "cleanup"):
                raise OSError("injected open failure")
        with real_open(path, *args, **kwargs) as stream:
            def write(raw):
                if path == target and fault == "partial_write":
                    stream.write(raw[:1])
                    raise OSError("injected partial write")
                return stream.write(raw[:-1] if path == target and fault == "short_write" else raw)
            yield SimpleNamespace(write=write) if args == ("xb",) else stream
    def read(path):
        return b"changed" if path == staging / "result.json" and fault == "readback" else real_read(path)
    def rename(path, *args, **kwargs):
        if path == staging and fault == "rename":
            raise OSError("injected rename failure")
        return real_rename(path, *args, **kwargs)
    def unlink(path, *args, **kwargs):
        if path == first and fault == "cleanup":
            raise OSError("injected cleanup failure")
        return real_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", opened)
    monkeypatch.setattr(Path, "read_bytes", read)
    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr(Path, "unlink", unlink)
    code = "output_verification_failed" if fault in ("short_write", "readback", "inventory") else "output_unwritable"
    with pytest.raises(coordinator.RunnerRefused, match="^" + code + "$") as refusal:
        coordinator.run_p4_root(evidence=evidence, out=out, workers=2, parent_denied=4)
    assert not out.exists() and capsys.readouterr().out == "" and snapshot(evidence) == before
    if fault in ("replacement", "inventory", "cleanup"):
        assert staging.is_dir()
        if fault == "inventory":
            assert real_read(staging / "unknown") == b"preserve"
        elif fault == "replacement":
            assert real_read(first) == b"foreign" and real_read(tmp_path / "displaced")
        else:
            assert real_read(first) and str(refusal.value.__cause__) == "injected open failure"
    else:
        assert not staging.exists()
