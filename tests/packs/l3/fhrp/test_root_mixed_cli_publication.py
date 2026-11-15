"""Root9 CLI publishes pure API bytes; separate witnesses confer no network or acceptance authority."""
import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_root_mixed_report import prepared as prepare_inputs

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from atlas_brain.evidence.admission import Budgets
from atlas_brain.runner import cli, coordinator
from atlas_brain.runner import p4_root_mixed_report as report

FORMAT = "p4-root-mixed-observations"
LIMITS = Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128)
RECEIPTS = tuple((f"witness/{index:02d}", 4) for index in range(8))


def snapshot(root):
    return {str(path.relative_to(root)).replace("\\", "/"): path.read_bytes()
        for path in root.rglob("*") if path.is_file()}


def stage(out):
    return out.with_name("." + out.name + ".p4-stage")


def estate(root):
    root.mkdir()
    return prepare_inputs(root)


def witness(files, parent):
    return {"schema": "atlas-brain.p4-root-mixed-cli-witness/1", "format": FORMAT,
        "report_schema": "atlas-brain.p4-root-mixed-observations/1", "scope": "runner_witness_only",
        "manifest_sha256": sha256(files["MANIFEST.sha256"]).hexdigest(),
        "execution": {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4},
            "egress": {"parent_denied": parent, "coordinator_denied": 4, "worker_denied": 32, "denied": parent + 36},
            "steps": [{"id": name, "denied": count} for name, count in RECEIPTS]}}


def child(arguments, *, seed="1"):
    return subprocess.run([sys.executable, "-B", "-m", "atlas_brain.runner", *arguments],
        env={**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, check=False, timeout=120)


def test_real_parent_workers_seeds_and_direct_coordinator_preserve_all_five_api_bytes(tmp_path):
    evidence = tmp_path / "inputs"
    before = estate(evidence)
    pure = report.analyse_root_mixed_folder(evidence, LIMITS)
    outputs = []
    for role, workers, seed, parent in (("parent", "1", "1", 4), ("parent", "4", "83", 4), ("coordinator", "2", "1", 0)):
        out = tmp_path / (role + workers)
        completed = child(["--role", role, "--format", FORMAT, "--evidence", str(evidence),
            "--out", str(out), "--workers", workers], seed=seed)
        assert completed.returncode == 0 and completed.stderr == "", completed.stderr
        files = snapshot(out)
        assert files == pure and snapshot(evidence) == before and not stage(out).exists()
        expected = "P4_ROOT_MIXED_CLI_RECEIPT " + canonical(witness(files, parent)).decode("ascii") + "\n"
        assert completed.stdout == expected + f"runner: ok egress_denied={parent + 36}\n"
        header = json.loads(files["result.json"])
        assert "execution" not in header and header["checks"] == "not_implemented"
        rows = [json.loads(line) for name, raw in files.items() if name.startswith("facts/") for line in raw.splitlines()]
        assert len({row["fact"] for row in rows}) == 9
        assert any(row["value"].get("value") == 0 and type(row["value"].get("value")) is int for row in rows)
        assert any(row["value"].get("value") is False for row in rows)
        outputs.append(files)
    assert outputs[0] == outputs[1] == outputs[2]


def test_direct_route_analyses_once_closes_witnesses_and_prints_only_after_shared_publication(tmp_path, monkeypatch, capsys):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    before = estate(evidence)
    analyse, publish, events = report.analyse_root_mixed_folder, coordinator._publish_p4, []
    pure = analyse(evidence, LIMITS)
    owner = report.owning.RootMixedComponentRun
    init, build, created, built = owner.__init__, owner.build, [], []
    def starting(self, root, budgets):
        created.append(self)
        init(self, root, budgets)
    def building(self):
        built.append(self)
        return build(self)
    monkeypatch.setattr(owner, "__init__", starting)
    monkeypatch.setattr(owner, "build", building)
    def analysing(root, budgets):
        assert root is evidence and budgets == LIMITS and not out.exists() and not stage(out).exists()
        events.append("analysis")
        return analyse(root, budgets)
    def probing():
        assert events == ["analysis"] and not stage(out).exists()
        events.append("probe")
        return 4
    def spawning(workers):
        assert events == ["analysis", "probe"] and workers == 2 and not stage(out).exists()
        events.append("workers")
        return RECEIPTS
    def publishing(destination, staging, files):
        assert events == ["analysis", "probe", "workers"] and capsys.readouterr().out == "" and files == pure
        publish(destination, staging, files)
        assert snapshot(destination) == pure
        events.append("published")
    monkeypatch.setattr(report, "analyse_root_mixed_folder", analysing)
    monkeypatch.setattr(coordinator.tripwire, "probe", probing)
    monkeypatch.setattr(coordinator, "_spawn_workers", spawning)
    monkeypatch.setattr(coordinator, "_publish_p4", publishing)
    assert coordinator.run_p4_root_mixed(evidence=evidence, out=out, workers=2, parent_denied=0) == 36
    assert events == ["analysis", "probe", "workers", "published"] and snapshot(evidence) == before
    assert len(created) == 1 and built == created
    assert capsys.readouterr().out == "P4_ROOT_MIXED_CLI_RECEIPT " + canonical(witness(pure, 0)).decode("ascii") + "\n"


@pytest.mark.parametrize("selected", [None, "legacy", "p4-observations", "p4-root-observations", FORMAT])
def test_parent_forwards_only_explicit_nonlegacy_mode_and_preserves_exit_status(tmp_path, monkeypatch, selected):
    evidence, commands = tmp_path / "inputs", []
    estate(evidence)
    out = tmp_path / "out"
    monkeypatch.setattr(cli.tripwire, "probe", lambda: 4)
    monkeypatch.setattr(cli.subprocess, "run", lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=3))
    arguments = ["--evidence", str(evidence), "--out", str(out), "--workers", "2"]
    assert cli._run(arguments + ([] if selected is None else ["--format", selected])) == 3
    expected = [sys.executable, "-m", "atlas_brain.runner", "--role", "coordinator", "--evidence", str(evidence),
        "--out", str(out), "--workers", "2", "--parent-denied", "4"]
    assert commands == [expected + (["--format", selected] if selected not in (None, "legacy") else [])]
    assert not out.exists() and not stage(out).exists()


@pytest.mark.parametrize("arguments", [("--format", "other"), ("--role", "worker", "--steps", "witness/00", "--format", FORMAT)])
def test_invalid_and_worker_formats_refuse_without_any_receipt_or_output(tmp_path, arguments):
    out = tmp_path / "out"
    completed = child([*arguments, "--evidence", str(tmp_path), "--out", str(out)])
    assert completed.returncode == 2 and completed.stdout == "" and completed.stderr == "runner refused: invalid_format\n"
    assert not out.exists() and not stage(out).exists()


@pytest.mark.parametrize("fault", ["analysis", "os", "budget", "late_owner", "schema", "scope", "checks",
    "qualification", "semantic_group", "root_scope", "execution", "manifest", "missing", "extra", "json", "not_object", "bytes_type",
    "probe", "probe_bool", "worker", "worker_os", "workers_bool", "parent_bool", "parent_count"])
def test_analysis_profile_budget_and_witness_failures_close_before_staging(tmp_path, monkeypatch, capsys, fault):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    before = estate(evidence)
    analyse, spawn, events = report.analyse_root_mixed_folder, coordinator._spawn_workers, []
    if fault == "late_owner":
        def late(self):
            raise ValueError("root_test_finish")
        monkeypatch.setattr(report.owning.RootMixedVRRPOwner, "finish", late)
    def analysing(root, budgets):
        assert not out.exists() and not stage(out).exists()
        events.append("analysis")
        if fault == "analysis":
            raise coordinator.RunnerRefused("synthetic_refused")
        if fault == "os":
            raise OSError("synthetic evidence failure")
        files = analyse(root, replace(budgets, artifacts=len(before) + 4) if fault == "budget" else budgets)
        if fault in ("schema", "scope", "checks", "qualification", "semantic_group", "root_scope", "execution"):
            header = json.loads(files["result.json"])
            header["execution" if fault == "execution" else fault] = {} if fault == "execution" else "wrong"
            files["result.json"] = canonical(header)
        elif fault == "json":
            files["result.json"] = b"{"
        elif fault == "not_object":
            files["result.json"] = canonical([])
        elif fault == "bytes_type":
            files["facts/fhrp_local.jsonl"] = bytearray(files["facts/fhrp_local.jsonl"])
        elif fault == "manifest":
            files["MANIFEST.sha256"] = b"wrong"
        elif fault == "missing":
            files.pop("facts/fhrp_local.jsonl")
        elif fault == "extra":
            files["facts/unexpected.jsonl"] = b""
        if fault != "manifest":
            files["MANIFEST.sha256"] = manifest({name: raw for name, raw in files.items() if name != "MANIFEST.sha256"})
        return files
    def probing():
        events.append("probe")
        return True if fault == "probe_bool" else 0 if fault == "probe" else 4
    def spawning(workers):
        events.append("workers")
        if fault in ("worker", "worker_os"):
            def child(*args, **kwargs):
                if fault == "worker_os":
                    raise OSError("synthetic spawn failure")
                return SimpleNamespace(returncode=0, stdout="not json")
            monkeypatch.setattr(coordinator.subprocess, "run", child)
            return spawn(workers)
        return RECEIPTS
    monkeypatch.setattr(report, "analyse_root_mixed_folder", analysing)
    monkeypatch.setattr(coordinator.tripwire, "probe", probing)
    monkeypatch.setattr(coordinator, "_spawn_workers", spawning)
    codes = {"analysis": "synthetic_refused", "os": "evidence_unreadable", "budget": "p4_budget_exceeded",
        "late_owner": "p4_root_test_finish", "probe": "egress_witness_failed", "probe_bool": "egress_witness_failed",
        "worker": "worker_protocol_failed", "worker_os": "worker_protocol_failed", "workers_bool": "invalid_workers",
        "parent_bool": "invalid_parent_witness", "parent_count": "invalid_parent_witness"}
    with pytest.raises(coordinator.RunnerRefused, match="^" + codes.get(fault, "p4_output_invalid") + "$"):
        coordinator.run_p4_root_mixed(evidence=evidence, out=out, workers=True if fault == "workers_bool" else 2,
            parent_denied=False if fault == "parent_bool" else 99 if fault == "parent_count" else 4)
    assert events == ([] if fault in ("workers_bool", "parent_bool", "parent_count") else
        ["analysis", "probe", "workers"] if fault in ("worker", "worker_os") else
        ["analysis", "probe"] if fault in ("probe", "probe_bool") else ["analysis"])
    assert capsys.readouterr().out == "" and not out.exists() and not stage(out).exists()
    assert snapshot(evidence) == before


@pytest.mark.parametrize("location", ["out", "stage", "same", "inside"])
def test_new_route_reuses_fresh_paths_and_overlap_checks_before_analysis(tmp_path, monkeypatch, location):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    before = estate(evidence)
    path = out if location == "out" else stage(out)
    if location in ("out", "stage"):
        path.mkdir()
        (path / "kept").write_bytes(b"preserved")
    else:
        out = evidence if location == "same" else evidence / "nested"
    monkeypatch.setattr(report, "analyse_root_mixed_folder", lambda *_: pytest.fail("analysis reached"))
    code = "output_exists" if location == "out" else "output_staging_exists" if location == "stage" else "evidence_output_overlap"
    with pytest.raises(coordinator.RunnerRefused, match="^" + code + "$"):
        coordinator.run_p4_root_mixed(evidence=evidence, out=out, workers=1, parent_denied=4)
    assert snapshot(evidence) == before
    if location in ("out", "stage"):
        assert (path / "kept").read_bytes() == b"preserved"


def test_new_route_cannot_emit_success_before_shared_publisher_rename_and_owned_cleanup(tmp_path, monkeypatch, capsys):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    before = estate(evidence)
    rename, events = Path.rename, []
    monkeypatch.setattr(coordinator.tripwire, "probe", lambda: events.append("probe") or 4)
    monkeypatch.setattr(coordinator, "_spawn_workers", lambda workers: events.append("workers") or RECEIPTS)
    def refusing(self, destination):
        assert self == stage(out) and events == ["probe", "workers"] and capsys.readouterr().out == ""
        raise OSError("synthetic rename failure")
    monkeypatch.setattr(Path, "rename", refusing)
    with pytest.raises(coordinator.RunnerRefused, match="^output_unwritable$"):
        coordinator.run_p4_root_mixed(evidence=evidence, out=out, workers=2, parent_denied=4)
    assert not out.exists() and not stage(out).exists() and capsys.readouterr().out == ""
    assert snapshot(evidence) == before and rename is not Path.rename
