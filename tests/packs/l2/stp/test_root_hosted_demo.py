"""Retained Root CLI host evidence using the separately qualified wire/source oracle."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from atlas_brain.runner import p4
from tools import p4_estate_cases as cases
from tools import p4_root_demo as demo

HEAD = "a" * 40
CASES = ("baseline", "pagp", "missing", "unprinted", "uncaptured")
KNOWN = (15, 15, 8, 13, 7)
PRIORITY = "l2.stp.reported_root_priority"
FACTS = "facts/stp_port_vlan.jsonl"
LIMITS = p4.Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128)


def reports(root, inputs):
    root.mkdir(parents=True)
    for name, raw in inputs.items():
        (root / name).write_bytes(raw)
    return p4.analyse_root_observations_folder(root, LIMITS)


def decoded(files):
    return json.loads(files["result.json"]), [json.loads(row) for row in files[FACTS].splitlines()]


def reseal(files, head, rows):
    files["result.json"] = canonical(head)
    files[FACTS] = b"".join(canonical(row) + b"\n" for row in rows)
    files["MANIFEST.sha256"] = manifest({name: raw for name, raw in files.items() if name != "MANIFEST.sha256"})


def frame(files):
    execution = {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4},
        "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
        "steps": [{"denied": 4, "id": f"witness/{i:02d}"} for i in range(8)]}
    value = {"schema": "atlas-brain.p4-root-cli-witness/1", "format": "p4-root-observations",
        "report_schema": "atlas-brain.p4-root-observations/1", "manifest_sha256": sha256(files["MANIFEST.sha256"]).hexdigest(),
        "execution": execution, "scope": "runner_witness_only"}
    return b"P4_ROOT_CLI_RECEIPT " + canonical(value) + b"\nrunner: ok egress_denied=40\n"


@pytest.mark.parametrize("fault", ["head", "total", "float", "duplicate", "spacing", "manifest", "status"])
def test_cli_receipt_raw_frames_have_exact_typed_manifest_bound_runner_counts(tmp_path, fault):
    files = reports(tmp_path / "inputs", cases.root_members(canonical, "baseline"))
    raw = frame(files)
    prefix, status = raw.splitlines()
    record = json.loads(prefix.removeprefix(b"P4_ROOT_CLI_RECEIPT "))
    if fault == "head":
        record["report_schema"] = "other"
    elif fault == "total":
        record["execution"]["egress"]["denied"] = 39
    elif fault == "float":
        record["execution"]["egress"]["parent_denied"] = 4.0
    elif fault == "manifest":
        record["manifest_sha256"] = "0" * 64
    payload = canonical(record) if fault != "float" else json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    if fault == "duplicate":
        payload = b'{"scope":"other",' + payload[1:]
    elif fault == "spacing":
        payload = json.dumps(record, sort_keys=True).encode()
    elif fault == "status":
        status = b"runner: ok egress_denied=36"
    with pytest.raises(ValueError, match="^p4_root_demo_cli_receipt$"):
        demo.cli_receipt(b"P4_ROOT_CLI_RECEIPT " + payload + b"\n" + status + b"\n", files, canonical)


@pytest.mark.parametrize("fault", ["host", "reviewed", "checkout", "arguments"])
def test_host_head_and_arguments_refuse_before_evidence_root_creation(tmp_path, monkeypatch, fault):
    root = tmp_path / "retained"
    monkeypatch.setattr(demo, "ROOT", root)
    monkeypatch.setattr(demo.sys, "argv", ["p4_root_demo", *(["extra"] if fault == "arguments" else [])])
    monkeypatch.setenv("GITHUB_ACTIONS", "false" if fault == "host" else "true")
    monkeypatch.setenv("P4_ROOT_REVIEWED_SHA", "bad" if fault == "reviewed" else HEAD)
    monkeypatch.setattr(demo.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=("b" * 40 if fault == "checkout" else HEAD)))
    with pytest.raises(ValueError, match="^p4_root_demo_" + {"host": "hosted_only", "reviewed": "reviewed_head", "checkout": "checkout_head", "arguments": "arguments"}[fault] + "$"):
        demo.main()
    assert not root.exists()


@pytest.mark.parametrize("timeout", [False, True])
def test_failed_or_timed_out_child_keeps_exact_partial_stdio_before_refusal(tmp_path, monkeypatch, capsys, timeout):
    def child(*args, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired("root CLI", 120, output=b"partial-out", stderr=b"partial-error")
        return subprocess.CompletedProcess("root CLI", 9, stdout=b"partial-out", stderr=b"partial-error")
    monkeypatch.setattr(demo.subprocess, "run", child)
    with pytest.raises(subprocess.TimeoutExpired if timeout else ValueError, match=None if timeout else "^p4_root_demo_child_failed$"):
        demo.run_saved(["root CLI"], {}, tmp_path, 1)
    assert (tmp_path / "batch1.stdout.txt").read_bytes() == b"partial-out"
    assert (tmp_path / "batch1.stderr.txt").read_bytes() == b"partial-error"
    assert "partial-error" in capsys.readouterr().err and not (tmp_path / "DIGESTS.json").exists()


@pytest.mark.parametrize("fault", ["partial", "input", "report", "missing", "receipt", "stderr", "determinism"])
def test_parent_never_prints_pass_after_partial_or_mutated_children(tmp_path, monkeypatch, capsys, fault):
    root, count = tmp_path / "retained", []
    validate = demo.validate_root
    monkeypatch.setattr(demo, "ROOT", root)
    monkeypatch.setattr(demo, "guard", lambda: HEAD)
    monkeypatch.setattr(demo.sys, "argv", ["p4_root_demo"])
    def saved(command, env, folder, batch):
        count.append((env["PYTHONHASHSEED"], command[-1]))
        if fault == "partial" and len(count) == 2:
            raise ValueError("planted_partial")
        source = Path(command[command.index("--evidence") + 1])
        files = p4.analyse_root_observations_folder(source, LIMITS)
        out = Path(command[command.index("--out") + 1])
        out.mkdir()
        if fault == "report":
            head, rows = decoded(files)
            next(row for row in rows if row["fact"] == PRIORITY and row["vlan"] == 1)["value"] = False
            reseal(files, head, rows)
        for name, raw in files.items():
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        if fault == "input":
            (root / "uncaptured/inputs/p4.json").write_bytes(b"changed")
        if fault == "missing":
            (out / "facts/fhrp_local.jsonl").unlink()
        stdout = frame(files).replace(b'"denied":40', b'"denied":39') if fault == "receipt" else frame(files)
        stderr = b"planted stderr" if fault == "stderr" else b""
        (folder / f"batch{batch}.stdout.txt").write_bytes(stdout)
        (folder / f"batch{batch}.stderr.txt").write_bytes(stderr)
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=stderr)
    def validated(files, *args):
        result = validate(files, *args)
        if fault == "determinism" and len(count) > 5:
            files["result.json"] += b" "
        return result
    monkeypatch.setattr(demo, "run_saved", saved)
    monkeypatch.setattr(demo, "validate_root", validated)
    code = {"partial": "planted_partial", "input": "p4_root_demo_input_changed", "report": "p4_estate_demo_report",
        "missing": "p4_root_demo_reports", "receipt": "p4_root_demo_cli_receipt", "stderr": "p4_root_demo_child_stderr",
        "determinism": "p4_root_demo_determinism"}[fault]
    with pytest.raises(ValueError, match="^" + code + "$"):
        demo.main()
    assert not (root / "DIGESTS.json").exists() and "P4_ROOT_RECEIPT" not in capsys.readouterr().out
    assert (root / "baseline/out0").is_dir() and (root / "baseline/batch0.stdout.txt").is_file()


def test_genuine_git_head_host_runs_ten_cli_processes_and_retains_complete_98_file_tree(tmp_path):
    repo = Path(__file__).resolve().parents[4]
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    gitdir = subprocess.run(["git", "rev-parse", "--absolute-git-dir"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    result = subprocess.run([sys.executable, "-B", "-m", "tools.p4_root_demo"], cwd=tmp_path,
        env={**os.environ, "GITHUB_ACTIONS": "true", "P4_ROOT_REVIEWED_SHA": head, "PYTHONPATH": str(repo),
            "GIT_DIR": gitdir, "GIT_WORK_TREE": str(repo), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, timeout=180, check=False)
    assert result.returncode == 0 and result.stderr == b"", result.stderr
    retained = tmp_path / ".ci-evidence/p4-root"
    all_files = demo.snapshot(retained)
    assert len(all_files) == 98
    raw = all_files["DIGESTS.json"]
    receipt = json.loads(raw)
    assert raw == canonical(receipt) + b"\n"
    assert result.stdout.decode("ascii").splitlines() == ["P4_ROOT_RECEIPT " + canonical(receipt).decode("ascii")]
    assert receipt["reviewed_head"] == head and receipt["qualification"] == "synthetic_root_observations_only"
    assert receipt["source_required"] == "original_pinned_evidence_folder" and receipt["cli_runs"] == 10
    assert receipt["hash_seeds"] == ["1", "83"] and receipt["worker_counts"] == [1, 4]
    assert set(receipt["cases"]) == set(CASES)
    for case, known in zip(CASES, KNOWN, strict=True):
        folder = retained / case
        inputs = demo.snapshot(folder / "inputs")
        first, second = demo.snapshot(folder / "out0"), demo.snapshot(folder / "out1")
        assert first == second and set(first) == cases.NAMES and inputs == cases.root_members(canonical, case)
        assert cases.validate_root(first, inputs, case, canonical)["known"] == known
        assert (receipt["cases"][case]["known"], receipt["cases"][case]["unknown"]) == (known, 25 - known)
        assert len(receipt["cli_witnesses"][case]) == 2 and all(w["scope"] == "runner_witness_only" for w in receipt["cli_witnesses"][case])
        for batch in (0, 1):
            assert (folder / f"batch{batch}.stderr.txt").read_bytes() == b""
            demo.cli_receipt((folder / f"batch{batch}.stdout.txt").read_bytes(), first, canonical)
