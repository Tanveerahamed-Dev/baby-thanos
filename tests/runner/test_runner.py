"""M0 PR 2 runner proofs: determinism, egress denial, refusal and worker invariance."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SUMMARY = "SUMMARY.txt"
MANIFEST = "MANIFEST.json"
WITNESS_ATTEMPTS = 4
STEP_COUNT = 8
WORKER_DENIED = STEP_COUNT * WITNESS_ATTEMPTS
TOTAL_DENIED = WITNESS_ATTEMPTS + WITNESS_ATTEMPTS + WORKER_DENIED


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "atlas_brain.runner", *arguments],
                          cwd=REPO_ROOT, capture_output=True, text=True, check=False)


def evidence_folder(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "show-version.txt").write_text("Cisco IOS XE Software, Version 17.09.04a\n", encoding="utf-8")
    (root / "show-interfaces.txt").write_text(
        "GigabitEthernet0/0 is up, line protocol is down\n", encoding="utf-8")
    return root


def read_manifest(out: Path) -> dict[str, object]:
    payload = json.loads((out / MANIFEST).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def read_outputs(out: Path) -> dict[str, bytes]:
    return {name: (out / name).read_bytes() for name in (SUMMARY, MANIFEST)}


def test_two_runs_over_same_evidence_are_byte_identical(tmp_path):
    evidence = evidence_folder(tmp_path)
    first, second = tmp_path / "out-first", tmp_path / "out-second"
    assert run_cli("--evidence", str(evidence), "--out", str(first), "--workers", "4").returncode == 0
    assert run_cli("--evidence", str(evidence), "--out", str(second), "--workers", "4").returncode == 0
    assert read_outputs(first) == read_outputs(second)
    assert sorted(path.name for path in first.iterdir()) == [MANIFEST, SUMMARY]
    digest = read_manifest(first)["evidence"]
    assert isinstance(digest, dict) and len(str(digest["digest"])) == 64
    assert b"egress denied: 40" in (first / SUMMARY).read_bytes()


def test_coordinator_egress_probe_is_denied_and_counted(tmp_path):
    evidence = evidence_folder(tmp_path)
    out = tmp_path / "out"
    completed = run_cli("--evidence", str(evidence), "--out", str(out))
    assert completed.returncode == 0, completed.stderr
    egress = read_manifest(out)["egress"]
    assert isinstance(egress, dict)
    assert egress["parent_denied"] == WITNESS_ATTEMPTS
    assert egress["coordinator_denied"] == WITNESS_ATTEMPTS
    assert egress["worker_denied"] == WORKER_DENIED
    assert egress["denied"] == TOTAL_DENIED
    # A coordinator spawned alone (no parent, no workers denied) still denies and counts.
    isolated = tmp_path / "coordinator-only"
    completed = run_cli("--role", "coordinator", "--evidence", str(evidence),
                        "--out", str(isolated), "--workers", "1")
    assert completed.returncode == 0, completed.stderr
    isolated_egress = read_manifest(isolated)["egress"]
    assert isinstance(isolated_egress, dict)
    assert isolated_egress["parent_denied"] == 0
    assert isolated_egress["coordinator_denied"] == WITNESS_ATTEMPTS


def test_worker_egress_probe_is_denied_and_counted(tmp_path):
    completed = run_cli("--role", "worker", "--steps", "witness/00,witness/01")
    assert completed.returncode == 0, completed.stderr
    receipts = [json.loads(line) for line in completed.stdout.splitlines() if line]
    assert [receipt["step"] for receipt in receipts] == ["witness/00", "witness/01"]
    assert all(receipt["denied"] == WITNESS_ATTEMPTS for receipt in receipts)
    evidence = evidence_folder(tmp_path)
    out = tmp_path / "out"
    assert run_cli("--evidence", str(evidence), "--out", str(out)).returncode == 0
    steps = read_manifest(out)["steps"]
    assert isinstance(steps, list) and len(steps) == STEP_COUNT
    assert [step["id"] for step in steps] == [f"witness/{index:02d}" for index in range(STEP_COUNT)]
    assert all(step["denied"] == WITNESS_ATTEMPTS for step in steps)


def test_tripwire_denies_real_operations_in_a_fresh_process():
    script = (
        "from atlas_brain.runner import tripwire\n"
        "assert tripwire.install() is True\n"
        "assert tripwire.install() is False\n"
        "assert tripwire.probe() == 4\n"
        "assert len(tripwire.violations()) == 4\n"
        "print('denied-and-counted')\n"
    )
    completed = subprocess.run([sys.executable, "-c", script], cwd=REPO_ROOT,
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "denied-and-counted"


def test_missing_evidence_dir_is_refused_with_stable_exit_code(tmp_path):
    out = tmp_path / "out"
    completed = run_cli("--evidence", str(tmp_path / "absent"), "--out", str(out))
    assert completed.returncode == 2
    assert completed.stderr == "runner refused: evidence_dir_missing\n"
    assert not out.exists()


def test_worker_count_does_not_change_output_bytes(tmp_path):
    evidence = evidence_folder(tmp_path)
    one, four = tmp_path / "out-one", tmp_path / "out-four"
    assert run_cli("--evidence", str(evidence), "--out", str(one), "--workers", "1").returncode == 0
    assert run_cli("--evidence", str(evidence), "--out", str(four), "--workers", "4").returncode == 0
    assert read_outputs(one) == read_outputs(four)


def test_python_api_returns_manifest_result(tmp_path):
    from atlas_brain.runner import RunnerRefused, RunResult, run

    evidence = evidence_folder(tmp_path)
    result = run(evidence, tmp_path / "out", workers=2)
    assert isinstance(result, RunResult)
    assert result.steps == STEP_COUNT
    assert result.evidence_files == 2
    assert len(result.evidence_digest) == 64
    assert result.egress_denied == TOTAL_DENIED
    assert (result.out / SUMMARY).exists() and (result.out / MANIFEST).exists()
    with pytest.raises(RunnerRefused) as refusal:
        run(tmp_path / "absent", tmp_path / "refused")
    assert refusal.value.code == "evidence_dir_missing"
