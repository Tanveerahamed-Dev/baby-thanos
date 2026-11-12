"""Hosted Root CLI witness: fixed synthetic observations, not network or host qualification."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from tools.p4_estate_cases import NAMES, ROOT_CASES, root_members, validate_root
from tools.p4_estate_demo import snapshot

ROOT = Path(".ci-evidence/p4-root")
SEEDS = ("1", "83")
WORKERS = (1, 4)


def need(condition, code):
    if not condition:
        raise ValueError("p4_root_demo_" + code)


def guard():
    need(os.environ.get("GITHUB_ACTIONS") == "true", "hosted_only")
    reviewed = os.environ.get("P4_ROOT_REVIEWED_SHA", "")
    need(len(reviewed) == 40 and all(char in "0123456789abcdef" for char in reviewed), "reviewed_head")
    actual = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    need(actual == reviewed, "checkout_head")
    return reviewed


def run_saved(command, env, root, batch):
    try:
        result = subprocess.run(command, env=env, capture_output=True, check=False, timeout=120)
    except subprocess.TimeoutExpired as error:
        (root / f"batch{batch}.stdout.txt").write_bytes(error.stdout or b"")
        (root / f"batch{batch}.stderr.txt").write_bytes(error.stderr or b"")
        print(f"P4_ROOT_TIMEOUT batch={batch}: " + (error.stderr or b"").decode("utf-8", "replace"), file=sys.stderr)
        raise
    (root / f"batch{batch}.stdout.txt").write_bytes(result.stdout)
    (root / f"batch{batch}.stderr.txt").write_bytes(result.stderr)
    if result.returncode:
        print(result.stderr.decode("utf-8", "replace"), file=sys.stderr)
    need(result.returncode == 0, "child_failed")
    return result


def cli_receipt(raw, reports, canonical):
    lines = raw.decode("ascii").splitlines()
    need(len(lines) == 2 and lines[0].startswith("P4_ROOT_CLI_RECEIPT ")
         and lines[1] == "runner: ok egress_denied=40", "cli_receipt")
    expected = {"schema": "atlas-brain.p4-root-cli-witness/1", "format": "p4-root-observations",
        "report_schema": "atlas-brain.p4-root-observations/1",
        "manifest_sha256": sha256(reports["MANIFEST.sha256"]).hexdigest(),
        "execution": {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4},
            "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
            "steps": [{"denied": 4, "id": f"witness/{index:02d}"} for index in range(8)]},
        "scope": "runner_witness_only"}
    need(lines[0].removeprefix("P4_ROOT_CLI_RECEIPT ").encode("ascii") == canonical(expected), "cli_receipt")
    return json.loads(lines[0].removeprefix("P4_ROOT_CLI_RECEIPT "))


def main():
    reviewed = guard()
    need(not sys.argv[1:], "arguments")
    from atlas_brain.contract.canonical import canonical
    ROOT.mkdir(parents=True, exist_ok=False)
    originals, outputs, cases, witnesses = {}, {}, {}, {}
    for case in ROOT_CASES:
        folder = ROOT / case / "inputs"
        folder.mkdir(parents=True)
        originals[case] = root_members(canonical, case)
        for name, raw in sorted(originals[case].items()):
            (folder / name).write_bytes(raw)
    for batch, (seed, workers) in enumerate(zip(SEEDS, WORKERS, strict=True)):
        for case in ROOT_CASES:
            folder = ROOT / case
            result = run_saved([sys.executable, "-B", "-m", "atlas_brain.runner",
                "--format", "p4-root-observations", "--evidence", str(folder / "inputs"),
                "--out", str(folder / f"out{batch}"), "--workers", str(workers)],
                {**os.environ, "PYTHONHASHSEED": seed}, folder, batch)
            need(all(snapshot(ROOT / name / "inputs") == raw for name, raw in originals.items()), "input_changed")
            reports = snapshot(folder / f"out{batch}")
            need(set(reports) == NAMES, "reports")
            cases[case] = validate_root(reports, originals[case], case, canonical)
            need(result.stderr == b"", "child_stderr")
            witness = cli_receipt(result.stdout, reports, canonical)
            witnesses.setdefault(case, []).append(witness)
            if batch == 0:
                outputs[case] = reports
            else:
                need(reports == outputs[case], "determinism")
    receipt = {"schema": "atlas-brain.p4-root-hosted-receipt/1", "reviewed_head": reviewed,
        "qualification": "synthetic_root_observations_only", "scope": "observations_only",
        "source_required": "original_pinned_evidence_folder", "cases": cases, "cli_witnesses": witnesses,
        "measured_cases": len(ROOT_CASES), "cells_per_case": 25,
        "denominator": {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5},
        "cli_runs": 10, "hash_seeds": list(SEEDS), "worker_counts": list(WORKERS),
        "witness_scope": "runner_witness_only_parent_counts_forwarded_not_attestation"}
    (ROOT / "DIGESTS.json").write_bytes(canonical(receipt) + b"\n")
    print("P4_ROOT_RECEIPT " + canonical(receipt).decode("ascii"))


if __name__ == "__main__":
    main()
