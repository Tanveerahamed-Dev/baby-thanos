"""Hosted-only generated three-pack observations; no mode, default or health qualification."""
import json
import os
import subprocess
import sys
from pathlib import Path

from tools.p4_estate_cases import CASES, NAMES, members, need, validate

ROOT = Path(".ci-evidence/p0-demo/p4-estate")
SEEDS = ("1", "83")


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def guard():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("p4_estate_demo_hosted_only")
    reviewed = os.environ.get("P4_ESTATE_REVIEWED_SHA", "")
    need(len(reviewed) == 40 and all(char in "0123456789abcdef" for char in reviewed), "reviewed_head")
    actual = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    need(actual == reviewed, "checkout_head")
    return reviewed


def run_saved(command, env, root, batch):
    try:
        result = subprocess.run(command, env=env, capture_output=True, check=False, timeout=60)
    except subprocess.TimeoutExpired as error:
        (root / f"batch{batch}.stdout.txt").write_bytes(error.stdout or b"")
        (root / f"batch{batch}.stderr.txt").write_bytes(error.stderr or b"")
        print(f"P4_ESTATE_TIMEOUT batch={batch}: " + (error.stderr or b"").decode("utf-8", "replace"), file=sys.stderr)
        raise
    (root / f"batch{batch}.stdout.txt").write_bytes(result.stdout)
    (root / f"batch{batch}.stderr.txt").write_bytes(result.stderr)
    if result.returncode:
        print(result.stderr.decode("utf-8", "replace"), file=sys.stderr)
    need(result.returncode == 0, "child_failed")
    return result


def run_batch(batch, reviewed):
    need(batch in (0, 1) and os.environ.get("PYTHONHASHSEED") == SEEDS[batch], "hash_seed")
    from atlas_brain.runner import tripwire
    need(tripwire.install() and tripwire.probe() == 4, "tripwire")
    events = tripwire.violations()
    need(len(events) == 4, "tripwire")
    from atlas_brain.contract.canonical import canonical
    from atlas_brain.evidence.admission import Budgets
    from atlas_brain.runner.p4 import analyse_folder
    for case in CASES:
        out = ROOT / case / f"out{batch}"
        reports = analyse_folder(ROOT / case / "inputs", Budgets(1000000, 1000000, 1000))
        need(set(reports) == NAMES, "reports")
        out.mkdir()
        for name, content in sorted(reports.items()):
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    extra = len(tripwire.violations()) - len(events)
    need(tripwire.violations() == events and extra == 0, "extra_egress")
    receipt = {"schema": "atlas-brain.p4-estate-api-batch/1", "reviewed_head": reviewed, "batch": batch,
        "seed": SEEDS[batch], "api_runs": len(CASES), "api_process_denied": len(events), "additional_denials": extra}
    print("P4_ESTATE_BATCH " + canonical(receipt).decode("ascii"))



def main():
    reviewed = guard()
    if sys.argv[1:]:
        need(len(sys.argv) == 3 and sys.argv[1] == "--run" and sys.argv[2] in ("0", "1"), "arguments")
        run_batch(int(sys.argv[2]), reviewed)
        return
    from atlas_brain.contract.canonical import canonical
    ROOT.mkdir(parents=True, exist_ok=False)
    originals = {}
    for case in CASES:
        folder = ROOT / case / "inputs"
        folder.mkdir(parents=True)
        originals[case] = members(canonical, case)
        for name, content in sorted(originals[case].items()):
            (folder / name).write_bytes(content)
    outputs, batches, cases = {}, [], {}
    for batch, seed in enumerate(SEEDS):
        result = run_saved([sys.executable, "-B", "-m", "tools.p4_estate_demo", "--run", str(batch)],
                           {**os.environ, "PYTHONHASHSEED": seed}, ROOT, batch)
        lines = result.stdout.decode("ascii").splitlines()
        need(len(lines) == 1 and lines[0].startswith("P4_ESTATE_BATCH "), "batch_receipt")
        receipt = json.loads(lines[0].removeprefix("P4_ESTATE_BATCH "))
        need(lines[0].removeprefix("P4_ESTATE_BATCH ").encode("ascii") == canonical({"schema": "atlas-brain.p4-estate-api-batch/1", "reviewed_head": reviewed, "batch": batch,
            "seed": seed, "api_runs": 3, "api_process_denied": 4, "additional_denials": 0}), "batch_receipt")
        batches.append(receipt)
        for case in CASES:
            need(snapshot(ROOT / case / "inputs") == originals[case], "input_changed")
            reports = snapshot(ROOT / case / f"out{batch}")
            cases[case] = validate(reports, originals[case], case, canonical)
            if batch == 0:
                outputs[case] = reports
            else:
                need(reports == outputs[case], "determinism")
    receipt = {"schema": "atlas-brain.p4-estate-hosted-receipt/1", "reviewed_head": reviewed,
        "qualification": "synthetic_observations_only", "scope": "observations_only",
        "source_required": "original_pinned_evidence_folder", "measured_cases": len(CASES), "cells_per_case": 19,
        "denominator": {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}, "api_runs": 6,
        "api_processes": 2, "hash_seeds": list(SEEDS), "api_process_denied": [row["api_process_denied"] for row in batches],
        "additional_denials": [row["additional_denials"] for row in batches], "cases": cases}
    (ROOT / "DIGESTS.json").write_bytes(canonical(receipt) + b"\n")
    print("P4_ESTATE_RECEIPT " + canonical(receipt).decode("ascii"))


if __name__ == "__main__":
    main()
