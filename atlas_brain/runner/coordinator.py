"""Coordinator and worker roles: explicit-spawn scheduler that writes the result bytes."""
import json
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical

from . import tripwire
from .records import RunnerRefused

SCHEMA = "atlas-brain.runner-manifest/1"
STEPS = tuple(f"witness/{index:02d}" for index in range(8))
STEP_PATTERN = r"witness/[0-9][0-9]"


def run_worker(steps: tuple[str, ...]) -> None:
    """Worker role: run the assigned witness steps, one receipt line each on stdout."""
    if not steps or any(re.fullmatch(STEP_PATTERN, step, re.ASCII) is None for step in steps):
        raise RunnerRefused("invalid_steps")
    for step in steps:
        denied = tripwire.probe()
        if denied != tripwire.WITNESS_ATTEMPTS:
            raise RunnerRefused("egress_witness_failed")
        print(json.dumps({"denied": denied, "step": step}, sort_keys=True))


def require_evidence(root: Path) -> None:
    """Refuse a missing or non-directory evidence path with a stable code."""
    if not root.is_dir():
        raise RunnerRefused("evidence_dir_missing")


def summarise_evidence(root: Path) -> tuple[int, str]:
    """Admit the folder; return a path-free deterministic digest of its names and bytes."""
    require_evidence(root)
    members = sorted(root.rglob("*"), key=lambda item: item.as_posix())
    files = [member for member in members if member.is_file()]
    entries = [{"path": member.relative_to(root).as_posix(), "sha256": sha256(member.read_bytes()).hexdigest()}
               for member in files]
    return len(files), sha256(canonical(entries)).hexdigest()


def run(*, evidence: Path, out: Path, workers: int, parent_denied: int) -> int:
    """Coordinator role: run the plan, collect workers, write SUMMARY.txt and MANIFEST.json."""
    if workers < 1:
        raise RunnerRefused("invalid_workers")
    files, evidence_digest = summarise_evidence(evidence)
    coordinator_denied = tripwire.probe()
    if coordinator_denied != tripwire.WITNESS_ATTEMPTS:
        raise RunnerRefused("egress_witness_failed")
    results = _spawn_workers(workers)
    worker_denied = sum(denied for _, denied in results)
    total = parent_denied + coordinator_denied + worker_denied
    out.mkdir(parents=True, exist_ok=True)
    summary = "\n".join((
        "BABY THANOS RUNNER - M0 WALKING SKELETON",
        f"schema: {SCHEMA}",
        f"evidence: files={files} digest={evidence_digest}",
        f"steps: {len(results)}",
        f"witness: {tripwire.WITNESS_ATTEMPTS} denied egress attempts per step",
        f"egress denied: {total} (parent={parent_denied} coordinator={coordinator_denied} workers={worker_denied})",
        "determinism: sorted keys, no timestamps, no addresses, no worker-count fields",
        "status: OK",
    )) + "\n"
    (out / "SUMMARY.txt").write_text(summary, encoding="utf-8")
    record = {
        "schema": SCHEMA,
        "evidence": {"digest": evidence_digest, "files": files},
        "plan": {"steps": len(results), "witness_attempts": tripwire.WITNESS_ATTEMPTS},
        "egress": {"parent_denied": parent_denied, "coordinator_denied": coordinator_denied,
                   "worker_denied": worker_denied, "denied": total},
        "steps": [{"denied": denied, "id": step} for step, denied in results],
    }
    (out / "MANIFEST.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return total


def _spawn_workers(workers: int) -> tuple[tuple[str, int], ...]:
    batches: list[list[str]] = [[] for _ in range(workers)]
    for index, step in enumerate(STEPS):
        batches[index % workers].append(step)
    results: list[tuple[str, int]] = []
    for batch in batches:
        if not batch:
            continue
        command = [sys.executable, "-m", "atlas_brain.runner", "--role", "worker", "--steps", ",".join(batch)]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line]
        if completed.returncode != 0 or len(rows) != len(batch):
            raise RunnerRefused("worker_protocol_failed")
        for row in rows:
            if not isinstance(row, dict):
                raise RunnerRefused("worker_protocol_failed")
            record = cast(dict[str, object], row)
            if set(record) != {"denied", "step"}:
                raise RunnerRefused("worker_protocol_failed")
            step, denied = record["step"], record["denied"]
            if not (isinstance(step, str) and isinstance(denied, int)
                    and step in batch and denied == tripwire.WITNESS_ATTEMPTS):
                raise RunnerRefused("worker_protocol_failed")
            results.append((step, denied))
    if sorted(step for step, _ in results) != sorted(STEPS):
        raise RunnerRefused("worker_protocol_failed")
    return tuple(sorted(results))
