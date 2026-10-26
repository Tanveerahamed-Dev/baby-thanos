"""Coordinator and worker roles: explicit-spawn scheduler that writes the result bytes."""
import json
import re
import stat
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical

from . import tripwire
from .evidence import analyse_input, require_evidence
from .p2 import analyse_group
from .records import RunnerRefused, capture_facts, missing_interfaces

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


def run(*, evidence: Path, out: Path, workers: int, parent_denied: int) -> int:
    """Coordinator role: run the plan, collect workers, write SUMMARY.txt and MANIFEST.json."""
    if workers < 1:
        raise RunnerRefused("invalid_workers")
    require_evidence(evidence)
    try:
        source, destination = Path.resolve(evidence), Path.resolve(out)
    except OSError as error:
        raise RunnerRefused("evidence_output_unreadable") from error
    if Path.is_relative_to(source, destination) or Path.is_relative_to(destination, source):
        raise RunnerRefused("evidence_output_overlap")
    for name in ("SUMMARY.txt", "MANIFEST.json"):
        try:
            info = Path.lstat(out / name)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RunnerRefused("output_unwritable") from error
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
            raise RunnerRefused("output_unsafe_member")
    admitted = analyse_input(evidence)
    if admitted.p3 is not None:
        raise RunnerRefused("p3_activation_pending")
    captures, group = admitted.captures, admitted.group
    files = len(captures) + int(group is not None)
    entries = [{"capture": str(capture.id), "sha256": capture.bytes_sha256} for capture in captures]
    digest_input: object = sorted(entries, key=lambda entry: entry["capture"])
    if group is not None:
        digest_input = {"captures": digest_input, "registry_sha256": sha256(group.raw).hexdigest()}
    evidence_digest = sha256(canonical(digest_input)).hexdigest()
    facts: dict[str, object] = {}
    fact_lines: list[str] = []
    p2: dict[str, object] | None = None
    if group is None:
        for capture in sorted(captures, key=lambda capture: capture.id):
            projected, lines = capture_facts(capture)
            facts[str(capture.id)] = projected
            fact_lines.extend(lines)
    else:
        try:
            p2, lines = analyse_group(group)
        except RunnerRefused:
            raise
        except ValueError as error:
            code = str(error)
            if re.fullmatch(r"[a-z][a-z0-9_]*", code, re.ASCII) is None:
                code = "analysis_failed"
            raise RunnerRefused("p2_" + code) from error
        fact_lines.extend(lines)
    interface_present = any(capture.operation in (
        "iosxe.show_interfaces", "iosxe.show_ip_interface_brief") for capture in captures)
    schema = SCHEMA if group is None else "atlas-brain.runner-manifest/2"
    missing, missing_text = missing_interfaces()
    coordinator_denied = tripwire.probe()
    if coordinator_denied != tripwire.WITNESS_ATTEMPTS:
        raise RunnerRefused("egress_witness_failed")
    results = _spawn_workers(workers)
    worker_denied = sum(denied for _, denied in results)
    total = parent_denied + coordinator_denied + worker_denied
    summary = "\n".join((
        "BABY THANOS RUNNER - P2 DECLARED SYNTHETIC TWO ENDS" if group is not None else
        "BABY THANOS RUNNER - P1 INTERFACE ANSWER" if interface_present else "BABY THANOS RUNNER - P0 SYSTEM FACTS",
        f"schema: {schema}",
        f"evidence: files={files} digest={evidence_digest}",
        f"steps: {len(results)}",
        f"witness: {tripwire.WITNESS_ATTEMPTS} denied egress attempts per step",
        f"egress denied: {total} (parent={parent_denied} coordinator={coordinator_denied} workers={worker_denied})",
        "determinism: sorted keys, no run timestamps, no host-root paths, no worker-count fields",
        "execution status: OK",
        *(("l1.interface: " + missing_text,) if not interface_present else ()),
        "",
        "FACTS",
        *fact_lines,
    )) + "\n"
    record = {
        "schema": schema,
        "evidence": {"digest": evidence_digest, "files": files},
        "plan": {"steps": len(results), "witness_attempts": tripwire.WITNESS_ATTEMPTS},
        "egress": {"parent_denied": parent_denied, "coordinator_denied": coordinator_denied,
                   "worker_denied": worker_denied, "denied": total},
        "steps": [{"denied": denied, "id": step} for step, denied in results],
        "facts": facts,
    }
    if not interface_present:
        record["interface_coverage"] = missing
    if p2 is not None and group is not None:
        record["p2"] = p2
        record["evidence"] = {"digest": evidence_digest, "files": files,
                              "captures": len(captures), "registry_sha256": sha256(group.raw).hexdigest()}
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "SUMMARY.txt").write_text(summary, encoding="utf-8", newline="\n")
        (out / "MANIFEST.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except OSError as error:
        raise RunnerRefused("output_unwritable") from error
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
