"""CLI: parent / spawned coordinator / spawned worker dispatch.

The egress tripwire is installed before argument parsing, validation or any child
process is launched, in this process and therefore in each re-invocation.
"""
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import coordinator, tripwire
from .records import DEFAULT_WORKERS, EXIT_OK, EXIT_REFUSED, RunnerRefused

ROLES = ("parent", "coordinator", "worker")
FLAGS = frozenset({"--evidence", "--out", "--workers", "--role", "--steps", "--parent-denied", "--format"})
USAGE = """usage: python -m atlas_brain.runner --evidence DIR --out DIR [--workers N] [--format p4-observations]

Analyse raw IOS-XE show-version/interface captures (P0/P1), or a declared
synthetic P2 p2.json group: schema 1 discovery/trunk observations, or schema 2
running-config with bounded static inheritance. Configured intent and observed
state remain separate. A P3 p3.json sidecar adds declared collection rounds and
conditional MTU/OSPF cause candidates with visible unknown hops; supplied collector
windows are not authenticated clocks or proof of continuous adjacency state.
Execute deterministic witness steps and write SUMMARY.txt
plus MANIFEST.json under --out. Egress is denied and counted; identical inputs
give identical output bytes across worker counts.
P4 requires --format p4-observations and a fresh output directory with an existing
parent. It writes result.json, three facts/*.jsonl files and MANIFEST.sha256.
These are partial observations; protocol checks and health are not implemented.
"""


@dataclass(frozen=True, slots=True, kw_only=True)
class Options:
    role: str
    evidence: Path | None
    out: Path | None
    workers: int
    steps: tuple[str, ...]
    parent_denied: int
    output_format: str


def _parse(arguments: list[str]) -> Options:
    values: dict[str, str] = {}
    position = 0
    while position < len(arguments):
        flag = arguments[position]
        if flag not in FLAGS or position + 1 >= len(arguments) or flag in values:
            raise RunnerRefused("invalid_arguments")
        values[flag] = arguments[position + 1]
        position += 2
    role = values.get("--role", "parent")
    output_format = values.get("--format", "legacy")
    if output_format not in ("legacy", "p4-observations") or role == "worker" and output_format != "legacy":
        raise RunnerRefused("invalid_format")
    if role not in ROLES:
        raise RunnerRefused("invalid_role")
    try:
        workers = int(values.get("--workers", str(DEFAULT_WORKERS)))
        parent_denied = int(values.get("--parent-denied", "0"))
    except ValueError:
        raise RunnerRefused("invalid_arguments") from None
    steps = tuple(value for value in values.get("--steps", "").split(",") if value)
    if workers < 1 or parent_denied < 0:
        raise RunnerRefused("invalid_arguments")
    if role == "worker" and (not steps or any(re.fullmatch(coordinator.STEP_PATTERN, step, re.ASCII) is None
                                              for step in steps)):
        raise RunnerRefused("invalid_steps")
    return Options(role=role,
                   evidence=Path(values["--evidence"]) if "--evidence" in values else None,
                   out=Path(values["--out"]) if "--out" in values else None,
                   workers=workers, steps=steps, parent_denied=parent_denied, output_format=output_format)


def _run(arguments: list[str]) -> int:
    options = _parse(arguments)
    if options.role == "worker":
        coordinator.run_worker(options.steps)
        return EXIT_OK
    if options.evidence is None or options.out is None:
        raise RunnerRefused("missing_evidence" if options.evidence is None else "missing_out")
    evidence, out = options.evidence, options.out
    if options.role == "coordinator":
        execute = coordinator.run_p4 if options.output_format == "p4-observations" else coordinator.run
        print("runner: ok egress_denied=" + str(execute(
            evidence=evidence, out=out, workers=options.workers, parent_denied=options.parent_denied)))
        return EXIT_OK
    coordinator.require_evidence(evidence)
    parent_denied = tripwire.probe()
    if parent_denied != tripwire.WITNESS_ATTEMPTS:
        raise RunnerRefused("egress_witness_failed")
    command = [sys.executable, "-m", "atlas_brain.runner", "--role", "coordinator",
               "--evidence", str(evidence), "--out", str(out),
               "--workers", str(options.workers), "--parent-denied", str(parent_denied)]
    if options.output_format == "p4-observations":
        command.extend(("--format", "p4-observations"))
    return subprocess.run(command, check=False).returncode


def main(argv: list[str] | None = None) -> int:
    """Entry point; the egress tripwire is installed before anything else."""
    tripwire.install()
    arguments = sys.argv[1:] if argv is None else argv
    if "--help" in arguments or "-h" in arguments:
        print(USAGE)
        return EXIT_OK
    try:
        return _run(arguments)
    except RunnerRefused as refusal:
        print("runner refused: " + refusal.code, file=sys.stderr)
        return EXIT_REFUSED
