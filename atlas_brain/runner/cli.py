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
FLAGS = frozenset({"--evidence", "--out", "--workers", "--role", "--steps", "--parent-denied"})
USAGE = """usage: python -m atlas_brain.runner --evidence DIR --out DIR [--workers N]

Analyse raw IOS-XE show-version captures, execute the built-in deterministic
witness steps in an explicit worker pool, and write SUMMARY.txt plus
MANIFEST.json under --out. Egress is denied and counted; output bytes do not depend
on the run or on the worker count.
"""


@dataclass(frozen=True, slots=True, kw_only=True)
class Options:
    role: str
    evidence: Path | None
    out: Path | None
    workers: int
    steps: tuple[str, ...]
    parent_denied: int


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
                   workers=workers, steps=steps, parent_denied=parent_denied)


def _run(arguments: list[str]) -> int:
    options = _parse(arguments)
    if options.role == "worker":
        coordinator.run_worker(options.steps)
        return EXIT_OK
    if options.evidence is None or options.out is None:
        raise RunnerRefused("missing_evidence" if options.evidence is None else "missing_out")
    evidence, out = options.evidence, options.out
    if options.role == "coordinator":
        print("runner: ok egress_denied=" + str(coordinator.run(
            evidence=evidence, out=out, workers=options.workers, parent_denied=options.parent_denied)))
        return EXIT_OK
    coordinator.require_evidence(evidence)
    parent_denied = tripwire.probe()
    if parent_denied != tripwire.WITNESS_ATTEMPTS:
        raise RunnerRefused("egress_witness_failed")
    command = [sys.executable, "-m", "atlas_brain.runner", "--role", "coordinator",
               "--evidence", str(evidence), "--out", str(out),
               "--workers", str(options.workers), "--parent-denied", str(parent_denied)]
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
