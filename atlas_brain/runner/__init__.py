"""Baby Thanos runner: CLI and Python API for the M0 walking skeleton.

Every runner process installs an audit-hook egress tripwire first; a witness that
fails to deny refuses the run.
"""
import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from .records import EXIT_OK, RunnerRefused, RunResult

__all__ = ("RunResult", "RunnerRefused", "run")


def run(evidence: Path, out: Path, workers: int = 4) -> RunResult:
    """Run the skeleton in a spawned CLI process and return its manifest result."""
    command = [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
               "--out", str(out), "--workers", str(workers)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != EXIT_OK:
        raise RunnerRefused(completed.stderr.strip().removeprefix("runner refused: ") or "runner_failed")
    payload = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RunnerRefused("invalid_manifest")
    record = cast(dict[str, object], payload)
    if set(record) != {"schema", "evidence", "plan", "egress", "steps"}:
        raise RunnerRefused("invalid_manifest")
    evidence_fields, egress_fields = record["evidence"], record["egress"]
    step_receipts = record["steps"]
    if not isinstance(evidence_fields, dict) or not isinstance(egress_fields, dict) or not isinstance(step_receipts, list):
        raise RunnerRefused("invalid_manifest")
    fields = cast(dict[str, object], evidence_fields)
    egress = cast(dict[str, object], egress_fields)
    files, evidence_digest, denied = fields["files"], fields["digest"], egress["denied"]
    if not isinstance(files, int) or not isinstance(evidence_digest, str) or not isinstance(denied, int):
        raise RunnerRefused("invalid_manifest")
    return RunResult(out=out, evidence_files=files, evidence_digest=evidence_digest,
                     steps=len(cast(list[object], step_receipts)), egress_denied=denied)
