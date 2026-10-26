"""Baby Thanos runner: CLI and Python API for offline system facts.

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
    """Analyse captures in a spawned CLI process and return its manifest result."""
    command = [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
               "--out", str(out), "--workers", str(workers)]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != EXIT_OK:
        raise RunnerRefused(completed.stderr.strip().removeprefix("runner refused: ") or "runner_failed")
    payload = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RunnerRefused("invalid_manifest")
    record = cast(dict[str, object], payload)
    schema = record.get("schema")
    required = {"schema", "evidence", "plan", "egress", "steps", "facts"}
    if schema == "atlas-brain.runner-manifest/2":
        required.add("p2")
    elif schema != "atlas-brain.runner-manifest/1":
        raise RunnerRefused("invalid_manifest")
    if (set(record) - {"interface_coverage"} != required
            or not isinstance(record["facts"], dict)
            or "interface_coverage" in record and not isinstance(record["interface_coverage"], dict)):
        raise RunnerRefused("invalid_manifest")
    if schema == "atlas-brain.runner-manifest/2":
        payload = record["p2"]
        if not isinstance(payload, dict):
            raise RunnerRefused("invalid_manifest")
        p2 = cast(dict[str, object], payload)
        inner_schema = p2.get("schema")
        if (inner_schema not in ("atlas-brain.p2-demo/1", "atlas-brain.p2-demo/2")
                or not isinstance(p2.get("findings"), list) or not isinstance(p2.get("endpoints"), list)
                or not isinstance(p2.get("denominator"), dict)):
            raise RunnerRefused("invalid_manifest")
        if inner_schema == "atlas-brain.p2-demo/2":
            value = p2.get("configuration")
            if not isinstance(value, dict):
                raise RunnerRefused("invalid_manifest")
            configuration = cast(dict[str, object], value)
            if (configuration.get("basis") != "configured"
                    or configuration.get("interpretation") != "supplied_statements_only"
                    or configuration.get("comparison") != "configuration_only_no_cross_basis_inference"
                    or not isinstance(configuration.get("coverage"), dict)
                    or not isinstance(configuration.get("denominator"), dict)):
                raise RunnerRefused("invalid_manifest")
        elif "configuration" in p2:
            raise RunnerRefused("invalid_manifest")
    evidence_fields, egress_fields = record["evidence"], record["egress"]
    step_receipts = record["steps"]
    if not isinstance(evidence_fields, dict) or not isinstance(egress_fields, dict) or not isinstance(step_receipts, list):
        raise RunnerRefused("invalid_manifest")
    fields = cast(dict[str, object], evidence_fields)
    egress = cast(dict[str, object], egress_fields)
    files, evidence_digest, denied = fields["files"], fields["digest"], egress["denied"]
    if type(files) is not int or not isinstance(evidence_digest, str) or type(denied) is not int:
        raise RunnerRefused("invalid_manifest")
    return RunResult(out=out, evidence_files=files, evidence_digest=evidence_digest,
                     steps=len(cast(list[object], step_receipts)), egress_denied=denied)
