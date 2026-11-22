"""Canonical conditional required-report presence; no health or True missing-report claim."""
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import required_report_proofs as proofs
from atlas_brain.packs.l3.fhrp import required_report_run as required
from atlas_brain.packs.l3.fhrp import required_report_wire as wire


def analyse_required_reports(root: Path,budgets: Budgets,policies: tuple[policy.GatewayPolicy,...],
    baseline_raw: bytes | None,
) -> dict[str,bytes]:
    run,result,projection=proofs.project_folder(root,budgets,policies,baseline_raw)
    limits=(budgets.bundle_bytes,budgets.artifact_bytes,budgets.artifacts)
    files=wire.render(projection.header,projection.inputs,limits,projection.captures,projection.registry,
        projection.local,projection.requirements)
    k.require(required.RequiredReportRun.close(run) is result,"required_report_projection")
    return files
