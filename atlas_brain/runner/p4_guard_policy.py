"""Trusted fixed three-pack composition for caller-declared STP guard-policy plans."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.etherchannel import build as etherchannel
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l2.stp import guard_check as check
from atlas_brain.packs.l2.stp import guard_policy as policy
from atlas_brain.packs.l2.stp import guard_report as report
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4 as observations
from atlas_brain.runner.p4_refs import ProofIndex
from atlas_brain.runner.records import RunnerRefused


def plan_guard_comparisons(envelope: p4.Envelope, budgets: Budgets,
                           policies: tuple[policy.GuardPolicy, ...]) -> policy.GuardPlan:
    if type(envelope) is not p4.Envelope:
        raise ValueError("stp_guard_policy_envelope")
    compiled = compile_packs((stp.DECLARATION, etherchannel.DECLARATION, fhrp.DECLARATION))
    if envelope.registration_sha256 != compiled.registration_sha256:
        raise ValueError("stp_guard_policy_profile")
    owners = {binding.operation: binding.step for binding in compiled.operations}
    if (type(envelope.targets) is not tuple or not all(type(target) is p4.Target and target.operation in owners
            and target.owner == owners[target.operation] for target in envelope.targets)):
        raise ValueError("stp_guard_policy_profile")
    return policy.plan_for_declared_scope(envelope, budgets, policies)


@dataclass(frozen=True, slots=True, kw_only=True)
class GuardEvaluation:
    source: stp.GlobalFacts[etherchannel.parse_summary.Result | fhrp.hsrp.Result]
    plan: policy.GuardPlan
    result: check.Result


def _inputs(root: object, budgets: object) -> None:
    if not isinstance(root, Path) or type(budgets) is not Budgets:
        raise ValueError("stp_guard_check_input")


def evaluate_guard_comparisons(root: Path, budgets: Budgets,
                               policies: tuple[policy.GuardPolicy, ...]) -> GuardEvaluation:
    """Own one fresh source run; caller-built execution, stores and plans are not admission inputs."""
    _inputs(root, budgets)
    if (type(policies) is not tuple or len(policies) > policy.MAX_POLICIES
            or not all(type(item) is policy.GuardPolicy for item in policies)):
        raise ValueError("stp_guard_check_policies")
    channel = SummaryPack[stp.stp.Result | fhrp.hsrp.Result](budgets)
    standby = StandbyBriefPack[stp.stp.Result | etherchannel.parse_summary.Result](budgets)
    source: stp.GlobalFacts[etherchannel.parse_summary.Result | fhrp.hsrp.Result] = stp.build_root_guard_global(root, budgets, peers=(channel, standby))
    finished, local = channel.finish(source.execution), standby.finish(source.execution)
    index = ProofIndex(source.execution, budgets)
    if index.execution is not source.execution:
        raise RunnerRefused("p4_observations_profile")
    trees, _, _ = observations.close_owned_facts(index, source.result, finished, local)
    plan = plan_guard_comparisons(source.execution.envelope, budgets, policies)
    return GuardEvaluation(source=source, plan=plan,
                           result=check.evaluate_declared(plan, source.result.store, tuple(sorted(trees))))


def report_guard_comparisons(root: Path, budgets: Budgets,
                             policies: tuple[policy.GuardPolicy, ...]) -> dict[str, bytes]:
    """Return a standalone report that still requires its original pinned evidence folder."""
    evaluation = evaluate_guard_comparisons(root, budgets, policies)
    index = ProofIndex(evaluation.source.execution, budgets)
    kind, facts = observations.project_owned_facts(index, evaluation.source.result, "stp")
    captures = observations.project_capture_metadata(index)
    return report.project_declared(evaluation.plan, evaluation.result, index, kind, facts, captures, budgets)
