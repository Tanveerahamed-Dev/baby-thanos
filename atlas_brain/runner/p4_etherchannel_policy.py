"""Fresh source-bound EC pair preparation; no verdict or standalone carrier admission."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import protocol_check as check
from atlas_brain.packs.l2.etherchannel import protocol_policy as policy
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4 as observations
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.p4_refs import ProofIndex, Value


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtocolPreparation:
    source: ec.Result
    execution: p4_pipeline.Result[Value]
    plan: policy.Plan


def _inputs(root: object, budgets: object) -> None:
    k.require(isinstance(root, Path) and type(budgets) is Budgets, "etherchannel_protocol_policy_input")


def prepare_protocol_comparisons(
    root: Path, budgets: Budgets, policies: tuple[policy.ProtocolPolicy, ...],
) -> ProtocolPreparation:
    _inputs(root, budgets)
    k.require(type(policies) is tuple and len(policies) <= 64
              and all(type(p) is policy.ProtocolPolicy for p in policies), "etherchannel_protocol_policy_input")
    channel = SummaryPack[stp.stp.Result | fhrp.hsrp.Result](budgets)
    standby = StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](budgets)
    tree = stp.build_root_guard_global(root, budgets, peers=(channel, standby))
    source, local = channel.finish(tree.execution), standby.finish(tree.execution)
    index = ProofIndex(tree.execution, budgets)
    k.require(index.execution is tree.execution, "etherchannel_protocol_policy_input")
    observations.close_owned_facts(index, tree.result, source, local)
    domains = channel.owner.validate_reported_protocol_values(source, bind_reader(source.store, step=observations.PROJECT), tree.execution.executed)
    plan = policy.plan_for_declared_scope(tree.execution.envelope, budgets, policies, domains)
    k.require(plan.envelope is tree.execution.envelope, "etherchannel_protocol_policy_input")
    return ProtocolPreparation(source=source, execution=tree.execution, plan=plan)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtocolEvaluation:
    source: ec.Result
    execution: p4_pipeline.Result[Value]
    plan: policy.Plan
    result: check.Result


def evaluate_protocol_comparisons(
    root: Path, budgets: Budgets, policies: tuple[policy.ProtocolPolicy, ...],
) -> ProtocolEvaluation:
    """Own fresh preparation for every evaluation; inspectable carriers are never inputs."""
    prepared = prepare_protocol_comparisons(root, budgets, policies)
    subjects = tuple(sorted(row.subject for row in prepared.source.rows))
    result = check.evaluate_declared(prepared.plan, prepared.source.store, subjects)
    return ProtocolEvaluation(source=prepared.source, execution=prepared.execution, plan=prepared.plan, result=result)
