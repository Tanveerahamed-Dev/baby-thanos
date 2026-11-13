"""Fresh FHRP source and declared logical bindings; no standalone carrier admission."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4 as observations
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.p4_refs import ProofIndex, Value


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpSource:
    source: fhrp.Result
    execution: p4_pipeline.Result[Value]
    domains: tuple[fhrp.Target, ...]


def _inputs(root: object, budgets: object) -> None:
    k.require(isinstance(root, Path) and type(budgets) is Budgets, "fhrp_source_input")


def prepare_fhrp_source(root: Path, budgets: Budgets) -> FhrpSource:
    _inputs(root, budgets)
    channel = SummaryPack[stp.stp.Result | fhrp.hsrp.Result](budgets)
    standby = StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](budgets)
    tree = stp.build_root_guard_global(root, budgets, peers=(channel, standby))
    bundle, source = channel.finish(tree.execution), standby.finish(tree.execution)
    index = ProofIndex(tree.execution, budgets)
    k.require(index.execution is tree.execution, "fhrp_source_input")
    observations.close_owned_facts(index, tree.result, bundle, source)
    order_steps((fhrp.STEP, fhrp.SOURCE_STEP))
    domains = standby.owner.validate_gateway_source_values(source,
        bind_reader(source.store, step=fhrp.SOURCE_STEP), tree.execution.executed)
    return FhrpSource(source=source, execution=tree.execution, domains=domains)


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayPreparation:
    source: fhrp.Result
    execution: p4_pipeline.Result[Value]
    plan: policy.Plan


def prepare_gateway_bindings(
    root: Path, budgets: Budgets, policies: tuple[policy.GatewayPolicy, ...],
) -> GatewayPreparation:
    k.require(type(policies) is tuple and len(policies) <= 64
              and all(type(item) is policy.GatewayPolicy for item in policies), "fhrp_gateway_policy_input")
    prepared = prepare_fhrp_source(root, budgets)
    plan = policy.plan_for_declared_scope(prepared.execution.envelope, budgets, policies, prepared.domains)
    k.require(plan.envelope is prepared.execution.envelope, "fhrp_gateway_policy_input")
    return GatewayPreparation(source=prepared.source, execution=prepared.execution, plan=plan)
