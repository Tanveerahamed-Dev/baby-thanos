"""Fresh FHRP source and declared logical bindings; no standalone carrier admission."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import virtual_ip_check as check
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack, VirtualIpPack
from atlas_brain.runner import p4 as observations
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.p4_refs import FhrpVipProofIndex, ProofIndex, Value


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


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpVirtualIpSource:
    source: fhrp.VipResult
    execution: p4_pipeline.Result[Value]
    domains: tuple[fhrp.Target, ...]
    proofs: FhrpVipProofIndex


def prepare_fhrp_virtual_ip_source(root: Path, budgets: Budgets) -> FhrpVirtualIpSource:
    """Own one fresh fixed GLOBAL run and close every owner, Reader, value and leaf proof."""
    _inputs(root, budgets)
    channel = SummaryPack[stp.stp.Result | fhrp.hsrp.Result](budgets)
    standby = VirtualIpPack[stp.stp.Result | ec.parse_summary.Result](budgets)
    tree = stp.build_root_guard_global(root, budgets, peers=(channel, standby))
    bundle, state = channel.finish(tree.execution), standby.finish(tree.execution)
    virtual_ip = standby.virtual_ip_owner.build_virtual_ip()
    index = FhrpVipProofIndex(tree.execution, budgets)
    k.require(index.execution is tree.execution, "fhrp_source_input")
    observations.close_owned_facts(index, tree.result, bundle, state)
    vip_source_step = StepSpec(id=StepId("l3.fhrp/prepare_virtual_ip_source"), pack=fhrp.PACK, kind="derive", scope="estate",
        reads=(fhrp.REPORTED_VIRTUAL_IP,), produces=(), evaluator="l3.fhrp.prepare_fhrp_virtual_ip_source")
    order_steps((fhrp.STEP, fhrp.VIP_STEP, fhrp.SOURCE_STEP, vip_source_step))
    domains = standby.owner.validate_gateway_source_values(state,
        bind_reader(state.store, step=fhrp.SOURCE_STEP), tree.execution.executed)
    reader = bind_reader(virtual_ip.store, step=vip_source_step)
    standby.virtual_ip_owner.validate_virtual_ip_values(virtual_ip, reader)
    index.close_virtual_ip(virtual_ip, reader)
    return FhrpVirtualIpSource(source=virtual_ip, execution=tree.execution, domains=domains, proofs=index)


@dataclass(frozen=True, slots=True, kw_only=True)
class VirtualIpEvaluation:
    preparation: FhrpVirtualIpSource
    plan: policy.Plan
    result: check.Result


def evaluate_virtual_ip_comparisons(
    root: Path, budgets: Budgets, policies: tuple[policy.GatewayPolicy, ...],
) -> VirtualIpEvaluation:
    """Own a fresh complete source; supplied carriers are never admission inputs."""
    _inputs(root, budgets)
    k.require(type(policies) is tuple and len(policies) <= 64
              and all(type(item) is policy.GatewayPolicy for item in policies), "fhrp_virtual_ip_check_input")
    prepared = prepare_fhrp_virtual_ip_source(root, budgets)
    plan = policy.plan_for_declared_scope(prepared.execution.envelope, budgets, policies, prepared.domains)
    k.require(plan.envelope is prepared.execution.envelope, "fhrp_virtual_ip_check_input")
    result = check.evaluate_declared(plan, prepared.source.store, tuple(sorted(row.subject for row in prepared.source.rows)))
    return VirtualIpEvaluation(preparation=prepared, plan=plan, result=result)
