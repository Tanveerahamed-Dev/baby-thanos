"""Conditional supplied-report VIP differences; trusted closed inputs, never admission."""
from dataclasses import dataclass
from typing import Literal, cast

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, StoredState, bind_reader
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import gateway_policy as policy

CHECK = "l3.fhrp.reported_virtual_ip_disagreement"
STEP = StepSpec(id=StepId("l3.fhrp/check_reported_virtual_ip"), pack=build.PACK, kind="check", scope="estate",
    reads=(build.REPORTED_VIRTUAL_IP,), produces=(), evaluator="l3.fhrp.virtual_ip_check.evaluate_declared")
type VipState = k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Operand:
    participant: policy.BoundParticipant
    state: VipState


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    check: str
    policy_id: str
    operands: tuple[Operand, ...]
    state: Literal["problem", "unknown"]
    reason: k.UnknownReason | None
    detail: str | None
    conditional: Literal[True]
    evidence: tuple[k.Evidence, ...]
    next_evidence: tuple[k.EvidenceNeed, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Finding, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _need(condition: bool, code: str) -> None:
    k.require(condition, "fhrp_virtual_ip_check_" + code)


def _value(value: StoredState) -> VipState:
    _need(type(value) in (k.Known, k.Unknown), "value")
    if isinstance(value, k.Known):
        _need(type(value.value) is str and type(value.raw) is str and value.raw == value.value
              and value.basis is k.Basis.OBSERVED and build.hsrp.ipv4_literal(value.value), "value")
    return cast(VipState, value)


def _needs(row: policy.Gateway, *, singleton: bool = False) -> tuple[k.EvidenceNeed, ...]:
    return tuple(k.EvidenceNeed(node=point.node, operation=build.hsrp.OP,
        params=(("group", point.group), ("interface", point.interface)), resolves=(build.REPORTED_VIRTUAL_IP,),
        reruns=(str(STEP.id),), after_s=None, unprintable=("additional_declared_comparison_operand",) if singleton else
        ("collector_recorded_time", "declared_gateway_policy")) for point in row.participants)


def evaluate_declared(plan: policy.Plan, store: FactStore, subjects: tuple[k.EntityKey, ...]) -> Result:
    """Trust original source/plan closure; shape checks are not producer or value seals."""
    _need(type(plan) is policy.Plan and type(store) is FactStore and type(subjects) is tuple
          and all(type(subject) is str for subject in subjects) and subjects == tuple(sorted(set(subjects))), "input")
    order_steps((build.STEP, build.VIP_STEP, STEP))
    reader = bind_reader(store, step=STEP)
    matrix = {subject: _value(reader.read(fact=build.REPORTED_VIRTUAL_IP, subject=subject)) for subject in subjects}
    _need(all(point.subject in matrix for row in plan.rows for point in row.participants)
          and all(row.key is not None or type(row.binding) is k.Unknown for row in plan.rows), "selector")
    findings: list[Finding] = []
    for row in plan.rows:
        operands = tuple(Operand(participant=point, state=matrix[point.subject]) for point in row.participants)
        gaps = tuple(operand.state for operand in operands if isinstance(operand.state, k.Unknown))
        known = {operand.state.value for operand in operands if isinstance(operand.state, k.Known)}
        gap = row.binding if isinstance(row.binding, k.Unknown) else gaps[0] if gaps else None
        problem = row.key is not None and not isinstance(row.binding, k.Unknown) and len(known) > 1
        if problem:
            reason, detail = None, "conditional_reported_virtual_ip_difference"
            needs = tuple(need for item in gaps for need in item.next_evidence) + _needs(row)
        elif gap is not None:
            reason, detail, needs = gap.reason, gap.detail, gap.next_evidence
        else:
            singleton = len(operands) < 2
            reason = k.UnknownReason.NOT_OBSERVABLE if singleton else k.UnknownReason.AS_OF_MISSING
            detail = "comparison_operand_missing" if singleton else "untimed_equal_virtual_ip_reports"
            needs = _needs(row, singleton=singleton)
        evidence = row.binding.evidence + tuple(k.FactRef(fact=build.REPORTED_VIRTUAL_IP,
            subject=point.subject) for point in row.participants)
        findings.append(Finding(check=CHECK, policy_id=row.policy_id, operands=operands,
            state="problem" if problem else "unknown", reason=reason, detail=detail, conditional=True,
            evidence=evidence, next_evidence=needs))
    return Result(rows=tuple(findings), denominator=plan.denominator, coverage=plan.coverage)
