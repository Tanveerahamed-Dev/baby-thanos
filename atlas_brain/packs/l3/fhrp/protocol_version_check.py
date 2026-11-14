"""Conditional reported HSRP version differences; trusted closed inputs, never admission."""
from dataclasses import dataclass
from typing import Literal, cast

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, StoredState, bind_reader
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import validate_version_state_graph

CHECK = "l3.fhrp.reported_protocol_version_disagreement"
STEP = StepSpec(id=StepId("l3.fhrp/check_reported_protocol_version"), pack=profile.PACK, kind="check", scope="estate",
    reads=(profile.REPORTED_PROTOCOL_VERSION,), produces=(), evaluator="l3.fhrp.protocol_version_check.evaluate_declared")
type VersionState = k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Operand:
    participant: policy.BoundParticipant
    state: VersionState


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
    k.require(condition, "fhrp_protocol_version_check_" + code)


def _value(value: StoredState) -> VersionState:
    _need(type(value) in (k.Known, k.Unknown), "value")
    selected = cast(VersionState, value)
    validate_version_state_graph(selected)
    if isinstance(selected, k.Known):
        _need(type(selected.value) is str and selected.value in ("1", "2") and type(selected.raw) is str
              and selected.raw == selected.value and selected.basis is k.Basis.OBSERVED, "value")
    return selected


def _needs(row: policy.Gateway, *, singleton: bool = False) -> tuple[k.EvidenceNeed, ...]:
    return tuple(k.EvidenceNeed(node=point.node, operation=parser.OP,
        params=(("group", point.group), ("interface", point.interface)), resolves=(profile.REPORTED_PROTOCOL_VERSION,),
        reruns=(str(STEP.id),), after_s=None, unprintable=("additional_declared_comparison_operand",) if singleton else
        ("collector_recorded_time", "declared_gateway_policy")) for point in row.participants)


def evaluate_declared(plan: policy.Plan, store: FactStore, subjects: tuple[k.EntityKey, ...]) -> Result:
    """Trust original source/plan closure; shape checks are not producer or value seals."""
    _need(type(plan) is policy.Plan and type(store) is FactStore and type(subjects) is tuple
          and all(type(subject) is str for subject in subjects) and subjects == tuple(sorted(set(subjects))), "input")
    profile.compile_version_profile()
    order_steps((profile.STEP, STEP))
    _need(type(store.owners) is dict and all(type(fact) is str and type(owner) is str
          for fact, owner in store.owners.items()) and store.owners == {profile.REPORTED_PROTOCOL_VERSION: profile.STEP.id}
          and type(store.values) is dict and all(type(ref) is k.FactRef and type(ref.fact) is str
              and type(ref.subject) is str for ref in store.values), "store")
    expected = {k.FactRef(fact=profile.REPORTED_PROTOCOL_VERSION, subject=subject) for subject in subjects}
    _need(len(store.values) == len(expected) and set(store.values) == expected, "store")
    _need(type(plan.rows) is tuple and len(plan.rows) <= 64 and type(plan.coverage) is k.Unknown
          and all(type(row) is policy.Gateway and type(row.policy_id) is str and bool(row.policy_id)
              and type(row.participants) is tuple and 1 <= len(row.participants) <= 128
              and all(type(point) is policy.BoundParticipant and all(type(value) is str and bool(value)
                  for value in (point.target_id, point.node, point.interface, point.group, point.subject)) for point in row.participants)
              and (row.key is None or type(row.key) is policy.GatewayKey)
              and type(row.binding) in (k.Known, k.Unknown) for row in plan.rows), "selector")
    validate_version_state_graph(plan.coverage)
    for row in plan.rows:
        validate_version_state_graph(row.binding)
        if isinstance(row.binding, k.Known):
            _need(row.binding.basis is k.Basis.DECLARED and row.binding.value == row.binding.raw == row.policy_id, "selector")
        if row.key is not None:
            key = row.key
            _need(all(type(value) is str and bool(value) for value in
                      (key.envelope_sha256, key.domain, key.address_family, key.protocol, key.group))
                  and type(key.vlan) is int and 1 <= key.vlan <= 4094 and key.address_family == "ipv4" and key.protocol == "hsrp"
                  and all(point.group == key.group for point in row.participants), "selector")
            k.digest(key.envelope_sha256)
    reader = bind_reader(store, step=STEP)
    matrix = {subject: _value(reader.read(fact=profile.REPORTED_PROTOCOL_VERSION, subject=subject)) for subject in subjects}
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
            reason, detail = None, "conditional_reported_protocol_version_difference"
            needs = tuple(need for item in gaps for need in item.next_evidence) + _needs(row)
        elif gap is not None:
            reason, detail, needs = gap.reason, gap.detail, gap.next_evidence
        else:
            singleton = len(operands) < 2
            reason = k.UnknownReason.NOT_OBSERVABLE if singleton else k.UnknownReason.AS_OF_MISSING
            detail = "comparison_operand_missing" if singleton else "untimed_equal_protocol_version_reports"
            needs = _needs(row, singleton=singleton)
        evidence = row.binding.evidence + tuple(k.FactRef(fact=profile.REPORTED_PROTOCOL_VERSION,
            subject=point.subject) for point in row.participants)
        findings.append(Finding(check=CHECK, policy_id=row.policy_id, operands=operands,
            state="problem" if problem else "unknown", reason=reason, detail=detail, conditional=True,
            evidence=evidence, next_evidence=needs))
    return Result(rows=tuple(findings), denominator=plan.denominator, coverage=plan.coverage)
