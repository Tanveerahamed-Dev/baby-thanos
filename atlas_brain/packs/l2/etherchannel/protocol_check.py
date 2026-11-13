"""Conditional reported-protocol discrepancy over already closed owning facts."""
from dataclasses import dataclass
from typing import Literal

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.etherchannel import build
from atlas_brain.packs.l2.etherchannel import protocol_policy as policy

CHECK = "l2.etherchannel.reported_protocol_mismatch"
STEP = StepSpec(id=StepId("l2.etherchannel/check_reported_protocol"), pack=build.PACK, kind="check", scope="estate",
    reads=(build.REPORTED_PROTOCOL,), produces=(), evaluator="l2.etherchannel.protocol_check.evaluate_declared")


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    check: str
    policy_id: str
    left: k.EntityKey
    right: k.EntityKey
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
    k.require(condition, "etherchannel_protocol_check_" + code)


def evaluate_declared(plan: policy.Plan, store: FactStore, subjects: tuple[k.EntityKey, ...]) -> Result:
    """Trusted component: caller owns original source, complete population and plan closure."""
    _need(type(plan) is policy.Plan and type(store) is FactStore and type(subjects) is tuple
          and all(type(subject) is str for subject in subjects) and subjects == tuple(sorted(set(subjects))), "input")
    order_steps((build.STEP, STEP))
    reader = bind_reader(store, step=STEP)
    matrix = {subject: reader.read(fact=build.REPORTED_PROTOCOL, subject=subject) for subject in subjects}
    for value in matrix.values():
        _need(type(value) is k.Unknown or type(value) is k.Known, "value")
        if isinstance(value, k.Known):
            _need(type(value.value) is str and value.value in ("lacp", "pagp", "none_reported")
                  and value.basis is k.Basis.OBSERVED and type(value.raw) is str
                  and value.raw == {"lacp": "LACP", "pagp": "PAgP", "none_reported": "-"}[value.value], "value")
    _need(all(point.subject in matrix for row in plan.rows for point in row.participants), "selector")
    findings: list[Finding] = []
    for row in plan.rows:
        evidence = row.declaration.evidence + tuple(k.FactRef(fact=build.REPORTED_PROTOCOL, subject=point.subject) for point in row.participants)
        values = tuple(matrix[point.subject] for point in row.participants)
        gap = next((value for value in values if isinstance(value, k.Unknown)), None)
        reason: k.UnknownReason | None = gap.reason if gap is not None else k.UnknownReason.NOT_OBSERVABLE
        detail = gap.detail if gap is not None else "negotiation_protocol_not_reported"
        problem = False
        if gap is not None:
            needs = gap.next_evidence
        else:
            match values:
                case (k.Known(value=left), k.Known(value=right)) if left != "none_reported" and right != "none_reported":
                    problem = left != right
                    reason = None if problem else k.UnknownReason.AS_OF_MISSING
                    detail = "conditional_reported_protocol_difference" if problem else "untimed_equal_protocol_reports"
            unprintable = ("explicit_negotiation_protocol",) if reason is k.UnknownReason.NOT_OBSERVABLE else (
                "collector_recorded_time", "declared_protocol_policy")
            needs = tuple(k.EvidenceNeed(node=point.node, operation=build.parse_summary.OP, params=(),
                resolves=(build.REPORTED_PROTOCOL,), reruns=(str(STEP.id),), after_s=None, unprintable=unprintable)
                for point in row.participants)
        findings.append(Finding(check=CHECK, policy_id=row.policy_id, left=row.participants[0].subject,
            right=row.participants[1].subject, state="problem" if problem else "unknown", reason=reason, detail=detail,
            conditional=True, evidence=evidence, next_evidence=needs))
    return Result(rows=tuple(findings), denominator=plan.denominator, coverage=plan.coverage)
