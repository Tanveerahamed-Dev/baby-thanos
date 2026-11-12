"""Conditional caller-declared guard reports; trusted inputs, never standalone admission."""
from dataclasses import dataclass
from typing import Literal

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, StoredState, bind_reader
from atlas_brain.packs.l2.stp import build
from atlas_brain.packs.l2.stp import guard_policy as policy

CHECK = "l2.stp.reported_root_guard_mismatch"
STEP = StepSpec(id=StepId("l2.stp/check_root_guard"), pack=build.PACK, kind="check", scope="estate",
    reads=tuple(sorted((build.ROOT_GUARD, build.REPORTED_ROLE))), produces=(), evaluator="l2.stp.guard_check.evaluate_declared")
type Premise = k.Known[bool] | k.Unknown | k.NotApplicable


@dataclass(frozen=True, slots=True, kw_only=True)
class Hop:
    id: str
    state: Premise


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    check: str
    policy_id: str
    left: k.EntityKey
    right: k.EntityKey
    state: Literal["problem", "unknown", "not_applicable"]
    reason: k.UnknownReason | k.NAReason | None
    conditional: Literal[True]
    gaps: tuple[str, ...]
    hops: tuple[Hop, ...]
    evidence: tuple[k.Evidence, ...]
    next_evidence: tuple[k.EvidenceNeed, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Finding, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _need(condition: bool) -> None:
    k.require(condition, "stp_guard_check_input")


def _validate(value: StoredState, *, role: bool) -> None:
    if type(value) is k.Unknown:
        return
    _need(isinstance(value, k.Known))
    if isinstance(value, k.Known):
        _need(value.basis is k.Basis.OBSERVED)
        if role:
            _need(type(value.value) is str and value.value in ("designated", "root", "alternate", "backup", "disabled")
                  and value.raw == value.value)
        else:
            _need(type(value.value) is bool and value.raw == ("enabled" if value.value else "disabled"))


def _needs(row: policy.GuardComparison) -> tuple[k.EvidenceNeed, ...]:
    return tuple(k.EvidenceNeed(node=point.target.node.key, operation=build.stp.OP, params=(("port", point.port),),
        resolves=tuple(sorted((build.ROOT_GUARD, build.REPORTED_ROLE))), reruns=(str(STEP.id),), after_s=None,
        unprintable=("collector_recorded_time", "declared_guard_policy")) for point in row.participants)


def _gap(value: k.Unknown, refs: tuple[k.Evidence, ...], needs: tuple[k.EvidenceNeed, ...]) -> k.Unknown:
    return k.Unknown(reason=value.reason, detail=value.detail, evidence=refs, candidates=value.candidates,
                     next_evidence=value.next_evidence or needs)


def _finding(row: policy.GuardComparison, hops: list[Hop], needs: tuple[k.EvidenceNeed, ...]) -> Finding:
    last = hops[-1].state
    state: Literal["problem", "unknown", "not_applicable"] = (
        "unknown" if isinstance(last, k.Unknown) else "not_applicable" if isinstance(last, k.NotApplicable) else "problem")
    return Finding(check=CHECK, policy_id=row.policy_id, left=row.participants[0].subject, right=row.participants[1].subject,
        state=state, reason=last.reason if isinstance(last, (k.Unknown, k.NotApplicable)) else None, conditional=True,
        gaps=row.gaps, hops=tuple(hops), evidence=tuple(ref for hop in hops for ref in hop.state.evidence),
        next_evidence=last.next_evidence if isinstance(last, k.Unknown) else needs if state == "problem" else ())


def evaluate_declared(plan: policy.GuardPlan, store: FactStore, subjects: tuple[k.EntityKey, ...]) -> Result:
    """Trust the application's original-source/plan closure; shape checks are not producer seals."""
    _need(type(plan) is policy.GuardPlan and type(store) is FactStore and type(subjects) is tuple
          and all(type(subject) is str for subject in subjects) and subjects == tuple(sorted(set(subjects))))
    order_steps((build.STEP, STEP))
    reader = bind_reader(store, step=STEP)
    matrix = {subject: (reader.read(fact=build.REPORTED_ROLE, subject=subject),
                       reader.read(fact=build.ROOT_GUARD, subject=subject)) for subject in subjects}
    for subject in subjects:
        _validate(matrix[subject][0], role=True)
        _validate(matrix[subject][1], role=False)
    _need(all(point.subject in matrix for row in plan.rows for point in row.participants))
    rows: list[Finding] = []
    for row in plan.rows:
        needs = _needs(row)
        scope: Premise = (k.Unknown(reason=k.UnknownReason.ANALYSIS_GAP, detail="declared_guard_policy_gap",
            evidence=row.declaration.evidence, candidates=(), next_evidence=needs) if row.gaps else
            k.Known(value=True, basis=k.Basis.DECLARED, evidence=row.declaration.evidence, raw=None))
        hops = [Hop(id="declared_scope", state=scope)]
        if isinstance(scope, k.Unknown):
            rows.append(_finding(row, hops, needs))
            continue
        roles = tuple(matrix[point.subject][0] for point in row.participants)
        role_refs = tuple(k.FactRef(fact=build.REPORTED_ROLE, subject=point.subject) for point in row.participants)
        if any(isinstance(value, k.Known) and value.value != "designated" for value in roles):
            role: Premise = k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=role_refs)
        else:
            gap = next((value for value in roles if isinstance(value, k.Unknown)), None)
            role = _gap(gap, role_refs, needs) if gap is not None else k.Known(
                value=True, basis=k.Basis.DERIVED, evidence=role_refs, raw=None)
        hops.append(Hop(id="reported_role", state=role))
        if not isinstance(role, k.Known):
            rows.append(_finding(row, hops, needs))
            continue
        guards = tuple(matrix[point.subject][1] for point in row.participants)
        guard_refs = tuple(k.FactRef(fact=build.ROOT_GUARD, subject=point.subject) for point in row.participants)
        gap = next((value for value in guards if isinstance(value, k.Unknown)), None)
        if gap is not None:
            guard: Premise = _gap(gap, guard_refs, needs)
        else:
            match guards:
                case (k.Known(value=a), k.Known(value=b)):
                    guard = (k.Known(value=True, basis=k.Basis.DERIVED, evidence=guard_refs, raw=None) if a != b else
                        k.Unknown(reason=k.UnknownReason.AS_OF_MISSING, detail="untimed_equal_guard_reports",
                                  evidence=guard_refs, candidates=(), next_evidence=needs))
                case _:
                    raise ValueError("stp_guard_check_input")
        hops.append(Hop(id="reported_root_guard", state=guard))
        rows.append(_finding(row, hops, needs))
    return Result(rows=tuple(rows), denominator=plan.denominator, coverage=plan.coverage)
