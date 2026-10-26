"""R1 is a conditional candidate over owned samples, never a unique causal proof."""
from dataclasses import dataclass
from typing import Literal, cast

from atlas_brain.evidence.p3_records import (
    Adjacency,
    Endpoint,
    P3Group,
    adjacency_subject,
    sample_subject,
)
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, StoredState, bind_reader
from atlas_brain.packs.l3.mtu import build as mtu
from atlas_brain.packs.l3.ospf import specs

CHECK = "l3.ospf.mtu_cause_candidate"
STEP = StepSpec(id=StepId("l3.ospf/r1"), pack=specs.PACK, kind="check", scope="estate",
    reads=tuple(sorted((specs.CONTEXT, specs.PERSISTENT, specs.SPAN, specs.IGNORE, mtu.MTU))),
    produces=(), evaluator="l3.ospf.r1")
type Premise = k.Known[bool] | k.Unknown | k.NotApplicable


@dataclass(frozen=True, slots=True, kw_only=True)
class Hop:
    id: str
    state: Premise


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    adjacency: Adjacency
    subject: k.EntityKey
    state: Literal["problem", "unknown", "not_applicable"]
    reason: k.UnknownReason | k.NAReason | None
    hops: tuple[Hop, ...]
    receiving_endpoint: k.EntityKey | None
    evidence: tuple[k.Evidence, ...]
    next_evidence: tuple[k.EvidenceNeed, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Finding, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _typed[T](state: StoredState, expected: type[T], basis: k.Basis) -> k.Known[T] | k.Unknown:
    if isinstance(state, k.Unknown):
        return state
    if not isinstance(state, k.Known) or type(state.value) is not expected or state.basis is not basis:
        raise ValueError("invalid_r1_input")
    return cast("k.Known[T]", state)


def _needs(adjacency: Adjacency, *, after: int | None = None) -> tuple[k.EvidenceNeed, ...]:
    return tuple(k.EvidenceNeed(node=point.node.key, operation=operation, params=(), resolves=(CHECK,),
        reruns=(str(STEP.id), str(specs.SETTLE.id)), after_s=after, unprintable=("collector_recorded_time",))
        for point in sorted((adjacency.left, adjacency.right), key=lambda p: p.node.key)
        for operation in ("iosxe.show_ip_interface", "iosxe.show_ip_ospf_interface",
                          "iosxe.show_ip_ospf_neighbor", "iosxe.show_running_config_all"))


def _gap(value: k.Unknown, evidence: tuple[k.Evidence, ...],
         needs: tuple[k.EvidenceNeed, ...]) -> k.Unknown:
    return k.Unknown(reason=value.reason, detail=value.detail, candidates=value.candidates,
                     evidence=evidence + value.evidence, next_evidence=value.next_evidence or needs)


def _finding(adjacency: Adjacency, hops: list[Hop], receiver: k.EntityKey | None,
             needs: tuple[k.EvidenceNeed, ...]) -> Finding:
    last = hops[-1].state
    state: Literal["problem", "unknown", "not_applicable"] = (
        "unknown" if isinstance(last, k.Unknown) else "not_applicable" if isinstance(last, k.NotApplicable) else "problem")
    reason = last.reason if isinstance(last, (k.Unknown, k.NotApplicable)) else None
    evidence = tuple(ref for hop in hops for ref in hop.state.evidence)
    return Finding(adjacency=adjacency, subject=adjacency_subject(adjacency), state=state, reason=reason,
        hops=tuple(hops), receiving_endpoint=receiver, evidence=evidence,
        next_evidence=last.next_evidence if isinstance(last, k.Unknown) else needs if state == "problem" else ())


def build_group(group: P3Group, store: FactStore) -> Result:
    """Read every declared input first; correlation never stores a fact or reparses."""
    reader = bind_reader(store, step=STEP)
    matrices = []
    for adjacency in sorted(group.adjacencies, key=lambda a: a.id):
        key = adjacency_subject(adjacency)
        settled = tuple(reader.read(fact=fact, subject=key) for fact in (specs.CONTEXT, specs.PERSISTENT, specs.SPAN))
        sampled = tuple(tuple((reader.read(fact=mtu.MTU, subject=sample_subject(adjacency, point, sample)),
                               reader.read(fact=specs.IGNORE, subject=sample_subject(adjacency, point, sample)))
                              for point in (adjacency.left, adjacency.right)) for sample in group.samples)
        matrices.append((adjacency, settled, sampled))
    rows: list[Finding] = []
    for adjacency, settled, sampled in matrices:
        context = _typed(settled[0], bool, k.Basis.DERIVED)
        persistent = _typed(settled[1], bool, k.Basis.DERIVED)
        span = _typed(settled[2], int, k.Basis.DERIVED)
        k.require(not isinstance(context, k.Known) or context.value, "invalid_r1_context")
        k.require(not isinstance(span, k.Known) or span.value >= 0, "invalid_r1_span")
        values = tuple(tuple((_typed(pair[0], int, k.Basis.OBSERVED), _typed(pair[1], bool, k.Basis.CONFIGURED))
                             for pair in round_values) for round_values in sampled)
        k.require(all(not isinstance(value, k.Known) or 1 <= value.value <= 65535
                      for round_values in values for value, _ in round_values), "invalid_r1_mtu")
        needs = _needs(adjacency, after=120)
        subject = adjacency_subject(adjacency)
        context_refs = (k.FactRef(fact=specs.CONTEXT, subject=subject),)
        context_hop = (_gap(context, context_refs, needs) if isinstance(context, k.Unknown) else
                       k.Known(value=True, basis=k.Basis.DERIVED, evidence=context_refs, raw=None))
        hops = [Hop(id="peer_context", state=context_hop)]
        if isinstance(context, k.Unknown):
            rows.append(_finding(adjacency, hops, None, needs))
            continue
        refs = tuple(k.FactRef(fact=mtu.MTU, subject=sample_subject(adjacency, point, sample))
                     for sample in group.samples for point in (adjacency.left, adjacency.right))
        missing = next((value for round_values in values for value, _ in round_values if isinstance(value, k.Unknown)), None)
        if missing is not None or not values:
            unknown = (k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="no_mtu_samples",
                       evidence=adjacency.declaration.evidence, candidates=(), next_evidence=needs) if missing is None
                       else _gap(missing, refs, needs))
            hops.append(Hop(id="ip_mtu", state=unknown))
            rows.append(_finding(adjacency, hops, None, needs))
            continue
        directions = tuple((cast("k.Known[int]", pair[0][0]).value > cast("k.Known[int]", pair[1][0]).value)
                           - (cast("k.Known[int]", pair[0][0]).value < cast("k.Known[int]", pair[1][0]).value)
                           for pair in values)
        if all(direction == 0 for direction in directions):
            hops.append(Hop(id="ip_mtu", state=k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=refs)))
            rows.append(_finding(adjacency, hops, None, needs))
            continue
        if 0 in directions or len(set(directions)) != 1:
            hops.append(Hop(id="ip_mtu", state=k.Unknown(reason=k.UnknownReason.CONFLICTING_EVIDENCE,
                detail="mtu_receiver_not_stable", evidence=refs, candidates=(), next_evidence=needs)))
            rows.append(_finding(adjacency, hops, None, needs))
            continue
        receiver_index = 0 if directions[0] < 0 else 1
        receiver: Endpoint = (adjacency.left, adjacency.right)[receiver_index]
        hops.append(Hop(id="ip_mtu", state=k.Known(value=True, basis=k.Basis.DERIVED, evidence=refs, raw=None)))
        persistence_refs = (k.FactRef(fact=specs.PERSISTENT, subject=subject), k.FactRef(fact=specs.SPAN, subject=subject))
        state: Premise = (_gap(persistent, persistence_refs, needs) if isinstance(persistent, k.Unknown) else
            k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=persistence_refs) if not persistent.value else
            k.Known(value=True, basis=k.Basis.DERIVED, evidence=persistence_refs, raw=None))
        hops.append(Hop(id="sampled_persistence", state=state))
        receiver_key = endpoint(receiver.node, receiver.port)
        if not isinstance(state, k.Known):
            rows.append(_finding(adjacency, hops, receiver_key, needs))
            continue
        k.require(isinstance(span, k.Known) and span.value >= 120000000, "invalid_persistence_span")
        controls = tuple(pair[receiver_index][1] for pair in values)
        control_refs = tuple(k.FactRef(fact=specs.IGNORE, subject=sample_subject(adjacency, receiver, sample))
                             for sample in group.samples)
        gap = next((value for value in controls if isinstance(value, k.Unknown)), None)
        enabled = tuple(value for value in controls if isinstance(value, k.Known) and value.value)
        if enabled:
            counter = tuple(k.EvidenceRef(capture=ref.capture, locator=ref.locator,
                            role=k.EvidenceRole.COUNTER_EVIDENCE, excerpt_sha256=ref.excerpt_sha256)
                            for value in enabled for ref in value.evidence if isinstance(ref, k.EvidenceRef))
            state = k.NotApplicable(reason=k.NAReason.FEATURE_NOT_ENABLED, evidence=control_refs + counter)
        elif gap is not None:
            state = _gap(gap, control_refs, needs)
        else:
            state = k.Known(value=True, basis=k.Basis.DERIVED, evidence=control_refs, raw=None)
        hops.append(Hop(id="receiving_control", state=state))
        if isinstance(state, k.Known):
            proof = tuple(ref for hop in hops for ref in hop.state.evidence)
            hops.append(Hop(id="candidate", state=k.Known(value=True, basis=k.Basis.DERIVED, evidence=proof, raw=None)))
        rows.append(_finding(adjacency, hops, receiver_key, needs))
    denominator = (("declared_adjacencies", len(group.adjacencies)), ("rounds", len(group.samples)),
                   ("expected_endpoint_samples", len(group.adjacencies) * len(group.samples) * 2))
    coverage = k.Unknown(reason=k.UnknownReason.DENOMINATOR_OPEN, detail="declared_synthetic_r1_scope",
        evidence=tuple(ref for adjacency in group.adjacencies for ref in adjacency.declaration.evidence),
        candidates=(), next_evidence=tuple(need for adjacency in group.adjacencies for need in _needs(adjacency)))
    return Result(rows=tuple(rows), denominator=denominator, coverage=coverage)
