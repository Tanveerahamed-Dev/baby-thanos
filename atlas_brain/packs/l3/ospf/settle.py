"""Owned sampled persistence; every declared round and endpoint is an operand."""
from dataclasses import dataclass
from typing import cast

from atlas_brain.evidence.p3_records import (
    Adjacency,
    Endpoint,
    P3Group,
    adjacency_subject,
    sample_subject,
)
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, StoredState, bind_reader, bind_writer
from atlas_brain.packs.l1.link.build import PEER
from atlas_brain.packs.l3.ospf import specs as s
from atlas_brain.packs.l3.ospf import timeline

MINIMUM_SEPARATION_US = 120000000
TIME = (s.CLOCK, s.EARLIEST, s.LATEST)
DECLARED = (s.ADJACENCY, s.INTERFACE) + TIME
STATES = ("DOWN", "ATTEMPT", "INIT", "2WAY", "EXSTART", "EXCHANGE", "LOADING", "FULL")
TYPES: dict[k.FactId, type[object]] = {
    s.STATE: str, s.ROLE: str, s.NEIGHBOR_ID: str, s.NEIGHBOR_ADDRESS: str,
    s.ROUTER_ID: str, s.ADDRESS: str, s.NETWORK: str, s.VRF: str,
    s.CLOCK: str, s.ADJACENCY: str, s.INTERFACE: str,
    s.PROCESS: int, s.AREA: int, s.EARLIEST: int, s.LATEST: int, s.IGNORE: bool,
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Fields:
    adjacency: Adjacency
    subject: k.EntityKey
    context: k.Known[bool] | k.Unknown
    persistent: k.Known[bool] | k.Unknown
    span: k.Known[int] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Fields, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Read:
    point: Endpoint
    subject: k.EntityKey
    values: dict[k.FactId, StoredState]

    def get(self, fact: k.FactId) -> StoredState:
        k.require(fact in self.values, "ospf_settle_fact")
        return self.values[fact]


def _token(state: StoredState) -> object | None:
    return state.value if isinstance(state, k.Known) else None


def _valid(state: StoredState, expected: type[object], basis: k.Basis) -> None:
    k.require(type(state) in (k.Known, k.Unknown), "ospf_settle_state")
    if isinstance(state, k.Known):
        k.require(type(state.value) is expected and state.basis is basis, "ospf_settle_fact_contract")


def _needs(adjacency: Adjacency) -> tuple[k.EvidenceNeed, ...]:
    return tuple(k.EvidenceNeed(node=point.node.key, operation=operation, params=(),
        resolves=tuple(str(fact) for fact in s.SETTLE.produces),
        reruns=tuple(sorted((str(s.STEP.id), str(s.SETTLE.id)))),
        after_s=120 if operation == "iosxe.show_ip_ospf_neighbor" else None,
        unprintable=("collector_clock_required", "collector_interval_unix_us_required", "declared_collection_round_required"))
        for point in sorted((adjacency.left, adjacency.right), key=lambda point: point.node.key)
        for operation in ("iosxe.show_ip_ospf_interface", "iosxe.show_ip_ospf_neighbor"))


def _context(adjacency: Adjacency, peers: tuple[StoredState, ...], rows: tuple[_Read, ...],
             proof: tuple[k.Evidence, ...], needs: tuple[k.EvidenceNeed, ...]) -> k.Known[bool] | k.Unknown:
    if not rows:
        return timeline.unknown(k.UnknownReason.NOT_COLLECTED, "no_collection_rounds", proof, needs)
    for peer, other in zip(peers, (adjacency.right, adjacency.left)):
        if isinstance(peer, k.Unknown):
            return timeline.unknown(peer.reason, peer.detail, proof, needs, peer)
        if cast(k.Known[str], peer).value != endpoint(other.node, other.port):
            return timeline.unknown(k.UnknownReason.JOIN_UNPROVEN, "declared_peer_unproven", proof, needs)
    for row in rows:
        point = row.point
        other = adjacency.right if point == adjacency.left else adjacency.left
        expected = ((s.ADJACENCY, adjacency_subject(adjacency)), (s.INTERFACE, endpoint(point.node, point.port)),
                    (s.PROCESS, point.process), (s.ROUTER_ID, point.router_id), (s.ADDRESS, point.address),
                    (s.NEIGHBOR_ID, other.router_id), (s.NEIGHBOR_ADDRESS, other.address), (s.AREA, adjacency.area))
        for fact, value in expected:
            state = row.get(fact)
            if isinstance(state, k.Unknown):
                return timeline.unknown(state.reason, state.detail, proof, needs, state)
            if cast(k.Known[object], state).value != value:
                return timeline.unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "ospf_context_mismatch", proof, needs)
        for fact, value in ((s.NETWORK, "POINT_TO_POINT"), (s.ROLE, "-"), (s.VRF, "default")):
            state = row.get(fact)
            if isinstance(state, k.Unknown):
                if fact == s.VRF and state.reason is k.UnknownReason.FIELD_NOT_PRINTED and point.vrf == "default":
                    continue
                return timeline.unknown(state.reason, state.detail, proof, needs, state)
            if point.vrf != "default" or cast(k.Known[str], state).value != value:
                return timeline.unknown(k.UnknownReason.NOT_OBSERVABLE, "unsupported_ospf_scope", proof, needs)
    return k.Known(value=True, basis=k.Basis.DERIVED, evidence=proof, raw=None)


def _persistent(context: k.Known[bool] | k.Unknown, rows: tuple[_Read, ...],
                span: k.Known[int] | k.Unknown, proof: tuple[k.Evidence, ...],
                needs: tuple[k.EvidenceNeed, ...]) -> k.Known[bool] | k.Unknown:
    if isinstance(context, k.Unknown):
        return timeline.unknown(context.reason, context.detail, proof, needs, context)
    states = tuple(value for row in rows for fact, value in row.values.items() if fact == s.STATE)
    known = {_token(state) for state in states if isinstance(state, k.Known)}
    if len(known) > 1:
        return timeline.unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "sample_states_disagree", proof, needs)
    gap = next((state for state in states if isinstance(state, k.Unknown)), None)
    if gap is not None:
        return timeline.unknown(gap.reason, gap.detail, proof, needs, gap)
    if len(rows) == 2:
        return timeline.unknown(k.UnknownReason.SINGLE_SAMPLE, "second_collection_round_required", proof, needs)
    if known not in ({"EXSTART"}, {"EXCHANGE"}):
        return k.Known(value=False, basis=k.Basis.DERIVED, evidence=proof, raw=None)
    if isinstance(span, k.Unknown):
        return timeline.unknown(span.reason, span.detail, proof, needs, span)
    if span.value < MINIMUM_SEPARATION_US:
        return timeline.unknown(k.UnknownReason.SINGLE_SAMPLE, "sample_separation_below_120s", proof, needs)
    return k.Known(value=True, basis=k.Basis.DERIVED, evidence=proof, raw=None)


def build_group(group: P3Group, store: FactStore) -> Result:
    reader = bind_reader(store, step=s.SETTLE)
    matrix: list[tuple[Adjacency, tuple[StoredState, ...], tuple[_Read, ...]]] = []
    for adjacency in sorted(group.adjacencies, key=lambda item: item.id):
        peers = tuple(reader.read(fact=PEER, subject=endpoint(point.node, point.port))
                      for point in (adjacency.left, adjacency.right))
        reads: list[_Read] = []
        for sample in sorted(group.samples, key=lambda item: item.id):
            for point in (adjacency.left, adjacency.right):
                subject = sample_subject(adjacency, point, sample)
                reads.append(_Read(point=point, subject=subject,
                                  values={fact: reader.read(fact=fact, subject=subject) for fact in s.IDS}))
        matrix.append((adjacency, peers, tuple(reads)))
    results: list[Fields] = []
    k.require(set(TYPES) == set(s.IDS), "ospf_settle_fact_types")
    for adjacency, peers, rows in matrix:
        for peer in peers:
            _valid(peer, str, k.Basis.DERIVED)
        for row in rows:
            for fact, state in row.values.items():
                basis = k.Basis.DECLARED if fact in DECLARED else k.Basis.CONFIGURED if fact == s.IGNORE else k.Basis.OBSERVED
                _valid(state, TYPES[fact], basis)
            state = next(value for fact, value in row.values.items() if fact == s.STATE)
            k.require(not isinstance(state, k.Known) or _token(state) in STATES, "ospf_settle_state_value")
            role = next(value for fact, value in row.values.items() if fact == s.ROLE)
            k.require(not isinstance(role, k.Known) or _token(role) in ("-", "DR", "BDR", "DROTHER"), "ospf_settle_role_value")
        proof = (group.base.declaration.evidence + adjacency.declaration.evidence
                 + adjacency.left.node.declaration.evidence + adjacency.right.node.declaration.evidence
                 + tuple(k.FactRef(fact=PEER, subject=endpoint(point.node, point.port))
                         for point in (adjacency.left, adjacency.right))
                 + tuple(k.FactRef(fact=fact, subject=row.subject) for row in rows for fact in s.IDS))
        needs = _needs(adjacency)
        times = tuple((cast(timeline.TimeFacts, tuple(rows[index].get(fact) for fact in TIME)),
                       cast(timeline.TimeFacts, tuple(rows[index + 1].get(fact) for fact in TIME)))
                      for index in range(0, len(rows), 2))
        span = timeline.measure(times, evidence=proof, needs=needs)
        context = _context(adjacency, peers, rows, proof, needs)
        persistent = _persistent(context, rows, span, proof, needs)
        results.append(Fields(adjacency=adjacency, subject=adjacency_subject(adjacency),
                              context=context, persistent=persistent, span=span))
    k.require(all(store.owners.get(fact) in (None, s.SETTLE.id) for fact in s.SETTLE.produces), "ospf_settle_owner")
    k.require(all(k.FactRef(fact=fact, subject=row.subject) not in store.values
                  for row in results for fact in s.SETTLE.produces), "ospf_settle_duplicate_write")
    writer = bind_writer(store, step=s.SETTLE)
    for row in results:
        writer.write(fact=s.CONTEXT, subject=row.subject, value=row.context)
        writer.write(fact=s.PERSISTENT, subject=row.subject, value=row.persistent)
        writer.write(fact=s.SPAN, subject=row.subject, value=row.span)
    return Result(rows=tuple(results))
