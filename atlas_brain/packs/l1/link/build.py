"""Reciprocal declared-synthetic discovery joins; no physical or current-link claim."""
from dataclasses import dataclass
from typing import cast

from atlas_brain.evidence.synthetic import Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import (
    EntityKindSpec,
    FactSpec,
    RelationSpec,
    StepId,
    StepSpec,
)
from atlas_brain.model.store import FactReader, FactStore, bind_reader, bind_writer
from atlas_brain.packs.l2.discovery import build as discovery

PACK = k.PackId("l1.link")
PEER = k.FactId("l1.link.peer")
STEP = StepSpec(id=StepId("l1.link/pair"), pack=PACK, kind="derive", scope="estate",
                reads=discovery.IDS, produces=(PEER,), evaluator="l1.link.build_group")
FACTS = (FactSpec(id=PEER, pack=PACK, subject="interface", value_type="entity_ref", step=STEP.id),)
KINDS = (EntityKindSpec(id="node", pack=PACK, root=True),
         EntityKindSpec(id="interface", pack=PACK, root=False))
RELATIONS = (RelationSpec(id=str(PEER), pack=PACK, source="interface", target="interface",
                          cardinality="one_to_one"),)


@dataclass(frozen=True, slots=True, kw_only=True)
class LinkRow:
    node: Node
    port: str
    subject: k.EntityKey
    peer: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class LinkResult:
    rows: tuple[LinkRow, ...]
    pairs: tuple[tuple[k.EntityKey, k.EntityKey], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Input:
    node: Node
    port: str
    subject: k.EntityKey
    device: k.Known[str] | k.Unknown
    remote: k.Known[str] | k.Unknown
    bridge: k.Known[bool] | k.Unknown

    @property
    def refs(self) -> tuple[k.Evidence, ...]:
        return tuple(k.FactRef(fact=fact, subject=self.subject) for fact in discovery.IDS)


def _read[T](reader: FactReader, fact: k.FactId, subject: k.EntityKey,
             expected: type[T]) -> k.Known[T] | k.Unknown:
    state = reader.read(fact=fact, subject=subject)
    if isinstance(state, k.Unknown):
        return state
    if not isinstance(state, k.Known) or type(state.value) is not expected:
        raise ValueError("invalid_discovery_state")
    return cast("k.Known[T]", state)


def _unknown(reason: k.UnknownReason, detail: str | None, evidence: tuple[k.Evidence, ...],
             node: Node, candidates: tuple[k.EntityKey, ...] = (), *,
             nodes: tuple[Node, ...] = ()) -> k.Unknown:
    needs = tuple(k.EvidenceNeed(node=collector.key, operation=command, params=(), resolves=(str(PEER),),
                                reruns=(str(STEP.id), str(discovery.STEP.id)), after_s=None, unprintable=())
                  for collector in sorted(nodes or (node,), key=lambda item: item.key)
                  for command in ("show cdp neighbors detail", "show lldp neighbors detail"))
    return k.Unknown(reason=reason, detail=detail, evidence=evidence,
                     candidates=candidates, next_evidence=needs)


def _gap(point: _Input) -> k.Unknown | None:
    return next((state for state in (point.device, point.remote, point.bridge)
                 if isinstance(state, k.Unknown)), None)


def build_group(group: SyntheticGroup, store: FactStore) -> LinkResult:
    """Read the entire declared discovery matrix, validate it, then write once."""
    reader = bind_reader(store, step=STEP)
    points: dict[k.EntityKey, _Input] = {}
    for node in sorted(group.nodes, key=lambda item: item.key):
        for port in sorted(node.ports):
            subject = endpoint(node, port)
            points[subject] = _Input(node=node, port=port, subject=subject,
                                    device=_read(reader, discovery.DEVICE_ID, subject, str),
                                    remote=_read(reader, discovery.REMOTE_PORT, subject, str),
                                    bridge=_read(reader, discovery.BRIDGE, subject, bool))
    aliases = {node.discovery_id: node for node in group.nodes}
    k.require(len(aliases) == len(group.nodes), "ambiguous_discovery_identity")
    targets: dict[k.EntityKey, k.EntityKey] = {}
    incoming: dict[k.EntityKey, list[k.EntityKey]] = {}
    for subject, point in points.items():
        if isinstance(point.device, k.Known) and isinstance(point.remote, k.Known):
            other = aliases.get(point.device.value)
            if other is not None:
                k.require(other.key != point.node.key, "self_discovery_claim")
                if point.remote.value in other.ports:
                    target = endpoint(other, point.remote.value)
                    targets[subject] = target
                    incoming.setdefault(target, []).append(subject)
    k.require(all(len(sources) == 1 for sources in incoming.values()), "contradictory_discovery_claims")
    for subject, target in targets.items():
        point, reverse = points[subject], points[target]
        if (isinstance(reverse.device, k.Known) and reverse.device.value != point.node.discovery_id
                or isinstance(reverse.remote, k.Known) and reverse.remote.value != point.port):
            raise ValueError("asymmetric_discovery_claim")
    rows: list[LinkRow] = []
    pairs: set[tuple[k.EntityKey, k.EntityKey]] = set()
    for subject, point in points.items():
        evidence = group.declaration.evidence + point.node.declaration.evidence + point.refs
        gap = _gap(point)
        peer: k.Known[str] | k.Unknown
        if gap is not None:
            peer = _unknown(gap.reason, gap.detail, evidence, point.node, gap.candidates)
        else:
            device = cast("k.Known[str]", point.device)
            remote = cast("k.Known[str]", point.remote)
            other = aliases.get(device.value)
            if other is None:
                peer = _unknown(k.UnknownReason.IDENTITY_UNRESOLVED, "exact_peer_alias_unmapped",
                                evidence, point.node)
            elif remote.value not in other.ports:
                peer = _unknown(k.UnknownReason.JOIN_UNPROVEN, "exact_peer_port_undeclared",
                                evidence + other.declaration.evidence, other, (other.key,))
            else:
                target = targets[subject]
                reverse = points[target]
                evidence += other.declaration.evidence + reverse.refs
                reverse_gap = _gap(reverse)
                if reverse_gap is not None:
                    why = (k.UnknownReason.PEER_NOT_COLLECTED if reverse_gap.reason in (
                        k.UnknownReason.NOT_COLLECTED, k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
                           else reverse_gap.reason)
                    peer = _unknown(why, reverse_gap.detail, evidence, other, (target,))
                elif not cast("k.Known[bool]", point.bridge).value or not cast("k.Known[bool]", reverse.bridge).value:
                    collectors = tuple(item.node for item in (point, reverse)
                                       if not cast("k.Known[bool]", item.bridge).value)
                    peer = _unknown(k.UnknownReason.NOT_OBSERVABLE, "bridge_peer_unproven",
                                    evidence, point.node, (target,), nodes=collectors)
                else:
                    k.require(targets.get(target) == subject, "asymmetric_discovery_claim")
                    peer = k.Known(value=str(target), basis=k.Basis.DERIVED, evidence=evidence, raw=None)
                    pair = (subject, target) if subject < target else (target, subject)
                    pairs.add(pair)
        rows.append(LinkRow(node=point.node, port=point.port, subject=subject, peer=peer))
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=PEER, subject=row.subject, value=row.peer)
    return LinkResult(rows=tuple(rows), pairs=tuple(sorted(pairs)))
