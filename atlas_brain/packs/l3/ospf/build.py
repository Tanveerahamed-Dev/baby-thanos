"""Owned OSPF sample facts; observed identity never inherits declared values."""
from dataclasses import dataclass
from typing import Literal

from atlas_brain.evidence.p3_records import (
    Adjacency,
    Endpoint,
    P3Group,
    Sample,
    adjacency_subject,
    sample_subject,
)
from atlas_brain.evidence.parsekit.rules import Captured, ParseResult
from atlas_brain.evidence.synthetic import Node, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, StoredState, bind_writer
from atlas_brain.packs.l3.ospf import ignore, interface, neighbor
from atlas_brain.packs.l3.ospf import sample_support as support
from atlas_brain.packs.l3.ospf import specs as s

type Kind = Literal["text", "integer", "boolean"]
_FIELDS: dict[str, tuple[tuple[str, k.FactId, Kind], ...]] = {
    neighbor.OP: (("state", s.STATE, "text"), ("role", s.ROLE, "text"),
                  ("neighbor_id", s.NEIGHBOR_ID, "text"), ("address", s.NEIGHBOR_ADDRESS, "text")),
    interface.OP: (("router_id", s.ROUTER_ID, "text"), ("address", s.ADDRESS, "text"),
                   ("process", s.PROCESS, "integer"), ("area", s.AREA, "integer"),
                   ("network_type", s.NETWORK, "text"), ("vrf", s.VRF, "text")),
    ignore.OP: (("mtu_ignore", s.IGNORE, "boolean"),),
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Fields:
    adjacency: Adjacency
    point: Endpoint
    subject: k.EntityKey
    facts: tuple[tuple[k.FactId, StoredState], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Fields, ...]
    parses: tuple[tuple[k.CaptureId, ParseResult], ...]
    quality: Literal["complete", "partial"]


def _known(value: object, basis: k.Basis, evidence: tuple[k.Evidence, ...], raw: str | None) -> StoredState:
    k.require(type(value) in (str, int, bool), "ospf_primitive_value")
    return k.Known(value=value, basis=basis, evidence=evidence, raw=raw)


def _unknown(reason: k.UnknownReason, evidence: tuple[k.Evidence, ...],
             node: Node, operation: str, fact: k.FactId) -> k.Unknown:
    need = k.EvidenceNeed(node=node.key, operation=operation, params=(), resolves=(str(fact),),
                         reruns=(str(s.STEP.id),), after_s=None, unprintable=())
    return k.Unknown(reason=reason, detail="sample_ospf_unresolved", evidence=evidence,
                     candidates=(), next_evidence=(need,))


def _scalar(name: str, field: Captured, kind: Kind) -> str | int | bool:
    k.require(isinstance(field.value, str), "ospf_parser_value")
    value = str(field.value)
    if kind == "boolean":
        commands = {"ip ospf mtu-ignore": "enabled", "no ip ospf mtu-ignore": "disabled"}
        k.require(commands.get(field.raw) == value, "ospf_ignore_witness")
        return value == "enabled"
    if kind == "integer":
        maximum = 65535 if name == "process" else 4294967295
        k.require(value.isascii() and value.isdigit() and len(value) <= 10
                  and int(value) <= maximum and str(int(value)) == value
                  and (name != "process" or int(value) > 0), "ospf_parser_integer")
        expected = field.raw
        if name == "area" and "." in field.raw:
            parts = field.raw.split(".")
            k.require(len(parts) == 4 and all(part.isascii() and part.isdigit() and len(part) <= 3
                      and int(part) <= 255 and str(int(part)) == part for part in parts), "ospf_area_witness")
            area = 0
            for part in parts:
                area = area * 256 + int(part)
            expected = str(area)
        k.require(value == expected, "ospf_integer_witness")
        return int(value)
    k.require(value == field.raw, "ospf_text_witness")
    return value


def _observations(context: support.Context, point: Endpoint,
                  evidence: tuple[k.Evidence, ...]) -> dict[k.FactId, StoredState]:
    facts: dict[k.FactId, StoredState] = {}
    for operation, definitions in _FIELDS.items():
        documents = tuple(item for item in context.documents if item[0].operation == operation)
        proof = evidence + tuple(support.reference(capture, k.WholeCapture()) for capture, _ in documents)
        fields: dict[str, Captured] = {}
        spans: tuple[k.Evidence, ...] = ()
        reason = (k.UnknownReason.NOT_COLLECTED if not documents else
                  k.UnknownReason.CONFLICTING_EVIDENCE if len(documents) != 1 else None)
        if reason is None:
            capture, document = documents[0]
            rows = tuple(row for row in document.rows if row.port == point.port)
            reason = document.reason or (k.UnknownReason.CONFLICTING_EVIDENCE if len(rows) != 1 else rows[0].reason)
            if reason is None and document.parse.quality != "complete":
                reason = k.UnknownReason.PARSE_PARTIAL
            if reason is None:
                row = rows[0]
                fields = dict(row.fields)
                spans = support.witnesses(capture, row)
        for name, identifier, kind in definitions:
            field = fields.get(name)
            gap = reason or (k.UnknownReason.FIELD_NOT_PRINTED if field is None else None)
            if gap is not None:
                facts[identifier] = _unknown(gap, proof, point.node, operation, identifier)
            else:
                if field is None:
                    raise ValueError("ospf_parser_field")
                capture = documents[0][0]
                basis = k.Basis.CONFIGURED if identifier == s.IGNORE else k.Basis.OBSERVED
                facts[identifier] = _known(_scalar(name, field, kind), basis,
                    evidence + (support.reference(capture, field.span),) + spans, field.raw)
    return facts


def _times(context: support.Context, point: Endpoint,
           evidence: tuple[k.Evidence, ...]) -> dict[k.FactId, StoredState]:
    documents = tuple(item for item in context.documents if item[0].operation == neighbor.OP)
    proof = evidence + tuple(support.reference(capture, k.WholeCapture()) for capture, _ in documents)
    reason = (k.UnknownReason.NOT_COLLECTED if not documents else
              k.UnknownReason.CONFLICTING_EVIDENCE if len(documents) != 1 else None)
    if reason is None:
        collected = documents[0][0].collected_utc
        if isinstance(collected, k.Unknown):
            reason = k.UnknownReason.AS_OF_MISSING
        else:
            earliest, latest = collected.earliest, collected.latest
            if earliest is None or latest is None:
                raise ValueError("ospf_unbounded_sample_time")
            return {identifier: _known(value, k.Basis.DECLARED, proof, None)
                    for identifier, value in ((s.CLOCK, collected.clock), (s.EARLIEST, earliest), (s.LATEST, latest))}
    return {identifier: _unknown(reason, proof, point.node, neighbor.OP, identifier)
            for identifier in (s.CLOCK, s.EARLIEST, s.LATEST)}


def build_sample(group: P3Group, sample: Sample, node: Node, store: FactStore) -> Result:
    context = support.prepare(group, sample, node)
    rows: list[Fields] = []
    for adjacency, point in context.points:
        evidence = context.declarations + adjacency.declaration.evidence
        facts = _observations(context, point, evidence) | _times(context, point, evidence)
        facts[s.ADJACENCY] = _known(str(adjacency_subject(adjacency)), k.Basis.DECLARED, evidence, None)
        facts[s.INTERFACE] = _known(str(endpoint(point.node, point.port)), k.Basis.DECLARED, evidence, None)
        k.require(set(facts) == set(s.IDS), "ospf_fact_population")
        rows.append(Fields(adjacency=adjacency, point=point, subject=sample_subject(adjacency, point, sample),
                           facts=tuple(sorted(facts.items()))))
    k.require(len({row.subject for row in rows}) == len(rows), "ospf_sample_subject_collision")
    k.require(all(store.owners.get(identifier) in (None, s.STEP.id) for identifier in s.IDS), "ospf_fact_owner")
    k.require(all(k.FactRef(fact=identifier, subject=row.subject) not in store.values
                  for row in rows for identifier, _ in row.facts), "ospf_duplicate_write")
    writer = bind_writer(store, step=s.STEP)
    for row in rows:
        for identifier, value in row.facts:
            writer.write(fact=identifier, subject=row.subject, value=value)
    quality: Literal["complete", "partial"] = "complete" if rows and all(
        isinstance(value, k.Known) for row in rows for _, value in row.facts) else "partial"
    return Result(rows=tuple(rows), parses=tuple((capture.id, document.parse) for capture, document in context.documents),
                  quality=quality)
