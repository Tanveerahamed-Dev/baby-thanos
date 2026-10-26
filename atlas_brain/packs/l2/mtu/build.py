"""Single-owner sample MTU facts; parser and custody checks precede every write."""
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.p3_records import (
    Adjacency,
    Endpoint,
    P3Group,
    Sample,
    sample_subject,
)
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource
from atlas_brain.model.specs import FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l2.mtu import parse as parser

PACK = k.PackId("l2.mtu")
MTU = k.FactId("l2.mtu.interface_bytes")
OP, COMMAND = parser.OP, parser.COMMAND
STEP = StepSpec(id=StepId("l2.mtu/parse_samples"), pack=PACK, kind="parse_build",
                scope="device", reads=(), produces=(MTU,), evaluator="l2.mtu.build_sample")
FACTS = (FactSpec(id=MTU, pack=PACK, subject="ospf_sample", value_type="integer", step=STEP.id),)


@dataclass(frozen=True, slots=True, kw_only=True)
class Fields:
    adjacency: Adjacency
    point: Endpoint
    subject: k.EntityKey
    value: k.Known[int] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Fields, ...]
    parses: tuple[tuple[k.CaptureId, ParseResult], ...]
    quality: Literal["complete", "partial"]


def _declaration(state: k.Known[str], raw: bytes, table: str, identifier: str) -> tuple[k.Evidence, ...]:
    k.require(state.basis is k.Basis.DECLARED and state.value == identifier, "mtu_declaration_identity")
    k.require(bool(state.evidence) and all(isinstance(ref, k.RegistryRef) and ref.table == table
              and ref.row_id == identifier and ref.table_digest == sha256(raw).hexdigest()
              for ref in state.evidence), "mtu_registry_binding")
    return state.evidence


def _ref(capture: Capture, span: k.ByteSpan | k.WholeCapture) -> k.EvidenceRef:
    if isinstance(span, k.ByteSpan):
        k.require(0 <= span.start <= span.end <= len(capture.raw), "mtu_span_bounds")
        raw = capture.raw[span.start:span.end]
    else:
        raw = capture.raw
    return k.EvidenceRef(capture=capture.id, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(raw).hexdigest())


def build_sample(group: P3Group, sample: Sample, node: Node, store: FactStore) -> Result:
    """Build only declared adjacency endpoints; interface MTU never supplies IP MTU."""
    k.require(group.base.schema == BASE_SCHEMA, "mtu_base_schema")
    k.require(node in group.base.nodes and node.group == group.base.id, "mtu_node_membership")
    k.require(sample in group.samples and sum(item.id == sample.id for item in group.samples) == 1,
              "mtu_sample_membership")
    points = tuple((adjacency, point) for adjacency in sorted(group.adjacencies, key=lambda item: item.id)
                   for point in (adjacency.left, adjacency.right) if point.node.key == node.key)
    k.require(all(point.node == node and point.port in node.ports for _, point in points), "mtu_endpoint_membership")
    ports = tuple(sorted(point.port for _, point in points))
    k.require(len(set(ports)) == len(ports), "mtu_duplicate_endpoint")
    scopes = {(point.vrf, str(point.process)) for _, point in points}
    k.require(len(scopes) <= 1, "mtu_node_scope")
    captures = tuple(sorted((capture for capture in sample.captures
                             if capture.source == node.key and capture.operation == OP), key=lambda item: str(item.id)))
    k.require(not captures or bool(points), "mtu_capture_without_endpoint")
    declarations = (_declaration(group.base.declaration, group.base.raw, "synthetic_p2.groups", group.base.id)
                    + _declaration(node.declaration, group.base.raw, "synthetic_p2.nodes", node.id)
                    + _declaration(sample.declaration, group.raw, "synthetic_p3.samples", sample.id))
    for capture in captures:
        point = points[0][1]
        expected_scope = Scope(node=node.key, vrf=point.vrf, instance=str(point.process), context=None,
                               vdc=None, tenant=None, afi=None, plane="exec")
        k.require(capture.source == node.key and capture.scope == expected_scope, "mtu_capture_scope")
        collected = capture.collected_utc
        if sample.time is None:
            k.require(isinstance(collected, k.Unknown) and collected.reason is k.UnknownReason.AS_OF_MISSING,
                      "mtu_sample_time")
        else:
            k.require(sample.time.bound is BoundSource.COLLECTOR_RECORDED
                      and sample.time.clock.startswith("collector:") and collected == sample.time, "mtu_sample_time")
    documents = tuple((capture, parser.parse_capture(capture, ports)) for capture in captures)
    for _, document in documents:
        k.require(len(document.rows) == len(ports) and {row.port for row in document.rows} == set(ports),
                  "mtu_parser_population")
    indexed = {row.port: row for row in documents[0][1].rows} if len(documents) == 1 else {}
    needs = (k.EvidenceNeed(node=node.key, operation=OP, params=(), resolves=(str(MTU),),
                            reruns=(str(STEP.id),), after_s=None, unprintable=()),)
    rows: list[Fields] = []
    for adjacency, point in points:
        evidence = declarations + _declaration(adjacency.declaration, group.raw, "synthetic_p3.adjacencies", adjacency.id)
        context = evidence + tuple(_ref(capture, k.WholeCapture()) for capture in captures)
        reason: k.UnknownReason | None = None
        value: k.Known[int] | k.Unknown = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED,
            detail="sample_mtu_unresolved", evidence=context, candidates=(), next_evidence=needs)
        if not captures:
            reason = k.UnknownReason.NOT_COLLECTED
        elif len(captures) != 1:
            reason = k.UnknownReason.CONFLICTING_EVIDENCE
        else:
            capture, document = documents[0]
            row = indexed[point.port]
            reason = document.reason or row.reason
            if reason is None and document.parse.quality != "complete":
                reason = k.UnknownReason.PARSE_PARTIAL
            if reason is None:
                fields = dict(row.fields)
                k.require(len(fields) == len(row.fields) and parser.FIELD in fields and "port" in fields,
                          "mtu_parser_fields")
                token = fields[parser.FIELD]
                raw = token.raw
                k.require(raw.isascii() and raw.isdigit() and 1 <= len(raw) <= 5
                          and 1 <= int(raw) <= 65535 and str(int(raw)) == raw and token.value == raw,
                          "mtu_parser_value")
                k.require(fields["port"].raw == point.port and bool(row.spans), "mtu_parser_subject")
                for span in row.spans:
                    k.require(0 <= span.start < span.end <= len(capture.raw), "mtu_span_bounds")
                for field in fields.values():
                    k.require(0 <= field.span.start < field.span.end <= len(capture.raw)
                              and capture.raw[field.span.start:field.span.end] == field.raw.encode("utf-8")
                              and any(span.start <= field.span.start < field.span.end <= span.end for span in row.spans),
                              "mtu_token_witness")
                value = k.Known(value=int(raw), basis=k.Basis.OBSERVED, raw=raw,
                                evidence=evidence + tuple(_ref(capture, span) for span in (token.span,) + row.spans))
            else:
                context += tuple(_ref(capture, span) for span in row.spans)
        if reason is not None:
            value = k.Unknown(reason=reason, detail="sample_mtu_unresolved", evidence=context,
                              candidates=(), next_evidence=needs)
        rows.append(Fields(adjacency=adjacency, point=point,
                           subject=sample_subject(adjacency, point, sample), value=value))
    k.require(len({row.subject for row in rows}) == len(rows), "mtu_sample_subject_collision")
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=MTU, subject=row.subject, value=row.value)
    quality: Literal["complete", "partial"] = "complete" if rows and all(
        isinstance(row.value, k.Known) for row in rows) else "partial"
    return Result(rows=tuple(rows), parses=tuple((capture.id, document.parse) for capture, document in documents),
                  quality=quality)
