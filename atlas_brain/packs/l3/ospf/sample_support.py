"""Pack-owned P3 custody and byte witnesses; this module never writes facts."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.p3_records import Adjacency, Endpoint, P3Group, Sample
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource
from atlas_brain.packs.l3.ospf import ignore, interface, neighbor

type Parsed = neighbor.Result | interface.Result | ignore.Result
type ParsedRow = neighbor.Row | interface.Row | ignore.Row
PARSERS = {
    neighbor.OP: neighbor.parse_capture, interface.OP: interface.parse_capture, ignore.OP: ignore.parse_capture,
}


@dataclass(frozen=True, slots=True, kw_only=True)
class Context:
    points: tuple[tuple[Adjacency, Endpoint], ...]
    declarations: tuple[k.Evidence, ...]
    documents: tuple[tuple[Capture, Parsed], ...]


def declaration(state: k.Known[str], raw: bytes, table: str, identifier: str) -> tuple[k.Evidence, ...]:
    k.require(state.basis is k.Basis.DECLARED and state.value == identifier, "ospf_declaration_identity")
    k.require(bool(state.evidence) and all(isinstance(ref, k.RegistryRef) and ref.table == table
              and ref.row_id == identifier and ref.table_digest == sha256(raw).hexdigest()
              for ref in state.evidence), "ospf_registry_binding")
    return state.evidence


def reference(capture: Capture, span: k.ByteSpan | k.WholeCapture) -> k.EvidenceRef:
    if isinstance(span, k.ByteSpan):
        k.require(0 <= span.start <= span.end <= len(capture.raw), "ospf_span_bounds")
        raw = capture.raw[span.start:span.end]
    else:
        raw = capture.raw
    return k.EvidenceRef(capture=capture.id, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(raw).hexdigest())


def prepare(group: P3Group, sample: Sample, node: Node) -> Context:
    """Admitted records are required; independently bind every selected receipt."""
    k.require(group.base.schema == BASE_SCHEMA, "ospf_base_schema")
    k.require(node in group.base.nodes and node.group == group.base.id, "ospf_node_membership")
    k.require(sample in group.samples and sum(item.id == sample.id for item in group.samples) == 1,
              "ospf_sample_membership")
    points = tuple((adjacency, point) for adjacency in sorted(group.adjacencies, key=lambda item: item.id)
                   for point in (adjacency.left, adjacency.right) if point.node.key == node.key)
    k.require(all(point.node == node and point.port in node.ports for _, point in points), "ospf_endpoint_membership")
    ports = tuple(sorted(point.port for _, point in points))
    k.require(len(set(ports)) == len(ports), "ospf_duplicate_endpoint")
    k.require(len({(point.vrf, point.process) for _, point in points}) <= 1, "ospf_node_scope")
    captures = tuple(sorted((capture for capture in sample.captures if capture.source == node.key
                             and capture.operation in PARSERS), key=lambda item: str(item.id)))
    k.require(not captures or bool(points), "ospf_capture_without_endpoint")
    declarations = (declaration(group.base.declaration, group.base.raw, "synthetic_p2.groups", group.base.id)
                    + declaration(node.declaration, group.base.raw, "synthetic_p2.nodes", node.id)
                    + declaration(sample.declaration, group.raw, "synthetic_p3.samples", sample.id))
    for adjacency, _ in points:
        declaration(adjacency.declaration, group.raw, "synthetic_p3.adjacencies", adjacency.id)
    for capture in captures:
        point = points[0][1]
        scope = Scope(node=node.key, vrf=point.vrf, instance=str(point.process), context=None,
                      vdc=None, tenant=None, afi=None, plane="exec")
        k.require(capture.source == node.key and capture.scope == scope, "ospf_capture_scope")
        collected = capture.collected_utc
        if sample.time is None:
            k.require(isinstance(collected, k.Unknown) and collected.reason is k.UnknownReason.AS_OF_MISSING
                      and collected.detail == "no_collector_time" and not collected.candidates
                      and not collected.next_evidence
                      and collected.evidence == (reference(capture, k.WholeCapture()),), "ospf_sample_time")
        else:
            k.require(sample.time.bound is BoundSource.COLLECTOR_RECORDED
                      and sample.time.clock.startswith("collector:") and collected == sample.time, "ospf_sample_time")
    documents: list[tuple[Capture, Parsed]] = []
    for capture in captures:
        operation = capture.operation
        if operation is None:
            raise ValueError("ospf_capture_operation")
        parsed = PARSERS[operation](capture, ports)
        k.require({row.port for row in parsed.rows} == set(ports)
                  and (operation == neighbor.OP or len(parsed.rows) == len(ports)), "ospf_parser_population")
        documents.append((capture, parsed))
    return Context(points=points, declarations=declarations, documents=tuple(documents))


def witnesses(capture: Capture, row: ParsedRow) -> tuple[k.Evidence, ...]:
    """A usable row must retain all fields inside its original complete records."""
    fields = dict(row.fields)
    k.require(len(fields) == len(row.fields) and "port" in fields
              and fields["port"].raw == row.port and bool(row.spans), "ospf_parser_subject")
    for span in row.spans:
        k.require(0 <= span.start < span.end <= len(capture.raw), "ospf_span_bounds")
    for field in fields.values():
        k.require(0 <= field.span.start < field.span.end <= len(capture.raw)
                  and capture.raw[field.span.start:field.span.end] == field.raw.encode("utf-8")
                  and any(span.start <= field.span.start < field.span.end <= span.end for span in row.spans),
                  "ospf_token_witness")
    return tuple(reference(capture, span) for span in row.spans)
