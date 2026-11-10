"""Root guard facts for separately declared targets and already-admitted captures.

Node registry references retain their admitted provenance. This builder has no registry bytes
with which to authenticate a node, context or VLAN declaration.
"""
import re
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Scope
from atlas_brain.evidence.synthetic import Node, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import OperationBinding, PackDeclaration
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Executed, Handler, Parsed, Parser, execute_parsers

PACK = k.PackId("l2.stp")
ROOT_GUARD = k.FactId("l2.stp.root_guard")
STEP = StepSpec(id=StepId("l2.stp/parse_root_guard"), pack=PACK, kind="parse_build", scope="device",
                reads=(), produces=(ROOT_GUARD,), evaluator="l2.stp.build_root_guard")
BINDING = OperationBinding(operation=stp.OP, step=STEP.id)
DECLARATION = PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="stp_port_vlan", pack=PACK, root=False),),
    facts=(FactSpec(id=ROOT_GUARD, pack=PACK, subject="stp_port_vlan", value_type="boolean", step=STEP.id),),
    relations=(), steps=(STEP,), operations=(BINDING,))


@dataclass(frozen=True, slots=True, kw_only=True)
class Target:
    context: str
    node: Node
    port: str
    vlans: tuple[int, ...]

    def __post_init__(self) -> None:
        k.require(type(self.context) is str and bool(self.context) and type(self.node) is Node, "stp_target")
        stp.command(self.port)
        endpoint(self.node, self.port)
        k.require(type(self.vlans) is tuple and 1 <= len(self.vlans) <= 16
                  and all(type(v) is int and 1 <= v <= 4094 for v in self.vlans)
                  and len(set(self.vlans)) == len(self.vlans), "invalid_stp_vlans")
        declaration = self.node.declaration
        k.require(type(declaration) is k.Known and declaration.basis is k.Basis.DECLARED
                  and declaration.value == declaration.raw == self.node.id and len(declaration.evidence) == 1
                  and all(type(ref) is k.RegistryRef and ref.table == "synthetic_p2.nodes"
                          and ref.row_id == self.node.id and re.fullmatch(r"/nodes/(0|[1-9][0-9]*)", ref.citation)
                          is not None for ref in declaration.evidence), "stp_node_declaration")


def subject(target: Target, vlan: int) -> k.EntityKey:
    k.require(type(target) is Target and type(vlan) is int and vlan in target.vlans, "stp_subject_vlan")
    key = canonical(("atlas-brain.stp-port-vlan/1", target.context, target.node.key, target.port, vlan))
    return k.EntityKey("stp_port_vlan:" + sha256(key).hexdigest())


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    target: Target
    vlan: int
    subject: k.EntityKey
    value: k.Known[bool] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    store: FactStore
    rows: tuple[Row, ...]
    executed: tuple[Executed[stp.Result], ...]


class _Adapter(Parser[stp.Result]):
    def __init__(self, targets: dict[k.CaptureId, Target]) -> None:
        self.targets = targets

    def parse(self, request: CaptureRequest) -> Parsed[stp.Result]:
        target = self.targets[request.capture.id]
        result = stp.parse_capture(request.capture, target.port, target.vlans)
        return result, result.parse


def _line(raw: bytes, span: k.ByteSpan) -> bytes:
    k.require(0 <= span.start < span.end <= len(raw) and (span.start == 0 or raw[span.start - 1] == 10)
              and (span.end == len(raw) or raw.startswith((b"\n", b"\r\n"), span.end)), "stp_proof_line")
    return raw[span.start:span.end]


def _observed(target: Target, row: stp.Row, output: Executed[stp.Result]) -> k.Known[bool]:
    capture = output.receipt.capture
    fields = dict(row.fields)
    names = tuple(name for name, _ in row.fields)
    k.require(all(names.count(name) == 1 for name in ("port", "vlan", "root_guard")), "stp_guard_fields")
    token = fields["root_guard"]
    k.require(token.value is stp.Switch.ENABLED or token.value is stp.Switch.DISABLED, "stp_guard_value")
    enabled = token.value is stp.Switch.ENABLED
    k.require(token.raw == ("enabled" if enabled else "disabled"), "stp_guard_value")
    records = output.receipt.parse.records
    guards = [r for r in records if r.rule_id == "root_guard" and r.span in row.spans]
    k.require(len(guards) == 1 and guards[0].fields == (("root_guard", token),), "stp_guard_record")
    guard = guards[0].span
    headers = [r for r in records if r.rule_id.startswith("header_") and r.span.start < guard.start]
    k.require(bool(headers), "stp_guard_header")
    nearest = max(headers, key=lambda record: record.span.start)
    k.require(nearest.span in row.spans, "stp_guard_header")
    header, header_fields = nearest.span, dict(nearest.fields)
    header_line = _line(capture.raw, header)
    words = header_line.split()
    k.require(len(words) == 8 and words[0] == b"Port" and words[1].isdigit()
              and words[2:6] == [b"(" + target.port.encode("ascii") + b")", b"of",
                                 f"VLAN{row.vlan:04d}".encode("ascii"), b"is"], "stp_guard_header")
    port, vid = fields["port"], fields["vlan"]
    before_port = b"Port " + words[1] + b" ("
    before_vlan = b"Port " + words[1] + b" " + words[2] + b" of VLAN"
    first = header.start + len(header_line) - len(header_line.lstrip(b" \t"))
    for name, field, expected, prefix_bytes in (("port", port, target.port, before_port),
                                                ("vlan", vid, f"{row.vlan:04d}", before_vlan)):
        k.require(name in header_fields and header_fields[name] == field and field.raw == field.value == expected
                  and field.span.start == first + len(prefix_bytes) and field.span.end == field.span.start + len(expected)
                  and field.span.end <= header.end and capture.raw[field.span.start:field.span.end] == expected.encode("ascii"),
                  "stp_guard_header")
    line = _line(capture.raw, guard)
    prefix = b"Root guard is "
    word = token.raw.encode("ascii")
    k.require(line.strip(b" \t") == prefix + word + b" on the port"
              and token.span.start == guard.start + len(line) - len(line.lstrip(b" \t")) + len(prefix)
              and token.span.end == token.span.start + len(word)
              and capture.raw[token.span.start:token.span.end] == word, "stp_guard_witness")
    refs = tuple(k.EvidenceRef(capture=capture.id, locator=s, role=k.EvidenceRole.SUBJECT,
                 excerpt_sha256=sha256(capture.raw[s.start:s.end]).hexdigest()) for s in (token.span, guard, port.span, vid.span, header))
    return k.Known(value=enabled, basis=k.Basis.OBSERVED, evidence=target.node.declaration.evidence + refs, raw=token.raw)


def _rows(target: Target, outputs: list[Executed[stp.Result]]) -> tuple[Row, ...]:
    needs = (k.EvidenceNeed(node=target.node.key, operation=stp.OP, params=(("port", target.port),),
             resolves=(ROOT_GUARD,), reruns=(STEP.id,), after_s=None, unprintable=()),)
    evidence = target.node.declaration.evidence + tuple(k.EvidenceRef(capture=o.receipt.capture.id,
        locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS, excerpt_sha256=o.receipt.capture.bytes_sha256) for o in outputs)
    rows: list[Row] = []
    for index, vlan in enumerate(target.vlans):
        reason: k.UnknownReason | None = k.UnknownReason.NOT_COLLECTED
        if outputs:
            output, = outputs
            row = output.value.rows[index]
            reason = output.value.reason or row.reason
            if reason is None and output.value.parse.quality != "complete":
                reason = k.UnknownReason.PARSE_PARTIAL
            if reason is None and "root_guard" not in dict(row.fields):
                reason = k.UnknownReason.FIELD_NOT_PRINTED
            if reason is None:
                rows.append(Row(target=target, vlan=vlan, subject=subject(target, vlan), value=_observed(target, row, output)))
                continue
        value = k.Unknown(reason=reason, detail="stp_root_guard_unresolved", evidence=evidence, candidates=(), next_evidence=needs)
        rows.append(Row(target=target, vlan=vlan, subject=subject(target, vlan), value=value))
    return tuple(rows)


def build_root_guard(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Accept at most one capture per target and execute before projecting any subject."""
    k.require(type(targets) is tuple and all(type(t) is Target for t in targets), "stp_targets")
    k.require(type(requests) is tuple and all(type(r) is CaptureRequest for r in requests), "stp_requests")
    indexed: dict[tuple[str, k.EntityKey, str], Target] = {}
    for item in targets:
        item = Target(context=item.context, node=item.node, port=item.port, vlans=item.vlans)
        target = Target(context=item.context, node=item.node, port=item.port, vlans=tuple(sorted(item.vlans)))
        key = (target.context, target.node.key, stp.command(target.port))
        k.require(key not in indexed, "stp_duplicate_target")
        indexed[key] = target
    by_capture: dict[k.CaptureId, Target] = {}
    supplied: set[tuple[str, k.EntityKey, str]] = set()
    for request in requests:
        capture = request.capture
        key = (request.context or "", capture.source, capture.rendered)
        k.require(key in indexed and capture.operation == stp.OP, "stp_request_target")
        k.require(capture.codec in ("ascii", "utf-8"), "unsupported_stp_capture")
        expected = Scope(node=capture.source, plane="exec", vrf=None, context=None, vdc=None, tenant=None, afi=None, instance=None)
        k.require(capture.scope == expected, "stp_request_scope")
        k.require(key not in supplied, "stp_duplicate_target_capture")
        supplied.add(key)
        by_capture[capture.id] = indexed[key]
    handler = Handler(binding=BINDING, parser=_Adapter(by_capture))
    executed = execute_parsers((DECLARATION,), (handler,), requests)
    grouped: dict[tuple[str, k.EntityKey, str], list[Executed[stp.Result]]] = {key: [] for key in indexed}
    for output in executed:
        target = by_capture[output.receipt.capture.id]
        k.require(type(output.value) is stp.Result and output.receipt.parse is output.value.parse, "stp_receipt_parse")
        k.require(type(output.value.rows) is tuple and all(type(r) is stp.Row and type(r.vlan) is int
                  and r.port == target.port for r in output.value.rows)
                  and tuple(r.vlan for r in output.value.rows) == target.vlans, "stp_parser_population")
        grouped[(target.context, target.node.key, stp.command(target.port))].append(output)
    rows = tuple(row for key in sorted(indexed) for row in _rows(indexed[key], grouped[key]))
    k.require(len({r.subject for r in rows}) == len(rows), "stp_subject_collision")
    store = FactStore()
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=ROOT_GUARD, subject=row.subject, value=row.value)
    return Result(store=store, rows=rows, executed=executed)
