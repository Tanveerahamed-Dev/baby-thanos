"""Observed EtherChannel summary protocols for trusted declared nodes and groups."""
import re
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Scope
from atlas_brain.evidence.parsekit.rules import Record
from atlas_brain.evidence.synthetic import Node, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l2.etherchannel import parse_summary
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import (
    Executed,
    Handler,
    Parsed,
    Parser,
    execute_parsers,
)

PACK = k.PackId("l2.etherchannel")
REPORTED_PROTOCOL = k.FactId("l2.etherchannel.reported_protocol")
STEP = StepSpec(id=StepId("l2.etherchannel/parse_protocol"), pack=PACK, kind="parse_build", scope="device",
                reads=(), produces=(REPORTED_PROTOCOL,), evaluator="l2.etherchannel.build_reported_protocol")
BINDING = pack_registration.OperationBinding(operation=parse_summary.OP, step=STEP.id)
DECLARATION = pack_registration.PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="etherchannel_group", pack=PACK, root=False),),
    facts=(FactSpec(id=REPORTED_PROTOCOL, pack=PACK, subject="etherchannel_group", value_type="text", step=STEP.id),),
    relations=(), steps=(STEP,), operations=(BINDING,))


@dataclass(frozen=True, slots=True, kw_only=True)
class Target:
    """The caller supplies an admitted node and independent expected populations."""
    context: str
    node: Node
    groups: tuple[str, ...]
    ports: tuple[str, ...]

    def __post_init__(self) -> None:
        k.require(type(self.context) is str and bool(self.context) and type(self.node) is Node, "etherchannel_target")
        k.require(type(self.groups) is tuple and 1 <= len(self.groups) <= 128 and all(type(g) is str
                  and re.fullmatch(r"[1-9][0-9]{0,4}", g, re.ASCII) is not None and int(g) <= 65535 for g in self.groups)
                  and len(set(self.groups)) == len(self.groups), "invalid_etherchannel_population")
        k.require(type(self.ports) is tuple and len(self.ports) <= 128 and all(type(p) is str
                  and re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}", p, re.ASCII) is not None for p in self.ports)
                  and len(set(self.ports)) == len(self.ports), "invalid_etherchannel_population")
        for port in self.ports:
            endpoint(self.node, port)
        state = self.node.declaration
        k.require(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.value == state.raw == self.node.id
                  and len(state.evidence) == 1 and all(type(ref) is k.RegistryRef and ref.table == "synthetic_p2.nodes"
                  and ref.row_id == self.node.id and re.fullmatch(r"/nodes/(0|[1-9][0-9]*)", ref.citation) is not None
                  for ref in state.evidence), "etherchannel_node_declaration")


def subject(target: Target, group: str) -> k.EntityKey:
    k.require(type(target) is Target and type(group) is str and group in target.groups, "etherchannel_subject_group")
    key = canonical(("atlas-brain.etherchannel-group/1", target.context, target.node.key, group))
    return k.EntityKey("etherchannel_group:" + sha256(key).hexdigest())


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    target: Target
    group: str
    subject: k.EntityKey
    value: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    store: FactStore
    rows: tuple[Row, ...]
    executed: tuple[Executed[parse_summary.Result], ...]


class _Adapter(Parser[parse_summary.Result]):
    def __init__(self, targets: dict[k.CaptureId, Target]) -> None:
        self.targets = targets

    def parse(self, request: CaptureRequest) -> Parsed[parse_summary.Result]:
        target = self.targets[request.capture.id]
        value = parse_summary.parse_capture(request.capture, target.groups, target.ports)
        return value, value.parse


def _observed(target: Target, row: parse_summary.Row, output: Executed[parse_summary.Result],
              group_records: tuple[Record, ...]) -> k.Known[str]:
    capture = output.receipt.capture
    records = [rec for rec in group_records if rec.span in row.spans or any(n == "group" and f.raw == row.group for n, f in rec.fields)]
    k.require(len(records) == 1 and records[0].span in row.spans, "etherchannel_protocol_record")
    record = records[0]
    fields, source = dict(row.fields), dict(record.fields)
    names = ("group", "channel", "protocol")
    k.require(len(fields) == len(row.fields) and len(source) == len(record.fields)
              and all(n in fields and n in source and fields[n] is source[n] for n in names), "etherchannel_protocol_record")
    group, channel, token = fields["group"], fields["channel"], fields["protocol"]
    k.require(group.raw == group.value == row.group and channel.raw == channel.value == "Po" + row.group,
              "etherchannel_protocol_record")
    if token.value is parse_summary.Protocol.LACP and token.raw == "LACP":
        value = "lacp"
    elif token.value is parse_summary.Protocol.PAGP and token.raw == "PAgP":
        value = "pagp"
    elif token.value is parse_summary.Protocol.NONE and token.raw == "-":
        value = "none_reported"
    else:
        raise ValueError("etherchannel_protocol_value")
    span, raw = record.span, capture.raw
    k.require(0 <= span.start < span.end <= len(raw) and (span.start == 0 or raw[span.start - 1] == 10)
              and (span.end == len(raw) or raw.startswith((b"\n", b"\r\n"), span.end))
              and b"\n" not in raw[span.start:span.end] and b"\r" not in raw[span.start:span.end], "etherchannel_protocol_witness")
    for field in (group, channel, token):
        k.require(span.start <= field.span.start < field.span.end <= span.end
                  and raw[field.span.start:field.span.end] == field.raw.encode("ascii"), "etherchannel_protocol_witness")
    k.require(group.span.start == span.start and re.fullmatch(rb"[ \t]+", raw[group.span.end:channel.span.start]) is not None
              and re.fullmatch(rb"\([A-Za-z]+\)[ \t]+", raw[channel.span.end:token.span.start]) is not None
              and (token.span.end == span.end or raw[token.span.end:token.span.end + 1] in (b" ", b"\t")), "etherchannel_protocol_witness")
    refs = tuple(k.EvidenceRef(capture=capture.id, locator=s, role=k.EvidenceRole.SUBJECT,
                 excerpt_sha256=sha256(raw[s.start:s.end]).hexdigest()) for s in (group.span, token.span, span))
    return k.Known(value=value, raw=token.raw, basis=k.Basis.OBSERVED, evidence=target.node.declaration.evidence + refs)


def _rows(target: Target, output: Executed[parse_summary.Result] | None) -> tuple[Row, ...]:
    needs = (k.EvidenceNeed(node=target.node.key, operation=parse_summary.OP, params=(), resolves=(REPORTED_PROTOCOL,),
                            reruns=(STEP.id,), after_s=None, unprintable=()),)
    evidence = target.node.declaration.evidence
    if output is not None:
        capture = output.receipt.capture
        evidence += (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS,
                                   excerpt_sha256=capture.bytes_sha256),)
    group_records = () if output is None else tuple(r for r in output.receipt.parse.records if r.rule_id == "group")
    rows: list[Row] = []
    for i, group in enumerate(target.groups):
        key = subject(target, group)
        reason: k.UnknownReason | None = k.UnknownReason.NOT_COLLECTED
        if output is not None:
            row = output.value.rows[i]
            reason = output.value.reason or row.reason
            if reason is None and output.receipt.parse.quality != "complete":
                reason = k.UnknownReason.PARSE_PARTIAL
            if reason is None:
                rows.append(Row(target=target, group=group, subject=key, value=_observed(target, row, output, group_records)))
                continue
        unknown = k.Unknown(reason=reason, detail="etherchannel_protocol_unresolved", evidence=evidence,
                            candidates=(), next_evidence=needs)
        rows.append(Row(target=target, group=group, subject=key, value=unknown))
    return tuple(rows)


def build_reported_protocol(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Build only reported protocol facts; registry provenance is structural without registry bytes."""
    k.require(type(targets) is tuple and all(type(t) is Target for t in targets), "etherchannel_targets")
    k.require(type(requests) is tuple and all(type(r) is CaptureRequest for r in requests), "etherchannel_requests")
    indexed: dict[tuple[str, k.EntityKey], Target] = {}
    for item in targets:
        item = Target(context=item.context, node=item.node, groups=item.groups, ports=item.ports)
        target = Target(context=item.context, node=item.node, groups=tuple(sorted(item.groups)), ports=tuple(sorted(item.ports)))
        key = (target.context, target.node.key)
        k.require(key not in indexed, "etherchannel_duplicate_target")
        indexed[key] = target
    by_capture: dict[k.CaptureId, Target] = {}
    supplied: set[tuple[str, k.EntityKey]] = set()
    for request in requests:
        capture = request.capture
        key = (request.context or "", capture.source)
        k.require(key in indexed and capture.operation == parse_summary.OP and capture.rendered == parse_summary.COMMAND,
                  "etherchannel_request_target")
        k.require(capture.codec in ("utf-8", "ascii"), "unsupported_etherchannel_summary")
        scope = Scope(node=capture.source, plane="exec", context=None, vrf=None, instance=None, vdc=None, tenant=None, afi=None)
        k.require(capture.scope == scope, "etherchannel_request_scope")
        k.require(key not in supplied, "etherchannel_duplicate_target_capture")
        supplied.add(key)
        by_capture[capture.id] = indexed[key]
    handler = Handler(binding=BINDING, parser=_Adapter(by_capture))
    executed = execute_parsers((DECLARATION,), (handler,), requests)
    expected = {r.capture.id: r for r in requests}
    k.require(len(executed) == len(expected) and {o.receipt.capture.id for o in executed} == set(expected), "etherchannel_receipt_coverage")
    registration = pack_registration.compile_packs((DECLARATION,)).registration_sha256
    outcomes: dict[tuple[str, k.EntityKey], Executed[parse_summary.Result]] = {}
    for output in executed:
        receipt = output.receipt
        request = expected[receipt.capture.id]
        k.require(receipt.capture is request.capture and receipt.owner == STEP.id and receipt.context == request.context
                  and receipt.registration_sha256 == registration, "etherchannel_receipt_owner")
        target = by_capture[receipt.capture.id]
        k.require(type(output.value) is parse_summary.Result and receipt.parse is output.value.parse, "etherchannel_receipt_parse")
        k.require(type(output.value.rows) is tuple and all(type(row) is parse_summary.Row and type(row.group) is str
                  for row in output.value.rows) and tuple(row.group for row in output.value.rows) == target.groups,
                  "etherchannel_parser_population")
        outcomes[(target.context, target.node.key)] = output
    rows = tuple(row for key in sorted(indexed) for row in _rows(indexed[key], outcomes[key] if key in outcomes else None))
    k.require(len({r.subject for r in rows}) == len(rows), "etherchannel_subject_collision")
    store = FactStore()
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=REPORTED_PROTOCOL, subject=row.subject, value=row.value)
    return Result(store=store, rows=rows, executed=executed)
