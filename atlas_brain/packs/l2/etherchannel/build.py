"""Observed EtherChannel summary protocols for trusted declared nodes and groups."""
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.parsekit.rules import Captured, Record
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l2.etherchannel import parse_summary
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
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
              group_records: tuple[Record, ...], declared: tuple[k.RegistryRef, ...]) -> k.Known[str]:
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
    return k.Known(value=value, raw=token.raw, basis=k.Basis.OBSERVED, evidence=target.node.declaration.evidence + declared + refs)


def _rows(target: Target, output: Executed[parse_summary.Result] | None, declared: tuple[k.RegistryRef, ...]) -> tuple[Row, ...]:
    needs = (k.EvidenceNeed(node=target.node.key, operation=parse_summary.OP, params=(), resolves=(REPORTED_PROTOCOL,),
                            reruns=(STEP.id,), after_s=None, unprintable=()),)
    evidence = target.node.declaration.evidence + declared
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
                rows.append(Row(target=target, group=group, subject=key, value=_observed(target, row, output, group_records, declared)))
                continue
        unknown = k.Unknown(reason=reason, detail="etherchannel_protocol_unresolved", evidence=evidence,
                            candidates=(), next_evidence=needs)
        rows.append(Row(target=target, group=group, subject=key, value=unknown))
    return tuple(rows)


def build_reported_protocol(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Build only reported protocol facts; registry provenance is structural without registry bytes."""
    plan = _plan(targets, requests, None)
    handler = Handler(binding=BINDING, parser=_Adapter(plan.by_capture))
    executed = execute_parsers((DECLARATION,), (handler,), plan.requests)
    return _materialize(plan, executed, pack_registration.compile_packs((DECLARATION,)).registration_sha256)


type _Key = tuple[str, k.EntityKey]
type _Proofs = dict[_Key, tuple[k.RegistryRef, ...]]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Plan:
    indexed: dict[_Key, Target]
    by_capture: dict[k.CaptureId, Target]
    requests: tuple[CaptureRequest, ...]
    proofs: _Proofs | None


def _plan(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...], proofs: _Proofs | None) -> _Plan:
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
    return _Plan(indexed=indexed, by_capture=by_capture, requests=requests, proofs=proofs)


def _materialize(plan: _Plan, executed: tuple[Executed[parse_summary.Result], ...], registration: str) -> Result:
    indexed, by_capture = plan.indexed, plan.by_capture
    expected = {r.capture.id: r for r in plan.requests}
    k.require(len(executed) == len(expected) and {o.receipt.capture.id for o in executed} == set(expected), "etherchannel_receipt_coverage")
    outcomes: dict[tuple[str, k.EntityKey], Executed[parse_summary.Result] | None] = {key: None for key in indexed}
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
    rows = tuple(row for key in sorted(indexed) for row in _rows(indexed[key], outcomes[key], () if plan.proofs is None else plan.proofs[key]))
    k.require(len({r.subject for r in rows}) == len(rows), "etherchannel_subject_collision")
    store = FactStore()
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=REPORTED_PROTOCOL, subject=row.subject, value=row.value)
    return Result(store=store, rows=rows, executed=executed)


def _declared(state: k.Known[str], table: str, identity: str, digest: str, pointer: str) -> k.RegistryRef:
    ref = k.RegistryRef(table=table, row_id=identity, table_digest=digest, citation=pointer)
    k.require(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.raw == state.value == identity
              and state.evidence == (ref,), "etherchannel_global_provenance")
    return ref


def _proofs(envelope: p4.Envelope, budgets: Budgets, indexed: dict[_Key, Target]) -> _Proofs:
    k.require(type(envelope) is p4.Envelope and type(envelope.raw) is bytes and type(envelope.base) is SyntheticGroup
              and type(envelope.base.raw) is bytes, "etherchannel_global_provenance")
    base, context = envelope.base, envelope.context
    digest, base_digest = sha256(envelope.raw).hexdigest(), sha256(base.raw).hexdigest()
    side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
                  ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    registry = record(strict_json(base.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
    k.require(side["schema"] == p4.SCHEMA and side["semantic_group"] == "declared_synthetic" and side["context"] == context
              and side["base_sha256"] == base_digest and registry["schema"] == base.schema == BASE_SCHEMA
              and registry["semantic_group"] == "declared_synthetic" and registry["group"] == base.id, "etherchannel_global_provenance")
    _declared(base.declaration, "synthetic_p2.groups", base.id, base_digest, "/group")
    context_ref = _declared(envelope.declaration, "synthetic_p4.context", context, digest, "/context")
    k.require(type(registry["nodes"]) is list and type(side["targets"]) is list, "etherchannel_global_provenance")
    nodes = tuple(record(row, ("id", "discovery_id", "ports")) for row in cast(list[object], registry["nodes"]))
    rows = tuple(record(row, ("id", "node", "operation", "params")) for row in cast(list[object], side["targets"]))
    k.require(len({string(row, "id") for row in nodes}) == len(nodes)
              and len({string(row, "id") for row in rows}) == len(rows), "etherchannel_global_provenance")
    k.require(type(envelope.targets) is tuple and all(type(t) is p4.Target for t in envelope.targets)
              and type(base.nodes) is tuple and all(type(n) is Node for n in base.nodes), "etherchannel_global_provenance")
    declared = {t.id: t for t in envelope.targets if t.operation == parse_summary.OP}
    own = tuple((i, row) for i, row in enumerate(rows) if row["operation"] == parse_summary.OP)
    k.require(len(declared) == len(own) == len(indexed) and {string(row, "id") for _, row in own} == set(declared),
              "etherchannel_global_provenance")
    proofs: _Proofs = {}
    for index, row in own:
        identifier, node_id = string(row, "id"), string(row, "node")
        item = declared[identifier]
        key = (context, item.node.key)
        k.require(key in indexed and key not in proofs and indexed[key].node is item.node and item.node.id == node_id
                  and item.owner == STEP.id and type(item.params) is bytes and canonical(row["params"]) == item.params
                  and any(item.node is node for node in base.nodes), "etherchannel_global_provenance")
        target = indexed[key]
        params = record(row["params"], ("groups", "ports"))
        for field, expected in (("groups", target.groups), ("ports", target.ports)):
            value = params[field]
            k.require(type(value) is list and all(type(v) is str for v in cast(list[object], value))
                      and tuple(sorted(cast(list[str], value))) == expected, "etherchannel_global_provenance")
        matches = tuple((i, n) for i, n in enumerate(nodes) if n["id"] == node_id)
        k.require(len(matches) == 1, "etherchannel_global_provenance")
        node_index, node = matches[0]
        ports = node["ports"]
        k.require(item.node.group == base.id and item.node.discovery_id == node["discovery_id"] and type(ports) is list
                  and all(type(p) is str for p in cast(list[object], ports))
                  and tuple(sorted(cast(list[str], ports))) == item.node.ports, "etherchannel_global_provenance")
        _declared(item.node.declaration, "synthetic_p2.nodes", node_id, base_digest, f"/nodes/{node_index}")
        proofs[key] = (context_ref, _declared(item.declaration, "synthetic_p4.targets", identifier, digest, f"/targets/{index}"))
    return proofs


class ProtocolOwner(Parser[parse_summary.Result]):
    """Own parsing/projection for trusted, admitted, SummaryPack-classified inputs.

    Registry declarations are rechecked; only finish verifies receipt metadata.
    Raw member-ID/hash/framing admission and global-run attestation remain outside this helper.
    """

    def __init__(self, envelope: p4.Envelope, budgets: Budgets, targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> None:
        plan = _plan(targets, requests, None)
        self.plan = _Plan(indexed=plan.indexed, by_capture=plan.by_capture, requests=plan.requests,
                          proofs=_proofs(envelope, budgets, plan.indexed))
        self.registration = envelope.registration_sha256
        k.digest(self.registration)
        members = {m.id: m for m in envelope.captures if m.target.operation == parse_summary.OP}
        k.require(len(members) == len(requests) and set(members) == {r.capture.id for r in requests}, "etherchannel_global_provenance")
        for request in requests:
            capture, member = request.capture, members[request.capture.id]
            k.require(capture.source == member.target.node.key and capture.raw == member.raw
                      and capture.bytes_sha256 == member.sha256, "etherchannel_global_provenance")
        self.produced: dict[k.CaptureId, parse_summary.Result] = {}
        self.finished = False

    def parse(self, request: CaptureRequest) -> Parsed[parse_summary.Result]:
        expected = {r.capture.id: r for r in self.plan.requests}
        k.require(request.capture.id in expected and request.capture is expected[request.capture.id].capture
                  and request.context == expected[request.capture.id].context, "etherchannel_global_capture")
        k.require(request.capture.id not in self.produced, "etherchannel_global_value")
        target = self.plan.by_capture[request.capture.id]
        value = parse_summary.parse_capture(request.capture, target.groups, target.ports)
        self.produced[request.capture.id] = value
        return value, value.parse

    def own[T](self, output: Executed[T]) -> Executed[parse_summary.Result]:
        k.require(type(output) is Executed and type(output.receipt) is ParseReceipt, "etherchannel_global_receipt")
        receipt = output.receipt
        expected = {r.capture.id: r for r in self.plan.requests}
        k.require(receipt.capture.id in expected and receipt.capture is expected[receipt.capture.id].capture, "etherchannel_global_capture")
        k.require(receipt.capture.id in self.produced, "etherchannel_global_value")
        value = self.produced[receipt.capture.id]
        k.require(output.value is value and receipt.parse is value.parse, "etherchannel_global_value")
        return Executed(receipt=receipt, value=value)

    def finish(self, executed: tuple[Executed[parse_summary.Result], ...]) -> Result:
        k.require(type(executed) is tuple, "etherchannel_global_receipt")
        k.require(not self.finished, "etherchannel_global_run")
        k.require(set(self.produced) == {r.capture.id for r in self.plan.requests}, "etherchannel_global_value")
        checked = tuple(self.own(output) for output in executed)
        result = _materialize(self.plan, checked, self.registration)
        self.finished = True
        return result


def fact_rows(result: Result) -> tuple[tuple[k.FactId, Row, k.Known[str] | k.Unknown], ...]:
    """Expose original owning rows/states for trusted projection; this is not result admission."""
    k.require(type(result) is Result and type(result.rows) is tuple and all(type(row) is Row for row in result.rows),
              "etherchannel_fact_rows")
    k.require(REPORTED_PROTOCOL in STEP.produces and any(spec.id == REPORTED_PROTOCOL for spec in DECLARATION.facts),
              "etherchannel_fact_rows")
    return tuple((REPORTED_PROTOCOL, row, row.value) for row in result.rows)


@dataclass(frozen=True, slots=True, kw_only=True)
class MemberProof:
    """Raw reported-token proof only; an empty artifact is not positive absence."""
    group: str
    text: str | None
    spans: tuple[k.ByteSpan, ...]
    anchor: k.ByteSpan | None


def _sections(output: Executed[parse_summary.Result]) -> dict[str, tuple[Record, ...]]:
    groups: dict[str, list[Record]] = {}
    current = ""
    previous = 0
    closed = False
    for item in (record for record in output.receipt.parse.records if record.rule_id in ("group", "wrap", "prompt")):
        k.require(not closed and previous <= item.span.start < item.span.end <= len(output.receipt.capture.raw), "etherchannel_members_record")
        previous = item.span.end
        if item.rule_id == "group":
            fields = dict(item.fields)
            k.require("group" in fields, "etherchannel_members_record")
            current = fields["group"].raw
            k.require(current not in groups, "etherchannel_members_record")
            groups[current] = [item]
        elif item.rule_id == "wrap":
            k.require(current in groups, "etherchannel_members_record")
            groups[current].append(item)
        elif item.rule_id == "prompt":
            closed = True
    return {group: tuple(groups[group]) for group in groups}


def _member_proof(target: Target, row: parse_summary.Row, output: Executed[parse_summary.Result],
                  section: tuple[Record, ...]) -> MemberProof:
    raw = output.receipt.capture.raw
    k.require(bool(section) and tuple(item.span for item in section) == row.spans, "etherchannel_members_record")
    k.require(type(row.members) is tuple and all(type(member) is parse_summary.Member and type(member.port) is Captured
              and type(member.flag) is Captured and type(member.span) is k.ByteSpan
              and type(member.port.span) is k.ByteSpan and type(member.flag.span) is k.ByteSpan for member in row.members), "etherchannel_members_record")
    fields, head = dict(row.fields), dict(section[0].fields)
    k.require(len(fields) == len(row.fields) and len(head) == len(section[0].fields)
              and all(name in fields and name in head and fields[name] is head[name] for name in ("group", "channel", "protocol")),
              "etherchannel_members_record")
    group, channel, protocol = fields["group"], fields["channel"], fields["protocol"]
    k.require(group.raw == group.value == row.group and channel.raw == channel.value == "Po" + row.group,
              "etherchannel_members_record")
    for token in (group, channel, protocol):
        k.require(type(token) is Captured and type(token.raw) is str and token.raw.isascii()
                  and section[0].span.start <= token.span.start < token.span.end <= section[0].span.end
                  and raw[token.span.start:token.span.end] == token.raw.encode("ascii"), "etherchannel_members_witness")
    k.require(group.span.start == section[0].span.start
              and re.fullmatch(rb"[ \t]+", raw[group.span.end:channel.span.start]) is not None
              and re.fullmatch(rb"\([A-Za-z]+\)[ \t]+", raw[channel.span.end:protocol.span.start]) is not None,
              "etherchannel_members_witness")
    spans = {group.span, channel.span}
    consumed: list[parse_summary.Member] = []
    for item in section:
        start, end = item.span.start, item.span.end
        k.require(0 <= start < end <= len(raw) and (start == 0 or raw[start - 1] == 10)
                  and (end == len(raw) or raw.startswith((b"\n", b"\r\n"), end))
                  and b"\n" not in raw[start:end] and b"\r" not in raw[start:end], "etherchannel_members_witness")
        cells = dict(item.fields)
        k.require(len(cells) == len(item.fields) and "members" in cells, "etherchannel_members_record")
        column = cells["members"]
        k.require(type(column.raw) is str and column.raw.isascii() and column.value == column.raw
                  and start <= column.span.start <= column.span.end == end
                  and raw[column.span.start:column.span.end] == column.raw.encode("ascii"), "etherchannel_members_witness")
        k.require(column.span.start == cells["protocol"].span.end if item.rule_id == "group" else
                  re.fullmatch(rb"[ \t]+", raw[start:column.span.start]) is not None, "etherchannel_members_record")
        cursor = column.span.start
        for member in row.members:
            if not column.span.start <= member.span.start < member.span.end <= column.span.end:
                continue
            port, flag = member.port, member.flag
            k.require(type(port.value) is str and port.value == port.raw and port.raw in target.ports
                      and type(flag.value) is str and flag.value == flag.raw and flag.raw in parse_summary.MEMBER_FLAGS,
                      "etherchannel_members_value")
            gap = rb"[ \t]+" if item.rule_id == "group" or cursor != column.span.start else rb"[ \t]*"
            k.require(cursor <= member.span.start == port.span.start and port.span.end + 1 == flag.span.start
                      and flag.span.end + 1 == member.span.end and re.fullmatch(gap, raw[cursor:member.span.start]) is not None
                      and raw[port.span.start:port.span.end] == port.raw.encode("ascii")
                      and raw[flag.span.start:flag.span.end] == flag.raw.encode("ascii")
                      and raw[member.span.start:member.span.end] == (port.raw + "(" + flag.raw + ")").encode("ascii"),
                      "etherchannel_members_witness")
            spans.update((member.span, port.span, flag.span))
            consumed.append(member)
            cursor = member.span.end
        k.require(re.fullmatch(rb"[ \t]*", raw[cursor:column.span.end]) is not None, "etherchannel_members_witness")
        spans.add(item.span)
    k.require(tuple(consumed) == row.members, "etherchannel_members_record")
    if not consumed:
        return MemberProof(group=row.group, text=None, spans=(), anchor=None)
    text = " ".join(raw[member.span.start:member.span.end].decode("ascii") for member in consumed)
    return MemberProof(group=row.group, text=text, spans=tuple(sorted(spans, key=lambda span: (span.start, span.end))), anchor=consumed[0].port.span)


def reported_member_proofs(target: Target, output: Executed[parse_summary.Result]) -> tuple[MemberProof, ...]:
    """Validate a trusted matching parse's entire roster; no owner/registry/global-run admission or replay."""
    k.require(type(target) is Target and type(output) is Executed and type(output.receipt) is ParseReceipt
              and type(output.value) is parse_summary.Result and type(output.receipt.capture) is Capture,
              "etherchannel_members_record")
    capture, value = output.receipt.capture, output.value
    k.require(output.receipt.parse is value.parse and capture.operation == parse_summary.OP
              and capture.rendered == parse_summary.COMMAND and capture.codec in ("utf-8", "ascii"), "etherchannel_members_record")
    k.require(type(value.rows) is tuple and all(type(row) is parse_summary.Row and type(row.group) is str for row in value.rows)
              and tuple(row.group for row in value.rows) == tuple(sorted(target.groups)), "etherchannel_members_record")
    empty = tuple(MemberProof(group=row.group, text=None, spans=(), anchor=None) for row in value.rows)
    if value.reason is not None or value.parse.quality != "complete" or capture.integrity is not k.IntegrityState.COMPLETE or capture.error is not None:
        return empty
    sections = _sections(output)
    k.require(set(sections) == {row.group for row in value.rows if row.reason is None}, "etherchannel_members_record")
    return tuple(_member_proof(target, row, output, sections[row.group]) if row.reason is None else vacant
                 for row, vacant in zip(value.rows, empty, strict=True))
