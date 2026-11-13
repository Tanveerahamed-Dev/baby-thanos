"""Pure local IPv4 HSRP state facts from trusted declared census and admitted capture requests."""
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
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactReader, FactStore, bind_writer
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import (
    Executed,
    Handler,
    Parsed,
    Parser,
    execute_parsers,
)

from . import parse_hsrp_brief as hsrp

PACK = k.PackId("l3.fhrp")
REPORTED_STATE = k.FactId("l3.fhrp.reported_state")
STEP = StepSpec(id=StepId("l3.fhrp/parse_hsrp_brief"), pack=PACK, kind="parse_build", scope="device",
                reads=(), produces=(REPORTED_STATE,), evaluator="l3.fhrp.build_reported_state")
BINDING = OperationBinding(operation=hsrp.OP, step=STEP.id)
DECLARATION = PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="fhrp_local", pack=PACK, root=False),),
    facts=(FactSpec(id=REPORTED_STATE, pack=PACK, subject="fhrp_local", value_type="text", step=STEP.id),),
    relations=(), steps=(STEP,), operations=(BINDING,))

SOURCE_STEP = StepSpec(id=StepId("l3.fhrp/prepare_gateway_source"), pack=PACK, kind="derive", scope="estate",
    reads=(REPORTED_STATE,), produces=(), evaluator="l3.fhrp.prepare_fhrp_source")


def _need(condition: bool, code: str) -> None:
    k.require(condition, "hsrp_" + code)


@dataclass(frozen=True, slots=True, kw_only=True)
class Target:
    """Exact logical-interface/group census; Node.ports is not a redundancy or logical-interface baseline."""
    context: str
    node: Node
    groups: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _need(type(self.context) is str and bool(self.context) and type(self.node) is Node, "target")
        _need(type(self.groups) is tuple and 1 <= len(self.groups) <= 128
              and all(type(pair) is tuple and len(pair) == 2 and all(type(value) is str for value in pair) for pair in self.groups),
              "population")
        _need(len(set(self.groups)) == len(self.groups) and all(
            re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}", interface, re.ASCII) is not None
            and re.fullmatch(r"0|[1-9][0-9]{0,3}", group, re.ASCII) is not None and int(group) <= 4095
            for interface, group in self.groups), "population")
        state = self.node.declaration
        _need(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.value == state.raw == self.node.id
              and len(state.evidence) == 1 and all(type(ref) is k.RegistryRef and ref.table == "synthetic_p2.nodes"
              and ref.row_id == self.node.id and re.fullmatch(r"/nodes/(0|[1-9][0-9]*)", ref.citation) is not None for ref in state.evidence), "node_declaration")


def subject(target: Target, interface: str, group: str) -> k.EntityKey:
    _need(type(target) is Target and (interface, group) in target.groups, "population")
    value = canonical(("atlas-brain.fhrp-local/1", target.context, target.node.key, interface, "ipv4", "hsrp", group))
    return k.EntityKey("fhrp_local:" + sha256(value).hexdigest())


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    target: Target
    interface: str
    group: str
    subject: k.EntityKey
    value: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    store: FactStore
    rows: tuple[Row, ...]
    executed: tuple[Executed[hsrp.Result], ...]


class _Adapter(Parser[hsrp.Result]):
    def parse(self, request: CaptureRequest) -> Parsed[hsrp.Result]:
        value = hsrp.parse_capture(request.capture)
        return value, value.parse


def _claims(output: Executed[hsrp.Result]) -> tuple[tuple[hsrp.Row, tuple[k.ByteSpan, ...]], ...]:
    capture, value = output.receipt.capture, output.value
    records = tuple(item for item in output.receipt.parse.records if item.rule_id in ("row", "row_preempt"))
    _need(type(value.rows) is tuple and len(value.rows) == len(records) and all(type(row) is hsrp.Row for row in value.rows), "record")
    checked: list[tuple[hsrp.Row, tuple[k.ByteSpan, ...]]] = []
    for row, item in zip(value.rows, records, strict=True):
        _need(type(item) is Record and row.span is item.span, "record")
        cells = dict(item.fields)
        tokens = (row.interface, row.group, row.priority) + (() if row.preempt is None else (row.preempt,)) + (
            row.state, row.active.token, row.standby.token, row.virtual_ip.token)
        names = ("interface", "group", "priority") + (() if row.preempt is None else ("preempt",)) + (
            "state", "active", "standby", "virtual_ip")
        _need(len(cells) == len(item.fields) and set(cells) == set(names)
              and all(type(token) is Captured and cells[name] is token for name, token in zip(names, tokens, strict=True)), "record")
        span, raw = item.span, capture.raw
        _need(type(span) is k.ByteSpan and 0 <= span.start < span.end <= len(raw)
              and (span.start == 0 or raw[span.start - 1] == 10)
              and (span.end == len(raw) or raw.startswith((b"\n", b"\r\n"), span.end))
              and b"\n" not in raw[span.start:span.end] and b"\r" not in raw[span.start:span.end], "witness")
        _need(tokens[0].span.start == span.start and all(type(token.span) is k.ByteSpan and type(token.raw) is str
              and token.raw.isascii() and span.start <= token.span.start < token.span.end <= span.end
              and raw[token.span.start:token.span.end] == token.raw.encode("ascii") for token in tokens), "witness")
        _need(all(re.fullmatch(rb"[ \t]+", raw[tokens[index].span.end:tokens[index + 1].span.start]) is not None
                  for index in range(len(tokens) - 1))
              and re.fullmatch(rb"[ \t]*", raw[tokens[-1].span.end:span.end]) is not None, "witness")
        af: list[k.ByteSpan] = []
        for name, endpoint in (("active", row.active), ("standby", row.standby), ("virtual_ip", row.virtual_ip)):
            _need(type(endpoint) is hsrp.Endpoint, "value")
            kind = ("local" if endpoint.token.raw == "local" and name != "virtual_ip" else "unknown" if endpoint.token.raw == "unknown"
                    else "ipv4" if hsrp.ipv4_literal(endpoint.token.raw) else None)
            _need(endpoint.kind == kind, "value")
            if kind == "ipv4":
                af.append(endpoint.token.span)
        _need(row.address_family == ("ipv4" if af else None) and type(row.af_spans) is tuple and row.af_spans == tuple(af), "af")
        _need(row.interface.value == row.interface.raw and row.group.value == row.group.raw
              and row.priority.value == row.priority.raw and (row.preempt is None or row.preempt.value == row.preempt.raw == "P"), "value")
        if value.reason is None:
            _need(value.parse.quality == "complete" and capture.integrity is k.IntegrityState.COMPLETE
                  and capture.error is None and row.reason is None and bool(af) and type(row.state.value) is hsrp.State
                  and all(endpoint.kind is not None for endpoint in (row.active, row.standby, row.virtual_ip)), "af")
            _need((row.state.raw, row.state.value) in (("Init", hsrp.State.INIT), ("Active", hsrp.State.ACTIVE),
                                                      ("Standby", hsrp.State.STANDBY)), "value")
        claims = {row.interface.span, row.group.span, row.state.span, item.span, *af}
        checked.append((row, tuple(sorted(claims, key=lambda point: (point.start, point.end)))))
    return tuple(checked)


def _unknown(target: Target, interface: str, group: str, output: Executed[hsrp.Result] | None,
             candidates: tuple[hsrp.Row, ...], reason: k.UnknownReason,
             declared: tuple[k.RegistryRef, ...] = ()) -> k.Unknown:
    evidence = target.node.declaration.evidence + declared
    if output is not None:
        capture = output.receipt.capture
        evidence += (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS, excerpt_sha256=capture.bytes_sha256),)
        evidence += tuple(k.EvidenceRef(capture=capture.id, locator=row.span, role=k.EvidenceRole.WITNESS,
                          excerpt_sha256=sha256(capture.raw[row.span.start:row.span.end]).hexdigest()) for row in candidates)
    need = k.EvidenceNeed(node=target.node.key, operation=hsrp.OP, params=(("group", group), ("interface", interface)),
                         resolves=(REPORTED_STATE,), reruns=(STEP.id,), after_s=None, unprintable=())
    return k.Unknown(reason=reason, detail="hsrp_state_unresolved", evidence=evidence, candidates=(), next_evidence=(need,))


type _Key = tuple[str, k.EntityKey]
type _Proofs = dict[_Key, tuple[k.RegistryRef, ...]]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Plan:
    indexed: dict[_Key, Target]
    expected: dict[k.CaptureId, CaptureRequest]
    requests: tuple[CaptureRequest, ...]
    proofs: _Proofs | None


def _plan(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> _Plan:
    _need(type(targets) is tuple and all(type(target) is Target for target in targets), "target")
    _need(type(requests) is tuple and all(type(request) is CaptureRequest for request in requests), "request_target")
    indexed: dict[tuple[str, k.EntityKey], Target] = {}
    for item in targets:
        target = Target(context=item.context, node=item.node, groups=tuple(sorted(item.groups)))
        key = (target.context, target.node.key)
        _need(key not in indexed, "duplicate_target")
        indexed[key] = target
    expected: dict[k.CaptureId, CaptureRequest] = {}
    supplied: set[tuple[str, k.EntityKey]] = set()
    for request in requests:
        capture = request.capture
        key = (request.context or "", capture.source)
        _need(key in indexed and capture.operation == hsrp.OP and capture.rendered == hsrp.COMMAND
              and capture.codec in ("utf-8", "ascii"), "request_target")
        _need(capture.scope == Scope(node=capture.source, plane="exec", context=None, vrf=None, instance=None, vdc=None, tenant=None, afi=None),
              "request_scope")
        _need(key not in supplied and capture.id not in expected, "duplicate_capture")
        supplied.add(key)
        expected[capture.id] = request
    return _Plan(indexed=indexed, expected=expected, requests=requests, proofs=None)


def _canonical_rows(plan: _Plan, executed: tuple[Executed[hsrp.Result], ...], registration: str | None = None) -> tuple[Row, ...]:
    indexed, expected = plan.indexed, plan.expected
    _need(type(executed) is tuple and len(executed) == len(expected)
          and {output.receipt.capture.id for output in executed} == set(expected), "receipt_coverage")
    if registration is None:
        registration = compile_packs((DECLARATION,)).registration_sha256
    outcomes: dict[tuple[str, k.EntityKey], tuple[Executed[hsrp.Result], tuple[tuple[hsrp.Row, tuple[k.ByteSpan, ...]], ...]]] = {}
    for output in executed:
        receipt = output.receipt
        request = expected[receipt.capture.id]
        _need(receipt.capture is request.capture and receipt.owner == STEP.id and receipt.context == request.context
              and receipt.registration_sha256 == registration, "receipt_owner")
        _need(type(output.value) is hsrp.Result and receipt.parse is output.value.parse, "receipt_parse")
        key = (request.context or "", receipt.capture.source)
        target = indexed[key]
        claims = _claims(output)
        _need(output.value.reason is not None or all((row.interface.raw, row.group.raw) in target.groups for row, _ in claims), "undeclared_subject")
        outcomes[key] = (output, claims)
    rows: list[Row] = []
    for key in sorted(indexed):
        target = indexed[key]
        declared = () if plan.proofs is None else plan.proofs[key]
        outcome = outcomes.get(key)
        for interface, group in target.groups:
            output = None if outcome is None else outcome[0]
            candidates = () if outcome is None else tuple(row for row, _ in outcome[1] if row.interface.raw == interface and row.group.raw == group)
            reason = k.UnknownReason.NOT_COLLECTED if output is None else output.value.reason
            if outcome is not None and reason is None and len(candidates) == 1:
                output, witnesses = outcome
                observed = candidates[0]
                claims = next(points for row, points in witnesses if row is observed)
                refs = tuple(k.EvidenceRef(capture=output.receipt.capture.id, locator=point, role=k.EvidenceRole.SUBJECT,
                             excerpt_sha256=sha256(output.receipt.capture.raw[point.start:point.end]).hexdigest()) for point in claims)
                value: k.Known[str] | k.Unknown = k.Known(value=observed.state.raw.lower(), raw=observed.state.raw,
                    basis=k.Basis.OBSERVED, evidence=target.node.declaration.evidence + declared + refs)
            else:
                reason = reason or (k.UnknownReason.CONFLICTING_EVIDENCE if candidates else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
                value = _unknown(target, interface, group, output, candidates, reason, declared)
            rows.append(Row(target=target, interface=interface, group=group, subject=subject(target, interface, group), value=value))
    return tuple(rows)


def _materialize(plan: _Plan, executed: tuple[Executed[hsrp.Result], ...], registration: str | None = None) -> Result:
    rows = _canonical_rows(plan, executed, registration)
    store = FactStore()
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=REPORTED_STATE, subject=row.subject, value=row.value)
    return Result(store=store, rows=rows, executed=executed)


def build_reported_state(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Direct trusted API; node provenance is structural, not raw-envelope or global-run admission."""
    plan = _plan(targets, requests)
    executed = execute_parsers((DECLARATION,), (Handler(binding=BINDING, parser=_Adapter()),), plan.requests)
    return _materialize(plan, executed)


def _declared(state: k.Known[str], table: str, identity: str, digest: str, pointer: str) -> k.RegistryRef:
    ref = k.RegistryRef(table=table, row_id=identity, table_digest=digest, citation=pointer)
    _need(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.raw == state.value == identity
          and state.evidence == (ref,), "global_provenance")
    return ref


def _proofs(envelope: p4.Envelope, budgets: Budgets, indexed: dict[_Key, Target]) -> _Proofs:
    _need(type(envelope) is p4.Envelope and type(envelope.raw) is bytes and type(envelope.base) is SyntheticGroup
          and type(envelope.base.raw) is bytes, "global_provenance")
    base, context = envelope.base, envelope.context
    digest, base_digest = sha256(envelope.raw).hexdigest(), sha256(base.raw).hexdigest()
    side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
                  ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    registry = record(strict_json(base.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
    _need(side["schema"] == p4.SCHEMA and side["semantic_group"] == "declared_synthetic" and side["context"] == context
          and side["base_sha256"] == base_digest and registry["schema"] == base.schema == BASE_SCHEMA
          and registry["semantic_group"] == "declared_synthetic" and registry["group"] == base.id, "global_provenance")
    _declared(base.declaration, "synthetic_p2.groups", base.id, base_digest, "/group")
    context_ref = _declared(envelope.declaration, "synthetic_p4.context", context, digest, "/context")
    _need(type(registry["nodes"]) is list and type(side["targets"]) is list, "global_provenance")
    nodes = tuple(record(row, ("id", "discovery_id", "ports")) for row in cast(list[object], registry["nodes"]))
    rows = tuple(record(row, ("id", "node", "operation", "params")) for row in cast(list[object], side["targets"]))
    _need(len({string(row, "id") for row in nodes}) == len(nodes)
          and len({string(row, "id") for row in rows}) == len(rows), "global_provenance")
    _need(type(envelope.targets) is tuple and all(type(t) is p4.Target for t in envelope.targets)
          and type(base.nodes) is tuple and all(type(n) is Node for n in base.nodes), "global_provenance")
    owned_targets = tuple(target for target in envelope.targets if target.operation == hsrp.OP)
    declared = {target.id: target for target in owned_targets}
    own = tuple((i, row) for i, row in enumerate(rows) if row["operation"] == hsrp.OP)
    _need(len(owned_targets) == len(declared) == len(own) == len(indexed)
          and {string(row, "id") for _, row in own} == set(declared),
          "global_provenance")
    proofs: _Proofs = {}
    for index, row in own:
        identifier, node_id = string(row, "id"), string(row, "node")
        item = declared[identifier]
        key = (context, item.node.key)
        _need(key in indexed and key not in proofs and indexed[key].node is item.node and item.node.id == node_id
              and item.owner == STEP.id and type(item.params) is bytes and canonical(row["params"]) == item.params
              and any(item.node is node for node in base.nodes), "global_provenance")
        pairs = record(row["params"], ("groups",))["groups"]
        _need(type(pairs) is list and all(type(pair) is list and len(cast(list[object], pair)) == 2
              and all(type(v) is str for v in cast(list[object], pair)) for pair in cast(list[object], pairs)), "global_provenance")
        groups = tuple(sorted((cast(list[str], pair)[0], cast(list[str], pair)[1]) for pair in cast(list[object], pairs)))
        _need(groups == indexed[key].groups, "global_provenance")
        matches = tuple((i, node) for i, node in enumerate(nodes) if node["id"] == node_id)
        _need(len(matches) == 1, "global_provenance")
        node_index, node = matches[0]
        ports = node["ports"]
        _need(item.node.group == base.id and item.node.discovery_id == node["discovery_id"] and type(ports) is list
              and all(type(port) is str for port in cast(list[object], ports))
              and tuple(sorted(cast(list[str], ports))) == item.node.ports, "global_provenance")
        _declared(item.node.declaration, "synthetic_p2.nodes", node_id, base_digest, f"/nodes/{node_index}")
        proofs[key] = (context_ref, _declared(item.declaration, "synthetic_p4.targets", identifier, digest, f"/targets/{index}"))
    return proofs


class StateOwner(Parser[hsrp.Result]):
    """Own parsing/facts for trusted, admitted, classified targets and requests.

    Declaration proofs are rechecked; finish authenticates owned receipt metadata.
    Raw member-ID/framing admission and whole-global-run attestation stay outside this helper.
    """

    def __init__(self, envelope: p4.Envelope, budgets: Budgets, targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> None:
        plan = _plan(targets, requests)
        self.plan = _Plan(indexed=plan.indexed, expected=plan.expected, requests=plan.requests,
                          proofs=_proofs(envelope, budgets, plan.indexed))
        self.registration = envelope.registration_sha256
        k.digest(self.registration)
        _need(type(envelope.captures) is tuple and all(type(member) is p4.CaptureMember and type(member.target) is p4.Target for member in envelope.captures),
              "global_provenance")
        owned = tuple(member for member in envelope.captures if member.target.operation == hsrp.OP)
        members = {member.id: member for member in owned}
        declared = {target.id: target for target in envelope.targets if target.operation == hsrp.OP}
        _need(len(members) == len(owned) == len(requests) and set(members) == set(plan.expected), "global_provenance")
        for request in requests:
            capture, member = request.capture, members[request.capture.id]
            _need(member.target.id in declared and member.target is declared[member.target.id]
                  and capture.source == member.target.node.key and capture.raw == member.raw
                  and capture.bytes_sha256 == member.sha256, "global_provenance")
        self.produced: dict[k.CaptureId, hsrp.Result] = {}
        self.finished = False

    def parse(self, request: CaptureRequest) -> Parsed[hsrp.Result]:
        expected = self.plan.expected
        _need(type(request) is CaptureRequest and request.capture.id in expected
              and request.capture is expected[request.capture.id].capture
              and request.context == expected[request.capture.id].context, "global_capture")
        _need(request.capture.id not in self.produced, "global_value")
        value = hsrp.parse_capture(request.capture)
        self.produced[request.capture.id] = value
        return value, value.parse

    def own[T](self, output: Executed[T]) -> Executed[hsrp.Result]:
        _need(type(output) is Executed and type(output.receipt) is ParseReceipt
              and type(output.receipt.capture) is Capture, "global_receipt")
        receipt, expected = output.receipt, self.plan.expected
        _need(receipt.capture.id in expected and receipt.capture is expected[receipt.capture.id].capture, "global_capture")
        _need(receipt.capture.id in self.produced, "global_value")
        value = self.produced[receipt.capture.id]
        _need(output.value is value and receipt.parse is value.parse, "global_value")
        return Executed(receipt=receipt, value=value)

    def finish(self, executed: tuple[Executed[hsrp.Result], ...]) -> Result:
        _need(type(executed) is tuple, "global_receipt")
        _need(not self.finished, "global_run")
        _need(set(self.produced) == set(self.plan.expected), "global_value")
        checked = tuple(self.own(output) for output in executed)
        result = _materialize(self.plan, checked, self.registration)
        self.finished = True
        return result

    def validate_gateway_source_values[T](self, result: Result, reader: FactReader, outputs: tuple[Executed[T], ...]) -> tuple[Target, ...]:
        """Close original source values after the application's complete run/proof closure; no admission seal."""
        _need(self.finished and type(result) is Result and type(result.rows) is tuple and type(result.executed) is tuple
              and all(type(row) is Row for row in result.rows) and type(reader) is FactReader
              and reader.store is result.store, "gateway_source_population")
        checked = tuple(self.own(output) for output in outputs if output.receipt.capture.operation == hsrp.OP)
        _need(len(checked) == len(self.plan.expected) == len(result.executed)
              and all(a.receipt is b.receipt and a.value is b.value for a, b in zip(checked, result.executed, strict=True)),
              "gateway_source_population")
        expected = _canonical_rows(self.plan, checked, self.registration)
        actual = {row.subject: row for row in result.rows}
        _need(len(actual) == len(result.rows) == len(expected) and set(actual) == {row.subject for row in expected},
              "gateway_source_population")
        for wanted in expected:
            row, value = actual[wanted.subject], wanted.value
            _need(row.target == wanted.target and row.interface == wanted.interface and row.group == wanted.group,
                  "gateway_source_population")
            state = reader.read(fact=REPORTED_STATE, subject=row.subject)
            if isinstance(value, k.Known):
                _need(type(state) is k.Known and type(state.value) is str and type(state.raw) is str
                      and state.basis is value.basis and state == value, "gateway_source_value")
            else:
                _need(type(state) is k.Unknown and state.reason is value.reason and state == value, "gateway_source_value")
        return tuple(self.plan.indexed[key] for key in sorted(self.plan.indexed))


def fact_rows(result: Result) -> tuple[tuple[k.FactId, Row, k.Known[str] | k.Unknown], ...]:
    """Expose original owning rows/states for trusted projection; this is not result admission."""
    _need(type(result) is Result and type(result.rows) is tuple and all(type(row) is Row for row in result.rows), "fact_rows")
    _need(STEP.produces == (REPORTED_STATE,) and tuple(spec.id for spec in DECLARATION.facts) == STEP.produces, "fact_rows")
    return tuple((REPORTED_STATE, row, row.value) for row in result.rows)


def reported_state_proofs[T](output: Executed[T]) -> tuple[tuple[hsrp.Row, tuple[k.ByteSpan, ...]], ...]:
    """Authenticate raw rows/claims only; callers close registration, owner and admission."""
    if (type(output) is not Executed or type(output.receipt) is not ParseReceipt
            or type(output.receipt.capture) is not Capture):
        raise ValueError("hsrp_proof_input")
    value = output.value
    if type(value) is not hsrp.Result or output.receipt.parse is not value.parse:
        raise ValueError("hsrp_proof_input")
    return _claims(Executed(receipt=output.receipt, value=value))
