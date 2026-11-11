"""Pure local IPv4 HSRP state facts from trusted declared census and admitted capture requests."""
import re
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Scope
from atlas_brain.evidence.parsekit.rules import Captured, Record
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.runner.pack_receipts import CaptureRequest
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
             candidates: tuple[hsrp.Row, ...], reason: k.UnknownReason) -> k.Unknown:
    evidence = target.node.declaration.evidence
    if output is not None:
        capture = output.receipt.capture
        evidence += (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS, excerpt_sha256=capture.bytes_sha256),)
        evidence += tuple(k.EvidenceRef(capture=capture.id, locator=row.span, role=k.EvidenceRole.WITNESS,
                          excerpt_sha256=sha256(capture.raw[row.span.start:row.span.end]).hexdigest()) for row in candidates)
    need = k.EvidenceNeed(node=target.node.key, operation=hsrp.OP, params=(("group", group), ("interface", interface)),
                         resolves=(REPORTED_STATE,), reruns=(STEP.id,), after_s=None, unprintable=())
    return k.Unknown(reason=reason, detail="hsrp_state_unresolved", evidence=evidence, candidates=(), next_evidence=(need,))


def build_reported_state(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Direct trusted API; node provenance is structural, not raw-envelope or global-run admission."""
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
    executed = execute_parsers((DECLARATION,), (Handler(binding=BINDING, parser=_Adapter()),), requests)
    _need(type(executed) is tuple and len(executed) == len(expected)
          and {output.receipt.capture.id for output in executed} == set(expected), "receipt_coverage")
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
                    basis=k.Basis.OBSERVED, evidence=target.node.declaration.evidence + refs)
            else:
                reason = reason or (k.UnknownReason.CONFLICTING_EVIDENCE if candidates else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
                value = _unknown(target, interface, group, output, candidates, reason)
            rows.append(Row(target=target, interface=interface, group=group, subject=subject(target, interface, group), value=value))
    store = FactStore()
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=REPORTED_STATE, subject=row.subject, value=row.value)
    return Result(store=store, rows=tuple(rows), executed=executed)
