"""Capture-scoped interface states; no device join or closed estate population."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import Captured, ParseResult, Record, Rule, TokenMap, run_rules
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer

CHECK = "l1.interface.admin_up_oper_down"
_ADMIN, _OPER_FACT = k.FactId("l1.interface.admin"), k.FactId("l1.interface.oper")
_STEP = StepSpec(id=StepId("l1.interface/parse"), pack=k.PackId("l1.interface"),
                 kind="parse_build", scope="device", reads=(), produces=(_ADMIN, _OPER_FACT),
                 evaluator="l1.interface.build_capture")
type Verdict = Literal["problem", "ok", "unknown"]


class Status(StrEnum):
    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "administratively down"


_STATUS = TokenMap.closed({"up": Status.UP, "down": Status.DOWN,
                           "administratively down": Status.ADMIN_DOWN})
_OPER = TokenMap.closed({"up": Status.UP, "down": Status.DOWN})
_NAME = r"(?P<name>[A-Za-z][A-Za-z-]*+[0-9][A-Za-z0-9./:-]*+)"
_SPACE = r"[ \t]++"
_HEADER = r"(?P<header>Interface[ \t]++IP-Address[ \t]++OK\?[ \t]++Method[ \t]++Status[ \t]++Protocol)[ \t]*+"


@dataclass(frozen=True, slots=True, kw_only=True)
class InterfaceFields:
    name: k.Known[str]
    admin: k.Known[str] | k.Unknown
    oper: k.Known[str] | k.Unknown
    verdict: Verdict
    reason: k.UnknownReason | None
    next_evidence: tuple[k.EvidenceNeed, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class InterfaceResult:
    interfaces: tuple[InterfaceFields, ...]
    parse: ParseResult
    observed: int
    coverage: k.Unknown


def _rules(command: str) -> tuple[Rule, ...]:
    def row(identifier: str, pattern: str, fields: tuple[str, ...], state: str) -> Rule:
        return Rule(identifier, state, pattern, "record", state, "", fields)
    state = "table" if command == "show ip interface brief" else "start"
    rules: list[Rule] = []
    if state == "table":
        rules.append(Rule("table_header", "start", _HEADER, "enter_state", state, "", ("header",)))
    for phase in (("start", "table") if state == "table" else ("start",)):
        rules.extend((
            row("command_" + phase, r"(?P<prompt>[A-Za-z0-9_.:-]++[#>])[ \t]*+" + command,
                ("prompt",), phase),
            row("prompt_" + phase, r"(?P<prompt>[A-Za-z0-9_.:-]++[#>])[ \t]*+", ("prompt",), phase),
            row("separator_" + phase, r"(?P<separator>[ \t]*+)", ("separator",), phase),
        ))
    if command == "show interfaces":
        prefix = _NAME + r" is (?P<status>[^,]++)"
        rules.extend((
            row("interface", prefix + r", line protocol is (?P<oper>.*+)", ("name", "status", "oper"), state),
            row("missing_oper", prefix + r", line protocol is", ("name", "status"), state),
            row("missing_protocol", prefix, ("name", "status"), state),
        ))
    else:
        prefix = (_NAME + _SPACE + r"(?P<address>[A-Za-z0-9.:-]++)" + _SPACE
                  + r"(?P<valid>[A-Z]++)" + _SPACE + r"(?P<method>[A-Za-z]++)" + _SPACE)
        base = ("name", "address", "valid", "method", "status")
        for identifier, status in (("admin", r"(?P<status>administratively down)"),
                                   ("state", r"(?P<status>[a-z]++)")):
            rules.append(row(identifier, prefix + status + _SPACE + r"(?P<oper>[^ \t]++)[ \t]*+",
                             base + ("oper",), state))
            rules.append(row(identifier + "_missing_oper", prefix + status + r"[ \t]*+", base, state))
    rules.extend((
        row("malformed_row", _NAME + r"(?P<unparsed>[ \t].*+)", ("name", "unparsed"), state),
        row("name_only", _NAME, ("name",), state),
    ))
    return tuple(rules)


def _reference(raw: bytes, capture: k.CaptureId, span: k.ByteSpan | k.WholeCapture) -> k.EvidenceRef:
    excerpt = raw[span.start:span.end] if isinstance(span, k.ByteSpan) else raw
    return k.EvidenceRef(capture=capture, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(excerpt).hexdigest())


def _needs(source: k.EntityKey, command: str) -> tuple[k.EvidenceNeed, ...]:
    return (k.EvidenceNeed(node=source, operation=command, params=(),
                          resolves=("l1.interface.admin", "l1.interface.oper"), reruns=(CHECK,),
                          after_s=None, unprintable=()),)


def _unknown(reason: k.UnknownReason, detail: str, evidence: tuple[k.EvidenceRef, ...],
             needs: tuple[k.EvidenceNeed, ...]) -> k.Unknown:
    return k.Unknown(reason=reason, detail=detail, evidence=evidence, candidates=(), next_evidence=needs)


def _field(field: Captured | None, *, admin: bool, raw: bytes, capture: k.CaptureId,
           context: tuple[k.EvidenceRef, ...], needs: tuple[k.EvidenceNeed, ...]) -> k.Known[str] | k.Unknown:
    if field is None:
        return _unknown(k.UnknownReason.PARSE_PARTIAL, "missing_interface_state", context, needs)
    evidence = (_reference(raw, capture, field.span),) + context
    if isinstance(field.value, k.Unknown):
        return _unknown(k.UnknownReason.PARSE_PARTIAL, "unmapped_interface_state", evidence, needs)
    if admin and field.value == Status.DOWN:
        return _unknown(k.UnknownReason.NOT_OBSERVABLE, "physical_down_admin_unproven", evidence, needs)
    value = "down" if field.value == Status.ADMIN_DOWN else str(field.value)
    return k.Known(value=value, basis=k.Basis.OBSERVED, evidence=evidence, raw=field.raw)


def admin_up_oper_down(admin: k.Known[str] | k.Unknown, oper: k.Known[str] | k.Unknown) -> Verdict:
    """Both inconsistent directions are problems; unknown input never passes."""
    if isinstance(admin, k.Unknown) or isinstance(oper, k.Unknown):
        return "unknown"
    if admin.value not in ("up", "down") or oper.value not in ("up", "down"):
        return "unknown"
    return "problem" if admin.value != oper.value else "ok"


def extract_interfaces(raw: bytes, capture: k.CaptureId, *, command: str,
                       integrity: k.IntegrityState, source: k.EntityKey) -> InterfaceResult:
    if command not in ("show interfaces", "show ip interface brief"):
        raise ValueError("unsupported_interface_command")
    if type(integrity) is not k.IntegrityState:
        raise TypeError("capture_integrity_required")
    parsed = run_rules(raw, capture, _rules(command), (("status", _STATUS), ("oper", _OPER)))
    grouped: dict[str, list[Record]] = {}
    for record in parsed.records:
        fields = dict(record.fields)
        if "name" in fields:
            grouped.setdefault(fields["name"].raw, []).append(record)
    whole = (_reference(raw, capture, k.WholeCapture()),)
    partial = (parsed.quality == "partial" or not grouped or integrity is not k.IntegrityState.COMPLETE
               or any(len(records) != 1 or not {"status", "oper"} <= dict(records[0].fields).keys()
                      for records in grouped.values()))
    rows: list[InterfaceFields] = []
    writer = bind_writer(FactStore(), step=_STEP)
    if integrity in (k.IntegrityState.ERROR, k.IntegrityState.EMPTY):
        grouped = {}
    for name, records in sorted(grouped.items()):
        needs = _needs(source, command)
        context = tuple(_reference(raw, capture, record.span) for record in records)
        fields = dict(records[0].fields)
        admin = _field(fields.get("status"), admin=True, raw=raw, capture=capture, context=context, needs=needs)
        oper = _field(fields.get("oper"), admin=False, raw=raw, capture=capture, context=context, needs=needs)
        if len(records) != 1:
            admin = oper = _unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "duplicate_interface", context, needs)
        if integrity is not k.IntegrityState.COMPLETE:
            reason = (k.UnknownReason.CAPTURE_TRUNCATED if integrity in
                      (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS)
                      else k.UnknownReason.EMPTY_UNREGISTERED if integrity is k.IntegrityState.EMPTY
                      else k.UnknownReason.CAPTURE_ERROR)
            admin = oper = _unknown(reason, "capture_not_complete", whole, needs)
        verdict = admin_up_oper_down(admin, oper)
        reason = next((fact.reason for fact in (admin, oper) if isinstance(fact, k.Unknown)), None)
        if verdict == "ok" and partial:
            verdict, reason = "unknown", k.UnknownReason.PARSE_PARTIAL
        named = k.Known(value=name, basis=k.Basis.OBSERVED,
                        evidence=(_reference(raw, capture, fields["name"].span),), raw=name)
        subject = k.EntityKey(str(capture) + ":" + name)
        writer.write(fact=_ADMIN, subject=subject, value=admin)
        writer.write(fact=_OPER_FACT, subject=subject, value=oper)
        rows.append(InterfaceFields(name=named, admin=admin, oper=oper, verdict=verdict, reason=reason,
                                    next_evidence=needs if verdict != "ok" else ()))
    parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial" if partial else "complete")
    coverage_reason = (k.UnknownReason.CAPTURE_ERROR if integrity is k.IntegrityState.ERROR else
                       k.UnknownReason.EMPTY_UNREGISTERED if not raw or integrity is k.IntegrityState.EMPTY
                       else k.UnknownReason.DENOMINATOR_OPEN)
    coverage = _unknown(coverage_reason, "capture_scoped_observed_names_only",
                        whole, _needs(source, command))
    return InterfaceResult(interfaces=tuple(rows), parse=parsed, observed=len(rows), coverage=coverage)


def build_capture(capture: Capture) -> InterfaceResult:
    if type(capture) is not Capture:
        raise TypeError("capture_record_required")
    operations = {"show interfaces": "iosxe.show_interfaces",
                  "show ip interface brief": "iosxe.show_ip_interface_brief"}
    if capture.rendered not in operations or capture.operation != operations[capture.rendered]:
        raise ValueError("unsupported_interface_operation")
    if capture.codec not in ("utf-8", "ascii"):
        raise ValueError("unsupported_interface_codec")
    if capture.error is not None and capture.integrity is not k.IntegrityState.ERROR:
        raise ValueError("capture_error_integrity_mismatch")
    return extract_interfaces(capture.raw, capture.id, command=capture.rendered,
                              integrity=capture.integrity, source=capture.source)


def missing_evidence() -> k.Unknown:
    return _unknown(k.UnknownReason.NOT_COLLECTED, "interface_commands_missing", (),
                    _needs(k.EntityKey("node:unresolved"), "show interfaces"))
