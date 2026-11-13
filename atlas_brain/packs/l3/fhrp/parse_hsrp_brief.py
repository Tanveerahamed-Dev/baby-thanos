"""Allowlisted IPv4 HSRP brief observations; exact local tokens, never redundancy or peer identity."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal, cast

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Record,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.kernel import states as k

OP, COMMAND = "iosxe.show_standby_brief", "show standby brief"
VARIANT_SUPPORT = "allowlisted"
# Apache-2.0 primary format lessons only; no donor bytes or implementation imported.
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "6e0b25eb76be058e787e2859a89bc6edfa4e0bf6/src/genie/libs/parser/"
          "iosxe/tests/ShowStandbyBrief/cli/equal/")
SOURCES = (SOURCE + "golden_output1_output.txt", SOURCE + "golden_output2_output.txt",
           SOURCE + "golden_output3_output.txt", SOURCE + "golden_output4_output.txt")
_ENDPOINT = r"[A-Za-z0-9:.]{1,64}+"
_VIP = _ENDPOINT


class State(StrEnum):
    INIT = "init"
    ACTIVE = "active"
    STANDBY = "standby"


@dataclass(frozen=True, slots=True, kw_only=True)
class Endpoint:
    token: Captured
    kind: Literal["local", "unknown", "ipv4"] | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    interface: Captured
    group: Captured
    priority: Captured
    preempt: Captured | None
    state: Captured
    active: Endpoint
    standby: Endpoint
    virtual_ip: Endpoint
    address_family: Literal["ipv4"] | None
    af_spans: tuple[k.ByteSpan, ...]
    span: k.ByteSpan
    reason: k.UnknownReason | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Row, ...]
    parse: ParseResult
    reason: k.UnknownReason | None


def _rules() -> tuple[Rule, ...]:
    rules = [
        Rule("bare", "start", COMMAND, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "echo", "", ("prompt",)),
    ]
    for phase in ("start", "echo", "legend", "arrow", "body", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)", "record", phase, "", ("blank",)))
    for phase in ("start", "echo"):
        rules.append(Rule("legend_" + phase, phase, r"[ \t]*+(?P<legend>P indicates configured to preempt\.)[ \t]*+",
                          "enter_state", "legend", "", ("legend",)))
    rules.extend((
        Rule("marker", "legend", r"[ \t]*+(?P<marker>\|)[ \t]*+", "enter_state", "arrow", "", ("marker",)),
        Rule("header", "arrow",
             r"(?P<header>Interface[ \t]++Grp[ \t]++Pri[ \t]++P[ \t]++State[ \t]++Active[ \t]++Standby[ \t]++Virtual IP)[ \t]*+",
             "enter_state", "body", "", ("header",)),
        Rule("prompt", "body", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])", "enter_state", "done", "", ("prompt",)),
    ))
    for rule_id, preempt in (("row_preempt", r"(?P<preempt>P)[ \t]++"), ("row", "")):
        fields = ("interface", "group", "priority") + (("preempt",) if preempt else ()) + ("state", "active", "standby", "virtual_ip")
        rules.append(Rule(rule_id, "body",
            r"(?P<interface>[A-Za-z][A-Za-z0-9./:_-]{0,63}+)[ \t]++(?P<group>[0-9]{1,4}+)[ \t]++"
            r"(?P<priority>[0-9]{1,3}+)[ \t]++" + preempt + r"(?P<state>[A-Za-z]{2,16}+)[ \t]++"
            + "(?P<active>" + _ENDPOINT + r")[ \t]++(?P<standby>" + _ENDPOINT
            + r")[ \t]++(?P<virtual_ip>" + _VIP + r")[ \t]*+", "record", "body", "", fields))
    return tuple(rules)


def ipv4_literal(value: str) -> bool:
    """Canonical ASCII dotted-decimal only; never bind an endpoint to a node."""
    if type(value) is not str or not value.isascii() or not 7 <= len(value) <= 15:
        return False
    octets = value.split(".")
    return len(octets) == 4 and all(1 <= len(part) <= 3 and part.isdigit() and int(part) <= 255
                                  and str(int(part)) == part for part in octets)


def _endpoint(token: Captured, allow_local: bool = True) -> Endpoint:
    kind: Literal["local", "unknown", "ipv4"] | None = (
        "local" if token.raw == "local" and allow_local else "unknown" if token.raw == "unknown"
        else "ipv4" if ipv4_literal(token.raw) else None)
    return Endpoint(token=token, kind=kind)


def _decimal(token: Captured, maximum: int) -> bool:
    return token.raw.isascii() and token.raw.isdigit() and len(token.raw) <= 4 and int(token.raw) <= maximum and str(int(token.raw)) == token.raw


def _row(item: Record, reason: k.UnknownReason | None) -> Row:
    fields = dict(item.fields)
    active, standby, vip = _endpoint(fields["active"]), _endpoint(fields["standby"]), _endpoint(fields["virtual_ip"], False)
    af_spans = tuple(value.token.span for value in (active, standby, vip) if value.kind == "ipv4")
    return Row(interface=fields["interface"], group=fields["group"], priority=fields["priority"],
               preempt=fields.get("preempt"), state=fields["state"], active=active, standby=standby, virtual_ip=vip,
               address_family="ipv4" if af_spans else None, af_spans=af_spans, span=item.span, reason=reason)


def parse_capture(capture: Capture) -> Result:
    """Keep every recognized physical row and all operands; a global reason forbids positive local binding."""
    if (type(capture) is not Capture or capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_hsrp_brief")
    mapping = TokenMap.closed({"Init": State.INIT, "Active": State.ACTIVE, "Standby": State.STANDBY})
    parsed = run_rules(capture.raw, capture.id, _rules(), (("state", mapping),))
    physical: list[Record] = []
    seen: set[tuple[str, str, str, str]] = set()
    invalid = conflict = unresolved = False
    opening = closing = ""
    header = legend = marker = 0
    for item in parsed.records:
        fields = dict(item.fields)
        if item.rule_id == "command":
            opening = fields["prompt"].raw
        elif item.rule_id == "prompt":
            closing = fields["prompt"].raw
        elif item.rule_id == "header":
            header += 1
        elif item.rule_id.startswith("legend_"):
            legend += 1
        elif item.rule_id == "marker":
            marker += 1
        elif item.rule_id in ("row", "row_preempt"):
            physical.append(item)
            invalid = invalid or not _decimal(fields["group"], 4095) or not _decimal(fields["priority"], 255)
            endpoints = (_endpoint(fields["active"]), _endpoint(fields["standby"]), _endpoint(fields["virtual_ip"], False))
            invalid = invalid or any(value.kind is None for value in endpoints)
            family = any(value.kind == "ipv4" for value in endpoints)
            unresolved = unresolved or not family
            if family:
                key = (fields["interface"].raw, "ipv4", "hsrp", fields["group"].raw)
                conflict = conflict or key in seen
                seen.add(key)
    invalid = invalid or header != 1 or legend != 1 or marker != 1 or bool(opening and closing != opening)
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw.strip() or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if invalid or parsed.quality != "complete" else
              k.UnknownReason.CONFLICTING_EVIDENCE if conflict else
              k.UnknownReason.IDENTITY_UNRESOLVED if unresolved else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    return Result(rows=tuple(_row(item, reason) for item in physical), parse=parsed, reason=reason)


def _claim_need(condition: bool, code: str) -> None:
    k.require(condition, "hsrp_brief_claims_" + code)


def validate_state_token_claim(capture: Capture, token: Captured) -> State | k.Unknown:
    """Validate one byte-anchored mapping; no row, header, AF, completeness or origin claim."""
    _claim_need(type(capture) is Capture and type(capture.raw) is bytes and type(capture.id) is str and bool(capture.id)
                and type(capture.operation) is str and capture.operation == OP
                and type(capture.rendered) is str and capture.rendered == COMMAND
                and type(capture.codec) is str and capture.codec in ("utf-8", "ascii"), "state_input")
    _claim_need(type(token) is Captured and type(token.raw) is str and token.raw.isascii()
                and token.raw.isalpha() and 2 <= len(token.raw) <= 16 and type(token.span) is k.ByteSpan
                and type(token.span.start) is int and type(token.span.end) is int
                and 0 <= token.span.start < token.span.end <= len(capture.raw)
                and capture.raw[token.span.start:token.span.end] == token.raw.encode("ascii"), "state_input")
    mapped = {"Init": State.INIT, "Active": State.ACTIVE, "Standby": State.STANDBY}.get(token.raw)
    if mapped is not None:
        _claim_need(type(token.value) is State and token.value is mapped, "state")
        return mapped
    _claim_need(type(token.value) is k.Unknown, "state")
    value = cast(k.Unknown, token.value)
    _claim_need(value.reason is k.UnknownReason.PARSE_PARTIAL and type(value.detail) is str and value.detail == "unmapped_token"
                and type(value.candidates) is tuple and not value.candidates
                and type(value.next_evidence) is tuple and not value.next_evidence
                and type(value.evidence) is tuple and len(value.evidence) == 1, "state")
    _claim_need(type(value.evidence[0]) is k.EvidenceRef, "state")
    ref = cast(k.EvidenceRef, value.evidence[0])
    _claim_need(type(ref.capture) is str and ref.capture == capture.id and ref.locator is token.span
                and ref.role is k.EvidenceRole.SUBJECT and type(ref.excerpt_sha256) is str
                and ref.excerpt_sha256 == sha256(capture.raw[token.span.start:token.span.end]).hexdigest(), "state")
    return value
