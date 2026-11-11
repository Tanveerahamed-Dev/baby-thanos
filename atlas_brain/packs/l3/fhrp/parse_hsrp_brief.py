"""Allowlisted IPv4 HSRP brief observations; exact local tokens, never redundancy or peer identity."""
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

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
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
_IPV4 = _OCTET + r"\." + _OCTET + r"\." + _OCTET + r"\." + _OCTET
_ENDPOINT = r"(?:local|unknown|" + _IPV4 + ")"
_VIP = r"(?:unknown|" + _IPV4 + ")"


class State(StrEnum):
    INIT = "init"
    ACTIVE = "active"
    STANDBY = "standby"


@dataclass(frozen=True, slots=True, kw_only=True)
class Endpoint:
    token: Captured
    kind: Literal["local", "unknown", "ipv4"]


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
            r"(?P<priority>[0-9]{1,3}+)[ \t]++" + preempt + r"(?P<state>[A-Za-z]{1,16}+)[ \t]++"
            + "(?P<active>" + _ENDPOINT + r")[ \t]++(?P<standby>" + _ENDPOINT
            + r")[ \t]++(?P<virtual_ip>" + _VIP + r")[ \t]*+", "record", "body", "", fields))
    return tuple(rules)


def _endpoint(token: Captured) -> Endpoint:
    kind: Literal["local", "unknown", "ipv4"] = "local" if token.raw == "local" else "unknown" if token.raw == "unknown" else "ipv4"
    return Endpoint(token=token, kind=kind)


def _decimal(token: Captured, maximum: int) -> bool:
    return token.raw.isascii() and token.raw.isdigit() and len(token.raw) <= 4 and int(token.raw) <= maximum and str(int(token.raw)) == token.raw


def _row(item: Record, reason: k.UnknownReason | None) -> Row:
    fields = dict(item.fields)
    active, standby, vip = (_endpoint(fields[name]) for name in ("active", "standby", "virtual_ip"))
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
            endpoints = tuple(_endpoint(fields[name]) for name in ("active", "standby", "virtual_ip"))
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
