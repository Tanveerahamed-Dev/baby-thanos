"""Synthetic allowlisted IPv4 VRRP detail observations; no version or qualification claim."""
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
from atlas_brain.packs.l3.fhrp.parse_hsrp_brief import ipv4_literal

OP, COMMAND = "iosxe.show_vrrp", "show vrrp"
VARIANT_SUPPORT = "allowlisted"
SYNTHETIC_GROUPS = ("100", "101")
# Primary format lessons only; no donor bytes or implementation imported.
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "6e0b25eb76be058e787e2859a89bc6edfa4e0bf6/src/genie/libs/parser/"
          "iosxe/tests/ShowVrrp/cli/equal/golden_output2_output.txt")
SOURCES = (SOURCE,)
_CATEGORIES = ("state", "virtual_ip", "virtual_mac", "advertisement", "preemption",
               "priority", "authentication", "master", "master_advertisement", "master_down")


class VRRPState(StrEnum):
    INIT = "init"
    MASTER = "master"
    BACKUP = "backup"


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    interface: Captured
    group: Captured
    state: Captured | None
    virtual_ip: Captured | None
    header: Record
    body: tuple[Record, ...]
    span: k.ByteSpan
    address_family: Literal["ipv4"] | None
    reason: k.UnknownReason | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Row, ...]
    parse: ParseResult
    reason: k.UnknownReason | None


def _rules() -> tuple[Rule, ...]:
    rules = [
        Rule("command", "start", COMMAND, "enter_state", "ready", "", ()),
        Rule("prompt_command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "ready", "", ("prompt",)),
    ]
    for phase in ("start", "ready", "block", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)", "record", phase, "", ("blank",)))
    prefix = r"(?P<interface>[A-Za-z][A-Za-z0-9./:_-]{0,63}+)[ ]++-[ ]++Group[ ]++(?P<group>[A-Za-z0-9_.:-]{1,64}+)"
    for phase in ("start", "ready", "block"):
        rules.append(Rule("heading_" + phase, phase, prefix + r"[ \t]*+", "enter_state", "block", "", ("interface", "group")))
        rules.append(Rule("heading_af_" + phase, phase, prefix + r" - Address-Family (?P<af>[A-Za-z0-9]{1,16}+)[ \t]*+",
                          "enter_state", "block", "", ("interface", "group", "af")))
    for phase in ("ready", "block"):
        rules.append(Rule("prompt_" + phase, phase, r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
                          "enter_state", "done", "", ("prompt",)))
    decimal = r"[0-9]{1,6}+\.[0-9]{3}+"
    bodies = (
        ("state", r"  State is (?P<state>[A-Za-z]{2,16}+)", ("state",)),
        ("virtual_ip", r"  Virtual IP address is (?P<virtual_ip>[A-Za-z0-9:.]{1,64}+)", ("virtual_ip",)),
        ("virtual_mac", r"  Virtual MAC address is (?P<virtual_mac>[0-9a-f]{4}+\.[0-9a-f]{4}+\.[0-9a-f]{4}+)", ("virtual_mac",)),
        ("advertisement", "  Advertisement interval is (?P<advertisement>" + decimal + ") sec", ("advertisement",)),
        ("preemption", r"  Preemption (?P<preemption>[A-Za-z]{2,16}+)", ("preemption",)),
        ("priority", r"  Priority is (?P<priority>[0-9]{1,3}+)", ("priority",)),
        ("authentication", r'  Authentication text "(?P<authentication>[A-Za-z0-9_.:-]{1,64}+)"', ("authentication",)),
        ("master", r"  Master Router is (?P<master>[A-Za-z0-9:.]{1,64}+), priority is (?P<master_priority>[0-9]{1,3}+)",
         ("master", "master_priority")),
        ("master_advertisement", "  Master Advertisement interval is (?P<master_advertisement>" + decimal + ") sec",
         ("master_advertisement",)),
        ("master_down", "  Master Down interval is (?P<master_down>" + decimal + ") sec", ("master_down",)),
    )
    for identity, pattern, fields in bodies:
        rules.append(Rule(identity, "block", pattern + r"[ \t]*+", "enter_state" if identity == "master_down" else "record",
                          "ready" if identity == "master_down" else "block", "", fields))
    return tuple(rules)


def parse_capture(capture: Capture) -> Result:
    """Retain every recognized header; incomplete or unsupported blocks grant no positive fact."""
    if (type(capture) is not Capture or type(capture.raw) is not bytes
            or not all(type(value) is str and bool(value) for value in
                (capture.id, capture.source, capture.operation, capture.rendered, capture.codec))
            or capture.operation != OP or capture.rendered != COMMAND or capture.codec not in ("utf-8", "ascii")
            or type(capture.integrity) is not k.IntegrityState):
        raise ValueError("unsupported_vrrp")
    mapping = TokenMap.closed({"Init": VRRPState.INIT, "INIT": VRRPState.INIT,
                               "Master": VRRPState.MASTER, "MASTER": VRRPState.MASTER,
                               "Backup": VRRPState.BACKUP, "BACKUP": VRRPState.BACKUP})
    parsed = run_rules(capture.raw, capture.id, _rules(), (("state", mapping),))
    blocks: list[tuple[Record, list[Record]]] = []
    for item in parsed.records:
        if item.rule_id.startswith("heading_"):
            blocks.append((item, []))
        elif item.rule_id in _CATEGORIES and blocks:
            blocks[-1][1].append(item)
    invalid = not blocks or parsed.quality != "complete"
    opening = tuple(dict(item.fields)["prompt"].raw for item in parsed.records if item.rule_id == "prompt_command")
    closing = tuple(dict(item.fields)["prompt"].raw for item in parsed.records if item.rule_id in ("prompt_ready", "prompt_block"))
    invalid = invalid or (bool(opening) and closing != opening) or (not opening and bool(closing))
    seen: set[tuple[str, str]] = set()
    conflict = unresolved = False
    for header, body in blocks:
        fields = dict(header.fields)
        invalid = invalid or header.rule_id.startswith("heading_af_") or fields["group"].raw not in SYNTHETIC_GROUPS
        invalid = invalid or tuple(item.rule_id for item in body) != _CATEGORIES
        for item in body:
            values = dict(item.fields)
            if item.rule_id in ("virtual_ip", "master"):
                value = values[item.rule_id].raw
                unresolved = unresolved or item.rule_id == "virtual_ip" and value == "unknown"
                invalid = invalid or (value != "unknown" or item.rule_id == "master") and not ipv4_literal(value)
            elif item.rule_id == "preemption":
                invalid = invalid or values["preemption"].raw not in ("enabled", "disabled")
        key = (fields["interface"].raw, fields["group"].raw)
        conflict = conflict or key in seen
        seen.add(key)
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw.strip() or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if invalid else
              k.UnknownReason.CONFLICTING_EVIDENCE if conflict else
              k.UnknownReason.IDENTITY_UNRESOLVED if unresolved else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    rows: list[Row] = []
    for header, body in blocks:
        fields = dict(header.fields)
        state = next((dict(item.fields)["state"] for item in body if item.rule_id == "state"), None)
        vip = next((dict(item.fields)["virtual_ip"] for item in body if item.rule_id == "virtual_ip"), None)
        family: Literal["ipv4"] | None = ("ipv4" if not header.rule_id.startswith("heading_af_")
                                         and vip is not None and ipv4_literal(vip.raw) else None)
        local_reason = reason or (k.UnknownReason.IDENTITY_UNRESOLVED if family is None else None)
        rows.append(Row(interface=fields["interface"], group=fields["group"], state=state, virtual_ip=vip,
                        header=header, body=tuple(body), span=k.ByteSpan(start=header.span.start,
                        end=body[-1].span.end if body else header.span.end), address_family=family, reason=local_reason))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
