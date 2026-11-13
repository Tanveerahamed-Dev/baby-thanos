"""Bounded synthetic IPv4 HSRP-all version observations; no defaults or qualification."""
from dataclasses import dataclass
from typing import Literal

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import Captured, ParseResult, Record, Rule, run_rules
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp.parse_hsrp_brief import ipv4_literal

OP, COMMAND = "iosxe.show_standby_all", "show standby all"
VARIANT_SUPPORT = "allowlisted"
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "6e0b25eb76be058e787e2859a89bc6edfa4e0bf6/src/genie/libs/parser/"
          "iosxe/tests/ShowStandbyAll/cli/equal/golden_output2_output.txt")
_REQUIRED = frozenset(("state", "virtual_ip", "active_mac", "local_mac", "hello",
                       "preempt", "active", "standby", "priority", "group_name"))


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    interface: Captured
    group: Captured
    version: Captured | None
    virtual_ip: Captured | None
    header: Record
    body: tuple[Record, ...]
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
        Rule("prompt", "ready", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
             "enter_state", "done", "", ("prompt",)),
    ]
    for phase in ("start", "ready", "block", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)", "record", phase, "", ("blank",)))
    for phase in ("start", "ready"):
        prefix = r"(?P<interface>[A-Za-z][A-Za-z0-9./:_-]{0,63}+)[ ]++-[ ]++Group[ ]++(?P<group>[0-9]{1,4}+)"
        rules.append(Rule("heading_version_" + phase, phase, prefix + r"[ ]++\(version (?P<version>[12])\)[ \t]*+",
                          "enter_state", "block", "", ("interface", "group", "version")))
        rules.append(Rule("heading_" + phase, phase, prefix + r"[ \t]*+",
                          "enter_state", "block", "", ("interface", "group")))
    mac = r"[0-9a-f]{4}+\.[0-9a-f]{4}+\.[0-9a-f]{4}+"
    number, decimal = r"[0-9]{1,10}+", r"[0-9]{1,10}+\.[0-9]{1,6}+"
    bodies = (
        ("state", tuple("  State is " + value for value in ("Active", "Standby", "Init", "Disabled"))),
        ("state_change", (r"    " + number + r" state changes?+, last state change [0-9wdhms:]{1,32}+",)),
        ("track", tuple("    Track object " + number + " \\(" + value + "\\)" for value in ("unknown", "Up", "Down"))),
        ("active_mac", tuple("  Active virtual MAC address is " + value + " \\(MAC " + status + "In Use\\)"
                            for value in (mac, "unknown") for status in ("", "Not "))),
        ("local_mac", tuple("    Local virtual MAC address is " + mac + " \\(" + value + "\\)"
                           for value in ("v1 default", "v2 default", "bia", "cfgd"))),
        ("hello", ("  Hello time " + number + " sec, hold time " + number + " sec",)),
        ("next_hello", tuple("    Next hello sent in " + value + " secs" for value in (number, decimal))),
        ("authentication", (r'  Authentication MD5, key-chain "[A-Za-z0-9_.:-]{1,64}+"',)),
        ("preempt", ("  Preemption enabled",
                     "  Preemption enabled, delay min " + number + " secs, reload " + number + " secs, sync " + number + " secs")),
        ("active", tuple("  Active router is " + value for value in ("local", "unknown", r"[0-9.]{7,15}+"))),
        ("standby", ("  Standby router is unknown",) + tuple(
            r"  Standby router is [0-9.]{7,15}+, priority [0-9]{1,3}+ \(expires in " + value + r" sec\)"
            for value in (number, decimal))),
        ("priority", tuple(r"  Priority [0-9]{1,3}+ \(" + value + r" [0-9]{1,3}+\)" for value in ("default", "configured"))),
    )
    for identity, patterns in bodies:
        for index, pattern in enumerate(patterns):
            rules.append(Rule(identity + ":" + str(index), "block", "(?P<body>" + pattern + r")[ \t]*+",
                              "record", "block", "", ("body",)))
    rules.extend((
        Rule("virtual_ip", "block", r"  Virtual IP address is (?P<virtual_ip>[A-Za-z0-9:.]{1,64}+)[ \t]*+",
             "record", "block", "", ("virtual_ip",)),
        Rule("group_name", "block", r'(?P<body>  Group name is "[A-Za-z0-9_.:/-]{1,96}+" \(default\))[ \t]*+',
             "enter_state", "ready", "", ("body",)),
    ))
    return tuple(rules)


def _blocks(parsed: ParseResult) -> tuple[tuple[Record, tuple[Record, ...]], ...]:
    blocks: list[tuple[Record, tuple[Record, ...]]] = []
    heading: Record | None = None
    body: list[Record] = []
    for item in parsed.records:
        if item.rule_id.startswith("heading_"):
            if heading is not None:
                blocks.append((heading, tuple(body)))
            heading, body = item, []
        elif item.rule_id.split(":")[0] in _REQUIRED or item.rule_id.split(":")[0] in ("state_change", "track", "next_hello", "authentication"):
            if heading is not None:
                body.append(item)
    if heading is not None:
        blocks.append((heading, tuple(body)))
    return tuple(blocks)


def parse_capture(capture: Capture) -> Result:
    """Preserve every recognized block; only explicit same-block IPv4 versions are usable."""
    if (type(capture) is not Capture or capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_hsrp_all")
    parsed = run_rules(capture.raw, capture.id, _rules(), ())
    blocks = _blocks(parsed)
    invalid = not blocks or parsed.quality != "complete"
    opening = tuple(dict(item.fields)["prompt"].raw for item in parsed.records if item.rule_id == "prompt_command")
    closing = tuple(dict(item.fields)["prompt"].raw for item in parsed.records if item.rule_id == "prompt")
    invalid = invalid or (bool(opening) and closing != opening) or (not opening and bool(closing))
    seen: set[tuple[str, str]] = set()
    conflict = False
    for heading, body in blocks:
        fields = dict(heading.fields)
        group = fields["group"].raw
        invalid = invalid or not (group.isascii() and group.isdigit() and int(group) <= 4095 and str(int(group)) == group)
        identities = tuple(item.rule_id.split(":")[0] for item in body)
        invalid = invalid or any(identities.count(identity) != 1 for identity in _REQUIRED)
        invalid = invalid or not body or body[-1].rule_id != "group_name"
        invalid = invalid or any(identities.count(identity) > 1 for identity in ("state_change", "track", "next_hello", "authentication"))
        vip = tuple(dict(item.fields)["virtual_ip"] for item in body if item.rule_id == "virtual_ip")
        invalid = invalid or any(token.raw != "unknown" and not ipv4_literal(token.raw) for token in vip)
        key = (fields["interface"].raw, group)
        conflict = conflict or key in seen
        seen.add(key)
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw.strip() or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if invalid else
              k.UnknownReason.CONFLICTING_EVIDENCE if conflict else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    rows: list[Row] = []
    for heading, body in blocks:
        fields = dict(heading.fields)
        version = fields.get("version")
        vip = next((dict(item.fields)["virtual_ip"] for item in body if item.rule_id == "virtual_ip"), None)
        family: Literal["ipv4"] | None = "ipv4" if vip is not None and ipv4_literal(vip.raw) else None
        local_reason = reason or (k.UnknownReason.IDENTITY_UNRESOLVED if family is None else
                                  k.UnknownReason.NOT_OBSERVABLE if version is None else None)
        rows.append(Row(interface=fields["interface"], group=fields["group"], version=version,
                        virtual_ip=vip, header=heading, body=body, address_family=family, reason=local_reason))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
