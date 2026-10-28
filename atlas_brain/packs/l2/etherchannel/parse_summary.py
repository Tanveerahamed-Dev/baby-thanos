"""Bounded EtherChannel summary observations; declarations are not membership intent."""
from dataclasses import dataclass
from enum import StrEnum

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.kernel import states as k

OP, COMMAND = "iosxe.show_etherchannel_summary", "show etherchannel summary"
VARIANT_SUPPORT = "allowlisted"
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "6e0b25eb76be058e787e2859a89bc6edfa4e0bf6/src/genie/libs/parser/"
          "iosxe/tests/ShowEtherchannelSummary/cli/equal/golden_output_3_output.txt")
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}+"
_PORT_TOKEN = compile_pattern(_PORT)
_MEMBER = compile_pattern("(?P<port>" + _PORT + r")\((?P<flag>[A-Za-z-]++)\)")
_MEMBER_FLAGS = ("P", "bndl", "D", "I", "s", "susp", "H", "hot-sby", "u", "w", "d", "f")


class Protocol(StrEnum):
    LACP = "LACP"
    PAGP = "PAgP"
    NONE = "none"


@dataclass(frozen=True, slots=True, kw_only=True)
class Member:
    port: Captured
    flag: Captured
    span: k.ByteSpan


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    group: str
    fields: tuple[tuple[str, Captured], ...]
    members: tuple[Member, ...]
    spans: tuple[k.ByteSpan, ...]
    reason: k.UnknownReason | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Row, ...]
    missing_ports: tuple[str, ...]
    parse: ParseResult
    reason: k.UnknownReason | None


def _rules() -> tuple[Rule, ...]:
    rules: list[Rule] = [
        Rule("bare", "start", COMMAND, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "echo", "", ("prompt",)),
    ]
    for phase in ("start", "echo", "groups", "aggregators", "separator", "body", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)", "record", phase, "", ("blank",)))
    for phase in ("start", "echo"):
        rules.extend((
            Rule("groups_" + phase, phase, r"Number of channel-groups in use:[ \t]*+(?P<count>[0-9]++)[ \t]*+",
                 "enter_state", "groups", "", ("count",)),
            Rule("legend_" + phase, phase, r"(?P<legend>[ \t]*+[A-Za-z][A-Za-z0-9 /():.,-]*+)",
                 "record", phase, "", ("legend",)),
        ))
    rules.extend((
        Rule("aggregators", "groups", r"Number of aggregators:[ \t]*+(?P<count>[0-9]++)[ \t]*+",
             "enter_state", "aggregators", "", ("count",)),
        Rule("header", "aggregators", r"(?P<header>Group[ \t]++Port-channel[ \t]++Protocol[ \t]++Ports)[ \t]*+",
             "enter_state", "separator", "", ("header",)),
        Rule("separator", "separator", r"(?P<separator>-{2,}+\+-{2,}+\+-{2,}+\+-{2,}+)",
             "enter_state", "body", "", ("separator",)),
        Rule("group", "body",
             r"(?P<group>[0-9]++)[ \t]++(?P<channel>Po[0-9]++)\((?P<flags>[A-Za-z]++)\)"
             r"[ \t]++(?P<protocol>[A-Za-z-]++)(?P<members>[ \tA-Za-z0-9./:_()-]*+)",
             "record", "body", "", ("group", "channel", "flags", "protocol", "members")),
        Rule("wrap", "body", r"[ \t]++(?P<members>[A-Za-z][A-Za-z0-9./:_() \t-]*+)",
             "record", "body", "", ("members",)),
        Rule("prompt", "body", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
             "enter_state", "done", "", ("prompt",)),
    ))
    return tuple(rules)


def _number(raw: str) -> int | None:
    return int(raw) if raw.isascii() and raw.isdigit() and len(raw) <= 5 and int(raw) <= 65535 and str(int(raw)) == raw else None


def _members(field: Captured, raw: bytes, exact_ports: tuple[str, ...]) -> tuple[tuple[Member, ...], bool]:
    members: list[Member] = []
    cursor, invalid = field.span.start, False
    for token in raw[field.span.start:field.span.end].split():
        start = raw.find(token, cursor, field.span.end)
        cursor = start + len(token)
        match = _MEMBER.fullmatch(token)
        if match is None:
            invalid = True
            continue
        name, flag = match.group("port").decode("ascii"), match.group("flag").decode("ascii")
        if name not in exact_ports:
            raise ValueError("undeclared_etherchannel_port")
        invalid = invalid or flag not in _MEMBER_FLAGS
        a, b = match.span("port")
        c, d = match.span("flag")
        members.append(Member(port=Captured(name, k.ByteSpan(start=start+a, end=start+b), name),
                              flag=Captured(flag, k.ByteSpan(start=start+c, end=start+d), flag),
                              span=k.ByteSpan(start=start, end=cursor)))
    return tuple(members), invalid


def parse_capture(capture: Capture, exact_groups: tuple[str, ...], exact_ports: tuple[str, ...]) -> Result:
    """Keep declared populations independent of observed or intended membership."""
    if capture.operation != OP or capture.rendered != COMMAND or capture.codec not in ("utf-8", "ascii"):
        raise ValueError("unsupported_etherchannel_summary")
    if (type(exact_groups) is not tuple or not exact_groups or len(set(exact_groups)) != len(exact_groups)
            or any(type(value) is not str or _number(value) is None or not 1 <= int(value) <= 65535
                   for value in exact_groups)
            or type(exact_ports) is not tuple or len(set(exact_ports)) != len(exact_ports)
            or any(type(port) is not str or _PORT_TOKEN.fullmatch(port.encode("ascii", "replace")) is None
                   for port in exact_ports)):
        raise ValueError("invalid_etherchannel_population")
    maps = (("protocol", TokenMap.closed({"LACP": Protocol.LACP, "PAgP": Protocol.PAGP, "-": Protocol.NONE})),)
    parsed = run_rules(capture.raw, capture.id, _rules(), maps)
    fields_by_group: dict[str, list[tuple[str, Captured]]] = {}
    members_by_group: dict[str, list[Member]] = {}
    spans_by_group: dict[str, list[k.ByteSpan]] = {}
    current: str | None = None
    counts: list[int | None] = []
    opening = closing = ""
    invalid = conflict = False
    all_ports: list[str] = []
    for record in parsed.records:
        fields = dict(record.fields)
        if record.rule_id.startswith("legend_"):
            text = " ".join(fields["legend"].raw.split())
            invalid = invalid or text not in (
                "Flags: D - down P - bundled in port-channel",
                "I - stand-alone s - suspended", "H - Hot-standby (LACP only)",
                "R - Layer3 S - Layer2", "U - in use f - failed to allocate aggregator",
                "M - not in use, minimum links not met", "u - unsuitable for bundling",
                "w - waiting to be aggregated", "d - default port", "A - formed by Auto LAG",
            )
        if record.rule_id.startswith("groups_") or record.rule_id == "aggregators":
            counts.append(_number(fields["count"].raw))
        if record.rule_id == "command":
            opening = fields["prompt"].raw
        if record.rule_id == "prompt":
            closing = fields["prompt"].raw
        if record.rule_id == "group":
            current = fields["group"].raw
            if current not in exact_groups:
                raise ValueError("undeclared_etherchannel_group")
            conflict = conflict or current in fields_by_group
            fields_by_group.setdefault(current, []).extend((name, token) for name, token in record.fields if name != "members")
            members_by_group.setdefault(current, [])
            spans_by_group.setdefault(current, [])
            invalid = invalid or fields["channel"].raw != "Po" + current
            flags = fields["flags"].raw
            invalid = invalid or flags not in ("SU", "SD", "RU", "RD")
        if record.rule_id in ("group", "wrap"):
            if current is None:
                invalid = True
            else:
                members, bad = _members(fields["members"], capture.raw, exact_ports)
                invalid = invalid or bad
                members_by_group[current].extend(members)
                spans_by_group[current].append(record.span)
                all_ports.extend(member.port.raw for member in members)
    conflict = conflict or len(set(all_ports)) != len(all_ports)
    invalid = (invalid or len(counts) != 2 or counts[0] != len(fields_by_group) or counts[1] is None
               or (counts[0] == 0) != (counts[1] == 0)
               or sum(record.rule_id == "separator" for record in parsed.records) != 1)
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (
                  k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.CONFLICTING_EVIDENCE if conflict else
              k.UnknownReason.PARSE_PARTIAL if parsed.quality == "partial" or invalid
              or opening and closing and opening != closing else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    rows = tuple(Row(group=group, fields=tuple(fields_by_group.get(group, [])),
                     members=tuple(members_by_group.get(group, [])), spans=tuple(spans_by_group.get(group, [])),
                     reason=reason or (None if group in fields_by_group else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE))
                 for group in sorted(exact_groups))
    return Result(rows=rows, missing_ports=tuple(sorted(set(exact_ports) - set(all_ports))), parse=parsed, reason=reason)
