"""Generated thin OSPF neighbor allowlist; observations never imply stuck/healthy."""
from dataclasses import dataclass
from enum import StrEnum

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Record,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.kernel import states as k

OP, COMMAND = "iosxe.show_ip_ospf_neighbor", "show ip ospf neighbor"
VARIANT_SUPPORT = "allowlisted"
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "e62f9467a383997e190e04679d769c5c009e7460/src/genie/libs/parser/"
          "iosxe/tests/ShowIpOspfNeighbor/cli/equal/golden_output_output.txt")
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}+"
_PORT_TOKEN = compile_pattern(_PORT)
_SPACE = r"[ \t]++"


class State(StrEnum):
    DOWN = "DOWN"
    ATTEMPT = "ATTEMPT"
    INIT = "INIT"
    TWO_WAY = "2WAY"
    EXSTART = "EXSTART"
    EXCHANGE = "EXCHANGE"
    LOADING = "LOADING"
    FULL = "FULL"


class Role(StrEnum):
    DR = "DR"
    BDR = "BDR"
    DROTHER = "DROTHER"
    NONE = "-"


_MAPS = (("state", TokenMap.closed({item.value: item for item in State})),
         ("role", TokenMap.closed({item.value: item for item in Role})))


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    port: str
    fields: tuple[tuple[str, Captured], ...]
    spans: tuple[k.ByteSpan, ...]
    reason: k.UnknownReason | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Row, ...]
    parse: ParseResult
    reason: k.UnknownReason | None


def _ipv4(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 4 and all(part.isascii() and part.isdigit() and len(part) <= 3
                                  and 0 <= int(part) <= 255 and str(int(part)) == part for part in parts)


def _rules() -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for phase in ("start", "echo", "table", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)",
                          "record", phase, "", ("blank",)))
    header = "(?P<header>Neighbor ID" + _SPACE + "Pri" + _SPACE + "State" + _SPACE + "Dead Time" + _SPACE + "Address" + _SPACE + "Interface)"
    for phase in ("start", "echo"):
        rules.append(Rule("header_" + phase, phase, header + r"[ \t]*+",
                          "enter_state", "table", "", ("header",)))
    pattern = (r"(?P<neighbor_id>[0-9.]++)" + _SPACE + r"(?P<priority>[0-9]++)" + _SPACE
               + r"(?P<state>[A-Z0-9]++)/[ \t]*+(?P<role>[A-Z-]++)" + _SPACE
               + r"(?P<dead_time>[0-9]{2}+:[0-9]{2}+:[0-9]{2}+)" + _SPACE
               + r"(?P<address>[0-9.]++)" + _SPACE + "(?P<port>" + _PORT + r")[ \t]*+")
    rules.extend((
        Rule("bare", "start", COMMAND, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "echo", "", ("prompt",)),
        Rule("prompt", "table", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
             "enter_state", "done", "", ("prompt",)),
        Rule("neighbor", "table", pattern, "record", "table", "",
             ("neighbor_id", "priority", "state", "role", "dead_time", "address", "port")),
    ))
    return tuple(rules)


def parse_capture(capture: Capture, exact_ports: tuple[str, ...]) -> Result:
    if (capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_ospf_neighbor_capture")
    if (type(exact_ports) is not tuple or not exact_ports or len(set(exact_ports)) != len(exact_ports)
            or any(type(port) is not str or _PORT_TOKEN.fullmatch(port.encode("ascii", "replace")) is None
                   for port in exact_ports)):
        raise ValueError("invalid_exact_ports")
    parsed = run_rules(capture.raw, capture.id, _rules(), _MAPS)
    for line in parsed.lines:
        words = capture.raw[line.span.start:line.span.end].split()
        if (len(words) >= 2 and _ipv4(words[0].decode("ascii", "replace"))
                and _PORT_TOKEN.fullmatch(words[-1]) is not None
                and words[-1].decode("ascii") not in exact_ports):
            raise ValueError("undeclared_local_port")
    groups: dict[tuple[str, str, str], list[Record]] = {}
    headers: list[k.ByteSpan] = []
    opening = closing = ""
    invalid = False
    for record in parsed.records:
        fields = dict(record.fields)
        if "header" in fields:
            headers.append(record.span)
        elif record.rule_id == "neighbor":
            port = fields["port"].raw
            if port not in exact_ports:
                raise ValueError("undeclared_local_port")
            identity = (port, fields["neighbor_id"].raw, fields["address"].raw)
            groups.setdefault(identity, []).append(record)
            priority = fields["priority"].raw
            invalid = invalid or not _ipv4(identity[1]) or not _ipv4(identity[2])
            invalid = invalid or len(priority) > 3 or (len(priority) > 1 and priority.startswith("0"))
            if len(priority) <= 3:
                invalid = invalid or int(priority) > 255
            invalid = invalid or any(int(part) > 59 for part in fields["dead_time"].raw.split(":")[1:])
        elif record.rule_id == "command":
            opening = fields["prompt"].raw
        elif record.rule_id == "prompt":
            closing = fields["prompt"].raw
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (
                  k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if parsed.quality == "partial" or invalid or len(headers) != 1
              or opening and closing and opening != closing else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    rows: list[Row] = []
    for port in sorted(exact_ports):
        identities = sorted(key for key in groups if key[0] == port)
        if not identities:
            rows.append(Row(port=port, fields=(), spans=(k.ByteSpan(start=0, end=len(capture.raw)),),
                            reason=reason or k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE))
        for identity in identities:
            records = groups[identity]
            fields = tuple(field for record in records for field in record.fields)
            gap = reason or (k.UnknownReason.CONFLICTING_EVIDENCE if len(records) != 1 else None)
            rows.append(Row(port=port, fields=fields,
                            spans=tuple(headers) + tuple(record.span for record in records), reason=gap))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
