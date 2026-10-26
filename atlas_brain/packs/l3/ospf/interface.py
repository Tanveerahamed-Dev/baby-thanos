"""Generated thin OSPF interface allowlist; routing scope is never defaulted."""
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

OP, COMMAND = "iosxe.show_ip_ospf_interface", "show ip ospf interface"
VARIANT_SUPPORT = "allowlisted"
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "e62f9467a383997e190e04679d769c5c009e7460/"
          "src/genie/libs/parser/iosxe/show_ospf.py#L1759-L1835")
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}+"
_PORT_TOKEN = compile_pattern(_PORT)
_REQUIRED = {"port", "address", "prefix", "area", "process", "router_id", "network_type"}


class NetworkType(StrEnum):
    POINT_TO_POINT = "POINT_TO_POINT"
    POINT_TO_MULTIPOINT = "POINT_TO_MULTIPOINT"
    BROADCAST = "BROADCAST"
    NON_BROADCAST = "NON_BROADCAST"
    LOOPBACK = "LOOPBACK"
    SHAM_LINK = "SHAM_LINK"
    VIRTUAL_LINK = "VIRTUAL_LINK"


_MAPS = (("network_type", TokenMap.closed({item.value: item for item in NetworkType})),)


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


def _number(token: str, maximum: int) -> bool:
    return (token.isascii() and token.isdigit() and len(token) <= 10
            and int(token) <= maximum and str(int(token)) == token)


def _ipv4(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 4 and all(_number(part, 255) for part in parts)


def _area(token: str) -> str | None:
    if _number(token, 4294967295):
        return token
    if not _ipv4(token):
        return None
    value = 0
    for part in token.split("."):
        value = value * 256 + int(part)
    return str(value)


def _rules() -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for phase in ("start", "echo", "body", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)",
                          "record", phase, "", ("blank",)))
    for phase in ("start", "echo", "body"):
        for index, status in enumerate(("up", "down", "administratively down")):
            for oper in ("up", "down"):
                pattern = "(?P<port>" + _PORT + ") is " + status + ", line protocol is " + oper + r"[ \t]*+"
                rules.append(Rule("port_" + phase + str(index) + oper, phase, pattern,
                                  "enter_state", "body", "", ("port",)))
    rules.extend((
        Rule("bare", "start", COMMAND, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "echo", "", ("prompt",)),
        Rule("prompt", "body", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
             "enter_state", "done", "", ("prompt",)),
    ))
    for suffix, extra, names in (("", "", ()), ("_id", r" Interface ID (?P<interface_id>[0-9]++),", ("interface_id",))):
        rules.append(Rule("address" + suffix, "body", r"[ \t]++Internet Address (?P<address>[0-9.]++)/(?P<prefix>[0-9]++),"
                          + extra + r" Area (?P<area>[0-9.]++)[ \t]*+", "record", "body", "",
                          ("address", "prefix", "area") + names))
    for suffix, extra, names in (("", "", ()), ("_vrf", r" VRF (?P<vrf>[A-Za-z_][A-Za-z0-9_.:-]{0,63}+)", ("vrf",))):
        rules.append(Rule("process" + suffix, "body", r"[ \t]++Process ID (?P<process>[0-9]++)," + extra
                          + r" Router ID (?P<router_id>[0-9.]++), Network Type (?P<network_type>[A-Z_]++), Cost: (?P<cost>[0-9]++)[ \t]*+",
                          "record", "body", "", ("process", "router_id", "network_type", "cost") + names))
    for index, text in enumerate(("Interface Enable", "Network Statement")):
        rules.append(Rule("attachment" + str(index), "body", r"[ \t]++Attached via (?P<attachment>" + text + r")[ \t]*+",
                          "record", "body", "", ("attachment",)))
    return tuple(rules)


def parse_capture(capture: Capture, exact_ports: tuple[str, ...]) -> Result:
    if (capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_ospf_interface_capture")
    if (type(exact_ports) is not tuple or not exact_ports or len(set(exact_ports)) != len(exact_ports)
            or any(type(port) is not str or _PORT_TOKEN.fullmatch(port.encode("ascii", "replace")) is None
                   for port in exact_ports)):
        raise ValueError("invalid_exact_ports")
    parsed = run_rules(capture.raw, capture.id, _rules(), _MAPS)
    for line in parsed.lines:
        words = capture.raw[line.span.start:line.span.end].split()
        if (len(words) > 1 and words[1] == b"is" and words[0] != b"Interface"
                and _PORT_TOKEN.fullmatch(words[0]) is not None
                and words[0].decode("ascii") not in exact_ports):
            raise ValueError("undeclared_local_port")
    groups: dict[str, list[Record]] = {}
    current: str | None = None
    opening = closing = ""
    invalid = False
    for record in parsed.records:
        fields = dict(record.fields)
        if "port" in fields:
            current = fields["port"].raw
            if current not in exact_ports:
                raise ValueError("undeclared_local_port")
            groups.setdefault(current, []).append(record)
        elif record.rule_id.startswith(("address", "process", "attachment")) and current is not None:
            if "address" in fields:
                area = _area(fields["area"].raw)
                invalid = invalid or not _ipv4(fields["address"].raw) or not _number(fields["prefix"].raw, 32) or area is None
                if area is not None:
                    field = fields["area"]
                    fields["area"] = Captured(field.raw, field.span, area)
            if "process" in fields:
                token = fields["process"].raw
                invalid = invalid or not _number(token, 65535) or token == "0" or not _ipv4(fields["router_id"].raw)
            groups[current].append(Record(record.rule_id, record.span, tuple(fields.items())))
        elif record.rule_id == "command":
            opening = fields["prompt"].raw
        elif record.rule_id == "prompt":
            closing = fields["prompt"].raw
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (
                  k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if parsed.quality == "partial" or invalid
              or opening and closing and opening != closing else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    rows: list[Row] = []
    for port in sorted(exact_ports):
        records = groups.get(port, [])
        fields = tuple(field for record in records for field in record.fields)
        gap = (reason if reason is not None else
               k.UnknownReason.CONFLICTING_EVIDENCE if len(fields) != len(dict(fields)) else
               k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE if not records else
               k.UnknownReason.FIELD_NOT_PRINTED if not _REQUIRED <= dict(fields).keys() else None)
        rows.append(Row(port=port, fields=fields,
                        spans=tuple(record.span for record in records) or (k.ByteSpan(start=0, end=len(capture.raw)),),
                        reason=gap))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
