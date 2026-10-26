"""Explicit supplied mtu-ignore statements; absence never proves disabled."""
from dataclasses import dataclass

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Record,
    Rule,
    run_rules,
)
from atlas_brain.kernel import states as k

OP, COMMAND = "iosxe.show_running_config_all", "show running-config all"
VARIANT_SUPPORT = "allowlisted"
# Commands are primary-source-confirmed; this thin synthetic envelope is not a format floor.
SOURCE = ("https://github.com/CiscoTestAutomation/genielibs/blob/"
          "9fd4846825c99ad8a954c89d245aff90a686a9f0/"
          "pkgs/sdk-pkg/src/genie/libs/sdk/apis/iosxe/ospf/configure.py#L1565-L1617")
COMMAND_SOURCE = ("https://github.com/CiscoTestAutomation/genielibs/blob/"
                  "9fd4846825c99ad8a954c89d245aff90a686a9f0/"
                  "pkgs/sdk-pkg/src/genie/libs/sdk/apis/utils.py#L4681-L4685")
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}+"
_PORT_TOKEN = compile_pattern(_PORT)


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


def _rules() -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for phase in ("start", "echo", "global", "block", "done", "closed"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)",
                          "record", phase, "", ("blank",)))
    for phase in ("start", "echo", "global", "block"):
        rules.extend((
            Rule("port_" + phase, phase, "interface (?P<port>" + _PORT + r")[ \t]*+",
                 "enter_state", "block", "", ("port",)),
            Rule("separator_" + phase, phase, r"(?P<separator>!)",
                 "enter_state", "global", "", ("separator",)),
            Rule("end_" + phase, phase, r"(?P<end>end)",
                 "enter_state", "done", "", ("end",)),
        ))
    rules.extend((
        Rule("bare", "start", COMMAND, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "echo", "", ("prompt",)),
        Rule("prompt", "done", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
             "enter_state", "closed", "", ("prompt",)),
        Rule("enabled", "block", r"[ \t]++(?P<mtu_ignore>ip ospf mtu-ignore)[ \t]*+",
             "record", "block", "", ("mtu_ignore",)),
        Rule("disabled", "block", r"[ \t]++(?P<mtu_ignore>no ip ospf mtu-ignore)[ \t]*+",
             "record", "block", "", ("mtu_ignore",)),
    ))
    return tuple(rules)


def parse_capture(capture: Capture, exact_ports: tuple[str, ...]) -> Result:
    if (capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_ospf_ignore_capture")
    if (type(exact_ports) is not tuple or not exact_ports or len(set(exact_ports)) != len(exact_ports)
            or any(type(port) is not str or _PORT_TOKEN.fullmatch(port.encode("ascii", "replace")) is None
                   for port in exact_ports)):
        raise ValueError("invalid_exact_ports")
    parsed = run_rules(capture.raw, capture.id, _rules(), ())
    unsupported = False
    for line in parsed.lines:
        words = capture.raw[line.span.start:line.span.end].split()
        if len(words) > 1 and words[0] == b"interface" and words[1].lower() == b"range":
            unsupported = True
            continue
        if (len(words) > 1 and words[0] == b"interface" and _PORT_TOKEN.fullmatch(words[1]) is not None
                and words[1].decode("ascii") not in exact_ports):
            raise ValueError("undeclared_local_port")
        if words:
            unsupported = unsupported or words[0] in (b"template", b"source", b"inherit", b"default", b"port-profile")
            unsupported = unsupported or words[0] == b"no" and words != [b"no", b"ip", b"ospf", b"mtu-ignore"]
    groups: dict[str, list[Record]] = {}
    current: str | None = None
    opening = closing = ""
    ends = 0
    for record in parsed.records:
        fields = dict(record.fields)
        if "port" in fields:
            if fields["port"].raw.casefold() == "range":
                current = None
                continue
            current = fields["port"].raw
            if current not in exact_ports:
                raise ValueError("undeclared_local_port")
            groups.setdefault(current, []).append(record)
        elif record.rule_id in ("enabled", "disabled") and current is not None:
            field = fields["mtu_ignore"]
            fields["mtu_ignore"] = Captured(field.raw, field.span, record.rule_id)
            groups[current].append(Record(record.rule_id, record.span, tuple(fields.items())))
        elif "separator" in fields or "end" in fields:
            current = None
            ends += int("end" in fields)
        elif record.rule_id == "command":
            opening = fields["prompt"].raw
        elif record.rule_id == "prompt":
            closing = fields["prompt"].raw
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (
                  k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if unsupported or capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if parsed.quality == "partial" or ends != 1
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
               k.UnknownReason.FIELD_NOT_PRINTED if "mtu_ignore" not in dict(fields) else None)
        rows.append(Row(port=port, fields=fields,
                        spans=tuple(record.span for record in records) or (k.ByteSpan(start=0, end=len(capture.raw)),),
                        reason=gap))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
