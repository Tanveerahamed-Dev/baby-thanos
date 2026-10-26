"""Generated thin allowlist for show ip interface; no device-format qualification."""
from dataclasses import dataclass

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import Captured, ParseResult, Record, Rule, run_rules
from atlas_brain.kernel import states as k

OP, COMMAND = "iosxe.show_ip_interface", "show ip interface"
FIELD, VARIANT_SUPPORT = "ip_bytes", "allowlisted"
# Form evidence only; fixtures and upstream parser code are not imported.
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "e62f9467a383997e190e04679d769c5c009e7460/src/genie/libs/parser/"
          "iosxe/tests/ShowIpInterface/cli/equal/golden_output_output.txt")
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
        Rule("mtu", "body", r"[ \t]*+MTU is (?P<ip_bytes>[0-9]++) bytes[ \t]*+",
             "record", "body", "", (FIELD,)),
    ))
    return tuple(rules)


def parse_capture(capture: Capture, exact_ports: tuple[str, ...]) -> Result:
    """Preserve every expected port; no default MTU or cross-layer substitution."""
    if (capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_mtu_capture")
    if (type(exact_ports) is not tuple or not exact_ports or len(set(exact_ports)) != len(exact_ports)
            or any(type(port) is not str or _PORT_TOKEN.fullmatch(port.encode("ascii", "replace")) is None
                   for port in exact_ports)):
        raise ValueError("invalid_exact_ports")
    parsed = run_rules(capture.raw, capture.id, _rules(), ())
    for line in parsed.lines:
        words = capture.raw[line.span.start:line.span.end].split()
        if (len(words) > 1 and words[1] == b"is" and _PORT_TOKEN.fullmatch(words[0]) is not None
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
        elif record.rule_id == "mtu" and current is not None:
            groups[current].append(record)
            token = fields[FIELD].raw
            invalid = invalid or len(token) > 5 or token.startswith("0")
            if len(token) <= 5:
                invalid = invalid or not 1 <= int(token) <= 65535
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
        headers = sum(record.rule_id.startswith("port_") for record in records)
        values = sum(name == FIELD for name, _ in fields)
        gap = (reason if reason is not None else
               k.UnknownReason.CONFLICTING_EVIDENCE if headers > 1 or values > 1 else
               k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE if not headers else
               k.UnknownReason.FIELD_NOT_PRINTED if not values else None)
        spans = tuple(record.span for record in records) or (k.ByteSpan(start=0, end=len(capture.raw)),)
        rows.append(Row(port=port, fields=fields, spans=spans, reason=gap))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
