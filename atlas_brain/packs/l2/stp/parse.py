"""Allowlisted VLAN STP detail observations; no device/train qualification."""
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

OP, VARIANT_SUPPORT = "iosxe.show_spanning_tree_interface_detail", "allowlisted"
SOURCE = ("https://github.com/CiscoTestAutomation/genieparser/blob/"
          "e62f9467a383997e190e04679d769c5c009e7460/src/genie/libs/parser/iosxe/"
          "tests/ShowSpanningTreeInterfaceDetail/cli/equal/golden_output_output.txt")
PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}+"
PORT_TOKEN = compile_pattern(PORT)
MAC = r"[0-9a-fA-F]{4}+\.[0-9a-fA-F]{4}+\.[0-9a-fA-F]{4}+"
GUARDS = ("bpdu_filter", "bpdu_guard", "loop_guard", "root_guard")


class Role(StrEnum):
    ROOT = "root"
    DESIGNATED = "designated"
    ALTERNATE = "alternate"
    BACKUP = "backup"
    DISABLED = "disabled"


class State(StrEnum):
    FORWARDING = "forwarding"
    LEARNING = "learning"
    BLOCKING = "blocking"
    LISTENING = "listening"
    DISABLED = "disabled"


class Switch(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"


MAPS = (("role", TokenMap.closed({item.value: item for item in Role})),
        ("state", TokenMap.closed({item.value: item for item in State}))) + tuple(
            (name, TokenMap.closed({item.value: item for item in Switch})) for name in GUARDS)


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    port: str
    vlan: int
    fields: tuple[tuple[str, Captured], ...]
    spans: tuple[k.ByteSpan, ...]
    reason: k.UnknownReason | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    rows: tuple[Row, ...]
    parse: ParseResult
    reason: k.UnknownReason | None


def command(port: str) -> str:
    k.require(type(port) is str and PORT_TOKEN.fullmatch(port.encode("ascii", "replace")) is not None,
              "invalid_stp_port")
    return "show spanning-tree interface " + port + " detail"


def _rules(rendered: str) -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for phase in ("start", "echo", "body", "done"):
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)",
                          "record", phase, "", ("blank",)))
    header = (r"[ \t]*+Port (?P<number>[0-9]++) \((?P<port>" + PORT
              + r")\) of VLAN(?P<vlan>[0-9]{4}+) is (?P<role>[a-z]++) (?P<state>[a-z]++)[ \t]*+")
    for phase in ("start", "echo", "body"):
        rules.append(Rule("header_" + phase, phase, header, "enter_state", "body", "",
                          ("number", "port", "vlan", "role", "state")))
    # Escape the admitted port's regex punctuation without changing its bytes.
    literal = rendered.replace(".", r"\.")
    rules.extend((
        Rule("bare", "start", literal, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + literal,
             "enter_state", "echo", "", ("prompt",)),
        Rule("prompt", "body", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])",
             "enter_state", "done", "", ("prompt",)),
    ))
    forms = (
        ("path", r"Port path cost (?P<path_cost>[0-9]++), Port priority (?P<port_priority>[0-9]++), Port Identifier (?P<port_identifier>[0-9]++\.[0-9]++)\.",
         ("path_cost", "port_priority", "port_identifier")),
        ("root", r"Designated root has priority (?P<root_priority>[0-9]++), address (?P<root_mac>" + MAC + ")",
         ("root_priority", "root_mac")),
        ("designated_bridge", r"Designated bridge has priority (?P<designated_bridge_priority>[0-9]++), address (?P<designated_bridge_mac>" + MAC + ")",
         ("designated_bridge_priority", "designated_bridge_mac")),
        ("designated", r"Designated port id is (?P<designated_port>[0-9]++\.[0-9]++), designated path cost (?P<designated_cost>[0-9]++)",
         ("designated_port", "designated_cost")),
        ("timers", r"Timers: message age (?P<age>[0-9]++), forward delay (?P<delay>[0-9]++), hold (?P<hold>[0-9]++)",
         ("age", "delay", "hold")),
        ("transitions", r"Number of transitions to forwarding state: (?P<transitions>[0-9]++)", ("transitions",)),
        ("portfast", r"The port is in the (?P<portfast>portfast) mode", ("portfast",)),
        ("link", r"Link type is (?P<link_type>point-to-point) by default", ("link_type",)),
        ("bpdu", r"BPDU: sent (?P<sent>[0-9]++), received (?P<received>[0-9]++)", ("sent", "received")),
    )
    for name, pattern, fields in forms:
        rules.append(Rule(name, "body", r"[ \t]*+" + pattern + r"[ \t]*+", "record", "body", "", fields))
    for name, label, suffix in (("bpdu_guard", "Bpdu guard", ""), ("bpdu_filter", "Bpdu filter", ""),
                                ("root_guard", "Root guard", " on the port"), ("loop_guard", "Loop guard", " on the port")):
        rules.append(Rule(name, "body", r"[ \t]*+" + label + " is (?P<" + name + ">[a-z]++)" + suffix + r"[ \t]*+",
                          "record", "body", "", (name,)))
    return tuple(rules)


def parse_capture(capture: Capture, exact_port: str, expected_vlans: tuple[int, ...]) -> Result:
    rendered = command(exact_port)
    if capture.operation != OP or capture.rendered != rendered or capture.codec not in ("ascii", "utf-8"):
        raise ValueError("unsupported_stp_capture")
    k.require(type(expected_vlans) is tuple and 1 <= len(expected_vlans) <= 16
              and all(type(vlan) is int and 1 <= vlan <= 4094 for vlan in expected_vlans)
              and len(set(expected_vlans)) == len(expected_vlans), "invalid_stp_vlans")
    parsed = run_rules(capture.raw, capture.id, _rules(rendered), MAPS)
    unsupported = False
    for line in parsed.lines:
        words = capture.raw[line.span.start:line.span.end].split()
        if (len(words) > 4 and words[0] == b"Port" and words[3] == b"of"
                and words[2].startswith(b"(") and words[2].endswith(b")")):
            port = words[2].removeprefix(b"(").removesuffix(b")")
            if PORT_TOKEN.fullmatch(port) is not None and port.decode("ascii") != exact_port:
                raise ValueError("undeclared_stp_port")
            unsupported = unsupported or words[4].startswith(b"MST")
            token = words[4].removeprefix(b"VLAN")
            if (words[4].startswith(b"VLAN") and token.isdigit() and len(token) <= 4
                    and int(token) not in expected_vlans):
                raise ValueError("undeclared_stp_vlan")
    groups: dict[int, list[Record]] = {}
    current: int | None = None
    opening = closing = ""
    invalid = False
    for record in parsed.records:
        fields = dict(record.fields)
        if record.rule_id.startswith("header_"):
            current = int(fields["vlan"].raw)
            groups.setdefault(current, []).append(record)
        elif record.rule_id == "command":
            opening = fields["prompt"].raw
        elif record.rule_id == "prompt":
            closing = fields["prompt"].raw
        elif current is not None and not record.rule_id.startswith("blank_"):
            groups[current].append(record)
        for name in ("root_priority", "designated_bridge_priority"):
            if name in fields:
                token = fields[name].raw
                invalid = invalid or len(token) > 5 or (len(token) <= 5 and
                    (int(token) > 65535 or str(int(token)) != token))
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not capture.raw or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if unsupported or capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if parsed.quality == "partial" or invalid
              or opening and closing and opening != closing else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    rows: list[Row] = []
    for vlan in sorted(expected_vlans):
        records = groups.get(vlan, [])
        fields = tuple(field for record in records for field in record.fields)
        names = tuple(name for name, _ in fields)
        gap = (reason if reason is not None else
               k.UnknownReason.CONFLICTING_EVIDENCE if len(set(names)) != len(names) else
               k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE if not records else None)
        spans = tuple(record.span for record in records) or (k.ByteSpan(start=0, end=len(capture.raw)),)
        rows.append(Row(port=exact_port, vlan=vlan, fields=fields, spans=spans, reason=gap))
    return Result(rows=tuple(rows), parse=parsed, reason=reason)
