"""Bounded static IOS-XE configuration grammar; supplied bytes stay authoritative."""
from dataclasses import dataclass
from typing import Literal

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Rule,
    run_rules,
)
from atlas_brain.evidence.synthetic import Node, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.vlan_trunk.build import canonical_allowed

OP, COMMAND = "iosxe.show_running_config", "show running-config"
_NAME = r"[A-Za-z_][A-Za-z0-9_.-]{0,63}+"
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}+"
_PORT_TOKEN = compile_pattern(_PORT)


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigSection:
    kind: Literal["interface", "template"]
    name: Captured
    header: k.ByteSpan
    entries: tuple[tuple[str, Captured], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigDocument:
    capture: Capture
    sections: tuple[ConfigSection, ...]
    parse: ParseResult
    reason: k.UnknownReason | None
    detail: str


def canonical_value(kind: str, token: str) -> int | str | None:
    if kind == "mode":
        return token if token in ("trunk", "access", "routed") else None
    if kind == "allowed":
        return canonical_allowed(token)
    if kind == "native" and token.isascii() and token.isdigit() and len(token) <= 4:
        value = int(token)
        return value if 1 <= value <= 4094 and str(value) == token else None
    return None


def _rules() -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for state in ("start", "global", "block", "done", "closed"):
        rules.append(Rule("blank_" + state, state, r"(?P<blank>[ \t]*+)", "record", state, "", ("blank",)))
    for state in ("start", "global", "block"):
        for kind, grammar in (("interface", _PORT), ("template", _NAME)):
            rules.append(Rule(kind + "_" + state, state, kind + " (?P<name>" + grammar + r")[ \t]*+",
                              "enter_state", "block", "", ("name",)))
        rules.extend((
            Rule("separator_" + state, state, "!", "enter_state", "global", "", ()),
            Rule("end_" + state, state, "end", "enter_state", "done", "", ()),
        ))
    for state in ("start", "global"):
        for name, pattern, fields in (
            ("building", r"Building configuration\.\.\.", ()),
            ("current", r"Current configuration : (?P<size>[0-9]++) bytes", ("size",)),
            ("version", r"version (?P<version>[A-Za-z0-9.()_-]++)", ("version",)),
            ("hostname", r"hostname (?P<hostname>[A-Za-z0-9_.:-]++)", ("hostname",)),
        ):
            rules.append(Rule(name + "_" + state, state, pattern, "enter_state", "global", "", fields))
    rules.extend((
        Rule("bare", "start", COMMAND, "enter_state", "global", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])[ ]?+" + COMMAND,
             "enter_state", "global", "", ("prompt",)),
        Rule("prompt", "done", r"(?P<prompt>[A-Za-z0-9_.:-]++[>#])", "enter_state", "closed", "", ("prompt",)),
    ))
    for value in ("trunk", "access"):
        rules.append(Rule("mode_" + value, "block", r"[ \t]++switchport mode (?P<mode>" + value + r")[ \t]*+",
                          "record", "block", "", ("mode",)))
    rules.extend((
        Rule("routed", "block", r"[ \t]++(?P<routed>no switchport)[ \t]*+", "record", "block", "", ("routed",)),
        Rule("native", "block", r"[ \t]++switchport trunk native vlan (?P<native>[0-9]++)[ \t]*+",
             "record", "block", "", ("native",)),
        Rule("source", "block", r"[ \t]++source template (?P<source>" + _NAME + r")[ \t]*+",
             "record", "block", "", ("source",)),
    ))
    for name, grammar in (("numeric", r"[0-9,-]++"), ("all", "all"), ("none", "none")):
        rules.append(Rule("allowed_" + name, "block",
                          r"[ \t]++switchport trunk allowed vlan (?P<allowed>" + grammar + r")[ \t]*+",
                          "record", "block", "", ("allowed",)))
    return tuple(rules)


def _unsupported(words: list[bytes]) -> bool:
    if not words:
        return False
    if words[0] in (b"default", b"port-profile", b"dynamic-template", b"inherit"):
        return True
    if words[0] == b"no":
        return words != [b"no", b"switchport"]
    return (words[:2] in ([b"interface", b"range"], [b"template", b"type"])
            or words[:3] == [b"switchport", b"mode", b"dynamic"]
            or words[:2] == [b"source", b"template"] and len(words) != 3
            or words[:4] == [b"switchport", b"trunk", b"allowed", b"vlan"]
            and len(words) > 4 and words[4] in (b"add", b"remove", b"except"))


def parse_capture(capture: Capture, node: Node) -> ConfigDocument:
    if (capture.source != node.key or capture.operation != OP or capture.rendered != COMMAND
            or capture.codec not in ("utf-8", "ascii")):
        raise ValueError("unsupported_config_capture")
    parsed = run_rules(capture.raw, capture.id, _rules(), ())
    unsupported = False
    for line in parsed.lines:
        words = capture.raw[line.span.start:line.span.end].split()
        unsupported = unsupported or _unsupported(words)
        if (line.status == "unrecognised" and len(words) > 1 and words[0] == b"interface"
                and words[1] != b"range" and _PORT_TOKEN.fullmatch(words[1]) is not None):
            endpoint(node, words[1].decode("ascii"))
    sections: list[ConfigSection] = []
    kind: Literal["interface", "template"] = "interface"
    name: Captured | None = None
    header = k.ByteSpan(start=0, end=0)
    entries: list[tuple[str, Captured]] = []
    opening = closing = ""
    ends = 0
    metadata: list[int] = []
    ranks = {"building": 0, "current": 1, "version": 2, "hostname": 3}
    invalid = False
    for record in parsed.records:
        fields = dict(record.fields)
        tag = record.rule_id.partition("_")[0]
        if tag in ("interface", "template", "separator", "end"):
            if name is not None:
                sections.append(ConfigSection(kind=kind, name=name, header=header, entries=tuple(entries)))
            name, entries = None, []
        if tag in ("interface", "template") and not (tag == "interface" and fields["name"].raw == "range"):
            kind = "interface" if tag == "interface" else "template"
            name, header = fields["name"], record.span
            if kind == "interface":
                endpoint(node, name.raw)
        if tag == "end":
            ends += 1
        if tag in ranks:
            invalid = invalid or bool(sections) or name is not None
            metadata.append(ranks[tag])
        if record.rule_id == "command":
            opening = fields["prompt"].raw
        if record.rule_id == "prompt":
            closing = fields["prompt"].raw
        for key in ("mode", "native", "allowed", "source", "routed"):
            if key in fields:
                field = fields[key]
                if key == "routed":
                    key, field = "mode", Captured(field.raw, field.span, "routed")
                entries.append((key, field))
                if key != "source" and canonical_value(key, str(field.value)) is None:
                    invalid = True
    if name is not None:
        sections.append(ConfigSection(kind=kind, name=name, header=header, entries=tuple(entries)))
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (
                  k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if capture.integrity is k.IntegrityState.EMPTY or not capture.raw else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if unsupported or capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if parsed.quality == "partial" or ends != 1 or name is not None
              or invalid or metadata != sorted(set(metadata)) or opening and closing and opening != closing else None)
    if reason is not None:
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    return ConfigDocument(capture=capture, sections=tuple(sections), parse=parsed, reason=reason,
                          detail="bounded_static_config" if reason is None else "config_capture_unusable")
