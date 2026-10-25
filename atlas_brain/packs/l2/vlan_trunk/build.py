"""Synthetic declared-node trunk observations; allowlisted tables, no estate verdict."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    ParseResult,
    Record,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.evidence.synthetic import Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer

VARIANT_SUPPORT = "allowlisted"
PACK = k.PackId("l2.vlan_trunk")
NATIVE, ALLOWED = k.FactId("l2.vlan_trunk.native"), k.FactId("l2.vlan_trunk.allowed")
OP, COMMAND = "iosxe.show_interfaces_trunk", "show interfaces trunk"
STEP = StepSpec(id=StepId("l2.vlan_trunk/parse"), pack=PACK, kind="parse_build",
                scope="device", reads=(), produces=(ALLOWED, NATIVE),
                evaluator="l2.vlan_trunk.build_node")
FACTS = (FactSpec(id=ALLOWED, pack=PACK, subject="interface", value_type="text", step=STEP.id),
         FactSpec(id=NATIVE, pack=PACK, subject="interface", value_type="integer", step=STEP.id))
_PORT = r"(?P<port>[A-Za-z][A-Za-z-]*+[0-9][A-Za-z0-9./:-]*+)"
_PORT_TOKEN = compile_pattern(r"[A-Za-z][A-Za-z-]*+[0-9][A-Za-z0-9./:-]*+")
_SPACE = r"[ \t]++"


class Status(StrEnum):
    TRUNKING = "trunking"
    NOT_TRUNKING = "not-trunking"
    ROUTED = "routed"


class Mode(StrEnum):
    ON = "on"
    AUTO = "auto"
    DESIRABLE = "desirable"
    OFF = "off"


class Encapsulation(StrEnum):
    DOT1Q = "802.1q"
    ISL = "isl"
    NEGOTIATE = "negotiate"


_MAPS = (("status", TokenMap.closed({s.value: s for s in Status})),
         ("mode", TokenMap.closed({m.value: m for m in Mode})),
         ("encapsulation", TokenMap.closed({e.value: e for e in Encapsulation})))


@dataclass(frozen=True, slots=True, kw_only=True)
class TrunkRow:
    local_port: str
    subject: k.EntityKey
    native: k.Known[int] | k.Unknown
    allowed: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class TrunkResult:
    rows: tuple[TrunkRow, ...]
    parses: tuple[tuple[k.CaptureId, ParseResult], ...]
    quality: Literal["complete", "partial"]


def _rules() -> tuple[Rule, ...]:
    rules: list[Rule] = []
    phases = ("start", "echo", "native", "allowed", "active", "forward", "done")
    for phase in phases:
        rules.append(Rule("blank_" + phase, phase, r"(?P<blank>[ \t]*+)",
                          "record", phase, "", ("blank",)))
    for source, target, title in (
        ("start", "native", "Mode" + _SPACE + "Encapsulation" + _SPACE + "Status" + _SPACE + "Native vlan"),
        ("echo", "native", "Mode" + _SPACE + "Encapsulation" + _SPACE + "Status" + _SPACE + "Native vlan"),
        ("native", "allowed", "Vlans allowed on trunk"),
        ("allowed", "active", "Vlans allowed and active in management domain"),
        ("active", "forward", "Vlans in spanning tree forwarding state and not pruned"),
    ):
        pattern = r"(?P<header>Port" + _SPACE + title + r")[ \t]*+"
        rules.append(Rule("header_" + source + "_" + target, source, pattern,
                          "enter_state", target, "", ("header",)))
    rules.extend((
        Rule("bare_command", "start", COMMAND, "enter_state", "echo", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[#>])[ \t]*+" + COMMAND,
             "enter_state", "echo", "", ("prompt",)),
    ))
    for phase in ("native", "allowed", "active", "forward"):
        rules.append(Rule("prompt_" + phase, phase, r"(?P<prompt>[A-Za-z0-9_.:-]++[#>])[ \t]*+",
                          "enter_state", "done", "", ("prompt",)))
    prefix = (_PORT + _SPACE + r"(?P<mode>[a-z]++)" + _SPACE
              + r"(?P<encapsulation>[a-z0-9.]++)" + _SPACE + r"(?P<status>[a-z-]++)")
    fields = ("port", "mode", "encapsulation", "status")
    rules.extend((
        Rule("native", "native", prefix + _SPACE + r"(?P<native>[0-9]++)[ \t]*+",
             "record", "native", "", fields + ("native",)),
        Rule("native_missing", "native", prefix + r"[ \t]*+",
             "record", "native", "", fields),
    ))
    for phase in ("allowed", "active", "forward"):
        for suffix, value in (("numeric", r"[0-9,-]++"), ("all", "all"), ("none", "none")):
            rules.append(Rule(phase + "_" + suffix, phase,
                              _PORT + _SPACE + "(?P<vlans>" + value + r")[ \t]*+",
                              "record", phase, "", ("port", "vlans")))
    return tuple(rules)


def _vlan(token: str) -> int | None:
    if not token.isascii() or not token.isdigit() or len(token) > 4:
        return None
    value = int(token)
    return value if 1 <= value <= 4094 and str(value) == token else None


def canonical_allowed(token: str) -> str | None:
    """all means VLANs 1..4094; none is an explicit empty set, never a blank default."""
    if token in ("all", "none"):
        return "1-4094" if token == "all" else "none"
    ranges: list[tuple[int, int]] = []
    for item in token.split(","):
        ends = item.split("-")
        if len(ends) not in (1, 2):
            return None
        lo, hi = _vlan(ends[0]), _vlan(ends[-1])
        if lo is None or hi is None or lo > hi:
            return None
        ranges.append((lo, hi))
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return ",".join(str(lo) if lo == hi else str(lo) + "-" + str(hi) for lo, hi in merged)


def _ref(raw: bytes, capture: k.CaptureId, span: k.ByteSpan | k.WholeCapture) -> k.EvidenceRef:
    data = raw[span.start:span.end] if isinstance(span, k.ByteSpan) else raw
    return k.EvidenceRef(capture=capture, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(data).hexdigest())


def build_node(group: SyntheticGroup, node: Node, store: FactStore) -> TrunkResult:
    k.require(node in group.nodes and node.group == group.id, "node_outside_synthetic_group")
    selected = tuple(sorted((c for c in group.captures if c.source == node.key and c.operation == OP),
                            key=lambda c: c.id))
    needs = (k.EvidenceNeed(node=node.key, operation=OP, params=(), resolves=(ALLOWED, NATIVE),
                            reruns=(str(STEP.id),), after_s=None, unprintable=()),)
    declaration = group.declaration.evidence + node.declaration.evidence
    evidence: tuple[k.Evidence, ...] = declaration
    parses: list[tuple[k.CaptureId, ParseResult]] = []
    sections: dict[tuple[str, str], list[Record]] = {}
    reason = k.UnknownReason.NOT_COLLECTED if not selected else None
    for capture in selected:
        evidence += (_ref(capture.raw, capture.id, k.WholeCapture()),)
        parsed = run_rules(capture.raw, capture.id, _rules(), _MAPS)
        invalid, duplicate = False, False
        for record in parsed.records:
            fields = dict(record.fields)
            if "port" not in fields:
                continue
            port = fields["port"].raw
            endpoint(node, port)
            section = record.rule_id.partition("_")[0]
            entries = sections.setdefault((section, port), [])
            duplicate = duplicate or bool(entries)
            entries.append(record)
            if "vlans" in fields and canonical_allowed(fields["vlans"].raw) is None:
                invalid = True
        for line in parsed.lines:
            if line.status == "unrecognised":
                tokens = capture.raw[line.span.start:line.span.end].split()
                if tokens and _PORT_TOKEN.fullmatch(tokens[0]) is not None:
                    endpoint(node, tokens[0].decode("ascii"))
        if invalid or duplicate:
            parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
        parses.append((capture.id, parsed))
        if duplicate or len(selected) > 1:
            reason = k.UnknownReason.CONFLICTING_EVIDENCE
        elif capture.error is not None or capture.integrity is k.IntegrityState.ERROR:
            reason = k.UnknownReason.CAPTURE_ERROR
        elif capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS):
            reason = k.UnknownReason.CAPTURE_TRUNCATED
        elif not capture.raw or capture.integrity is k.IntegrityState.EMPTY:
            reason = k.UnknownReason.EMPTY_UNREGISTERED
        elif capture.integrity is not k.IntegrityState.COMPLETE or capture.rendered != COMMAND:
            reason = k.UnknownReason.PARSE_UNSUPPORTED_VARIANT
        elif capture.codec not in ("utf-8", "ascii") or parsed.quality == "partial":
            reason = k.UnknownReason.PARSE_PARTIAL

    def unknown(why: k.UnknownReason, detail: str) -> k.Unknown:
        return k.Unknown(reason=why, detail=detail, evidence=evidence, candidates=(), next_evidence=needs)

    rows: list[TrunkRow] = []
    for port in sorted(node.ports):
        native: k.Known[int] | k.Unknown
        allowed: k.Known[str] | k.Unknown
        base = sections.get(("native", port), [])
        lists = sections.get(("allowed", port), [])
        if reason is not None:
            native = allowed = unknown(reason, "trunk_capture_unusable")
        elif not base:
            native = allowed = unknown(k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE, "trunk_port_not_printed")
        else:
            fields = dict(base[0].fields)
            capture = selected[0]
            context = (_ref(capture.raw, capture.id, base[0].span),) + declaration
            if (fields["status"].value != Status.TRUNKING
                    or fields["encapsulation"].value != Encapsulation.DOT1Q):
                native = allowed = unknown(k.UnknownReason.NOT_OBSERVABLE, "port_not_printed_dot1q_trunking")
            elif fields["mode"].value == Mode.OFF:
                native = allowed = unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "inconsistent_trunk_state")
            else:
                field = fields.get("native")
                value = _vlan(field.raw) if field is not None else None
                if field is None:
                    native = unknown(k.UnknownReason.FIELD_NOT_PRINTED, "native_vlan_not_printed")
                elif value is None:
                    native = unknown(k.UnknownReason.PARSE_PARTIAL, "native_vlan_invalid")
                else:
                    native = k.Known(value=value, basis=k.Basis.OBSERVED,
                                     evidence=(_ref(capture.raw, capture.id, field.span),) + context, raw=field.raw)
                if not lists:
                    allowed = unknown(k.UnknownReason.FIELD_NOT_PRINTED, "allowed_vlans_not_printed")
                else:
                    field = dict(lists[0].fields)["vlans"]
                    canonical = canonical_allowed(field.raw)
                    allowed = (unknown(k.UnknownReason.PARSE_PARTIAL, "allowed_vlan_list_invalid")
                               if canonical is None else k.Known(value=canonical, basis=k.Basis.OBSERVED,
                               evidence=(_ref(capture.raw, capture.id, field.span),
                                         _ref(capture.raw, capture.id, lists[0].span)) + context, raw=field.raw))
        rows.append(TrunkRow(local_port=port, subject=endpoint(node, port), native=native, allowed=allowed))
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=NATIVE, subject=row.subject, value=row.native)
        writer.write(fact=ALLOWED, subject=row.subject, value=row.allowed)
    quality: Literal["complete", "partial"] = "complete" if rows and all(isinstance(r.native, k.Known) and isinstance(r.allowed, k.Known)
                                      for r in rows) else "partial"
    return TrunkResult(rows=tuple(rows), parses=tuple(parses), quality=quality)
