"""Synthetic allowlisted IPv4 VRRP detail observations; no version or qualification claim."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.capture import Capture, CaptureMetadata, ErrorKind
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    LineAccounting,
    ParseResult,
    Record,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.evidence.text import text_lines
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


def _claim_need(condition: bool, code: str) -> None:
    k.require(condition, "vrrp_claims_" + code)


def _claim_span(point: k.ByteSpan, limit: int) -> bool:
    return (type(point) is k.ByteSpan and type(point.start) is int and type(point.end) is int
            and 0 <= point.start <= point.end <= limit)


def _state_claim(capture: Capture, token: Captured) -> bool:
    expected = {"Init": VRRPState.INIT, "INIT": VRRPState.INIT, "Master": VRRPState.MASTER,
                "MASTER": VRRPState.MASTER, "Backup": VRRPState.BACKUP, "BACKUP": VRRPState.BACKUP}.get(token.raw)
    if expected is not None:
        _claim_need(type(token.value) is VRRPState and token.value is expected, "state")
        return False
    value = token.value
    if type(value) is not k.Unknown:
        raise ValueError("vrrp_claims_state")
    _claim_need(value.reason is k.UnknownReason.PARSE_PARTIAL and type(value.detail) is str and value.detail == "unmapped_token"
                and type(value.candidates) is tuple and not value.candidates
                and type(value.next_evidence) is tuple and not value.next_evidence
                and type(value.evidence) is tuple and len(value.evidence) == 1, "state")
    ref = value.evidence[0]
    _claim_need(type(ref) is k.EvidenceRef and type(ref.capture) is str and ref.capture == capture.id
                and ref.locator is token.span and ref.role is k.EvidenceRole.SUBJECT
                and type(ref.excerpt_sha256) is str
                and ref.excerpt_sha256 == sha256(capture.raw[token.span.start:token.span.end]).hexdigest(), "state")
    return True


def validate_claims(capture: Capture, result: Result) -> tuple[tuple[Row, tuple[k.ByteSpan, ...]], ...]:
    """Authenticate current byte claims; no admission, execution origin or positive fact grant."""
    _claim_need(type(capture) is Capture and type(capture.raw) is bytes and all(type(value) is str and bool(value) for value in
                (capture.id, capture.source, capture.operation, capture.rendered, capture.codec))
                and capture.operation == OP and capture.rendered == COMMAND and capture.codec in ("utf-8", "ascii")
                and type(capture.integrity) is k.IntegrityState and type(result) is Result, "input")
    metadata = capture.metadata
    _claim_need(metadata is None or type(metadata) is CaptureMetadata
                and (metadata.error is None or type(metadata.error) is ErrorKind), "input")
    parsed, raw = result.parse, capture.raw
    _claim_need(type(parsed) is ParseResult and type(parsed.records) is tuple and type(parsed.lines) is tuple
                and type(parsed.tokens) is tuple and type(parsed.quality) is str and parsed.quality in ("complete", "partial")
                and type(result.rows) is tuple and all(type(row) is Row for row in result.rows), "shape")
    physical = text_lines(raw, capture.codec)
    _claim_need(type(capture.lines) is tuple and len(capture.lines) == len(physical) == len(parsed.lines), "accounting")
    for held, actual in zip(capture.lines, physical, strict=True):
        _claim_need(type(held) is type(actual) and type(held.text) is str and type(held.decoding_errors) is bool
                    and _claim_span(held.span, len(raw)) and type(held.offsets) is tuple
                    and all(type(offset) is int for offset in held.offsets) and held == actual, "accounting")
    records: dict[int, Record] = {}
    for item in parsed.records:
        _claim_need(type(item) is Record and _claim_span(item.span, len(raw)) and type(item.rule_id) is str
                    and type(item.fields) is tuple and all(type(pair) is tuple and len(pair) == 2
                        and type(pair[0]) is str and type(pair[1]) is Captured for pair in item.fields), "record")
        _claim_need(item.span.start not in records, "record")
        records[item.span.start] = item
    _claim_need(all(a.span.end < b.span.start for a, b in zip(parsed.records, parsed.records[1:])), "order")
    rules = tuple((rule, compile_pattern(rule.pattern)) for rule in _rules())
    phase, partial = "start", False
    recognized: set[int] = set()
    tokens: list[Captured] = []
    for line, actual in zip(parsed.lines, physical, strict=True):
        _claim_need(type(line) is LineAccounting and _claim_span(line.span, len(raw)) and line.span == actual.span
                    and all(type(value) is str for value in (line.status, line.rule_id, line.reason)), "accounting")
        content = raw[actual.span.start:actual.span.end]
        content = content[:-2] if content.endswith(b"\r\n") else content[:-1] if content.endswith(b"\n") else content
        selected = next(((rule, match) for rule, pattern in rules
                         if rule.state == phase and (match := pattern.fullmatch(content)) is not None), None)
        item = records.get(actual.span.start)
        if selected is None:
            _claim_need(line.status == "unrecognised" and not line.rule_id and not line.reason and item is None, "accounting")
            partial = True
            continue
        rule, match = selected
        _claim_need(line.status == "consumed" and line.rule_id == rule.rule_id and line.reason == rule.reason, "phase")
        phase = rule.target
        if not rule.fields and rule.kind != "record":
            _claim_need(item is None, "record")
            continue
        if item is None:
            raise ValueError("vrrp_claims_record")
        recognized.add(item.span.start)
        _claim_need(item.rule_id == rule.rule_id and item.span == k.ByteSpan(start=actual.span.start, end=actual.span.start + len(content))
                    and tuple(name for name, _ in item.fields) == rule.fields, "record")
        for name, token in item.fields:
            start, end = match.span(name)
            _claim_need(type(token.raw) is str and token.raw.isascii() and _claim_span(token.span, len(raw))
                        and token.span == k.ByteSpan(start=actual.span.start + start, end=actual.span.start + end)
                        and raw[token.span.start:token.span.end] == token.raw.encode("ascii"), "column")
            if name == "state":
                partial = _state_claim(capture, token) or partial
                tokens.append(token)
            else:
                _claim_need(type(token.value) is str and token.value == token.raw, "column")
    _claim_need(recognized == set(records) and len(parsed.tokens) == len(tokens)
                and all(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str and pair[0] == "state"
                    and pair[1] is token for pair, token in zip(parsed.tokens, tokens, strict=True)), "tokens")
    blocks: list[tuple[Record, list[Record]]] = []
    for item in parsed.records:
        if item.rule_id.startswith("heading_"):
            blocks.append((item, []))
        elif item.rule_id in _CATEGORIES and blocks:
            blocks[-1][1].append(item)
    invalid = not blocks or partial
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
            fields_body = dict(item.fields)
            if item.rule_id in ("virtual_ip", "master"):
                value = fields_body[item.rule_id].raw
                unresolved = unresolved or item.rule_id == "virtual_ip" and value == "unknown"
                invalid = invalid or (value != "unknown" or item.rule_id == "master") and not ipv4_literal(value)
            elif item.rule_id == "preemption":
                invalid = invalid or fields_body["preemption"].raw not in ("enabled", "disabled")
        key = (fields["interface"].raw, fields["group"].raw)
        conflict = conflict or key in seen
        seen.add(key)
    reason = (k.UnknownReason.CAPTURE_ERROR if capture.error is not None or capture.integrity is k.IntegrityState.ERROR else
              k.UnknownReason.CAPTURE_TRUNCATED if capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) else
              k.UnknownReason.EMPTY_UNREGISTERED if not raw.strip() or capture.integrity is k.IntegrityState.EMPTY else
              k.UnknownReason.PARSE_UNSUPPORTED_VARIANT if capture.integrity is not k.IntegrityState.COMPLETE else
              k.UnknownReason.PARSE_PARTIAL if invalid else k.UnknownReason.CONFLICTING_EVIDENCE if conflict else
              k.UnknownReason.IDENTITY_UNRESOLVED if unresolved else None)
    _claim_need(result.reason is reason and parsed.quality == ("complete" if reason is None else "partial")
                and len(result.rows) == len(blocks), "reason")
    proofs: list[tuple[Row, tuple[k.ByteSpan, ...]]] = []
    for row, (header, body) in zip(result.rows, blocks, strict=True):
        fields = dict(header.fields)
        state = next((dict(item.fields)["state"] for item in body if item.rule_id == "state"), None)
        vip = next((dict(item.fields)["virtual_ip"] for item in body if item.rule_id == "virtual_ip"), None)
        family = "ipv4" if not header.rule_id.startswith("heading_af_") and vip is not None and ipv4_literal(vip.raw) else None
        local = reason or (k.UnknownReason.IDENTITY_UNRESOLVED if family is None else None)
        _claim_need(row.header is header and row.interface is fields["interface"] and row.group is fields["group"]
                    and row.state is state and row.virtual_ip is vip and type(row.body) is tuple and len(row.body) == len(body)
                    and all(a is b for a, b in zip(row.body, body, strict=True)) and _claim_span(row.span, len(raw))
                    and row.span == k.ByteSpan(start=header.span.start, end=body[-1].span.end if body else header.span.end)
                    and row.reason is local and (row.address_family is None if family is None else
                        type(row.address_family) is str and row.address_family == family), "row")
        points = {header.span, row.interface.span, row.group.span}
        for item in body:
            if item.rule_id in ("state", "virtual_ip", "master_down"):
                points.add(item.span)
                if item.rule_id != "master_down":
                    points.update(token.span for _, token in item.fields)
        proofs.append((row, tuple(sorted(points, key=lambda point: (point.start, point.end)))))
    return tuple(proofs)
