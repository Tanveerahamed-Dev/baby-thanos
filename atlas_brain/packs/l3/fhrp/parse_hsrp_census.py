"""Project-owned synthetic HSRP IPv4 framing; no capture or evidence authority."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.evidence.capture import Capture, CaptureMetadata, ErrorKind
from atlas_brain.evidence.parsekit import rules
from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.kernel import states as k

OP = "synthetic.hsrp_ipv4_interface_census"
COMMAND = "synthetic hsrp ipv4 interface census v1"
_MAX_GROUPS = 4096
_MAX_BYTES = 680_000

_SCOPE_LABELS = (
    r"node=(?P<node>node:[a-z][a-z0-9_-]{0,31}+:[a-z][a-z0-9_-]{0,31}+) "
    r"interface=(?P<interface>[A-Za-z][A-Za-z0-9./:_-]{0,63}+)"
)
_RULES = (
    rules.Rule("scope", "start",
        r"(?P<schema>baby-thanos\.hsrp-census/1) " + _SCOPE_LABELS
        + r" af=(?P<af>ipv4) protocol=(?P<protocol>hsrp) groups=(?P<coverage>all)",
        "enter_state", "body", "", ("schema", "node", "interface", "af", "protocol", "coverage")),
    rules.Rule("group", "body", r"group " + _SCOPE_LABELS + r" id=(?P<group>[0-9]{1,4}+)",
        "record", "body", "", ("node", "interface", "group")),
    rules.Rule("footer", "body", r"(?P<completion>success) rows=(?P<count>[0-9]{1,4}+) sha256=(?P<digest>[0-9a-f]{64}+)",
        "record", "body", "", ("completion", "count", "digest")),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class Group:
    number: int
    record: rules.Record


@dataclass(frozen=True, slots=True, kw_only=True)
class Census:
    scope: rules.Record
    scope_raw: bytes
    groups: tuple[Group, ...]
    footer: rules.Record
    body_span: k.ByteSpan


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    census: Census | None
    parse: rules.ParseResult | None
    reason: k.UnknownReason | None
    detail: str | None


def _unresolved(reason: k.UnknownReason, detail: str, parsed: rules.ParseResult | None = None) -> Result:
    if parsed is not None:
        parsed = rules.ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
    return Result(census=None, parse=parsed, reason=reason, detail=detail)


def _capture_refusal(capture: Capture, node: k.EntityKey, interface: str) -> Result | None:
    k.require(type(capture) is Capture and type(capture.raw) is bytes
              and type(capture.id) is str and bool(capture.id)
              and type(capture.operation) is str and capture.operation == OP
              and type(capture.rendered) is str and capture.rendered == COMMAND
              and type(capture.source) is str and type(node) is str and type(interface) is str
              and type(capture.codec) is str and type(capture.integrity) is k.IntegrityState,
              "hsrp_census_source")
    metadata = capture.metadata
    error = None
    if metadata is not None:
        k.require(type(metadata) is CaptureMetadata, "hsrp_census_source")
        error = metadata.error
        k.require(error is None or type(error) is ErrorKind, "hsrp_census_source")
    if (error is not None and error is not ErrorKind.INCOMPLETE) or capture.integrity is k.IntegrityState.ERROR:
        return _unresolved(k.UnknownReason.CAPTURE_ERROR, "capture_error")
    if capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS) or error is ErrorKind.INCOMPLETE:
        return _unresolved(k.UnknownReason.CAPTURE_TRUNCATED, "capture_incomplete")
    if not capture.raw or capture.integrity is k.IntegrityState.EMPTY:
        return _unresolved(k.UnknownReason.EMPTY_UNREGISTERED, "empty_capture")
    if capture.integrity not in (k.IntegrityState.COMPLETE, k.IntegrityState.UNKNOWN_FORMAT):
        return _unresolved(k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_integrity")
    if capture.source != node:
        return _unresolved(k.UnknownReason.OUT_OF_SCOPE, "capture_source")
    if len(capture.raw) > _MAX_BYTES or capture.raw.count(b"\n") > _MAX_GROUPS + 2:
        return _unresolved(k.UnknownReason.BUDGET_EXCEEDED, "wire_bounds")
    if capture.codec not in ("ascii", "utf-8") or not capture.raw.isascii():
        return _unresolved(k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_encoding")
    return None


def _is_scope(fields: dict[str, rules.Captured], node: k.EntityKey, interface: str) -> bool:
    return fields["node"].raw == node and fields["interface"].raw == interface


def _interpret(raw: bytes, parsed: rules.ParseResult, node: k.EntityKey, interface: str) -> Result:
    if not raw.endswith(b"\n"):
        return _unresolved(k.UnknownReason.CAPTURE_TRUNCATED, "missing_final_lf", parsed)
    if b"\r" in raw:
        return _unresolved(k.UnknownReason.PARSE_PARTIAL, "noncanonical_line_end", parsed)
    records = parsed.records
    if (parsed.quality != "complete" or len(records) < 2 or records[0].rule_id != "scope"
            or records[-1].rule_id != "footer" or any(row.rule_id != "group" for row in records[1:-1])):
        return _unresolved(k.UnknownReason.PARSE_PARTIAL, "wire_shape", parsed)
    scope, footer = records[0], records[-1]
    if not _is_scope(dict(scope.fields), node, interface):
        return _unresolved(k.UnknownReason.OUT_OF_SCOPE, "header_scope", parsed)
    claimed = dict(footer.fields)
    if claimed["count"].raw != str(len(records) - 2):
        return _unresolved(k.UnknownReason.PARSE_PARTIAL, "footer_count", parsed)
    if claimed["digest"].raw != sha256(raw[:footer.span.start]).hexdigest():
        return _unresolved(k.UnknownReason.PARSE_PARTIAL, "footer_hash", parsed)

    groups: list[Group] = []
    seen: set[int] = set()
    for record in records[1:-1]:
        fields = dict(record.fields)
        if not _is_scope(fields, node, interface):
            return _unresolved(k.UnknownReason.OUT_OF_SCOPE, "row_scope", parsed)
        label = fields["group"].raw
        number = int(label)
        if label != str(number) or number >= _MAX_GROUPS:
            return _unresolved(k.UnknownReason.PARSE_PARTIAL, "group_number", parsed)
        if number in seen:
            return _unresolved(k.UnknownReason.CONFLICTING_EVIDENCE, "duplicate_group", parsed)
        seen.add(number)
        groups.append(Group(number=number, record=record))
    census = Census(scope=scope, scope_raw=raw[:parsed.lines[0].span.end], groups=tuple(groups),
                    footer=footer, body_span=k.ByteSpan(start=0, end=footer.span.start))
    return Result(census=census, parse=parsed, reason=None, detail=None)


def parse_capture(capture: Capture, *, node: k.EntityKey, interface: str) -> Result:
    """Read one framed census for the supplied expected scope, yielding only byte claims."""
    refused = _capture_refusal(capture, node, interface)
    if refused is not None:
        return refused
    raw = capture.raw
    parsed = rules.run_rules(raw, capture.id, _RULES, ())
    return _interpret(raw, parsed, node, interface)


def _product(condition: bool, reason: str) -> None:
    k.require(condition, "hsrp_census_product_" + reason)


def _same_span(span: k.ByteSpan, start: int, end: int) -> bool:
    return (type(span) is k.ByteSpan and type(span.start) is int and type(span.end) is int
            and span.start == start and span.end == end)


def _check_record(record: rules.Record, label: str, start: int, end: int,
                  fields: tuple[tuple[str, str, int, int], ...]) -> None:
    _product(type(record) is rules.Record and type(record.rule_id) is str and record.rule_id == label
             and _same_span(record.span, start, end)
             and type(record.fields) is tuple and len(record.fields) == len(fields), "record")
    for pair, (name, raw, left, right) in zip(record.fields, fields, strict=True):
        _product(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str and pair[0] == name, "token")
        token = pair[1]
        _product(type(token) is rules.Captured and type(token.raw) is str and token.raw == raw
                 and type(token.value) is str and token.value == raw and _same_span(token.span, left, right), "token")


def _check_lexical(raw: bytes, parsed: rules.ParseResult) -> rules.ParseResult:
    """Check every supplied claim against the existing rule table without running the parser."""
    _product(type(parsed) is rules.ParseResult and type(parsed.records) is tuple
             and all(type(record) is rules.Record for record in parsed.records)
             and type(parsed.lines) is tuple and type(parsed.tokens) is tuple and not parsed.tokens
             and type(parsed.quality) is str, "parse")
    compiled = tuple((rule, compile_pattern(rule.pattern)) for rule in _RULES)
    state, offset, index, complete = "start", 0, 0, True
    for line in parsed.lines:
        _product(offset < len(raw), "accounting")
        lf = raw.find(b"\n", offset)
        end = len(raw) if lf < 0 else lf + 1
        content_end = end if lf < 0 else lf
        if lf > offset and raw[lf - 1:lf] == b"\r":
            content_end -= 1
        content = raw[offset:content_end]
        _product(type(line) is rules.LineAccounting and _same_span(line.span, offset, end)
                 and all(type(value) is str for value in (line.status, line.rule_id, line.reason)), "accounting")
        for rule, pattern in compiled:
            if rule.state != state:
                continue
            match = pattern.fullmatch(content)
            if match is None:
                continue
            _product(line.status == "consumed" and line.rule_id == rule.rule_id and line.reason == rule.reason
                     and index < len(parsed.records), "accounting")
            fields: list[tuple[str, str, int, int]] = []
            for name in rule.fields:
                left, right = match.span(name)
                _product(0 <= left <= right <= content_end - offset, "token")
                piece = raw[offset + left:offset + right].decode("ascii")
                fields.append((name, piece, offset + left, offset + right))
            _check_record(parsed.records[index], rule.rule_id, offset, content_end, tuple(fields))
            state = rule.target
            index += 1
            break
        else:
            _product(line.status == "unrecognised" and not line.rule_id and not line.reason, "accounting")
            complete = False
        offset = end
    _product(offset == len(raw) and index == len(parsed.records), "accounting")
    return rules.ParseResult(parsed.records, parsed.lines, (), "complete" if complete else "partial")


def validate_product(capture: Capture, *, node: k.EntityKey, interface: str, value: Result) -> None:
    """Check the reported parser product against the original bytes and scope."""
    _product(type(value) is Result, "result")
    refused = _capture_refusal(capture, node, interface)
    if refused is not None:
        _product(value.census is None and value.parse is None and value.reason is refused.reason
                 and type(value.detail) is str and value.detail == refused.detail, "refusal")
        return
    parsed = value.parse
    if type(parsed) is not rules.ParseResult:
        raise ValueError("hsrp_census_product_parse")
    semantic = _interpret(capture.raw, _check_lexical(capture.raw, parsed), node, interface)
    expected_parse, expected = semantic.parse, semantic.census
    _product(expected_parse is not None and parsed.quality == expected_parse.quality
             and value.reason is semantic.reason and (value.detail is None or type(value.detail) is str)
             and value.detail == semantic.detail, "result")
    actual = value.census
    if expected is None:
        _product(actual is None, "result")
        return
    if type(actual) is not Census:
        raise ValueError("hsrp_census_product_result")
    _product(actual.scope is expected.scope and actual.footer is expected.footer
             and type(actual.scope_raw) is bytes and actual.scope_raw == expected.scope_raw
             and _same_span(actual.body_span, expected.body_span.start, expected.body_span.end)
             and type(actual.groups) is tuple and len(actual.groups) == len(expected.groups), "result")
    for group, wanted in zip(actual.groups, expected.groups, strict=True):
        _product(type(group) is Group and type(group.number) is int and group.number == wanted.number
                 and group.record is wanted.record, "group")
