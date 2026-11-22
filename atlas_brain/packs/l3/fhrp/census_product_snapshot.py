"""Close census product shape for detached comparison of actual parser products."""
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit import rules
from atlas_brain.evidence.text import TextLine
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census


def _need(value: bool, reason: str) -> None:
    k.require(value, "hsrp_census_owner_" + reason)


def _span(span: k.ByteSpan, limit: int) -> tuple[int, int]:
    _need(type(span) is k.ByteSpan and type(span.start) is int and type(span.end) is int
          and 0 <= span.start <= span.end <= limit, "span")
    return span.start, span.end


def _record(value: rules.Record, raw: bytes) -> tuple[object, ...]:
    _need(type(value) is rules.Record and type(value.rule_id) is str and type(value.fields) is tuple, "record")
    line = _span(value.span, len(raw))
    fields: list[object] = []
    for pair in value.fields:
        _need(type(pair) is tuple and len(pair) == 2, "field")
        name, token = pair
        _need(type(name) is str and type(token) is rules.Captured and type(token.raw) is str
              and type(token.value) is str and token.value == token.raw and token.raw.isascii(), "field")
        start, end = _span(token.span, len(raw))
        _need(line[0] <= start <= end <= line[1] and raw[start:end] == token.raw.encode("ascii"), "field")
        fields.append((name, token.raw, start, end))
    return value.rule_id, line, tuple(fields)


def snapshot_product(value: census.Result, parsed: rules.ParseResult, capture: Capture) -> tuple[object, ...]:
    _need(type(capture) is Capture and type(capture.raw) is bytes and type(capture.lines) is tuple, "capture")
    _need(type(value) is census.Result and type(parsed) is rules.ParseResult
          and type(parsed.records) is tuple and type(parsed.lines) is tuple
          and type(parsed.tokens) is tuple and not parsed.tokens and type(parsed.quality) is str, "result")
    raw = capture.raw
    records = tuple(_record(record, raw) for record in parsed.records)
    _need(len(capture.lines) == len(parsed.lines), "accounting")
    lines: list[object] = []
    for original, line in zip(capture.lines, parsed.lines, strict=True):
        _need(type(original) is TextLine, "accounting")
        physical = _span(original.span, len(raw))
        _need(type(line) is rules.LineAccounting and all(type(item) is str
              for item in (line.status, line.rule_id, line.reason)), "accounting")
        point = _span(line.span, len(raw))
        _need(point == physical and line.status in ("consumed", "unrecognised"), "accounting")
        if value.parse is None:
            _need(line.status == "unrecognised" and not line.rule_id and type(value.detail) is str
                  and line.reason == value.detail, "accounting")
        lines.append((point, line.status, line.rule_id, line.reason))
    result = value.census
    if result is None:
        _need(type(value.reason) is k.UnknownReason and type(value.detail) is str and bool(value.detail)
              and parsed.quality == "partial" and (not parsed.records if value.parse is None else value.parse is parsed),
              "result")
        return value.reason, value.detail, parsed.quality, records, tuple(lines)
    _need(type(result) is census.Census and value.reason is None and value.detail is None
          and value.parse is parsed and parsed.quality == "complete" and len(records) == len(lines) >= 2
          and all(line.status == "consumed" for line in parsed.lines)
          and result.scope is parsed.records[0] and result.footer is parsed.records[-1]
          and result.scope.rule_id == "scope" and result.footer.rule_id == "footer" and type(result.groups) is tuple
          and len(result.groups) == len(records) - 2 and type(result.scope_raw) is bytes
          and result.scope_raw == raw[:capture.lines[0].span.end], "result")
    body = _span(result.body_span, len(raw))
    _need(body == (0, parsed.records[-1].span.start), "result")
    numbers: list[int] = []
    for group, record in zip(result.groups, parsed.records[1:-1], strict=True):
        _need(type(group) is census.Group and type(group.number) is int and group.record is record
              and record.rule_id == "group", "result")
        field = dict(record.fields).get("group")
        _need(field is not None and field.raw == str(group.number) and 0 <= group.number <= 4095, "result")
        numbers.append(group.number)
    return parsed.quality, records, tuple(lines), result.scope_raw, body, tuple(numbers)
