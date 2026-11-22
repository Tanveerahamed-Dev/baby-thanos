"""Project-owned synthetic HSRP IPv4 framing; no capture or evidence authority."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.evidence.capture import Capture, CaptureMetadata, ErrorKind
from atlas_brain.evidence.parsekit import rules
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


def parse_capture(capture: Capture, *, node: k.EntityKey, interface: str) -> Result:
    """Read one framed census for the supplied expected scope, yielding only byte claims."""
    refused = _capture_refusal(capture, node, interface)
    if refused is not None:
        return refused
    raw = capture.raw
    parsed = rules.run_rules(raw, capture.id, _RULES, ())
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
