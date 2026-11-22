"""Callback-free comparison of original census request coordinates and cached lines."""
from dataclasses import dataclass

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import TextLine
from atlas_brain.kernel import states as k
from atlas_brain.runner.pack_receipts import CaptureRequest

type _RequestCoordinates = tuple[k.CaptureId, k.EntityKey, str, str, str, bytes]
type _LineData = tuple[TextLine, k.ByteSpan, int, int, str, tuple[int, ...], bool]


@dataclass(frozen=True, slots=True)
class RequestAnchor:
    """Original coordinates and cached lines for one already admitted request."""

    capture: Capture
    identity: k.CaptureId
    node: k.EntityKey
    operation: str
    context: str
    command: str
    raw: bytes
    lines: tuple[TextLine, ...]
    line_data: tuple[_LineData, ...]


def _need(condition: bool, code: str) -> None:
    k.require(condition, "hsrp_census_" + code)


def request_coordinates(request: CaptureRequest) -> _RequestCoordinates:
    if type(request) is not CaptureRequest or type(request.capture) is not Capture:
        raise ValueError("hsrp_census_request")
    capture = request.capture
    operation, context_id = capture.operation, request.context
    if type(operation) is not str or type(context_id) is not str:
        raise ValueError("hsrp_census_request")
    _need(all(type(value) is str for value in (
        capture.id, capture.source, capture.rendered, capture.codec
    )) and type(capture.raw) is bytes, "request")
    expected_integrity = k.IntegrityState.UNKNOWN_FORMAT if capture.raw else k.IntegrityState.EMPTY
    _need(capture.codec == "utf-8" and capture.integrity is expected_integrity
          and capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
          and capture.metadata is None, "request")
    return capture.id, capture.source, operation, context_id, capture.rendered, capture.raw


def _line_values(lines: tuple[TextLine, ...], limit: int) -> tuple[_LineData, ...]:
    _need(type(lines) is tuple, "request")
    values: list[_LineData] = []
    for line in lines:
        _need(type(line) is TextLine and type(line.span) is k.ByteSpan and type(line.text) is str
              and type(line.offsets) is tuple and all(type(offset) is int for offset in line.offsets)
              and type(line.decoding_errors) is bool, "request")
        span = line.span
        _need(type(span.start) is int and type(span.end) is int and 0 <= span.start <= span.end <= limit, "request")
        values.append((line, span, span.start, span.end, line.text, line.offsets, line.decoding_errors))
    return tuple(values)


def retain_live_request(request: CaptureRequest) -> RequestAnchor:
    """Freeze already owned input coordinates without calling preparation or parsing."""
    identity, node, operation, context_id, command, raw = request_coordinates(request)
    capture = request.capture
    lines = capture.lines
    return RequestAnchor(capture, identity, node, operation, context_id, command, raw, lines,
                         _line_values(lines, len(raw)))


def validate_live_request(request: CaptureRequest, original: RequestAnchor) -> None:
    """Check the live carrier against its retained request anchor without callbacks."""
    _need(type(original) is RequestAnchor, "request")
    values = request_coordinates(request)
    _need(request.capture is original.capture and values[:5] == (
        original.identity, original.node, original.operation, original.context, original.command
    ) and values[5] is original.raw and request.capture.lines is original.lines, "request")
    latest = _line_values(request.capture.lines, len(original.raw))
    _need(len(latest) == len(original.line_data) and all(
        a[0] is b[0] and a[1] is b[1] and a[2:] == b[2:] for a, b in zip(latest, original.line_data, strict=True)
    ), "request")
