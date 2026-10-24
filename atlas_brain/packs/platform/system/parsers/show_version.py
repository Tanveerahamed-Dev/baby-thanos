"""Observed field extraction only; no registered train or absolute-time claims."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from atlas_brain.evidence.parsekit.patterns import compile_pattern
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.kernel.states import (
    Basis,
    ByteSpan,
    CaptureId,
    EvidenceRef,
    EvidenceRole,
    IntegrityState,
    Known,
    Unknown,
    UnknownReason,
    WholeCapture,
)


class Unit(StrEnum):
    WEEK = "week"
    DAY = "day"
    HOUR = "hour"
    MINUTE = "minute"
    SECOND = "second"


_UNITS = TokenMap.closed({
    "week": Unit.WEEK, "weeks": Unit.WEEK, "day": Unit.DAY, "days": Unit.DAY,
    "hour": Unit.HOUR, "hours": Unit.HOUR, "minute": Unit.MINUTE,
    "minutes": Unit.MINUTE, "second": Unit.SECOND, "seconds": Unit.SECOND,
})
_ORDER = (Unit.WEEK, Unit.DAY, Unit.HOUR, Unit.MINUTE, Unit.SECOND)
_COMPONENT = compile_pattern(r"(?P<count>[0-9]++) (?P<unit>[A-Za-z]++)")
_RULES = (
    Rule("uptime", "start", r"[A-Za-z0-9_.-]++ uptime is (?P<uptime>.++)", "record", "start", "", ("uptime",)),
    Rule("image", "start", r'System image file is "(?P<image>[^"]++)"', "record", "start", "", ("image",)),
    Rule("reload", "start", r"Last reload reason: (?P<reload_reason>.++)", "record", "start", "", ("reload_reason",)),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class SystemFields:
    uptime: Known[tuple[tuple[int, Unit], ...]] | Unknown
    image: Known[str] | Unknown
    reload_reason: Known[str] | Unknown
    boot_epoch: Unknown
    parse: ParseResult


def _unknown(reason: UnknownReason, detail: str, evidence: tuple[EvidenceRef, ...]) -> Unknown:
    return Unknown(reason=reason, detail=detail, evidence=evidence, candidates=(), next_evidence=())


def _reference(raw: bytes, capture: CaptureId, span: ByteSpan | WholeCapture) -> EvidenceRef:
    excerpt = raw[span.start:span.end] if isinstance(span, ByteSpan) else raw
    return EvidenceRef(capture=capture, locator=span, role=EvidenceRole.SUBJECT,
                       excerpt_sha256=sha256(excerpt).hexdigest())


def _field(parsed: ParseResult, name: str, raw: bytes, capture: CaptureId) -> Known[str] | Unknown:
    fields = tuple(field for record in parsed.records for key, field in record.fields if key == name)
    if not fields:
        return _unknown(UnknownReason.PARSE_UNSUPPORTED_VARIANT, "no_recognized_system_record",
                        (_reference(raw, capture, WholeCapture()),))
    evidence = tuple(_reference(raw, capture, field.span) for field in fields)
    if len(fields) != 1:
        return _unknown(UnknownReason.CONFLICTING_EVIDENCE, "duplicate_system_field", evidence)
    text = fields[0].raw
    if not text.isascii() or not text.strip() or any(ord(char) < 32 or ord(char) == 127 for char in text):
        return _unknown(UnknownReason.PARSE_PARTIAL, "invalid_system_text", evidence)
    return Known(value=text, basis=Basis.OBSERVED, evidence=evidence, raw=text)


def _bind_missing[T](field: Known[T] | Unknown, evidence: tuple[EvidenceRef, ...], partial: bool) -> Known[T] | Unknown:
    if isinstance(field, Unknown) and field.reason is UnknownReason.PARSE_UNSUPPORTED_VARIANT and evidence:
        if partial:
            context = tuple(ref for ref in field.evidence if isinstance(ref, EvidenceRef))
            return _unknown(UnknownReason.PARSE_PARTIAL, "partial_system_record", context)
        return _unknown(UnknownReason.FIELD_NOT_PRINTED, "field_not_printed", evidence)
    return field

def _uptime(field: Known[str] | Unknown, raw: bytes, capture: CaptureId) -> tuple[
    Known[tuple[tuple[int, Unit], ...]] | Unknown, tuple[tuple[str, Captured], ...],
]:
    if isinstance(field, Unknown):
        return field, ()
    reference = field.evidence[0]
    if not isinstance(reference, EvidenceRef) or not isinstance(reference.locator, ByteSpan):
        raise TypeError("uptime_requires_byte_span")
    start, end = reference.locator.start, reference.locator.end
    components: list[tuple[int, Unit]] = []
    tokens: list[tuple[str, Captured]] = []
    previous = -1
    while start < end:
        delimiter = raw.find(b", ", start, end)
        stop = end if delimiter < 0 else delimiter
        match = _COMPONENT.fullmatch(raw[start:stop])
        if match is None:
            return _unknown(UnknownReason.PARSE_PARTIAL, "invalid_uptime", (reference,)), tuple(tokens)
        text = match["unit"].decode("ascii")
        unit_start = start + match.start("unit")
        unit_field = Captured(text, ByteSpan(start=unit_start, end=unit_start + len(text)), text)
        resolved = _UNITS.resolve(unit_field, capture)
        tokens.append(("uptime_unit", resolved))
        if isinstance(resolved.value, Unknown):
            return resolved.value, tuple(tokens)
        if not isinstance(resolved.value, Unit):
            raise TypeError("unit_table_type_mismatch")
        rank = _ORDER.index(resolved.value)
        if len(match["count"]) > 16:
            return _unknown(UnknownReason.PARSE_PARTIAL, "invalid_uptime_integer", (reference,)), tuple(tokens)
        count = int(match["count"])
        if rank <= previous or count > 2**53 - 1:
            return _unknown(UnknownReason.PARSE_PARTIAL, "invalid_uptime_units", (reference,)), tuple(tokens)
        components.append((count, resolved.value))
        previous = rank
        start = stop + 2 if delimiter >= 0 else end
        if delimiter >= 0 and start == end:
            return _unknown(UnknownReason.PARSE_PARTIAL, "invalid_uptime", (reference,)), tuple(tokens)
    return Known(value=tuple(components), basis=Basis.OBSERVED, evidence=(reference,), raw=field.raw), tuple(tokens)


def extract_fields(raw: bytes, capture: CaptureId, *, integrity: IntegrityState) -> SystemFields:
    """Retain literal duration units; collector-clock boot derivation is unavailable."""
    if type(integrity) is not IntegrityState:
        raise TypeError("capture_integrity_required")
    if integrity not in (IntegrityState.COMPLETE, IntegrityState.ERROR, IntegrityState.EMPTY):
        raise ValueError("capture_integrity_not_admitted")
    parsed = run_rules(raw, capture, _RULES, ())
    if integrity is not IntegrityState.COMPLETE or not raw:
        reason = UnknownReason.CAPTURE_ERROR if integrity is IntegrityState.ERROR else UnknownReason.EMPTY_UNREGISTERED
        rejected = _unknown(reason, "capture_not_recognized", (_reference(raw, capture, WholeCapture()),))
        parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens, "partial")
        return SystemFields(uptime=rejected, image=rejected, reload_reason=rejected, boot_epoch=rejected, parse=parsed)
    uptime, tokens = _uptime(_field(parsed, "uptime", raw, capture), raw, capture)
    image = _field(parsed, "image", raw, capture)
    reload_reason = _field(parsed, "reload_reason", raw, capture)
    witnesses = tuple(ref for field in (uptime, image, reload_reason) if isinstance(field, Known)
                      for ref in field.evidence if isinstance(ref, EvidenceRef))
    partial = parsed.quality == "partial" or not witnesses or any(isinstance(field, Unknown) and field.reason in
                  (UnknownReason.PARSE_PARTIAL, UnknownReason.CONFLICTING_EVIDENCE)
                  for field in (uptime, image, reload_reason))
    uptime = _bind_missing(uptime, witnesses, partial)
    image = _bind_missing(image, witnesses, partial)
    reload_reason = _bind_missing(reload_reason, witnesses, partial)
    parsed = ParseResult(parsed.records, parsed.lines, parsed.tokens + tokens,
                         "partial" if partial else parsed.quality)
    return SystemFields(uptime=uptime, image=image, reload_reason=reload_reason,
                        boot_epoch=_unknown(UnknownReason.NOT_COLLECTED, "no_collector_time", ()), parse=parsed)
