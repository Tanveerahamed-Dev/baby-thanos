"""Synthetic field-extraction cases; these do not establish a platform floor."""
from hashlib import sha256

import pytest

from atlas_brain.kernel.states import (
    ByteSpan,
    CaptureId,
    EvidenceRef,
    IntegrityState,
    Known,
    Unknown,
    UnknownReason,
)
from atlas_brain.packs.platform.system.parsers.show_version import Unit, extract_fields

CAPTURE = CaptureId("synthetic-cap-a")
RAW = (b'sw-a uptime is 1 day, 2 hours, 3 minutes\r\n'
       b'System image file is "bootflash:packages.conf"\r\n'
       b'Last reload reason: PowerOn\r\n')


def test_missing_fields_and_boot_epoch_never_become_defaults():
    result = extract_fields(b"", CAPTURE, integrity=IntegrityState.COMPLETE)
    for fact in (result.uptime, result.image, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.EMPTY_UNREGISTERED
    assert isinstance(result.boot_epoch, Unknown)
    assert result.boot_epoch.reason is UnknownReason.EMPTY_UNREGISTERED
    assert result.parse.quality == "partial"


def test_positive_observed_fields_round_trip_to_original_bytes():
    result = extract_fields(RAW, CAPTURE, integrity=IntegrityState.COMPLETE)
    assert result.parse.quality == "complete"
    assert isinstance(result.uptime, Known)
    assert result.uptime.value == ((1, Unit.DAY), (2, Unit.HOUR), (3, Unit.MINUTE))
    assert isinstance(result.image, Known)
    assert result.image.value == "bootflash:packages.conf"
    assert isinstance(result.reload_reason, Known)
    assert result.reload_reason.value == "PowerOn"
    for fact in (result.uptime, result.image, result.reload_reason):
        for evidence in fact.evidence:
            assert isinstance(evidence, EvidenceRef)
            excerpt = RAW[evidence.locator.start:evidence.locator.end]
            assert sha256(excerpt).hexdigest() == evidence.excerpt_sha256
    assert isinstance(result.boot_epoch, Unknown)
    assert not hasattr(result, "family")
    assert not hasattr(result, "train")
    assert not hasattr(result, "mode")


def test_unmapped_unit_keeps_raw_and_is_partial():
    result = extract_fields(b"sw-a uptime is 2 fortnights\n", CAPTURE, integrity=IntegrityState.COMPLETE)
    assert isinstance(result.uptime, Unknown)
    assert result.uptime.reason is UnknownReason.PARSE_PARTIAL
    assert result.parse.quality == "partial"
    assert result.parse.tokens[0][1].raw == "fortnights"


def test_duplicate_and_reversed_units_are_refused():
    for value in (b"1 day, 2 days", b"1 minute, 2 hours", b"one day", b"9007199254740992 seconds", b"9" * 5000 + b" seconds"):
        result = extract_fields(b"sw-a uptime is " + value + b"\n", CAPTURE, integrity=IntegrityState.COMPLETE)
        assert isinstance(result.uptime, Unknown)
        assert result.parse.quality == "partial"


def test_duplicate_fields_are_conflicting_even_if_values_match():
    result = extract_fields(RAW + RAW, CAPTURE, integrity=IntegrityState.COMPLETE)
    for fact in (result.uptime, result.image, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.CONFLICTING_EVIDENCE
        assert len(fact.evidence) == 2


def test_unrecognised_line_stays_visible_and_lf_offsets_are_stable():
    for raw in (RAW + b"new firmware line\n", RAW.replace(b"\r\n", b"\n") + b"new firmware line"):
        result = extract_fields(raw, CAPTURE, integrity=IntegrityState.COMPLETE)
        assert result.parse.quality == "partial"
        assert result.parse.lines[-1].status == "unrecognised"
        span = result.parse.lines[-1].span
        assert raw[span.start:span.end].startswith(b"new firmware line")
        assert isinstance(result.image, Known)


def test_invalid_text_is_not_promoted_to_a_known_image():
    result = extract_fields(b'System image file is "\xff"\n', CAPTURE, integrity=IntegrityState.COMPLETE)
    assert isinstance(result.image, Unknown)
    assert result.image.reason is UnknownReason.PARSE_PARTIAL


def test_wholly_unrecognised_response_is_not_a_recognised_record():
    result = extract_fields(b"unrecognised firmware response\n", CAPTURE, integrity=IntegrityState.COMPLETE)
    assert result.parse.quality == "partial"
    for fact in (result.uptime, result.image, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.PARSE_UNSUPPORTED_VARIANT


def test_failed_capture_cannot_promote_even_matching_fields():
    for raw in (b"", b"% Invalid input\n", RAW):
        result = extract_fields(raw, CAPTURE, integrity=IntegrityState.ERROR)
        assert result.parse.quality == "partial"
        for fact in (result.uptime, result.image, result.reload_reason, result.boot_epoch):
            assert isinstance(fact, Unknown)
            assert fact.reason is UnknownReason.CAPTURE_ERROR


def test_missing_field_is_bound_to_positive_record_bytes():
    raw = b'System image file is "bootflash:packages.conf"\n'
    result = extract_fields(raw, CAPTURE, integrity=IntegrityState.COMPLETE)
    assert isinstance(result.image, Known)
    for fact in (result.uptime, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.FIELD_NOT_PRINTED
        assert fact.evidence == result.image.evidence
        assert isinstance(fact.evidence[0].locator, ByteSpan)


def test_malformed_only_record_cannot_witness_an_omitted_field():
    result = extract_fields(b"sw-a uptime is not a duration\n", CAPTURE, integrity=IntegrityState.COMPLETE)
    assert result.parse.quality == "partial"
    for fact in (result.image, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.PARSE_UNSUPPORTED_VARIANT

def test_non_admitted_integrity_is_refused_without_fact_promotion():
    for state in (IntegrityState.TRUNCATED, IntegrityState.PAGING_ARTIFACTS,
                  IntegrityState.UNVERIFIED_PROMPT, IntegrityState.UNKNOWN_FORMAT, IntegrityState.ABSENCE_BANNER):
        with pytest.raises(ValueError, match="capture_integrity_not_admitted"):
            extract_fields(RAW, CAPTURE, integrity=state)
    with pytest.raises(TypeError, match="capture_integrity_required"):
        extract_fields(RAW, CAPTURE, integrity="complete")

def test_partial_record_cannot_claim_a_field_was_not_printed():
    raw = b'System image file is "bootflash:packages.conf"\nnew uptime format\n'
    result = extract_fields(raw, CAPTURE, integrity=IntegrityState.COMPLETE)
    assert isinstance(result.image, Known)
    assert result.parse.quality == "partial"
    for fact in (result.uptime, result.reload_reason):
        assert isinstance(fact, Unknown)
        assert fact.reason is UnknownReason.PARSE_PARTIAL


def test_malformed_field_prevents_omission_claims_for_other_fields():
    raw = b'System image file is "bootflash:packages.conf"\nsw-a uptime is not a duration\n'
    result = extract_fields(raw, CAPTURE, integrity=IntegrityState.COMPLETE)
    assert isinstance(result.image, Known)
    assert isinstance(result.reload_reason, Unknown)
    assert result.reload_reason.reason is UnknownReason.PARSE_PARTIAL
    assert result.parse.quality == "partial"
