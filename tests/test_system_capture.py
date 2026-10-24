"""Synthetic capture-binding witnesses; no device/train or clock qualification."""
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import (
    Capture,
    CaptureMetadata,
    Channel,
    ErrorKind,
    Scope,
    unrecorded_time,
)
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.packs.platform.system.build import build_capture

RAW = (b'sw-a uptime is 1 day, 2 hours, 3 minutes\n'
       b'System image file is "bootflash:packages.conf"\n'
       b'Last reload reason: PowerOn\n')


def record(raw=RAW, operation="iosxe.show_version", rendered="show version",
           integrity=k.IntegrityState.COMPLETE, time=None, error=None, codec="utf-8"):
    capture_id = k.CaptureId("synthetic-cap-a")
    source = k.EntityKey("node:sw-a")
    witness = k.EvidenceRef(capture=capture_id, locator=k.WholeCapture(), role=k.EvidenceRole.SUBJECT,
                            excerpt_sha256=sha256(raw).hexdigest())
    metadata = CaptureMetadata(channel=Channel.CLI, scope=Scope(node=source, vrf=None, context=None, vdc=None,
                   tenant=None, afi=None, instance=None, plane="exec"),
                   collected_utc=unrecorded_time(witness) if time is None else time,
                   error=error, integrity_evidence=(witness,), read_scope_evidence=(), envelope=None)
    return Capture(id=capture_id, source=source, operation=operation, rendered=rendered,
                   codec=codec, integrity=integrity, read_scope=k.ReadScope.UNKNOWN,
                   view=k.ViewConsistency.SINGLE_RESPONSE, raw=raw, lines=text_lines(raw, codec), metadata=metadata)


@pytest.mark.parametrize("codec", ["utf-8", "ascii"])
def test_capture_binding_preserves_observed_fields_and_time_unknown(codec):
    item = record(codec=codec)
    result = build_capture(item)
    assert isinstance(result.image, k.Known)
    assert result.image.value == "bootflash:packages.conf"
    assert result.boot_epoch is item.collected_utc
    for fact in (result.uptime, result.image, result.reload_reason):
        assert isinstance(fact, k.Known)
        assert all(ref.capture == item.id for ref in fact.evidence)
    assert result.parse.quality == "complete"


def test_legacy_capture_keeps_evidenced_missing_time_instead_of_a_boot_guess():
    item = Capture(k.CaptureId("synthetic-legacy"), k.EntityKey("node:sw-a"),
                   "iosxe.show_version", "show version", "utf-8", RAW, k.IntegrityState.COMPLETE,
                   text_lines(RAW, "utf-8"), k.ReadScope.UNKNOWN, k.ViewConsistency.SINGLE_RESPONSE)
    assert item.metadata is None
    result = build_capture(item)
    assert isinstance(result.uptime, k.Known)
    assert isinstance(result.boot_epoch, k.Unknown)
    assert result.boot_epoch.reason is k.UnknownReason.AS_OF_MISSING
    assert result.boot_epoch.evidence == item.integrity_evidence
    witness, = result.boot_epoch.evidence
    assert isinstance(witness, k.EvidenceRef) and witness.capture == item.id
    assert witness.excerpt_sha256 == sha256(RAW).hexdigest()


@pytest.mark.parametrize("operation,rendered", [
    (None, "show version"), ("nxos.show_version", "show version"),
    ("iosxe.show_interfaces", "show version"), ("iosxe.show_version", "show clock"),
    ("iosxe.show_version", "sh ver"),
])
def test_wrong_or_unbound_operation_never_promotes_matching_text(operation, rendered):
    with pytest.raises(ValueError, match="unsupported_system_operation"):
        build_capture(record(operation=operation, rendered=rendered))


def test_foreign_capture_type_and_unimplemented_codec_are_refused():
    with pytest.raises(TypeError, match="capture_record_required"):
        build_capture(None)
    with pytest.raises(ValueError, match="unsupported_system_codec"):
        build_capture(record(codec="latin-1"))


@pytest.mark.parametrize("integrity", [k.IntegrityState.COMPLETE, k.IntegrityState.EMPTY])
@pytest.mark.parametrize("error", list(ErrorKind))
def test_error_metadata_requires_error_integrity(integrity, error):
    raw = b"" if integrity is k.IntegrityState.EMPTY else RAW
    with pytest.raises(ValueError, match="capture_error_integrity_mismatch"):
        build_capture(record(raw=raw, integrity=integrity, error=error))


@pytest.mark.parametrize("raw", [RAW, b""])
@pytest.mark.parametrize("error", list(ErrorKind))
def test_explicit_capture_errors_never_become_empty_or_observed(raw, error):
    result = build_capture(record(raw=raw, integrity=k.IntegrityState.ERROR, error=error))
    for field in (result.uptime, result.image, result.reload_reason, result.boot_epoch):
        assert isinstance(field, k.Unknown)
        assert field.reason is k.UnknownReason.CAPTURE_ERROR
        assert field.evidence
    assert result.parse.quality == "partial"


@pytest.mark.parametrize("integrity,reason,raw", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR, RAW),
    (k.IntegrityState.COMPLETE, k.UnknownReason.EMPTY_UNREGISTERED, b""),
])
def test_capture_failure_or_empty_precedes_missing_time(integrity, reason, raw):
    result = build_capture(record(raw=raw, integrity=integrity))
    assert isinstance(result.boot_epoch, k.Unknown)
    assert result.boot_epoch.reason is reason
    assert result.parse.quality == "partial"


@pytest.mark.parametrize("earliest,latest,bound,reason,detail", [
    (None, None, BoundSource.UNBOUNDED, k.UnknownReason.AS_OF_MISSING, "unbounded_collector_time"),
    (1000000, 2000000, BoundSource.COLLECTOR_RECORDED, k.UnknownReason.NOT_OBSERVABLE, "uptime_clock_bound_unqualified"),
])
def test_recorded_time_never_invents_an_unqualified_boot_interval(earliest, latest, bound, reason, detail):
    time = TimeInterval(earliest=earliest, latest=latest, clock="collector:synthetic", bound=bound)
    result = build_capture(record(time=time))
    assert isinstance(result.image, k.Known)
    assert isinstance(result.boot_epoch, k.Unknown)
    assert result.boot_epoch.reason is reason and result.boot_epoch.detail == detail
    assert result.boot_epoch.evidence
