"""Capture metadata witnesses, prepared before the constructor changes."""
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256

import pytest
from test_evidence import bundle

from atlas_brain.evidence import admission as a
from atlas_brain.evidence.capture import Capture, CaptureMetadata, Channel, Scope
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval


def capture(tmp_path, raw=b"record\n"):
    bundle(tmp_path, raw)
    legacy = a.import_folder(tmp_path, a.Budgets(10000, 10000, 10)).captures[0]
    return replace(legacy, metadata=legacy.resolved_metadata)




def change_capture(item, **changes):
    metadata_fields = {"channel", "scope", "collected_utc", "error", "integrity_evidence",
                       "read_scope_evidence", "envelope"}
    metadata = replace(item.resolved_metadata, **{key: value for key, value in changes.items()
                                                if key in metadata_fields})
    return replace(item, metadata=metadata, **{key: value for key, value in changes.items()
                                             if key not in metadata_fields})

def test_cli_capture_metadata_and_raw_witness(tmp_path):
    item = capture(tmp_path)
    assert item.channel is Channel.CLI
    assert item.scope.node == item.source == k.EntityKey("node:sw-a")
    assert item.scope.plane == "exec"
    assert item.scope.vrf is None
    assert item.error is None and item.envelope is None
    assert item.read_scope is k.ReadScope.UNKNOWN
    assert item.read_scope_evidence == ()
    assert item.view is k.ViewConsistency.UNKNOWN
    witness, = item.integrity_evidence
    assert witness.capture == item.id
    assert type(witness.locator) is k.WholeCapture
    assert witness.excerpt_sha256 == item.bytes_sha256 == sha256(item.raw).hexdigest()
    assert item.byte_len == len(item.raw)
    assert item.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert item.collected_utc.detail == "no_collector_time"
    assert item.collected_utc.evidence == (witness,)
    assert item.channel.value == "cli"
    with pytest.raises(FrozenInstanceError):
        item.raw = b"changed"


def test_identity_changes_with_capture_content(tmp_path):
    before = capture(tmp_path)
    after_folder = tmp_path / "second"
    after_folder.mkdir()
    bundle(after_folder, b"changed\n")
    after = a.import_folder(after_folder, a.Budgets(10000, 10000, 10)).captures[0]
    assert after.id != before.id


@pytest.mark.parametrize("change", [
    {"source": k.EntityKey("node:other")}, {"channel": "cli"},
    {"integrity": "empty"}, {"read_scope": "unknown"}, {"view": "unknown"},
    {"raw": bytearray(b"record\n")}, {"integrity_evidence": ()},
    {"envelope": {}}, {"operation": ""}, {"error": "timeout"},
    {"id": ""}, {"rendered": ""}, {"codec": ""}, {"collected_utc": None},
    {"read_scope": k.ReadScope.FULL_EVIDENCED},
])
def test_planted_invalid_capture_metadata_refuses(tmp_path, change):
    with pytest.raises((TypeError, ValueError)):
        change_capture(capture(tmp_path), **change)


@pytest.mark.parametrize("change", [{"node": ""}, {"plane": "other"}, {"vrf": ""}, {"afi": 4}])
def test_planted_invalid_scope_refuses(change):
    scope = Scope(node=k.EntityKey("node:sw-a"), vrf=None, context=None, vdc=None,
                  tenant=None, afi=None, instance=None, plane="exec")
    with pytest.raises((TypeError, ValueError)):
        replace(scope, **change)


def test_planted_witness_cannot_name_another_capture(tmp_path):
    item = capture(tmp_path)
    witness, = item.integrity_evidence
    with pytest.raises(ValueError, match="capture_witness_mismatch"):
        change_capture(item, integrity_evidence=(replace(witness, capture=k.CaptureId("cap:other")),))


def test_cli_integrity_witness_can_bind_an_exact_raw_span(tmp_path):
    item = capture(tmp_path)
    witness, = item.integrity_evidence
    span = k.ByteSpan(start=0, end=6)
    witness = replace(witness, locator=span, excerpt_sha256=sha256(b"record").hexdigest())
    result = change_capture(item, integrity_evidence=(witness,))
    assert result.integrity_evidence[0].locator == span


@pytest.mark.parametrize("locator,digest", [
    (k.ByteSpan(start=0, end=100), sha256(b"record").hexdigest()),
    (k.ByteSpan(start=0, end=6), "a" * 64),
    (k.WholeCapture(), "a" * 64),
    (k.FieldPointer(pointer="/record"), sha256(b"record\n").hexdigest()),
    (k.XmlPath(path="/record[1]"), sha256(b"record\n").hexdigest()),
])
def test_planted_invalid_cli_witness_locator_or_digest_refuses(tmp_path, locator, digest):
    item = capture(tmp_path)
    witness, = item.integrity_evidence
    with pytest.raises(ValueError):
        change_capture(item, integrity_evidence=(replace(witness, locator=locator, excerpt_sha256=digest),))

def test_legacy_folder_constructor_keeps_positional_api_and_evidenced_unknown(tmp_path):
    bundle(tmp_path, b"record\n")
    original = a.import_folder(tmp_path, a.Budgets(10000, 10000, 10)).captures[0]
    item = Capture(original.id, original.source, original.operation, original.rendered, original.codec,
                   original.raw, original.integrity, original.lines, original.read_scope, original.view)
    assert item.metadata is None
    assert item.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert item.collected_utc.evidence == item.integrity_evidence
    assert item.scope.node == item.source
    assert item.error is None
    explicit = replace(item, metadata=item.resolved_metadata)
    assert explicit.resolved_metadata == item.resolved_metadata
    assert explicit.id == item.id and explicit.bytes_sha256 == item.bytes_sha256


def test_explicit_metadata_is_required_and_frozen(tmp_path):
    with pytest.raises(TypeError):
        CaptureMetadata()
    item = capture(tmp_path)
    with pytest.raises(FrozenInstanceError):
        item.metadata.error = None
    with pytest.raises(ValueError, match="invalid_capture_metadata"):
        replace(item, metadata={})


@pytest.mark.parametrize("ends", [(1, 2), (None, 2), (1, None), (None, None)])
def test_collector_interval_identity_and_unbounded_ends_survive(tmp_path, ends):
    bound = BoundSource.UNBOUNDED if None in ends else BoundSource.COLLECTOR_RECORDED
    interval = TimeInterval(earliest=ends[0], latest=ends[1], clock="collector:session-a", bound=bound)
    item = change_capture(capture(tmp_path), collected_utc=interval)
    assert item.collected_utc is interval
    assert (item.collected_utc.earliest, item.collected_utc.latest) == ends


@pytest.mark.parametrize("clock,bound", [("node:sw-a/epoch:a", BoundSource.COLLECTOR_RECORDED),
                                        ("collector:a", BoundSource.PER_EVENT_QUALITY)])
def test_noncollector_time_provenance_refuses(tmp_path, clock, bound):
    interval = TimeInterval(earliest=1, latest=2, clock=clock, bound=bound)
    with pytest.raises(ValueError, match="recorded_collector_time_required"):
        change_capture(capture(tmp_path), collected_utc=interval)
