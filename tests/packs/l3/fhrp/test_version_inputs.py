"""Synthetic input-graph custody; retained comparison data is not source admission."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_all import BODY, capture
from test_reported_state_build import B, target

from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser
from atlas_brain.packs.l3.fhrp import version_inputs as inputs
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest

GROUPS = (("Vlan10", "0"), ("Vlan99", "2"))


def fixture(node=None, identity="a", timed=False):
    item = target(groups=GROUPS, **({} if node is None else {"node": node}))
    sample = replace(capture(BODY), source=item.node.key, id=k.CaptureId("cap:" + identity))
    metadata = sample.resolved_metadata
    need = k.EvidenceNeed(node=item.node.key, operation="iosxe.show_standby_all", params=(("group", "0"),),
        resolves=("l3.fhrp.reported_protocol_version",), reruns=("l3.fhrp/parse_hsrp_all_version",),
        after_s=1, unprintable=("synthetic_only",))
    time = TimeInterval(earliest=1, latest=2, clock="collector:fixture", bound=BoundSource.COLLECTOR_RECORDED) if timed else (
        replace(metadata.collected_utc, candidates=(item.node.key,), next_evidence=(need,)))
    subject = build.subject(item, "Vlan10", "0")
    references = (k.FactRef(fact="l3.fhrp.reported_protocol_version", subject=subject), *item.node.declaration.evidence,
        k.EvidenceRef(capture=sample.id, locator=k.FieldPointer(pointer="/fixture"), role=k.EvidenceRole.WITNESS,
                      excerpt_sha256=sample.bytes_sha256),
        k.EvidenceRef(capture=sample.id, locator=k.XmlPath(path="/fixture"), role=k.EvidenceRole.WITNESS,
                      excerpt_sha256=sample.bytes_sha256),
        k.EvidenceRef(capture=sample.id, locator=k.ByteSpan(start=0, end=1), role=k.EvidenceRole.WITNESS,
                      excerpt_sha256=sha256(sample.raw[:1]).hexdigest()))
    sample = replace(sample, metadata=replace(metadata, collected_utc=time, read_scope_evidence=references))
    return deepcopy((item, CaptureRequest(context=item.context, capture=sample)))


def forbid_bad_snapshots(monkeypatch, item, request, target_bad):
    target_snapshot, request_snapshot = inputs.asdict, inputs.custody.asdict
    def target_watch(value):
        if target_bad and value is item:
            pytest.fail("traversed a malformed Target graph")
        return target_snapshot(value)
    def request_watch(value):
        if not target_bad and value is request:
            pytest.fail("traversed a malformed request graph")
        return request_snapshot(value)
    monkeypatch.setattr(inputs, "asdict", target_watch)
    monkeypatch.setattr(inputs.custody, "asdict", request_watch)


def plant(item, request, field):
    sample, metadata = request.capture, request.capture.metadata
    if field == "ports":
        object.__setattr__(item.node, "ports", list(item.node.ports))
    elif field == "groups":
        object.__setattr__(item, "groups", list(item.groups))
    elif field == "node_id":
        object.__setattr__(item.node, "id", [])
    elif field == "declaration":
        object.__setattr__(item.node.declaration, "value", [])
    elif field == "registry_digest":
        object.__setattr__(item.node.declaration.evidence[0], "table_digest", [])
    elif field in ("span_start", "span_end_bool"):
        object.__setattr__(sample.lines[0].span, "start" if field == "span_start" else "end", [] if field == "span_start" else False)
    elif field in ("offsets", "line_text"):
        object.__setattr__(sample.lines[0], "offsets" if field == "offsets" else "text", [])
    elif field == "scope":
        object.__setattr__(metadata.scope, "vrf", [])
    elif field == "time_endpoint":
        object.__setattr__(metadata.collected_utc, "earliest", [])
    elif field in ("unknown_needs", "unknown_candidates", "unknown_evidence"):
        name = {"unknown_needs": "next_evidence", "unknown_candidates": "candidates", "unknown_evidence": "evidence"}[field]
        object.__setattr__(metadata.collected_utc, name, [])
    elif field in ("need_params", "need_resolves"):
        object.__setattr__(metadata.collected_utc.next_evidence[0], "params" if field == "need_params" else "resolves", [])
    elif field == "fact_subject":
        object.__setattr__(metadata.read_scope_evidence[0], "subject", [])
    elif field == "field_pointer":
        object.__setattr__(metadata.read_scope_evidence[-3].locator, "pointer", [])
    elif field == "xml_path":
        object.__setattr__(metadata.read_scope_evidence[-2].locator, "path", [])
    elif field == "witness_span":
        object.__setattr__(metadata.read_scope_evidence[-1].locator, "start", [])
    elif field == "integrity_evidence":
        object.__setattr__(metadata, "integrity_evidence", [])
    else:
        object.__setattr__(metadata, "channel", [])


@pytest.mark.parametrize("timed", [False, True])
def test_retention_is_pointer_bound_closed_comparison_data_with_independent_derived_maps(timed):
    first, supplied = fixture(timed=timed)
    cold, _ = fixture(B, "b", timed)
    result = inputs.retain_version_inputs((first, cold), (supplied,))
    assert result.targets == (first, cold) and result.requests == (supplied,)
    assert result.indexed == {(first.context, first.node.key): first, (cold.context, cold.node.key): cold}
    assert result.indexed[first.context, first.node.key] is first and result.expected[supplied.capture.id] is supplied
    held, = result.retained_requests
    assert held.request is supplied and held.capture is supplied.capture
    assert result.retained_targets[0][:3] == (first, first.node, first.node.declaration)
    assert inputs.validate_version_request(supplied) is None and inputs.validate_version_inputs(result) is None
    assert set(result.indexed) == {(first.context, first.node.key), (cold.context, cold.node.key)}
    assert inputs.validate_version_inputs(replace(result)) is None


@pytest.mark.parametrize("stage", ["initial", "retained"])
@pytest.mark.parametrize("field", [
    "ports", "groups", "node_id", "declaration", "registry_digest",
    "span_start", "span_end_bool", "offsets", "line_text", "scope", "time_endpoint",
    "unknown_needs", "unknown_candidates", "unknown_evidence", "need_params", "need_resolves",
    "fact_subject", "field_pointer", "xml_path", "witness_span", "integrity_evidence", "channel",
])
def test_malformed_builtin_graphs_refuse_before_any_affected_snapshot(monkeypatch, stage, field):
    item, supplied = fixture(timed=field == "time_endpoint")
    retained = inputs.retain_version_inputs((item,), (supplied,)) if stage == "retained" else None
    plant(item, supplied, field)
    forbid_bad_snapshots(monkeypatch, item, supplied, field in ("ports", "groups", "node_id", "declaration", "registry_digest"))
    with pytest.raises(ValueError):
        inputs.retain_version_inputs((item,), (supplied,)) if retained is None else inputs.validate_version_inputs(retained)


@pytest.mark.parametrize("change", ["drop_cold", "replace_target", "wrong_index_key", "drop_expected", "replace_request",
                                    "wrong_expected_key", "drop_retention", "replace_retained_request"])
def test_derived_indexes_and_retention_census_cannot_erase_or_replace_original_inputs(change):
    first, supplied = fixture()
    cold, _ = fixture(B, "b")
    retained = inputs.retain_version_inputs((first, cold), (supplied,))
    key = cold.context, cold.node.key
    if change == "drop_cold":
        retained.indexed.pop(key)
    elif change == "replace_target":
        retained.indexed[key] = replace(cold)
    elif change == "wrong_index_key":
        retained.indexed[("other", cold.node.key)] = retained.indexed.pop(key)
    elif change == "drop_expected":
        retained.expected.pop(supplied.capture.id)
    elif change == "replace_request":
        retained.expected[supplied.capture.id] = replace(supplied)
    elif change == "wrong_expected_key":
        retained.expected["cap:other"] = retained.expected.pop(supplied.capture.id)
    elif change == "drop_retention":
        retained = replace(retained, retained_targets=retained.retained_targets[:1])
    else:
        held, = retained.retained_requests
        retained = replace(retained, retained_requests=(replace(held, request=replace(supplied)),))
    with pytest.raises(ValueError):
        inputs.validate_version_inputs(retained)


@pytest.mark.parametrize("change", ["context", "raw", "capture_copy", "node_copy", "declaration_copy", "groups"])
def test_late_well_shaped_value_or_pointer_changes_are_not_original_input_custody(change):
    item, supplied = fixture()
    retained = inputs.retain_version_inputs((item,), (supplied,))
    if change == "context":
        object.__setattr__(supplied, "context", "other")
    elif change == "raw":
        sample = capture(BODY + b"\n")
        object.__setattr__(supplied, "capture", replace(sample, source=item.node.key, id=supplied.capture.id))
    elif change == "capture_copy":
        object.__setattr__(supplied, "capture", replace(supplied.capture))
    elif change == "node_copy":
        object.__setattr__(item, "node", replace(item.node))
    elif change == "declaration_copy":
        object.__setattr__(item.node, "declaration", replace(item.node.declaration))
    else:
        object.__setattr__(item, "groups", (("Vlan10", "0"),))
    with pytest.raises(ValueError):
        inputs.validate_version_inputs(retained)


@pytest.mark.parametrize("change", ["operation", "command", "codec", "scope", "duplicate_target", "duplicate_request",
                                    "foreign_node", "target_list", "request_list"])
def test_request_form_scope_and_whole_population_close_before_retention(change):
    item, supplied = fixture()
    if change in ("operation", "command", "codec"):
        field = "rendered" if change == "command" else change
        value = {"operation": "iosxe.other", "command": "show standby", "codec": "latin-1"}[change]
        supplied = replace(supplied, capture=replace(supplied.capture, **{field: value}))
    elif change == "scope":
        metadata = supplied.capture.metadata
        supplied = replace(supplied, capture=replace(supplied.capture, metadata=replace(metadata, scope=replace(metadata.scope, vrf="fixture"))))
    elif change == "foreign_node":
        _, supplied = fixture(B, "b")
    targets = (item, item) if change == "duplicate_target" else (item,)
    requests = (supplied, supplied) if change == "duplicate_request" else (supplied,)
    with pytest.raises(ValueError):
        inputs.retain_version_inputs(list(targets) if change == "target_list" else targets,
                                     list(requests) if change == "request_list" else requests)


def test_valid_request_check_never_parses_snapshots_or_dispatches(monkeypatch):
    _, supplied = fixture()
    def forbidden(*args, **kwargs):
        pytest.fail("request graph validation traversed a snapshot or executed work")
    monkeypatch.setattr(inputs, "asdict", forbidden)
    monkeypatch.setattr(inputs.custody, "asdict", forbidden)
    monkeypatch.setattr(parser, "parse_capture", forbidden)
    monkeypatch.setattr(build.hsrp, "parse_capture", forbidden)
    monkeypatch.setattr(pack_runtime, "execute_parsers", forbidden)
    assert inputs.validate_version_request(supplied) is None


def test_empty_and_permuted_input_sets_remain_metadata_without_erasing_participants():
    empty = inputs.retain_version_inputs((), ())
    assert inputs.validate_version_inputs(empty) is None
    assert empty.targets == empty.requests == empty.retained_targets == empty.retained_requests == ()
    assert empty.indexed == empty.expected == {}
    first, left = fixture()
    second, right = fixture(B, "b")
    forward = inputs.retain_version_inputs((first, second), (left, right))
    reverse = inputs.retain_version_inputs((second, first), (right, left))
    assert inputs.validate_version_inputs(forward) is inputs.validate_version_inputs(reverse) is None
    assert forward.indexed == reverse.indexed and forward.expected == reverse.expected
