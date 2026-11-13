"""Invocation-relative request custody; no admission, parser semantics or source authenticity seal."""
from dataclasses import FrozenInstanceError, asdict, replace

import pytest
from test_pack_runtime import request, setup_plan

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.kernel import states as k
from atlas_brain.runner import pack_receipts as custody
from atlas_brain.runner.pack_runtime import execute_parsers

PREFIX = "pack_receipts_retention_"


def planned(explicit=False):
    packs, handlers, requests, trace = setup_plan()
    if explicit:
        for item in requests:
            object.__setattr__(item.capture, "metadata", item.capture.resolved_metadata)
    return packs, handlers, requests, trace


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("reverse_requests", [False, True])
@pytest.mark.parametrize("reverse_retained", [False, True])
def test_original_requests_survive_real_execution_and_permutation_without_replacement(empty, reverse_requests, reverse_retained):
    packs, handlers, requests, trace = planned(explicit=True)
    requests = () if empty else tuple(reversed(requests)) if reverse_requests else requests
    retained = custody.retain_requests(requests)
    assert tuple(row.identity for row in retained) == tuple(sorted(item.capture.id for item in requests))
    for row in retained:
        original = next(item for item in requests if item.capture.id == row.identity)
        assert row.request is original and row.capture is original.capture and row.value == asdict(original)
        assert row.value["capture"]["raw"] == b"synthetic\n"
        assert row.value["capture"]["metadata"]["scope"]["node"] == "node:fixture"
    executed = execute_parsers(packs, handlers, requests)
    assert len(trace) == len(executed) == len(requests)
    assert all(any(output.receipt.capture is row.capture for row in retained) for output in executed)
    assert custody.validate_retained_requests(requests, tuple(reversed(retained)) if reverse_retained else retained) is None
    assert custody.retain_requests(requests) == retained


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("plant", ["rendered", "operation", "codec", "source", "context", "raw_append", "raw_prefix",
    "integrity", "read_scope", "view", "line_text", "line_span", "line_offsets", "scope_vrf", "scope_node",
    "scope_plane", "time_detail", "error"])
def test_actual_post_execution_inplace_metadata_drift_cannot_rewrite_the_retained_baseline(plant, reverse):
    packs, handlers, requests, trace = planned(explicit=True)
    retained = custody.retain_requests(requests)
    execute_parsers(packs, handlers, requests)
    item = next(item for item in requests if item.capture.id == "cap:d")
    capture = item.capture
    before = next(row for row in retained if row.capture is capture)
    if plant == "context":
        object.__setattr__(item, "context", "other")
    elif plant.startswith("scope_"):
        attribute, value = {"scope_vrf": ("vrf", "other"), "scope_node": ("node", k.EntityKey("node:other")),
            "scope_plane": ("plane", "controller")}[plant]
        object.__setattr__(capture.scope, attribute, value)
    elif plant == "time_detail":
        object.__setattr__(capture.collected_utc, "detail", "different time provenance")
    elif plant == "error":
        object.__setattr__(capture.metadata, "error", ErrorKind.TIMEOUT)
    elif plant.startswith("line_"):
        line = capture.lines[0]
        if plant == "line_span":
            object.__setattr__(line.span, "start", line.span.start + 1)
        else:
            attribute, value = ("text", "different") if plant == "line_text" else ("offsets", tuple(offset + 1 for offset in line.offsets))
            object.__setattr__(line, attribute, value)
    else:
        attribute, value = {"rendered": ("rendered", "show other"), "operation": ("operation", "collect.other"),
            "codec": ("codec", "ascii"), "source": ("source", k.EntityKey("node:other")),
            "raw_append": ("raw", capture.raw + b"not parsed\n"), "raw_prefix": ("raw", b"prefix\n" + capture.raw),
            "integrity": ("integrity", k.IntegrityState.TRUNCATED),
            "read_scope": ("read_scope", next(value for value in k.ReadScope if value is not k.ReadScope.UNKNOWN)),
            "view": ("view", next(value for value in k.ViewConsistency if value is not k.ViewConsistency.UNKNOWN))}[plant]
        object.__setattr__(capture, attribute, value)
    assert len(trace) == 4 and before.request is item and before.capture is capture
    assert before.value["capture"]["rendered"] == "show synthetic"
    assert before.value["capture"]["raw"] == b"synthetic\n" and before.value["context"] == "context:d"
    assert before.value["capture"]["metadata"]["scope"]["vrf"] is None
    with pytest.raises(ValueError, match="^" + PREFIX + "mismatch$"):
        custody.validate_retained_requests(tuple(reversed(requests)) if reverse else requests, retained)


@pytest.mark.parametrize("plant,code", [("new_id", "coverage"), ("duplicate_current", "duplicate"),
    ("missing_current", "coverage"), ("extra_current", "coverage"), ("missing_retained", "coverage"),
    ("duplicate_retained", "duplicate"), ("changed_retained_id", "coverage")])
def test_ids_and_exact_population_are_checked_before_object_values(plant, code):
    packs, handlers, requests, _ = planned()
    retained = custody.retain_requests(requests)
    execute_parsers(packs, handlers, requests)
    if plant in ("new_id", "duplicate_current"):
        object.__setattr__(requests[-1].capture, "id", k.CaptureId("cap:new") if plant == "new_id" else requests[0].capture.id)
    elif plant == "missing_current":
        requests = requests[:-1]
    elif plant == "extra_current":
        requests += (request("new", "collect.alpha"),)
    elif plant == "missing_retained":
        retained = retained[:-1]
    elif plant == "duplicate_retained":
        retained += (retained[0],)
    else:
        retained = (replace(retained[0], identity=k.CaptureId("cap:new")), *retained[1:])
    with pytest.raises(ValueError, match="^" + PREFIX + code + "$"):
        custody.validate_retained_requests(requests, retained)


@pytest.mark.parametrize("axis", ["request", "capture"])
def test_equal_copies_cannot_replace_either_original_pointer_after_real_execution(axis):
    packs, handlers, requests, _ = planned()
    retained = custody.retain_requests(requests)
    execute_parsers(packs, handlers, requests)
    item = requests[0]
    if axis == "request":
        requests = (replace(item), *requests[1:])
    else:
        object.__setattr__(item, "capture", replace(item.capture))
    assert {item.capture.id: asdict(item) for item in requests} == {row.identity: row.value for row in retained}
    with pytest.raises(ValueError, match="^" + PREFIX + "mismatch$"):
        custody.validate_retained_requests(requests, retained)


@pytest.mark.parametrize("plant", ["request_list", "request_member", "retained_list", "retained_member"])
def test_nominal_outer_shapes_refuse_controlled_inputs(plant):
    _, _, requests, _ = planned()
    retained = custody.retain_requests(requests)
    if plant == "request_list":
        requests = list(requests)
    elif plant == "request_member":
        requests = (object(),)
    elif plant == "retained_list":
        retained = list(retained)
    else:
        retained = (object(),)
    with pytest.raises(ValueError, match="^" + PREFIX + "input$"):
        custody.validate_retained_requests(requests, retained)


@pytest.mark.parametrize("plant,code", [("capture", "pack_receipts_capture"), ("context", "pack_receipts_context"),
    ("lines", "pack_receipts_capture_lines"), ("line_member", "pack_receipts_capture_lines")])
def test_existing_capture_and_context_shape_refusals_are_preserved(plant, code):
    _, _, requests, _ = planned()
    item = requests[-1]
    if plant == "capture":
        object.__setattr__(item, "capture", object())
    elif plant == "context":
        object.__setattr__(item, "context", "")
    else:
        object.__setattr__(item.capture, "lines", [] if plant == "lines" else (object(),))
    with pytest.raises(ValueError, match="^" + code + "$"):
        custody.retain_requests(requests)


def test_snapshot_is_detached_and_relative_to_the_callers_selected_baseline():
    packs, handlers, requests, _ = planned(explicit=True)
    retained = custody.retain_requests(requests)
    execute_parsers(packs, handlers, requests)
    with pytest.raises(FrozenInstanceError):
        retained[0].identity = k.CaptureId("cap:other")
    item = retained[0].request
    object.__setattr__(item.capture, "rendered", "an unadmitted command")
    assert retained[0].value["capture"]["rendered"] == "show synthetic"
    with pytest.raises(ValueError, match="^" + PREFIX + "mismatch$"):
        custody.validate_retained_requests(requests, retained)
    changed_baseline = custody.retain_requests(requests)
    assert custody.validate_retained_requests(requests, changed_baseline) is None
    assert item.capture.rendered == "an unadmitted command"
