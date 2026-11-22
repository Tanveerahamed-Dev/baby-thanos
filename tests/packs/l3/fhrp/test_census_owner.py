"""Actual census ownership over admitted folders, including unresolved accounting."""
from dataclasses import replace

import pytest
from census_owner_cases import (
    INTAKE_CASES,
    assert_real_scope_products,
    group_three_frame,
    observe_parser,
    plant_copied_pair,
    plant_earlier_negative,
    plant_forged_success,
    plant_input_graph,
    plant_late_plan_class,
    plant_parser_failure,
    plant_prepared_carrier,
    plant_reentry,
    plant_snapshot_capture_id,
    zero_frame,
)
from census_request_cases import input_folder
from test_gateway_source import LIMITS

from atlas_brain.packs.l3.fhrp import census_owner as owner
from atlas_brain.runner.pack_receipts import CaptureRequest


def _observed_owner(tmp_path, monkeypatch, second=None):
    root = tmp_path / "inputs"
    input_folder(root, second)
    calls = observe_parser(monkeypatch)
    return owner.CensusOwner(root, LIMITS), calls


@pytest.mark.parametrize("case, detail", [
    ("valid_empty", None), ("hash_refusal", "footer_hash"), ("empty_bytes", "empty_capture"), ("uncollected", None),
])
def test_actual_owner_pairs_real_parse_or_exact_fallback_and_preserves_uncollected_scope(tmp_path, monkeypatch, case, detail):
    root = tmp_path / "inputs"
    second = {"uncollected": None, "empty_bytes": b""}.get(case, zero_frame(valid=case == "valid_empty"))
    input_folder(root, second)
    calls = observe_parser(monkeypatch)
    run = owner.CensusOwner(root, LIMITS)
    assert_real_scope_products(run, calls, case, detail, second, owner.CensusOwner.parse, owner.CensusOwner.close)


def test_equal_capture_copy_and_duplicate_observation_refuse_before_dispatch(tmp_path, monkeypatch):
    run, calls = _observed_owner(tmp_path, monkeypatch)
    request = run.plan.scopes[0].request
    duplicate = replace(request.capture)
    assert duplicate == request.capture and duplicate is not request.capture
    with pytest.raises(ValueError, match="^hsrp_census_owner_request$"):
        owner.CensusOwner.parse(run, CaptureRequest(capture=duplicate, context=request.context))
    assert not calls
    pair = owner.CensusOwner.parse(run, request)
    with pytest.raises(ValueError, match="^hsrp_census_owner_request$"):
        owner.CensusOwner.parse(run, request)
    assert len(calls) == 1 and owner.CensusOwner.close(run)[0] is pair


@pytest.mark.parametrize("plant, error", [
    ("before", "hsrp_presence_custody"), ("member_after", "hsrp_presence_custody"),
    ("capture_after", "hsrp_census_owner_inputs"),
])
def test_original_input_graph_is_reclosed_before_use_and_after_actual_parser(tmp_path, monkeypatch, plant, error):
    run, calls = _observed_owner(tmp_path, monkeypatch, zero_frame())
    first, cold = run.plan.scopes
    plant_input_graph(monkeypatch, cold, plant)
    with pytest.raises(ValueError, match=f"^{error}$"):
        owner.CensusOwner.parse(run, first.request)
    assert len(calls) == int(plant != "before") and not run.emitted


def test_second_actual_parser_cannot_rewrite_earlier_coherent_negative(tmp_path, monkeypatch):
    run, calls = _observed_owner(tmp_path, monkeypatch, zero_frame())
    first, cold = run.plan.scopes
    earlier, accounting = owner.CensusOwner.parse(run, first.request)
    plant_earlier_negative(monkeypatch, earlier, accounting)
    with pytest.raises(ValueError, match="^hsrp_census_owner_emissions$"):
        owner.CensusOwner.parse(run, cold.request)
    assert len(calls) == 2 and calls[1][0] is cold.request.capture
    assert cold.request.capture.id not in run.emitted and earlier.detail == "changed"


def test_group_result_retains_real_record_and_refuses_later_group_change(tmp_path, monkeypatch):
    run, calls = _observed_owner(tmp_path, monkeypatch, group_three_frame())
    first, cold = run.plan.scopes
    value, parsed = owner.CensusOwner.parse(run, cold.request)
    assert calls[0][0] is cold.request.capture and value is calls[0][3] and parsed is value.parse
    group, = value.census.groups
    assert group.number == 3 and group.record is parsed.records[1]
    object.__setattr__(group, "number", 4)
    with pytest.raises(ValueError, match="^hsrp_census_owner_result$"):
        owner.CensusOwner.parse(run, first.request)
    assert len(calls) == 1


def test_parser_failure_cannot_retry_one_observation_in_the_same_run(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    input_folder(root)
    run = owner.CensusOwner(root, LIMITS)
    calls = plant_parser_failure(monkeypatch)
    with pytest.raises(RuntimeError, match="^parser_failed$"):
        owner.CensusOwner.parse(run, run.plan.scopes[0].request)
    with pytest.raises(ValueError, match="^hsrp_census_owner_emissions$"):
        owner.CensusOwner.parse(run, run.plan.scopes[0].request)
    assert len(calls) == 1 and not run.emitted


@pytest.mark.parametrize("fault, raw, error", INTAKE_CASES)
def test_actual_prepared_carriers_close_before_first_owner_access(tmp_path, monkeypatch, fault, raw, error):
    root = tmp_path / "inputs"
    input_folder(root, raw)
    calls = observe_parser(monkeypatch)
    hits = plant_prepared_carrier(monkeypatch, owner.requests, fault)
    with pytest.raises(ValueError, match=f"^hsrp_census_{error}$"):
        owner.CensusOwner(root, LIMITS)
    assert len(hits) == 1 and not calls


@pytest.mark.parametrize("stale", ["plan", "member", "brief", "bindings"])
def test_actual_custody_callback_cannot_dispatch_stale_input(tmp_path, monkeypatch, stale):
    run, calls = _observed_owner(tmp_path, monkeypatch)
    scope = run.plan.scopes[0]
    hits = plant_late_plan_class(monkeypatch, owner.custody, run, stale)
    error = "plan_scopes" if stale == "member" else "owner_plan"
    with pytest.raises(ValueError, match=f"^hsrp_census_{error}$"):
        owner.CensusOwner.parse(run, scope.request)
    assert len(hits) == 1 and not calls and not run.attempted


def test_clearing_attempts_inside_real_parser_does_not_allow_reentry_or_retry(tmp_path, monkeypatch):
    run, calls = _observed_owner(tmp_path, monkeypatch)
    request = run.plan.scopes[0].request
    plant_reentry(monkeypatch, run, request, owner.CensusOwner.parse, calls)
    with pytest.raises(ValueError, match="^hsrp_census_owner_emissions$"):
        owner.CensusOwner.parse(run, request)
    with pytest.raises(ValueError, match="^hsrp_census_owner_emissions$"):
        owner.CensusOwner.parse(run, request)
    assert len(calls) == 1 and not run.emitted


@pytest.mark.parametrize("kind", ["value", "effective_parse"])
def test_actual_sibling_cannot_substitute_equal_copy_for_original_emission(tmp_path, monkeypatch, kind):
    run, calls = _observed_owner(tmp_path, monkeypatch, zero_frame())
    earlier, later = run.plan.scopes
    value, effective = owner.CensusOwner.parse(run, earlier.request)
    assert value.parse is None and effective.quality == "partial"
    plant_copied_pair(monkeypatch, run, earlier, kind)
    with pytest.raises(ValueError, match="^hsrp_census_owner_emissions$"):
        owner.CensusOwner.parse(run, later.request)
    assert len(calls) == 2 and later.request.capture.id not in run.emitted


def test_real_parser_bad_footer_cannot_be_published_as_a_forged_success(tmp_path, monkeypatch):
    run, calls = _observed_owner(tmp_path, monkeypatch, zero_frame(valid=False))
    plant_forged_success(monkeypatch)
    with pytest.raises(ValueError, match="^hsrp_census_product_result$"):
        owner.CensusOwner.parse(run, run.plan.scopes[1].request)
    assert len(calls) == 1 and not run.emitted


@pytest.mark.parametrize("stale", ["id", "member"])
def test_actual_snapshot_callback_cannot_dispatch_stale_input(tmp_path, monkeypatch, stale):
    run, calls = _observed_owner(tmp_path, monkeypatch)
    scope = run.plan.scopes[0]
    request = scope.request
    member = scope.member if stale == "member" else None
    seen = plant_snapshot_capture_id(monkeypatch, owner.context, request.capture, member)
    error = "presence_custody" if stale == "member" else "census_request"
    with pytest.raises(ValueError, match=f"^hsrp_{error}$"):
        owner.CensusOwner.parse(run, request)
    assert len(seen) == 1 and not calls and not run.attempted
