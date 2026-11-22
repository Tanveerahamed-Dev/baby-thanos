"""Census request preparation and original BRIEF binding from real admitted folders."""
import pytest
from census_request_cases import (
    BRIEF_PLANTS,
    FOLDER_CASES,
    INVALID_SCOPES,
    MATERIALIZATION_PLANTS,
    assert_census_plan,
    forbid_census_lines,
    forbid_observations,
    input_folder,
    invalid_scope_folder,
    observe_admission,
    observe_brief_preparation,
    plant_brief_preparation,
    plant_earlier_census_request,
    plant_final_request_snapshot,
    plant_later_member,
    plant_original_envelope_after_brief,
    plant_profile_declaration,
    plant_snapshot_batch_class,
)
from test_gateway_source import LIMITS

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import census_requests as requests


@pytest.mark.parametrize("second, missing", FOLDER_CASES)
def test_actual_folder_binds_original_brief_scope_and_members_without_dispatch(tmp_path, monkeypatch, second, missing):
    root = tmp_path / "inputs"
    files, side = input_folder(root, second, missing=missing)
    forbid_observations(monkeypatch)
    admitted = observe_admission(monkeypatch)
    batches = observe_brief_preparation(monkeypatch, forbid_owner=True)
    plan = requests.prepare_census_folder(root, LIMITS)
    assert len(admitted) == len(batches) == 1 and plan.envelope is admitted[0]
    batch = batches[0]
    assert plan.brief_bindings.owner is plan.brief is batch.handlers[0].parser
    assert plan.brief_bindings.requests is batch.requests
    assert_census_plan(plan, root, files, side, second)


@pytest.mark.parametrize("fault, error", INVALID_SCOPES)
def test_invalid_census_scope_or_member_refuses_before_census_capture_allocation(tmp_path, monkeypatch, fault, error):
    root = tmp_path / "inputs"
    invalid_scope_folder(root, fault)
    forbid_observations(monkeypatch)

    forbid_census_lines(monkeypatch, requests)
    with pytest.raises(ValueError, match=f"^{error}$"):
        requests.prepare_census_folder(root, LIMITS)


@pytest.mark.parametrize("cap", ["bytes", "lines"])
def test_all_census_members_pass_resource_preflight_before_any_lines_are_allocated(tmp_path, monkeypatch, cap):
    root = tmp_path / "inputs"
    raw = b"x" * 680_001 if cap == "bytes" else b"\n" * 4_098 + b"x"
    input_folder(root, raw)
    forbid_observations(monkeypatch)

    forbid_census_lines(monkeypatch, requests)
    with pytest.raises(BudgetExceeded) as refusal:
        requests.prepare_census_folder(root, LIMITS)
    assert refusal.value.member == "census-b.txt"


def test_line_limit_and_unterminated_byte_accounting_are_exact(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    input_folder(root, b"\n" * 4_097 + b"x")
    forbid_observations(monkeypatch)
    cold = requests.prepare_census_folder(root, LIMITS).scopes[1]
    capture = cold.request.capture
    assert len(capture.lines) == 4_098
    assert capture.lines[-1].span == k.ByteSpan(start=4_097, end=4_098)


@pytest.mark.parametrize("fault", ["registration", "member", "source"])
def test_original_brief_binding_rejects_changes_to_admitted_census_graph(tmp_path, monkeypatch, fault):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    scope = plan.scopes[0]
    if fault == "registration":
        object.__setattr__(plan.envelope, "registration_sha256", "0" * 64)
    elif fault == "member":
        object.__setattr__(scope.member, "raw", b"replacement")
    else:
        object.__setattr__(scope.source, "params", b"{}")
    with pytest.raises(ValueError, match="^hsrp_presence_custody$"):
        requests.prepare_census_inputs(plan.envelope, LIMITS, plan.brief, plan.brief_bindings)


def test_original_envelope_is_retained_before_the_real_brief_prepare_callback(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    seen = plant_original_envelope_after_brief(monkeypatch)
    with pytest.raises(ValueError, match="^hsrp_census_prepare_custody$"):
        requests.prepare_census_folder(root, LIMITS)
    assert len(seen) == 1


@pytest.mark.parametrize("plant, code", BRIEF_PLANTS)
def test_actual_brief_prepare_closes_batch_handler_and_original_binding(tmp_path, monkeypatch, plant, code):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    seen, restore = plant_brief_preparation(monkeypatch, plant)
    try:
        with pytest.raises(ValueError, match=f"^hsrp_census_{code}$"):
            requests.prepare_census_folder(root, LIMITS)
    finally:
        for obj, name, value in restore:
            object.__setattr__(obj, name, value)
    assert len(seen) == 1


@pytest.mark.parametrize("mark", ["produced", "finished"])
def test_fresh_request_seam_refuses_consumed_brief_plan(tmp_path, monkeypatch, mark):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    if mark == "produced":
        identity = next(iter(plan.brief_bindings.expected))
        plan.brief.produced[identity] = state.hsrp.Result(rows=(), parse=ParseResult((), (), (), "partial"), reason=None)
    else:
        plan.brief.finished = True
    with pytest.raises(ValueError, match="^hsrp_census_brief_consumed$"):
        requests.prepare_census_inputs(plan.envelope, LIMITS, plan.brief, plan.brief_bindings)


@pytest.mark.parametrize("plant, error", MATERIALIZATION_PLANTS)
def test_materialization_uses_frozen_member_arguments_and_then_recloses(tmp_path, monkeypatch, plant, error):
    root = tmp_path / "inputs"
    files, _ = input_folder(root, b"second original")
    forbid_observations(monkeypatch)
    admitted = observe_admission(monkeypatch)
    seen = plant_later_member(monkeypatch, requests, admitted, plant)
    with pytest.raises(ValueError, match=f"^{error}$"):
        requests.prepare_census_folder(root, LIMITS)
    assert seen == [files["census-a.txt"], files["census-b.txt"]]


@pytest.mark.parametrize("plant, error", [("params", "hsrp_presence_custody"), ("open_op", "hsrp_census_profile")])
def test_profile_callback_is_closed_before_census_selection(tmp_path, monkeypatch, plant, error):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    admitted = observe_admission(monkeypatch)
    hits = plant_profile_declaration(monkeypatch, requests.profile, admitted, plant)
    forbid_census_lines(monkeypatch, requests)
    with pytest.raises(ValueError, match=f"^{error}$"):
        requests.prepare_census_folder(root, LIMITS)
    assert len(hits) == 1


def test_actual_custody_snapshot_cannot_open_the_original_batch(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    batches = observe_brief_preparation(monkeypatch)
    hits = plant_snapshot_batch_class(monkeypatch, requests.custody, batches)
    with pytest.raises(ValueError, match="^hsrp_census_brief_prepared$"):
        requests.prepare_census_folder(root, LIMITS)
    assert len(batches) == len(hits) == 1 and hits[0] is batches[0]


@pytest.mark.parametrize("plant", ["raw", "raw_identity", "open_context", "view", "codec", "metadata"])
def test_completed_request_recloses_after_the_second_actual_materialization(tmp_path, monkeypatch, plant):
    root = tmp_path / "inputs"
    input_folder(root, b"second original")
    forbid_observations(monkeypatch)
    built = plant_earlier_census_request(monkeypatch, requests, plant)
    with pytest.raises(ValueError, match="^hsrp_census_request$"):
        requests.prepare_census_folder(root, LIMITS)
    assert len(built) == 2


def test_actual_final_request_snapshot_cannot_change_live_lines(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    seen = plant_final_request_snapshot(monkeypatch, requests)
    with pytest.raises(ValueError, match="^hsrp_census_request$"):
        requests.prepare_census_folder(root, LIMITS)
    assert len(seen) == 1
