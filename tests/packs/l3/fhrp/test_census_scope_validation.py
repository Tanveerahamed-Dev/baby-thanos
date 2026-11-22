"""Check the entire freshly admitted census scope inventory without reopening it."""
from dataclasses import replace

import pytest
from census_request_cases import assert_census_plan, forbid_observations, input_folder
from test_gateway_source import LIMITS

from atlas_brain.packs.l3.fhrp import census_requests as requests
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack


def _forbid_new_preparation(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("scope validation admitted, prepared or allocated another request")

    monkeypatch.setattr(requests.p4, "admit_folder", forbidden)
    monkeypatch.setattr(StandbyBriefPack, "prepare", forbidden)
    monkeypatch.setattr(requests, "_request", forbidden)


@pytest.mark.parametrize("second", [None, b""])
def test_actual_complete_scope_inventory_recloses_without_new_requests(tmp_path, monkeypatch, second):
    root = tmp_path / "inputs"
    files, side = input_folder(root, second)
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    old_scopes, old_values = plan.scopes, plan.request_values
    _forbid_new_preparation(monkeypatch)
    requests.validate_census_scopes(plan, LIMITS)
    assert plan.scopes is old_scopes and plan.request_values is old_values
    assert_census_plan(plan, root, files, side, second)


@pytest.mark.parametrize("fault, error", [
    ("ordering", "plan_scopes"), ("key", "plan_scopes"), ("member", "plan_scopes"),
    ("request_copy", "plan_scopes"), ("capture_copy", "plan_scopes"), ("raw_copy", "request"),
])
def test_origin_scope_and_prepared_request_correspondence_are_exact(tmp_path, monkeypatch, fault, error):
    root = tmp_path / "inputs"
    input_folder(root, b"second")
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    original, other = plan.scopes
    request = original.request
    capture = request.capture
    if fault == "ordering":
        object.__setattr__(plan, "scopes", (other, original))
    elif fault == "key":
        object.__setattr__(original, "key", other.key)
    elif fault == "member":
        object.__setattr__(original, "member", other.member)
    elif fault == "request_copy":
        object.__setattr__(original, "request", replace(request))
    elif fault == "capture_copy":
        object.__setattr__(request, "capture", replace(capture))
    else:
        copied = bytes(bytearray(capture.raw))
        assert copied == capture.raw and copied is not capture.raw
        object.__setattr__(capture, "raw", copied)
    _forbid_new_preparation(monkeypatch)
    with pytest.raises(ValueError, match=f"^hsrp_census_{error}$"):
        requests.validate_census_scopes(plan, LIMITS)


def test_actual_request_snapshot_cannot_donate_a_different_scope(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    input_folder(root, b"second")
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    snapshot = requests.context.request_values
    seen = []

    def snapshotting(original):
        values = snapshot(original)
        object.__setattr__(plan.scopes[1], "interface", "Vl30")
        seen.append(values)
        return values

    _forbid_new_preparation(monkeypatch)
    monkeypatch.setattr(requests.context, "request_values", snapshotting)
    with pytest.raises(ValueError, match="^hsrp_census_plan_scopes$"):
        requests.validate_census_scopes(plan, LIMITS)
    assert len(seen) == 1


@pytest.mark.parametrize("fault, error", [
    ("capture", "plan_scopes"), ("lines", "request"), ("span", "request"),
])
def test_late_actual_envelope_close_cannot_replace_capture_accounting(tmp_path, monkeypatch, fault, error):
    root = tmp_path / "inputs"
    input_folder(root)
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    validate = requests.custody.validate_plan
    request = plan.scopes[0].request
    capture = request.capture
    seen = []

    def validating(*args):
        validate(*args)
        seen.append(True)
        if len(seen) == 2:
            if fault == "capture":
                replacement = replace(capture)
                assert replacement == capture and replacement is not capture
                object.__setattr__(request, "capture", replacement)
            elif fault == "lines":
                lines = (replace(capture.lines[0], text="different"), *capture.lines[1:])
                object.__setattr__(capture, "lines", lines)
            else:
                span = capture.lines[0].span
                object.__setattr__(span, "start", span.start + 1)

    _forbid_new_preparation(monkeypatch)
    monkeypatch.setattr(requests.custody, "validate_plan", validating)
    with pytest.raises(ValueError, match=f"^hsrp_census_{error}$"):
        requests.validate_census_scopes(plan, LIMITS)
    assert len(seen) == 2


@pytest.mark.parametrize("change", ["interface", "inventory"])
def test_late_actual_envelope_close_cannot_relabel_or_drop_a_census_target(tmp_path, monkeypatch, change):
    root = tmp_path / "inputs"
    input_folder(root, b"second original" if change == "interface" else None)
    forbid_observations(monkeypatch)
    plan = requests.prepare_census_folder(root, LIMITS)
    scope = plan.scopes[1]
    target = scope.target
    assert target.params == b'{"interface":"BD10","source_target":"hsrp-cold"}'
    if change == "interface":
        domain = plan.brief_bindings.indexed[(plan.envelope.context, scope.source.node.key)]
        assert any(name == "Vl30" for name, _ in domain.groups)
    else:
        assert scope.member is scope.request is None
    validate = requests.custody.validate_plan
    seen = []

    def validating(*args):
        validate(*args)
        seen.append(True)
        if len(seen) == 2:
            if change == "interface":
                object.__setattr__(target, "params", b'{"interface":"Vl30","source_target":"hsrp-cold"}')
            else:
                targets = tuple(item for item in plan.envelope.targets if item is not target)
                object.__setattr__(plan.envelope, "targets", targets)

    _forbid_new_preparation(monkeypatch)
    monkeypatch.setattr(requests.custody, "validate_plan", validating)
    with pytest.raises(ValueError, match="^hsrp_census_plan_scopes$"):
        requests.validate_census_scopes(plan, LIMITS)
    assert seen == [True, True]
