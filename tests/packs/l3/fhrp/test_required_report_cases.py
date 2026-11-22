"""Test the required-report budget fixtures against the real owning factory."""
from dataclasses import replace

import pytest
from required_report_cases import budget_inputs, forbid_observations, original_inputs
from test_gateway_source import LIMITS

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.packs.l3.fhrp import reported_presence as presence


@pytest.mark.parametrize("limit", ["exact", "bundle", "count", "artifact", "artifact_boundary"])
def test_budget_cases_match_actual_required_report_inputs_and_refusals(tmp_path, monkeypatch, limit):
    oracle_root = tmp_path / "oracle"
    _, oracle_policies, oracle_raw, _ = original_inputs(oracle_root)
    original = {path.name: path.read_bytes() for path in oracle_root.iterdir()}
    oracle = presence.PresenceRun.open_required_report_folder(oracle_root, LIMITS, oracle_policies, oracle_raw)
    held = presence.PresenceRun.required_premises(oracle)
    assert oracle_raw is not None and held.baseline_raw is oracle_raw
    measured = original | {"fhrp_gateway_policy": held.scope.raw, "fhrp_redundancy_baseline": oracle_raw}
    sizes = {name: len(raw) for name, raw in measured.items()}
    largest = max(sizes.values())
    expected = replace(LIMITS,
        bundle_bytes=sum(sizes.values()) - (limit == "bundle"),
        artifacts=len(sizes) - (limit == "count"),
        artifact_bytes=len(oracle_raw) - 1 if limit == "artifact" else largest - (limit == "artifact_boundary"))

    root = tmp_path / "inputs"
    with monkeypatch.context() as rejecting:
        forbid_observations(rejecting)
        budgets, policies, raw = budget_inputs(root, limit)
        assert budgets == expected and policies == oracle_policies and raw == oracle_raw
        assert {path.name: path.read_bytes() for path in root.iterdir()} == original
        if limit != "exact":
            with pytest.raises(BudgetExceeded) as refused:
                presence.PresenceRun.open_required_report_folder(root, budgets, policies, raw)
            if limit in ("bundle", "count"):
                assert refused.value.member == "fhrp_redundancy_baseline"
            else:
                assert sizes[refused.value.member] > budgets.artifact_bytes
            return

    live = presence.PresenceRun.open_required_report_folder(root, budgets, policies, raw)
    prepared = presence.PresenceRun.required_premises(live)
    assert prepared.scope.raw == held.scope.raw and prepared.baseline_raw is raw
    assert len(prepared.rows) == 1 and prepared.rows[0].primary_gap is None
    assert len(presence.PresenceRun.presence_rows(live)) == 6


@pytest.mark.parametrize("active", ["hsrp", "stp", "ec", "reader", "writer"])
def test_each_observation_tripwire_is_reachable_in_the_real_factory(tmp_path, monkeypatch, active):
    root = tmp_path / "inputs"
    _, policies, raw, _ = original_inputs(root)
    originals = forbid_observations(monkeypatch)
    for name, (owner, attr, original) in originals.items():
        if name != active:
            monkeypatch.setattr(owner, attr, original)
    with pytest.raises(pytest.fail.Exception, match=f"^unexpected {active} observation$"):
        presence.PresenceRun.open_required_report_folder(root, LIMITS, policies, raw)
