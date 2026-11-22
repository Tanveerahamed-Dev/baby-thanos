"""Use the actual P4 envelope for census preparation without reopening its folder."""
import pytest
from census_request_cases import (
    assert_census_plan,
    forbid_observations,
    input_folder,
    observe_admission,
    observe_brief_preparation,
)
from test_gateway_source import LIMITS

from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import census_requests as requests
from atlas_brain.packs.l3.fhrp import required_report_census_profile as profile
from atlas_brain.runner import p4_pipeline


class _PreparationObserved(Exception):
    """Stop the test adapter at the genuine preparation handoff."""


@pytest.mark.parametrize("second", [None, b""])
def test_pipeline_census_preparation_uses_its_one_actual_envelope(tmp_path, monkeypatch, second):
    root = tmp_path / "inputs"
    files, side = input_folder(root, second)
    forbid_observations(monkeypatch)
    admitted = observe_admission(monkeypatch)
    batches = observe_brief_preparation(monkeypatch, forbid_owner=True)
    plans = []

    class CensusPreparation(p4_pipeline.Pack[object]):
        def declaration(self):
            return profile.declaration()

        def prepare(self, envelope):
            assert len(admitted) == 1 and envelope is admitted[0]
            plans.append(requests.prepare_census_envelope(envelope, LIMITS))
            raise _PreparationObserved

    peers = stp.RootGuardPack[object](LIMITS), SummaryPack[object](LIMITS), CensusPreparation()
    with pytest.raises(_PreparationObserved):
        p4_pipeline.execute_p4_folder(root, LIMITS, packs=peers)
    assert len(admitted) == len(batches) == len(plans) == 1
    plan, = plans
    batch, = batches
    assert plan.envelope is admitted[0] and plan.brief is batch.handlers[0].parser
    assert plan.brief_bindings.requests is batch.requests
    assert_census_plan(plan, root, files, side, second)
