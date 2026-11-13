"""Real FHRP shared execution/canonical data only; no Writer or source/admission seal."""
from dataclasses import replace

import pytest
from test_state_owner import LIMITS
from test_state_version_input_preparation import folder

from atlas_brain.model.store import FactStore
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import state_version_execution as runtime
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as profile


def no_store(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("lower execution constructed a Store or Writer")
    monkeypatch.setattr(FactStore, "__init__", forbidden)
    monkeypatch.setattr(b, "bind_writer", forbidden)
    monkeypatch.setattr(vo, "bind_writer", forbidden)


def test_one_actual_fixed_batch_returns_original_owning_data_and_recloses_without_replay(tmp_path, monkeypatch):
    folder(tmp_path)
    no_store(monkeypatch)
    execute, calls = runtime.execute_parsers, []
    def executing(*args):
        outputs = execute(*args)
        calls.append((args, outputs))
        return outputs
    monkeypatch.setattr(runtime, "execute_parsers", executing)
    for module in (b, vo):
        monkeypatch.setattr(module, "execute_parsers", lambda *args: pytest.fail("local executor"))
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    assert source.attempted and len(calls) == 1
    envelope, outputs, state, owner, brief_outputs, version_outputs, original_budget = source.canonical_outputs()
    assert source.batch.envelope is envelope and source.batch.outputs is outputs is calls[0][1]
    assert calls[0][0][0] == (profile.STATE_VERSION_DECLARATION,)
    assert len(outputs) == 2 and len(brief_outputs) == len(version_outputs) == 1
    assert type(state) is b.StateOwner and type(owner) is vo.GlobalVersionOwner
    assert owner.envelope is envelope and owner.budgets is original_budget is LIMITS
    assert source.batch.budgets is original_budget
    for out in outputs:
        original = next(item for item in brief_outputs + version_outputs if item.receipt is out.receipt)
        assert original.value is out.value and out.receipt.parse is out.value.parse
        assert out.receipt.registration_sha256 == envelope.registration_sha256
    def forbidden(*args):
        pytest.fail("canonical data closure replayed parser or batch")
    monkeypatch.setattr(runtime, "execute_parsers", forbidden)
    monkeypatch.setattr(b.hsrp, "parse_capture", forbidden)
    monkeypatch.setattr(gp.all_hsrp, "parse_capture", forbidden)
    assert source.canonical_outputs()[0] is envelope
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        source.execute()


@pytest.mark.parametrize("phase", ["preparation", "batch", "canonical"])
def test_actual_lower_attempt_consumed_on_refusal_without_publishing_batch(tmp_path, monkeypatch, phase):
    folder(tmp_path)
    no_store(monkeypatch)
    source = runtime.StateVersionExecution(tmp_path, LIMITS)
    def refusing(*args, **kwargs):
        raise ValueError("planted_lower")
    if phase == "preparation":
        monkeypatch.setattr(runtime.preparation, "prepare_state_version_inputs", refusing)
    elif phase == "batch":
        monkeypatch.setattr(runtime, "execute_parsers", refusing)
    else:
        execute = runtime.execute_parsers
        def changed(*args):
            outputs = execute(*args)
            return outputs[:-1]
        monkeypatch.setattr(runtime, "execute_parsers", changed)
    with pytest.raises(ValueError):
        source.execute()
    assert source.attempted and source.batch is None
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        source.execute()


@pytest.mark.parametrize("plant", ["receipt", "capture", "parse", "cold_domain", "request_line"])
def test_current_real_batch_graph_and_ledger_refuse_without_stores(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    no_store(monkeypatch)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    batch = source.batch
    item = batch.outputs[-1]
    if plant == "cold_domain":
        batch.source.indexed.pop(next(key for key, target in batch.source.indexed.items() if target.node.id == "b"))
    elif plant == "request_line":
        object.__setattr__(batch.brief_requests[0].capture.lines[0].span, "start", [])
    else:
        changed = replace(item, receipt=replace(item.receipt, owner="l3.fhrp/wrong")) if plant == "receipt" else (
            replace(item, receipt=replace(item.receipt, capture=replace(item.receipt.capture))) if plant == "capture" else
            replace(item, receipt=replace(item.receipt, parse=replace(item.receipt.parse))))
        object.__setattr__(batch, "outputs", tuple(changed if out is item else out for out in batch.outputs))
    with pytest.raises(ValueError):
        source.canonical_outputs()


def test_lower_canonical_data_does_not_claim_production_readiness(tmp_path, monkeypatch):
    folder(tmp_path)
    no_store(monkeypatch)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    owner = source.batch.owner
    owner.production_attempted = True
    assert source.canonical_outputs()[3] is owner
    assert owner.production is None


def test_unexecuted_carrier_has_no_canonical_batch(tmp_path):
    source = runtime.StateVersionExecution(tmp_path, LIMITS)
    with pytest.raises(ValueError, match="hsrp_state_version_batch"):
        source.canonical_outputs()
