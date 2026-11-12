"""Retain the one legacy producer across real admission, runtime, writers and evidence needs."""
import json
from dataclasses import FrozenInstanceError, replace

import pytest
from test_build import body, request, target

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.specs import StepId
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import p4
from tools import p4_estate_cases as estate

LIMITS = Budgets(1000000, 1000000, 1000)
ROOT, ROLE, STEP = "l2.stp.root_guard", "l2.stp.reported_role", "l2.stp/parse_root_guard"


def files(root, case="baseline", *, singleton=False, captured=True):
    inputs = estate.members(canonical, case)
    if singleton:
        side = json.loads(inputs["p4.json"])
        side["targets"] = [row for row in side["targets"] if row["id"] == "tree"]
        side["captures"] = [row for row in side["captures"] if captured and row["target"] == "tree"]
        keep = {"p2.json", "p4.json", "discovery.txt", *(row["path"] for row in side["captures"])}
        inputs = {name: raw for name, raw in inputs.items() if name in keep}
        inputs["p4.json"] = canonical(side)
    root.mkdir(parents=True, exist_ok=True)
    for name, raw in inputs.items():
        (root / name).write_bytes(raw)
    return inputs


def invoke(flow, root, *, captured=True):
    if flow == "local":
        point = target()
        requests = (request(point, body(point, "disabled", 1) + body(point, "disabled", 2)),) if captured else ()
        return b.build_root_guard((point,), requests), requests
    files(root, singleton=True, captured=captured)
    if flow == "folder":
        result = b.build_root_guard_folder(root, LIMITS)
        return result.result, result.envelope
    result = b.build_root_guard_global(root, LIMITS, peers=())
    return result.result, result.execution


def assert_canonical_rows(result, *, missing=False):
    expected = {k.FactRef(fact=k.FactId(fact), subject=row.subject)
        for row in result.rows for fact in (ROOT, ROLE)}
    assert set(result.store.values) == expected and result.store.owners == {ROOT: StepId(STEP), ROLE: StepId(STEP)}
    reader = bind_reader(result.store, step=p4.PROJECT)
    for row in result.rows:
        for fact, value in ((ROOT, row.value), (ROLE, row.role)):
            assert reader.read(fact=k.FactId(fact), subject=row.subject) is value
            assert result.store.values[k.FactRef(fact=k.FactId(fact), subject=row.subject)] is value
            if missing:
                assert type(value) is k.Unknown and value.reason is k.UnknownReason.NOT_COLLECTED
                need, = value.next_evidence
                assert need.reruns == (StepId(STEP),) and need.resolves == (k.FactId(fact),)
                assert need.operation == "iosxe.show_spanning_tree_interface_detail" and need.params == (("port", row.target.port),)


@pytest.mark.parametrize("case", ["baseline", "pagp", "missing"])
def test_all_five_observation_files_match_the_independent_fixed_qualified_oracle(tmp_path, case):
    inputs = files(tmp_path, case)
    before = dict(inputs)
    reports = p4.analyse_folder(tmp_path, LIMITS)
    receipt = estate.validate(reports, inputs, case, canonical)
    assert set(reports) == {"result.json", "MANIFEST.sha256", "facts/stp_port_vlan.jsonl",
        "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl"}
    assert receipt["facts"] == 19 and (receipt["known"], receipt["unknown"]) == ((4, 15) if case == "missing" else (11, 8))
    assert receipt["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}
    assert {name: (tmp_path / name).read_bytes() for name in inputs} == before


@pytest.mark.parametrize("field", ["declaration", "binding", "step"])
def test_private_closed_bundle_is_identity_bound_frozen_and_not_a_profile_parameter(field):
    producer = b._legacy_producer()
    assert producer.declaration is b.DECLARATION and producer.binding is b.BINDING and producer.step is b.STEP
    assert not hasattr(producer, "__dict__")
    with pytest.raises(FrozenInstanceError):
        producer.step = b.STEP
    changed = {"declaration": b.DECLARATION, "binding": b.BINDING, "step": b.STEP}
    changed[field] = replace(changed[field])
    with pytest.raises(ValueError, match="^stp_producer_profile$"):
        b._Producer(**changed)
    with pytest.raises(TypeError):
        b._legacy_producer(producer)


@pytest.mark.parametrize("flow", ["local", "folder", "global"])
def test_public_builders_have_no_caller_selected_producer_argument(tmp_path, monkeypatch, flow):
    producer = b._legacy_producer()
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before unsupported public argument"))
    with pytest.raises(TypeError, match="producer"):
        if flow == "local":
            b.build_root_guard((target(),), (), producer=producer)
        elif flow == "folder":
            b.build_root_guard_folder(tmp_path, LIMITS, producer=producer)
        else:
            b.build_root_guard_global(tmp_path, LIMITS, peers=(), producer=producer)


@pytest.mark.parametrize("flow", ["local", "folder", "global"])
def test_one_bundle_survives_equal_metadata_and_foreign_binding_rebinding(tmp_path, monkeypatch, flow):
    baseline, _ = invoke(flow, tmp_path / "source")
    calls, scopes, writes = [], [], []
    factory, scoped, writer = b._legacy_producer, b._scope, b.bind_writer
    execute = b.p4_pipeline.execute_parsers if flow == "global" else b.execute_parsers
    legacy = b.DECLARATION, b.BINDING, b.STEP
    def captured():
        producer = factory()
        calls.append(producer)
        patch.setattr(b, "DECLARATION", replace(legacy[0]))
        patch.setattr(b, "STEP", replace(legacy[2]))
        patch.setattr(b, "BINDING", replace(legacy[1], step=StepId("l2.stp/foreign_binding")))
        return producer
    def scope(envelope, budgets, producer, **kwargs):
        assert producer is calls[0]
        scopes.append(envelope)
        return scoped(envelope, budgets, producer, **kwargs)
    def runtime(declarations, handlers, requests):
        assert len(calls) == 1 and declarations == (legacy[0],) and declarations[0] is calls[0].declaration
        assert len(handlers) == 1 and handlers[0].binding is calls[0].binding is legacy[1]
        return execute(declarations, handlers, requests)
    def bound(store, *, step):
        assert step is calls[0].step is legacy[2]
        writes.append(step)
        return writer(store, step=step)
    with monkeypatch.context() as patch:
        patch.setattr(b, "_legacy_producer", captured)
        patch.setattr(b, "_scope", scope)
        patch.setattr(b, "bind_writer", bound)
        patch.setattr(b.p4_pipeline if flow == "global" else b, "execute_parsers", runtime)
        result, context = invoke(flow, tmp_path / "source")
        assert b.BINDING.step == "l2.stp/foreign_binding" and b.STEP is not legacy[2]
    assert len(calls) == len(writes) == 1 and len(scopes) == (0 if flow == "local" else 1)
    assert result.rows == baseline.rows and result.store.values == baseline.store.values
    assert result.store.owners == baseline.store.owners and result.executed == baseline.executed
    for output in result.executed:
        assert output.receipt.parse is output.value.parse and output.receipt.owner == STEP
        assert output.receipt.registration_sha256 == compile_packs((legacy[0],)).registration_sha256
    if flow == "local":
        assert result.executed[0].receipt.capture is context[0].capture
    else:
        envelope = context.envelope if flow == "global" else context
        assert envelope.registration_sha256 == compile_packs((legacy[0],)).registration_sha256
    assert_canonical_rows(result)


@pytest.mark.parametrize("flow", ["local", "folder", "global"])
def test_real_empty_execution_retains_original_writer_and_both_unknown_rerun_needs(tmp_path, monkeypatch, flow):
    legacy, writes, calls = b.STEP, [], []
    execute = b.p4_pipeline.execute_parsers if flow == "global" else b.execute_parsers
    writer = b.bind_writer
    def completed(declarations, handlers, requests):
        assert requests == ()
        outputs = execute(declarations, handlers, requests)
        assert outputs == ()
        patch.setattr(b, "STEP", replace(legacy, id=StepId("l2.stp/foreign_after_execution")))
        calls.append(outputs)
        return outputs
    def bound(store, *, step):
        assert step is legacy
        writes.append(step)
        return writer(store, step=step)
    with monkeypatch.context() as patch:
        patch.setattr(b.p4_pipeline if flow == "global" else b, "execute_parsers", completed)
        patch.setattr(b, "bind_writer", bound)
        result, _ = invoke(flow, tmp_path, captured=False)
        assert b.STEP.id == "l2.stp/foreign_after_execution" and len(calls) == len(writes) == 1
        assert_canonical_rows(result, missing=True)
    assert result.executed == () and result.rows


@pytest.mark.parametrize("flow", ["local", "folder", "global"])
def test_captured_execution_cannot_launder_a_foreign_raw_hook_owner_before_writer(tmp_path, monkeypatch, flow):
    legacy = b.STEP
    execute = b.p4_pipeline.execute_parsers if flow == "global" else b.execute_parsers
    def completed(declarations, handlers, requests):
        outputs = execute(declarations, handlers, requests)
        assert outputs
        patch.setattr(b, "STEP", replace(legacy, id=StepId("l2.stp/foreign_after_execution")))
        return outputs
    with monkeypatch.context() as patch:
        patch.setattr(b.p4_pipeline if flow == "global" else b, "execute_parsers", completed)
        patch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before foreign raw-owner refusal"))
        with pytest.raises(ValueError, match="^stp_proof_binding$"):
            invoke(flow, tmp_path)


@pytest.mark.parametrize("flow", ["local", "folder", "global"])
@pytest.mark.parametrize("plant", ["owner", "operation"])
def test_initial_wrong_binding_is_rejected_by_real_runtime_before_writes(tmp_path, monkeypatch, flow, plant):
    binding = replace(b.BINDING, **({"step": StepId("l2.stp/foreign_binding")} if plant == "owner" else {"operation": "iosxe.show_unregistered"}))
    monkeypatch.setattr(b, "BINDING", binding)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before real binding gate"))
    code = "p4_pipeline_handler_claims" if flow == "global" else "pack_runtime_handler_owner" if plant == "owner" else "pack_runtime_handler_coverage"
    with pytest.raises(ValueError, match="^" + code + "$"):
        invoke(flow, tmp_path)


@pytest.mark.parametrize("flow", ["folder", "global"])
def test_forged_profile_digest_refuses_after_real_admission_before_writes(tmp_path, monkeypatch, flow):
    admitted = b.p4_admission.admit_folder
    def changed(*args, **kwargs):
        envelope = admitted(*args, **kwargs)
        return replace(envelope, registration_sha256="0" * 64)
    monkeypatch.setattr(b.p4_admission, "admit_folder", changed)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before registration guard"))
    with pytest.raises(ValueError, match="^" + ("stp_folder_registration" if flow == "folder" else "p4_pipeline_registration") + "$"):
        invoke(flow, tmp_path)
