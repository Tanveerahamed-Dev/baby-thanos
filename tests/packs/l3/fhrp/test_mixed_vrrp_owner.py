"""Actual test-owned mixed VRRP production; no product executor, Source or five-Store qualification."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_version_owner import dispatch, freeze, reader, stage

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import global_parse, mixed_profile
from atlas_brain.packs.l3.fhrp import version_profile as vp
from atlas_brain.packs.l3.fhrp import vrrp_owner as vr
from atlas_brain.packs.l3.fhrp import vrrp_profile as rp
from atlas_brain.packs.l3.fhrp.vrrp_proofs import LocalVRRPProofIndex
from atlas_brain.runner.pack_runtime import Handler


def staged(root, mode="normal", execute=True):
    run = stage(root, mode, execute=False)
    unused = run.vrrp
    run.vrrp = vr.MixedVRRPOwner(run.envelope, run.budgets, run.v.domains, run.v.requests)
    run.handlers = run.handlers[:-1] + (Handler(binding=rp.BINDING, parser=run.vrrp),)
    assert not unused.attempted and unused.production is None
    if execute:
        dispatch(run)
    return run


def production(root, monkeypatch, mode="normal"):
    run = staged(root, mode)
    run.result = run.vrrp.finish()
    run.version_result = run.version.finish(run.all_outputs)
    freeze(monkeypatch)
    assert run.vrrp.validate_values(run.result, reader(run.result, rp.REPORTED_VRRP_STATE)) is None
    return run


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "partial", "error"])
def test_actual_mixed_batch_rows_have_fixed_outer_metadata_original_evidence_and_unchanged_population(tmp_path, monkeypatch, mode):
    run = staged(tmp_path, mode)
    assert len(run.handlers) == 5 and {handler.binding for handler in run.handlers} == set(mixed_profile.compile_mixed_profile().operations)
    assert run.handlers[-1].parser is run.vrrp and run.handlers[-2].parser is run.version
    assert run.vrrp.inputs.registration_sha256 == rp.compile_vrrp_profile().registration_sha256
    assert run.vrrp.registration == (run.v.compiled.catalogue_bytes, run.v.compiled.registration_bytes, run.v.compiled.registration_sha256)
    assert run.vrrp.inputs.registration_sha256 != run.envelope.registration_sha256
    for output in run.vrrp.executed:
        request = next(request for request in run.v.requests if request.capture.id == output.receipt.capture.id)
        assert output.receipt.capture is request.capture and output.receipt.parse is output.value.parse
        assert output.receipt.owner == rp.STEP.id and output.receipt.registration_sha256 == run.envelope.registration_sha256
    result = run.vrrp.finish()
    freeze(monkeypatch)
    assert result.executed is run.vrrp.executed and result.registration_sha256 == run.envelope.registration_sha256
    assert run.vrrp.canonical_rows() == result.rows
    assert run.vrrp.validate_values(result, reader(result, rp.REPORTED_VRRP_STATE)) is None
    assert len(result.rows) == len(result.store.values) == len(run.v.subjects) == 2
    for row in result.rows:
        refs = run.v.declarations[row.target.context, row.target.node.key]
        assert len(refs) == 3 and row.value.evidence[:3] == refs
        assert all(a is b for a, b in zip(row.value.evidence, refs))
        assert result.store.values[k.FactRef(fact=rp.REPORTED_VRRP_STATE, subject=row.subject)] is row.value
        if type(row.value) is k.Unknown:
            need, = row.value.next_evidence
            assert need.operation == rp.BINDING.operation and need.resolves == (rp.REPORTED_VRRP_STATE,)
            assert row.value.candidates == ()
    if mode == "normal":
        assert {row.value.value for row in result.rows if type(row.value) is k.Known} == {"backup"}
        assert any(type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE for row in result.rows)
    else:
        reason = k.UnknownReason.PARSE_PARTIAL if mode == "partial" else k.UnknownReason.CAPTURE_ERROR if mode == "error" else k.UnknownReason.NOT_COLLECTED
        if mode != "only_vrrp":
            assert all(type(row.value) is k.Unknown and row.value.reason is reason for row in result.rows)


@pytest.mark.parametrize("plant", ["local_receipt", "foreign_output", "value_copy", "parse_copy", "drop",
    "cache", "cold_node", "unrelated_owner", "raw_member", "budget"])
def test_actual_cache_receipts_and_all_current_context_data_close_before_vrrp_store(tmp_path, monkeypatch, plant):
    run = staged(tmp_path)
    owner, outputs = run.vrrp, run.vrrp.executed
    freeze(monkeypatch)
    assert owner.canonical_rows()
    code, exception = "vrrp_owner_cache", ValueError
    if plant in ("local_receipt", "foreign_output", "value_copy", "parse_copy", "drop"):
        output = outputs[0]
        if plant == "local_receipt":
            outputs = (replace(output, receipt=replace(output.receipt, registration_sha256=rp.compile_vrrp_profile().registration_sha256)),)
            code = "vrrp_owner_receipt"
        elif plant == "foreign_output":
            outputs = run.all_outputs
            code = "vrrp_owner_receipt"
        elif plant == "value_copy":
            outputs = (replace(output, value=replace(output.value)),)
        elif plant == "parse_copy":
            outputs = (replace(output, receipt=replace(output.receipt, parse=replace(output.receipt.parse))),)
        else:
            outputs, code = (), "vrrp_owner_coverage"
        owner.executed = outputs
    elif plant == "cache":
        owner.produced.clear()
    elif plant == "cold_node":
        object.__setattr__(next(node for node in run.envelope.base.nodes if node.id == "b"), "ports", ("Gi1/0/2",))
        code = "fhrp_mixed_context_node"
    elif plant == "unrelated_owner":
        object.__setattr__(next(target for target in run.envelope.targets if target.operation == vp.BINDING.operation), "owner", "l3.fhrp/other")
        code = "fhrp_mixed_context_target"
    elif plant == "raw_member":
        member = next(member for member in run.envelope.captures if member.target.operation == vp.BINDING.operation)
        object.__setattr__(member, "raw", member.raw + b"\n")
        code = "hsrp_folder_member"
    else:
        object.__setattr__(run.budgets, "artifacts", 1)
        code, exception = "budget_exceeded", global_parse.BudgetExceeded
    with pytest.raises(exception, match="^" + code + "$") as caught:
        owner.finish()
    if plant == "budget":
        assert caught.value.member == "fhrp_mixed_context_raw_budget"
    assert owner.production_attempted and owner.production is owner.completed is None


@pytest.mark.parametrize("state", ["known", "unknown", "cold"])
@pytest.mark.parametrize("plant", ["equal_cell", "store_copy", "cross_protocol", "declaration"])
def test_original_selected_and_unselected_vrrp_cells_are_retained_under_mixed_metadata(tmp_path, monkeypatch, state, plant):
    run = production(tmp_path, monkeypatch, "cold_vrrp" if state == "cold" else "normal")
    owner, result = run.vrrp, run.result
    row = next(row for row in result.rows if (type(row.value) is k.Known) == (state == "known"))
    assert state != "cold" or row.value.reason is k.UnknownReason.NOT_COLLECTED
    ref = k.FactRef(fact=rp.REPORTED_VRRP_STATE, subject=row.subject)
    copy = replace(row.value)
    assert copy == row.value and copy is not row.value
    if plant == "equal_cell":
        object.__setattr__(row, "value", copy)
        result.store.values[ref] = copy
    elif plant == "declaration":
        object.__setattr__(row.value, "evidence", row.target.node.declaration.evidence)
    else:
        result.store.values[ref] = copy if plant == "store_copy" else run.version_result.rows[0].value
    with pytest.raises(ValueError, match="^vrrp_owner_" + ("value_cell" if plant in ("equal_cell", "declaration") else "value_reader") + "$"):
        owner.validate_values(result, reader(result, rp.REPORTED_VRRP_STATE))


@pytest.mark.parametrize("plant", ["result_copy", "owner", "extra_cell", "alias_key", "foreign_reader", "reader_grant"])
def test_current_mixed_result_store_and_reader_binding_preserve_base_guards(tmp_path, monkeypatch, plant):
    run = production(tmp_path, monkeypatch)
    result, handle, code = run.result, reader(run.result, rp.REPORTED_VRRP_STATE), "vrrp_owner_value_store"
    assert run.vrrp.validate_values(result, replace(handle)) is None
    if plant == "result_copy":
        result, code = replace(result), "vrrp_owner_value_source"
    elif plant == "owner":
        result.store.owners[rp.REPORTED_VRRP_STATE] = vp.STEP.id
    elif plant == "extra_cell":
        result.store.values[k.FactRef(fact=vp.REPORTED_PROTOCOL_VERSION, subject=run.version_result.rows[0].subject)] = run.version_result.rows[0].value
    elif plant == "alias_key":
        old = next(iter(result.store.values))
        new = k.FactRef(fact=old.fact, subject=old.subject)
        object.__setattr__(new, "fact", StrEnum("Alias", {"VALUE": old.fact}).VALUE)
        result.store.values = {new if ref == old else ref: value for ref, value in result.store.values.items()}
    else:
        handle = replace(handle, store=run.version_result.store) if plant == "foreign_reader" else replace(handle,
            step=replace(handle.step, reads=(vp.REPORTED_PROTOCOL_VERSION,)))
        code = "vrrp_owner_reader"
    with pytest.raises(ValueError, match="^" + code + "$"):
        run.vrrp.validate_values(result, handle)


def test_parse_and_finish_are_once_and_legacy_local_proofs_refuse_mixed_owner(tmp_path, monkeypatch):
    run = staged(tmp_path)
    local = vr.execute_local_vrrp_inputs(run.v.domains, run.v.requests)
    result = run.vrrp.finish()
    freeze(monkeypatch)
    index = LocalVRRPProofIndex(owner=local.owner, result=local.result, reader=reader(local.result, rp.REPORTED_VRRP_STATE))
    for row in local.result.rows:
        assert tuple(ref for ref in row.value.evidence if type(ref) is k.RegistryRef) == row.target.node.declaration.evidence
        assert index.resolve(k.FactRef(fact=rp.REPORTED_VRRP_STATE, subject=row.subject)).state is row.value
    with pytest.raises(ValueError, match="^vrrp_proofs_owner$"):
        LocalVRRPProofIndex(owner=run.vrrp, result=result, reader=reader(result, rp.REPORTED_VRRP_STATE))
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        run.vrrp.finish()
    with pytest.raises(ValueError, match="^vrrp_owner_request$"):
        run.vrrp.parse(run.v.requests[0])
    local.owner.registration = run.vrrp.registration
    local.owner.validate_registration = lambda: None
    with pytest.raises(ValueError, match="^vrrp_owner_registration$"):
        vr.VRRPOwner.validate_inputs(local.owner)


def test_writer_failure_retains_actual_unreturned_partial_store_and_consumed_owner(tmp_path, monkeypatch):
    run = staged(tmp_path)
    freeze(monkeypatch, writers=False)
    assert run.vrrp.canonical_rows()
    original, stores = FactWriter.write, []
    def writing(self, **kwargs):
        stores.append(self.store)
        if len(stores) == 2:
            raise ValueError("planted_writer")
        return original(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^planted_writer$"):
        run.vrrp.finish()
    assert run.vrrp.production_attempted and run.vrrp.production is run.vrrp.completed is None
    assert len(stores) == 2 and stores[0] is stores[1] and len(stores[0].values) == 1
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        run.vrrp.finish()


def test_failed_actual_batch_finally_keeps_attempted_not_running_without_vrrp_result(tmp_path, monkeypatch):
    baseline = staged(tmp_path / "baseline")
    assert baseline.vrrp.canonical_rows()
    run = staged(tmp_path / "failed", execute=False)
    def refusing(*args, **kwargs):
        raise ValueError("planted_vrrp_parse")
    monkeypatch.setattr(rp.parser, "parse_capture", refusing)
    with pytest.raises(ValueError, match="^planted_vrrp_parse$"):
        dispatch(run)
    assert run.ledger is run.vrrp.executed is None and run.vrrp.attempted and not run.vrrp.running
    assert run.vrrp.production is run.vrrp.completed is None and not run.vrrp.production_attempted
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        run.vrrp.finish()


@pytest.mark.parametrize("path", ["construct", "base_construct", "mixed_construct", "wrong_receiver",
    "parse", "inputs", "registration", "evidence", "canonical", "finish", "values"])
def test_derived_and_wrong_receivers_refuse_before_shadowed_hooks_on_every_supported_path(tmp_path, monkeypatch, path):
    run = production(tmp_path, monkeypatch)
    calls = []
    class Derived(vr.MixedVRRPOwner):
        def validate_inputs(self):
            calls.append("inputs")
        def validate_registration(self):
            calls.append("registration")
        def declaration_evidence(self):
            calls.append("evidence")
            return {}
        def canonical_rows(self):
            calls.append("canonical")
            return ()
    with pytest.raises(ValueError, match="^vrrp_owner_receiver$"):
        if path == "construct":
            Derived(run.envelope, run.budgets, run.v.domains, run.v.requests)
        else:
            forged = object.__new__(Derived)
            for name, value in vars(run.vrrp).items():
                setattr(forged, name, value)
            if path == "base_construct":
                vr.VRRPOwner.__init__(forged, run.v.domains, run.v.requests)
            elif path in ("mixed_construct", "wrong_receiver"):
                vr.MixedVRRPOwner.__init__(forged if path == "mixed_construct" else object(), run.envelope, run.budgets, run.v.domains, run.v.requests)
            elif path == "parse":
                vr.VRRPOwner.parse(forged, run.v.requests[0])
            elif path == "values":
                vr.VRRPOwner.validate_values(forged, run.result, reader(run.result, rp.REPORTED_VRRP_STATE))
            else:
                getattr(vr.VRRPOwner, {"inputs": "validate_inputs", "registration": "validate_registration",
                    "evidence": "declaration_evidence", "canonical": "canonical_rows", "finish": "finish"}[path])(forged)
    assert calls == []


@pytest.mark.parametrize("hook", ["validate_inputs", "validate_registration", "declaration_evidence", "canonical_rows"])
def test_exact_named_owner_ignores_weak_instance_hooks_and_still_requires_current_context(tmp_path, monkeypatch, hook):
    run = staged(tmp_path, execute=False)
    calls = []
    def weakened(*args, **kwargs):
        calls.append(hook)
        return {} if hook == "declaration_evidence" else () if hook == "canonical_rows" else None
    setattr(run.vrrp, hook, weakened)
    dispatch(run)
    result = vr.VRRPOwner.finish(run.vrrp)
    freeze(monkeypatch)
    assert vr.VRRPOwner.validate_values(run.vrrp, result, reader(result, rp.REPORTED_VRRP_STATE)) is None
    assert len(result.rows) == 2 and all(row.value.evidence[:3] == run.v.declarations[row.target.context, row.target.node.key] for row in result.rows)
    object.__setattr__(next(target for target in run.envelope.targets if target.operation == vp.BINDING.operation), "owner", "l3.fhrp/other")
    with pytest.raises(ValueError, match="^fhrp_mixed_context_target$"):
        vr.VRRPOwner.validate_values(run.vrrp, result, reader(result, rp.REPORTED_VRRP_STATE))
    assert calls == []


@pytest.mark.parametrize("field", ["catalogue", "registration", "hash", "hash_alias", "local_hash"])
def test_outer_fixed_metadata_and_local_hash_remain_separate_before_store_production(tmp_path, monkeypatch, field):
    run = staged(tmp_path)
    freeze(monkeypatch)
    assert run.vrrp.canonical_rows()
    if field == "local_hash":
        object.__setattr__(run.vrrp.inputs, "registration_sha256", run.envelope.registration_sha256)
    else:
        values = list(run.vrrp.registration)
        index = 0 if field == "catalogue" else 1 if field == "registration" else 2
        values[index] = b"changed" if index < 2 else StrEnum("Alias", {"VALUE": values[index]}).VALUE if field == "hash_alias" else "0" * 64
        run.vrrp.registration = tuple(values)
    with pytest.raises(ValueError, match="^" + ("vrrp_inputs_input" if field == "local_hash" else "vrrp_owner_mixed_registration") + "$"):
        run.vrrp.finish()
    assert run.vrrp.production_attempted and run.vrrp.production is run.vrrp.completed is None
