"""Test-owned five-operation batches qualify VERSION only; mixed VRRP production remains outside."""
from dataclasses import replace
from enum import StrEnum
from types import SimpleNamespace

import pytest
from test_mixed_context import admitted
from test_parse_vrrp import BODY
from test_peer_execution import forbidden
from test_peer_version_closure import actual as legacy_closed
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactStore, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import (
    build,
    global_parse,
    mixed_profile,
    mixed_vrrp_inputs,
)
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as vp
from atlas_brain.packs.l3.fhrp import vrrp_owner as vr
from atlas_brain.packs.l3.fhrp import vrrp_profile as rp
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_runtime import Handler


def stage(root, mode="normal", execute=True):
    if mode in ("partial", "error"):
        def changing(side, files):
            side["targets"].append({"id": "vrrp", "node": "a", "operation": rp.parser.OP,
                "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]}})
            files["vrrp.txt"] = BODY + (b"unrecognized\n" if mode == "partial" else b"% synthetic error\n")
            side["captures"].append({"target": "vrrp", "path": "vrrp.txt"})
        folder(root, change=changing)
        envelope = global_parse.p4.admit_folder(root, LIMITS, declarations=mixed_profile.DECLARATIONS)
    else:
        envelope, _ = admitted(root, mode)
    budgets = replace(LIMITS)
    h = global_parse.prepare_mixed_hsrp_inputs(envelope, budgets)
    v = mixed_vrrp_inputs.prepare_mixed_vrrp_inputs(envelope, budgets)
    tree, channel = stp.RootGuardPack(budgets), SummaryPack(budgets)
    first, second = tree.prepare(envelope), channel.prepare(envelope)
    state = build.StateOwner(envelope, budgets, h.domains, h.requests)
    version = vo.MixedGlobalVersionOwner(envelope, budgets, h.domains, h.version.requests)
    vrrp = vr.VRRPOwner(v.domains, v.requests)
    handlers = first.handlers + second.handlers + (Handler(binding=build.BINDING, parser=state),
        Handler(binding=vp.BINDING, parser=version), Handler(binding=rp.BINDING, parser=vrrp))
    requests = first.requests + second.requests + h.requests + h.version.requests + v.requests
    run = SimpleNamespace(envelope=envelope, budgets=budgets, h=h, v=v, version=version, vrrp=vrrp,
        tree=tree, channel=channel, state=state, handlers=handlers, requests=requests, ledger=None)
    if execute:
        dispatch(run)
    return run


def dispatch(run):
    run.vrrp.attempted = run.vrrp.running = True
    try:
        run.ledger = pack_runtime.execute_parsers(mixed_profile.DECLARATIONS, run.handlers, run.requests)
    finally:
        run.vrrp.running = False
    run.vrrp.executed = tuple(out for out in run.ledger if out.receipt.capture.operation == rp.parser.OP)
    run.all_outputs = tuple(out for out in run.ledger if out.receipt.capture.operation == vp.BINDING.operation)


def reader(result, fact=vp.REPORTED_PROTOCOL_VERSION):
    return bind_reader(result.store, step=StepSpec(id="l3.fhrp/read_mixed", pack="l3.fhrp", kind="check",
        scope="estate", reads=(fact,), produces=(), evaluator="l3.fhrp.read_mixed"))


def freeze(monkeypatch, writers=True):
    for module in (stp.stp, global_parse.mixed_profile.ec.parse_summary, build.hsrp, global_parse.all_hsrp, rp.parser):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    for module in (pack_runtime, global_parse.p4_pipeline, vr, vo):
        monkeypatch.setattr(module, "execute_parsers", forbidden)
    if writers:
        monkeypatch.setattr(vr, "bind_writer", forbidden)
        monkeypatch.setattr(vo, "bind_writer", forbidden)
        monkeypatch.setattr(FactWriter, "write", forbidden)
        monkeypatch.setattr(FactStore, "__init__", forbidden)


def production(root, monkeypatch):
    run = stage(root)
    run.result = run.version.finish(run.all_outputs)
    run.foreign = FactStore()
    run.foreign.owners, run.foreign.values = dict(run.result.store.owners), dict(run.result.store.values)
    freeze(monkeypatch)
    assert run.version.validate_values(run.result, reader(run.result)) is None
    return run


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "partial", "error"])
def test_real_five_operation_batch_retains_original_version_subset_and_all_declared_evidence(tmp_path, monkeypatch, mode):
    calls, original = [], pack_runtime.execute_parsers
    def executing(declarations, handlers, requests):
        calls.append((declarations, handlers, requests, result := original(declarations, handlers, requests)))
        return result
    monkeypatch.setattr(pack_runtime, "execute_parsers", executing)
    run = stage(tmp_path, mode)
    assert len(calls) == 1 and calls[0] == (mixed_profile.DECLARATIONS, run.handlers, run.requests, run.ledger)
    assert len(run.handlers) == 5 and {handler.binding for handler in run.handlers} == set(mixed_profile.compile_mixed_profile().operations)
    assert tuple(handler.parser for handler in run.handlers[-3:]) == (run.state, run.version, run.vrrp)
    assert {out.receipt.capture.id for out in run.ledger} == {member.id for member in run.envelope.captures}
    for output in run.ledger:
        request = next(request for request in run.requests if request.capture.id == output.receipt.capture.id)
        member = next(member for member in run.envelope.captures if member.id == output.receipt.capture.id)
        assert output.receipt.capture is request.capture and request.capture.raw is member.raw
        assert output.receipt.owner == member.target.owner and output.receipt.registration_sha256 == run.envelope.registration_sha256
        assert output.receipt.parse is output.value.parse
    result = run.version.finish(run.all_outputs)
    freeze(monkeypatch)
    assert result.registration_sha256 == run.envelope.registration_sha256
    assert run.version.canonical_rows(run.all_outputs) == result.rows
    assert run.version.validate_values(result, reader(result)) is None
    assert len(result.rows) == len(result.store.values) == sum(len(domain.groups) for domain in run.h.domains)
    for row in result.rows:
        refs = run.h.declarations[row.target.context, row.target.node.key]
        assert row.value.evidence[:len(refs)] == refs and all(a is b for a, b in zip(row.value.evidence, refs))
        assert result.store.values[k.FactRef(fact=vp.REPORTED_PROTOCOL_VERSION, subject=row.subject)] is row.value
        if type(row.value) is k.Unknown:
            need, = row.value.next_evidence
            assert need.operation == vp.BINDING.operation and need.resolves == (vp.REPORTED_PROTOCOL_VERSION,)
            assert row.value.candidates == ()
    if mode == "none":
        assert all(type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED for row in result.rows)
    if mode == "normal":
        assert {row.value.value for row in result.rows if type(row.value) is k.Known} == {"1", "2"}
    assert run.vrrp.production is None and not run.vrrp.production_attempted


@pytest.mark.parametrize("plant", ["local_receipt", "foreign_output", "value_copy", "parse_copy", "drop",
    "cache", "cold_node", "unrelated_owner", "raw_member", "budget"])
def test_current_version_cache_receipts_and_whole_mixed_context_refuse_before_writer(tmp_path, monkeypatch, plant):
    run = stage(tmp_path)
    owner, outputs = run.version, run.all_outputs
    freeze(monkeypatch)
    assert owner.canonical_rows(outputs)
    code, exception = "hsrp_version_cache", ValueError
    if plant in ("local_receipt", "foreign_output", "value_copy", "parse_copy", "drop"):
        output = outputs[0]
        if plant == "local_receipt":
            outputs = (replace(output, receipt=replace(output.receipt, registration_sha256=vp.compile_version_profile().registration_sha256)),)
            code = "hsrp_version_receipt"
        elif plant == "foreign_output":
            outputs = (next(out for out in run.ledger if out.receipt.capture.operation == rp.BINDING.operation),)
        elif plant == "value_copy":
            outputs = (replace(output, value=replace(output.value)),)
        elif plant == "parse_copy":
            outputs = (replace(output, receipt=replace(output.receipt, parse=replace(output.receipt.parse))),)
        else:
            outputs = ()
    elif plant == "cache":
        owner.inputs.produced.clear()
    elif plant == "cold_node":
        object.__setattr__(next(node for node in run.envelope.base.nodes if node.id == "b"), "ports", ("Gi1/0/2",))
        code = "fhrp_mixed_context_node"
    elif plant == "unrelated_owner":
        object.__setattr__(next(target for target in run.envelope.targets if target.operation == stp.BINDING.operation), "owner", "l3.fhrp/other")
        code = "fhrp_mixed_context_target"
    elif plant == "raw_member":
        member = next(member for member in run.envelope.captures if member.target.operation == stp.BINDING.operation)
        object.__setattr__(member, "raw", member.raw + b"\n")
        code = "hsrp_folder_member"
    else:
        object.__setattr__(run.budgets, "artifacts", 1)
        code, exception = "budget_exceeded", global_parse.BudgetExceeded
    with pytest.raises(exception, match="^" + code + "$") as caught:
        owner.finish(outputs)
    if plant == "budget":
        assert caught.value.member == "fhrp_mixed_context_raw_budget"
    assert owner.production_attempted and owner.production is owner.completed is None


@pytest.mark.parametrize("state", ["known", "unknown", "cold"])
@pytest.mark.parametrize("plant", ["equal_cell", "store_copy", "neighbor_cell"])
def test_every_selected_absent_or_cold_original_version_cell_remains_identity_bound(tmp_path, monkeypatch, state, plant):
    run = production(tmp_path, monkeypatch)
    owner, result = run.version, run.result
    row = next(row for row in result.rows if (type(row.value) is k.Known if state == "known" else type(row.value) is k.Unknown and (row.value.reason is k.UnknownReason.NOT_COLLECTED) == (state == "cold")))
    reference = k.FactRef(fact=vp.REPORTED_PROTOCOL_VERSION, subject=row.subject)
    copy = replace(row.value)
    assert copy == row.value and copy is not row.value
    if plant == "equal_cell":
        object.__setattr__(row, "value", copy)
        result.store.values[reference] = copy
    else:
        result.store.values[reference] = copy if plant == "store_copy" else next(other.value for other in result.rows if other is not row)
    with pytest.raises(ValueError, match="^hsrp_version_" + ("value_cell" if plant == "equal_cell" else "value_reader") + "$"):
        owner.validate_values(result, reader(result))


@pytest.mark.parametrize("plant", ["result_copy", "owner", "extra_cell", "alias_key", "foreign_reader", "reader_grant"])
def test_version_store_and_reader_guards_remain_exact_under_mixed_registration(tmp_path, monkeypatch, plant):
    run = production(tmp_path, monkeypatch)
    owner, result = run.version, run.result
    handle, code = reader(result), "hsrp_version_value_store"
    assert owner.validate_values(result, replace(handle)) is None
    if plant == "result_copy":
        result, code = replace(result), "hsrp_version_value_source"
    elif plant == "owner":
        result.store.owners[vp.REPORTED_PROTOCOL_VERSION] = "l3.fhrp/other"
    elif plant == "extra_cell":
        result.store.values[k.FactRef(fact=vp.REPORTED_PROTOCOL_VERSION, subject="fhrp_local:foreign")] = result.rows[0].value
    elif plant == "alias_key":
        old = next(iter(result.store.values))
        new = k.FactRef(fact=old.fact, subject=old.subject)
        object.__setattr__(new, "fact", StrEnum("Alias", {"VALUE": old.fact}).VALUE)
        result.store.values = {new if reference == old else reference: value for reference, value in result.store.values.items()}
    else:
        handle = replace(handle, store=run.foreign) if plant == "foreign_reader" else replace(handle,
            step=replace(handle.step, reads=(rp.REPORTED_VRRP_STATE,)))
        code = "hsrp_version_reader"
    with pytest.raises(ValueError, match="^" + code + "$"):
        owner.validate_values(result, handle)


def test_successful_version_parse_and_finish_are_consumed_once(tmp_path, monkeypatch):
    run = production(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="^hsrp_version_production_once$"):
        run.version.finish(run.all_outputs)
    with pytest.raises(ValueError, match="^hsrp_version_cache$"):
        run.version.parse(run.h.version.requests[0])


def test_writer_exception_retains_unreturned_partial_store_without_publishing_version(tmp_path, monkeypatch):
    run = stage(tmp_path)
    freeze(monkeypatch, writers=False)
    assert run.version.canonical_rows(run.all_outputs)
    original, stores = FactWriter.write, []
    def writing(self, **kwargs):
        stores.append(self.store)
        if len(stores) == 2:
            raise ValueError("planted_writer")
        return original(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^planted_writer$"):
        run.version.finish(run.all_outputs)
    assert run.version.production_attempted and run.version.production is run.version.completed is None
    assert len(stores) == 2 and stores[0] is stores[1] and len(stores[0].values) == 1
    with pytest.raises(ValueError, match="^hsrp_version_production_once$"):
        run.version.finish(run.all_outputs)


def test_test_owned_finally_clears_running_after_real_batch_failure_without_publishing(tmp_path, monkeypatch):
    baseline = stage(tmp_path / "baseline")
    assert baseline.version.canonical_rows(baseline.all_outputs)
    run = stage(tmp_path / "failed", execute=False)
    cache = run.version.inputs.produced
    def refusing(*args, **kwargs):
        raise ValueError("planted_vrrp_parse")
    monkeypatch.setattr(rp.parser, "parse_capture", refusing)
    with pytest.raises(ValueError, match="^planted_vrrp_parse$"):
        dispatch(run)
    assert run.ledger is run.vrrp.executed is None and run.vrrp.attempted and not run.vrrp.running
    assert run.version.inputs.produced is cache and run.version.production is None
    assert not run.version.production_attempted


def test_old_version_proof_gate_refuses_named_mixed_owner_before_value_callback(tmp_path, monkeypatch):
    with monkeypatch.context() as temporary:
        _, index, _ = legacy_closed(tmp_path / "old", temporary)
    run = production(tmp_path / "mixed", monkeypatch)
    monkeypatch.setattr(vo.MixedGlobalVersionOwner, "validate_values", forbidden)
    with pytest.raises(ValueError, match="^p4_projection_store$"):
        index.close_protocol_version(run.result, reader(run.result), run.version)


@pytest.mark.parametrize("path", ["construct", "unbound_construct", "wrong_receiver", "parse", "canonical", "finish", "values"])
def test_derived_named_receivers_refuse_constructor_and_unbound_inherited_paths(tmp_path, monkeypatch, path):
    run = production(tmp_path, monkeypatch)
    calls = []
    class Derived(vo.MixedGlobalVersionOwner):
        def validate_registration(self):
            calls.append("registration")
        def declaration_evidence(self):
            calls.append("evidence")
            return {}
        def canonical_rows(self, outputs):
            calls.append("canonical")
            return ()
        def own(self, output):
            calls.append("own")
            return output
    with pytest.raises(ValueError, match="^hsrp_version_mixed_receiver$"):
        if path == "construct":
            Derived(run.envelope, run.budgets, run.h.domains, run.h.version.requests)
        elif path in ("unbound_construct", "wrong_receiver"):
            vo.MixedGlobalVersionOwner.__init__(object.__new__(Derived) if path == "unbound_construct" else object(), run.envelope, run.budgets, run.h.domains, run.h.version.requests)
        else:
            forged = object.__new__(Derived)
            for name, value in vars(run.version).items():
                setattr(forged, name, value)
            if path == "parse":
                vo.VersionOwner.parse(forged, run.h.version.requests[0])
            elif path == "canonical":
                vo.VersionOwner.canonical_rows(forged, run.all_outputs)
            elif path == "finish":
                vo.VersionOwner.finish(forged, run.all_outputs)
            else:
                vo.VersionOwner.validate_values(forged, run.result, reader(run.result))
    assert calls == []


@pytest.mark.parametrize("hook", ["validate_registration", "declaration_evidence", "canonical_rows", "own"])
def test_exact_named_owner_ignores_instance_hook_shadowing_and_still_closes_real_context(tmp_path, monkeypatch, hook):
    run = stage(tmp_path, execute=False)
    calls = []
    def weakened(*args, **kwargs):
        calls.append(hook)
        return {} if hook == "declaration_evidence" else () if hook == "canonical_rows" else None
    setattr(run.version, hook, weakened)
    dispatch(run)
    result = vo.VersionOwner.finish(run.version, run.all_outputs)
    freeze(monkeypatch)
    assert vo.VersionOwner.validate_values(run.version, result, reader(result)) is None
    assert len(result.rows) == sum(len(domain.groups) for domain in run.h.domains) == 5
    assert all(row.value.evidence[:len(run.h.declarations[row.target.context, row.target.node.key])] ==
        run.h.declarations[row.target.context, row.target.node.key] for row in result.rows)
    object.__setattr__(next(target for target in run.envelope.targets if target.operation == stp.BINDING.operation), "owner", "l3.fhrp/other")
    with pytest.raises(ValueError, match="^fhrp_mixed_context_target$"):
        vo.VersionOwner.validate_values(run.version, result, reader(result))
    assert calls == []
