"""Named Root9 owners in test-owned five-handler batches; no whole Source or nine-fact production."""
import json
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256
from types import SimpleNamespace

import pytest
from test_mixed_version_owner import freeze, legacy_closed, reader
from test_root_mixed_inputs import root_folder
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import (
    build,
    global_parse,
    mixed_profile,
    mixed_vrrp_inputs,
)
from atlas_brain.packs.l3.fhrp import root_mixed_profile as profile
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as vp
from atlas_brain.packs.l3.fhrp import vrrp_owner as vr
from atlas_brain.packs.l3.fhrp import vrrp_profile as rp
from atlas_brain.packs.l3.fhrp.vrrp_proofs import LocalVRRPProofIndex
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_runtime import Handler


def stage(root, mode="normal", execute=True):
    envelope, old, files = root_folder(root, "normal" if mode in ("partial", "error") else mode)
    if mode in ("partial", "error"):
        side = json.loads(files["p4.json"])
        for row in side["captures"]:
            if row["target"] in ("all-a", "vrrp"):
                files[row["path"]] += b"unrecognized\n" if mode == "partial" else b"% synthetic error\n"
                row["sha256"] = sha256(files[row["path"]]).hexdigest()
        files["p4.json"] = canonical(side)
        for name, raw in files.items():
            (root / name).write_bytes(raw)
        envelope = global_parse.p4.admit_folder(root, LIMITS, declarations=profile.DECLARATIONS)
    budgets = replace(LIMITS)
    h = global_parse.prepare_root_mixed_hsrp_inputs(envelope, budgets)
    v = mixed_vrrp_inputs.prepare_root_mixed_vrrp_inputs(envelope, budgets)
    tree, channel = stp.RootObservationPack(budgets), SummaryPack(budgets)
    first, second = tree.prepare(envelope), channel.prepare(envelope)
    state = build.StateOwner(envelope, budgets, h.domains, h.requests)
    version = vo.RootMixedGlobalVersionOwner(envelope, budgets, h.domains, h.version.requests)
    vrrp = vr.RootMixedVRRPOwner(envelope, budgets, v.domains, v.requests)
    handlers = first.handlers + second.handlers + (Handler(binding=build.BINDING, parser=state),
        Handler(binding=vp.BINDING, parser=version), Handler(binding=rp.BINDING, parser=vrrp))
    run = SimpleNamespace(envelope=envelope, budgets=budgets, h=h, v=v, tree=tree, channel=channel,
        state=state, version=version, vrrp=vrrp, handlers=handlers, files=files, old=old, ledger=None,
        requests=first.requests + second.requests + h.requests + h.version.requests + v.requests)
    if execute:
        dispatch(run)
    return run


def dispatch(run):
    run.vrrp.attempted = run.vrrp.running = True
    try:
        run.ledger = pack_runtime.execute_parsers(profile.DECLARATIONS, run.handlers, run.requests)
    finally:
        run.vrrp.running = False
    run.vrrp.executed = tuple(output for output in run.ledger if output.receipt.capture.operation == rp.BINDING.operation)
    run.all_outputs = tuple(output for output in run.ledger if output.receipt.capture.operation == vp.BINDING.operation)


def selected(run, protocol):
    return (run.version, run.h, vp.REPORTED_PROTOCOL_VERSION, "hsrp_version") if protocol == "version" else (
        run.vrrp, run.v, rp.REPORTED_VRRP_STATE, "vrrp_owner")


def finish(run, protocol):
    return vo.VersionOwner.finish(run.version, run.all_outputs) if protocol == "version" else vr.VRRPOwner.finish(run.vrrp)


def validate(run, result, protocol, handle=None):
    owner, _, fact, _ = selected(run, protocol)
    handle = reader(result, fact) if handle is None else handle
    return vo.VersionOwner.validate_values(owner, result, handle) if protocol == "version" else vr.VRRPOwner.validate_values(owner, result, handle)


def production(root, monkeypatch, mode="normal"):
    run = stage(root, mode)
    run.version_result, run.vrrp_result = finish(run, "version"), finish(run, "vrrp")
    freeze(monkeypatch)
    assert validate(run, run.version_result, "version") is validate(run, run.vrrp_result, "vrrp") is None
    return run


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "zero_vrrp", "no_all_capture", "partial", "error"])
def test_real_root9_five_handler_batch_keeps_original_outputs_two_owned_stores_and_declared_denominators(tmp_path, monkeypatch, mode):
    execute, calls = pack_runtime.execute_parsers, []
    def executing(declarations, handlers, requests):
        result = execute(declarations, handlers, requests)
        calls.append((declarations, handlers, requests, result))
        return result
    monkeypatch.setattr(pack_runtime, "execute_parsers", executing)
    run = stage(tmp_path, mode)
    assert len(calls) == 1 and calls[0] == (profile.DECLARATIONS, run.handlers, run.requests, run.ledger)
    assert type(run.tree) is stp.RootObservationPack and run.tree.declaration() is stp.root_declaration()
    assert len(run.handlers) == 5 and {item.binding for item in run.handlers} == set(profile.compile_root_mixed_profile().operations)
    assert {output.receipt.capture.id for output in run.ledger} == {member.id for member in run.envelope.captures}
    for output in run.ledger:
        request = next(request for request in run.requests if request.capture.id == output.receipt.capture.id)
        member = next(member for member in run.envelope.captures if member.id == output.receipt.capture.id)
        assert output.receipt.capture is request.capture and request.capture.raw is member.raw
        assert output.receipt.owner == member.target.owner and output.receipt.registration_sha256 == run.envelope.registration_sha256
        assert output.receipt.parse is output.value.parse
    first, second = finish(run, "version"), finish(run, "vrrp")
    freeze(monkeypatch)
    assert first.store is not second.store and run.vrrp.inputs.registration_sha256 == rp.compile_vrrp_profile().registration_sha256
    assert run.vrrp.inputs.registration_sha256 != run.envelope.registration_sha256
    for protocol, result in (("version", first), ("vrrp", second)):
        owner, inputs, fact, _ = selected(run, protocol)
        assert validate(run, result, protocol) is None and result.registration_sha256 == run.envelope.registration_sha256
        assert len(result.rows) == len(result.store.values) == sum(len(domain.groups) for domain in inputs.domains)
        assert result.store.owners == {fact: vp.STEP.id if protocol == "version" else rp.STEP.id}
        for row in result.rows:
            refs = inputs.declarations[row.target.context, row.target.node.key]
            assert all(a is b for a, b in zip(row.value.evidence, refs)) and row.value.evidence[:len(refs)] == refs
            assert result.store.values[k.FactRef(fact=fact, subject=row.subject)] is row.value
            if type(row.value) is k.Unknown:
                need, = row.value.next_evidence
                assert need.resolves == (fact,) and need.operation == (vp.BINDING.operation if protocol == "version" else rp.BINDING.operation)
                assert row.value.candidates == ()
        assert owner.production is result and owner.completed is not None
    if mode == "normal":
        assert {row.value.value for row in first.rows if type(row.value) is k.Known} == {"1", "2"}
        assert {row.value.value for row in second.rows if type(row.value) is k.Known} == {"backup"}
        assert any(row.value.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE for row in second.rows if type(row.value) is k.Unknown)
    if mode in ("partial", "error"):
        reason = k.UnknownReason.PARSE_PARTIAL if mode == "partial" else k.UnknownReason.CAPTURE_ERROR
        assert all(type(row.value) is k.Unknown and row.value.reason is reason for row in second.rows)
    assert not run.state.finished and not run.channel.finished
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == run.files


@pytest.mark.parametrize("protocol", ["version", "vrrp"])
@pytest.mark.parametrize("plant", ["cache", "receipt", "value", "drop", "owner", "node", "raw", "budget", "outer_hash"])
def test_new_root_receiver_keeps_cache_receipt_whole_context_and_budget_refusals_before_writer(tmp_path, monkeypatch, protocol, plant):
    run = stage(tmp_path)
    owner, _, _, prefix = selected(run, protocol)
    outputs = run.all_outputs if protocol == "version" else owner.executed
    assert owner.canonical_rows(outputs) if protocol == "version" else owner.canonical_rows()
    freeze(monkeypatch)
    code, exception = prefix + "_cache", ValueError
    if plant in ("receipt", "value", "drop"):
        if plant == "drop":
            outputs = ()
            code = prefix + ("_cache" if protocol == "version" else "_coverage")
        elif plant == "value":
            outputs = (replace(outputs[0], value=replace(outputs[0].value)),)
        else:
            local_hash = vp.compile_version_profile().registration_sha256 if protocol == "version" else rp.compile_vrrp_profile().registration_sha256
            outputs = (replace(outputs[0], receipt=replace(outputs[0].receipt, registration_sha256=local_hash)),)
            code = prefix + "_receipt"
        if protocol == "version":
            run.all_outputs = outputs
        else:
            owner.executed = outputs
    elif plant == "cache":
        (owner.inputs.produced if protocol == "version" else owner.produced).clear()
    elif plant == "outer_hash":
        digest = mixed_profile.compile_mixed_profile().registration_sha256
        object.__setattr__(owner.inputs, "registration_sha256", digest) if protocol == "version" else setattr(owner, "registration", (*owner.registration[:2], digest))
        code = prefix + "_mixed_registration"
    elif plant == "owner":
        object.__setattr__(next(target for target in run.envelope.targets if target.operation == stp.BINDING.operation), "owner", "l3.fhrp/other")
        code = "fhrp_mixed_context_target"
    elif plant == "node":
        object.__setattr__(next(node for node in run.envelope.base.nodes if node.id == "b"), "ports", ("Gi1/0/2",))
        code = "fhrp_mixed_context_node"
    elif plant == "raw":
        member = next(member for member in run.envelope.captures if member.target.operation == stp.BINDING.operation)
        object.__setattr__(member, "raw", member.raw + b"\n")
        code = "hsrp_folder_member"
    else:
        object.__setattr__(run.budgets, "artifacts", 1)
        code, exception = "budget_exceeded", global_parse.BudgetExceeded
    with pytest.raises(exception, match="^" + code + "$") as caught:
        finish(run, protocol)
    if plant == "budget":
        assert caught.value.member == "fhrp_mixed_context_raw_budget"
    assert owner.production_attempted and owner.production is owner.completed is None


@pytest.mark.parametrize("protocol", ["version", "vrrp"])
@pytest.mark.parametrize("plant", ["equal_pair", "store_only", "cross_protocol", "owners", "extra", "alias", "reader"])
def test_original_root9_cells_stores_and_narrow_readers_are_retained_after_real_production(tmp_path, monkeypatch, protocol, plant):
    run = production(tmp_path, monkeypatch)
    owner, _, fact, prefix = selected(run, protocol)
    result = run.version_result if protocol == "version" else run.vrrp_result
    other = run.vrrp_result if protocol == "version" else run.version_result
    row = result.rows[0]
    reference, handle = k.FactRef(fact=fact, subject=row.subject), reader(result, fact)
    assert validate(run, result, protocol, replace(handle)) is None
    with pytest.raises(ValueError, match="^" + prefix + "_production_once$"):
        finish(run, protocol)
    with pytest.raises(ValueError, match="^" + prefix + ("_cache$" if protocol == "version" else "_request$")):
        owner.parse(run.h.version.requests[0] if protocol == "version" else run.v.requests[0])
    code = prefix + "_value_store"
    if plant in ("equal_pair", "store_only", "cross_protocol"):
        copy = replace(row.value)
        assert copy == row.value and copy is not row.value
        result.store.values[reference] = other.rows[0].value if plant == "cross_protocol" else copy
        if plant == "equal_pair":
            object.__setattr__(row, "value", copy)
        code = prefix + ("_value_cell" if plant == "equal_pair" else "_value_reader")
    elif plant == "owners":
        result.store.owners[fact] = "l3.fhrp/other"
    elif plant == "extra":
        result.store.values[k.FactRef(fact=fact, subject="fhrp_local:foreign")] = row.value
    elif plant == "alias":
        copy = k.FactRef(fact=fact, subject=row.subject)
        object.__setattr__(copy, "fact", StrEnum("Alias", {"VALUE": fact}).VALUE)
        result.store.values = {copy if ref == reference else ref: value for ref, value in result.store.values.items()}
    else:
        handle, code = replace(handle, store=other.store), prefix + "_reader"
    with pytest.raises(ValueError, match="^" + code + "$"):
        validate(run, result, protocol, handle)


@pytest.mark.parametrize("protocol,path", [(protocol, path) for protocol in ("version", "vrrp") for path in
    ("construct", "unbound", "wrong_receiver", "parse", "canonical", "finish", "values", "registration", "evidence")]
    + [("version", "own"), ("vrrp", "inputs")])
def test_derived_and_wrong_named_receivers_refuse_before_any_weakened_hook(tmp_path, monkeypatch, protocol, path):
    run = production(tmp_path, monkeypatch)
    owner, inputs, fact, prefix = selected(run, protocol)
    cls = vo.RootMixedGlobalVersionOwner if protocol == "version" else vr.RootMixedVRRPOwner
    base = vo.VersionOwner if protocol == "version" else vr.VRRPOwner
    calls = []
    def weakened(*args, **kwargs):
        calls.append("hook")
        return {}
    class Derived(cls):
        pass
    for name in ("validate_registration", "declaration_evidence", "canonical_rows", "own", "validate_inputs"):
        setattr(Derived, name, weakened)
    forged = object.__new__(Derived)
    for name, value in vars(owner).items():
        setattr(forged, name, value)
    result = run.version_result if protocol == "version" else run.vrrp_result
    with pytest.raises(ValueError, match="^" + prefix + ("_mixed_receiver" if protocol == "version" else "_receiver") + "$"):
        if path in ("construct", "unbound", "wrong_receiver"):
            args = (run.envelope, run.budgets, inputs.domains, inputs.version.requests if protocol == "version" else inputs.requests)
            Derived(*args) if path == "construct" else cls.__init__(object() if path == "wrong_receiver" else forged, *args)
        elif path == "parse":
            base.parse(forged, inputs.version.requests[0] if protocol == "version" else inputs.requests[0])
        elif path == "values":
            base.validate_values(forged, result, reader(result, fact))
        elif path == "own":
            vo.VersionOwner.own(forged, run.all_outputs[0])
        elif path == "canonical":
            vo.VersionOwner.canonical_rows(forged, run.all_outputs) if protocol == "version" else vr.VRRPOwner.canonical_rows(forged)
        elif path == "finish":
            vo.VersionOwner.finish(forged, run.all_outputs) if protocol == "version" else vr.VRRPOwner.finish(forged)
        else:
            getattr(cls if path in ("registration", "evidence") else base,
                {"registration": "validate_registration", "evidence": "declaration_evidence", "inputs": "validate_inputs"}[path])(forged)
    assert calls == []


@pytest.mark.parametrize("protocol", ["version", "vrrp"])
@pytest.mark.parametrize("hook", ["validate_registration", "declaration_evidence", "canonical_rows", "ingest"])
def test_exact_root_named_owner_uses_closed_dispatch_despite_instance_shadows(tmp_path, monkeypatch, protocol, hook):
    run = stage(tmp_path, execute=False)
    owner, inputs, _, _ = selected(run, protocol)
    calls = []
    def weakened(*args, **kwargs):
        calls.append(hook)
        return {}
    setattr(owner, ("own" if protocol == "version" else "validate_inputs") if hook == "ingest" else hook, weakened)
    dispatch(run)
    result = finish(run, protocol)
    freeze(monkeypatch)
    assert validate(run, result, protocol) is None and calls == []
    assert all(row.value.evidence[:len(inputs.declarations[row.target.context, row.target.node.key])] ==
        inputs.declarations[row.target.context, row.target.node.key] for row in result.rows)
    object.__setattr__(next(target for target in run.envelope.targets if target.operation == stp.BINDING.operation), "owner", "l3.fhrp/other")
    with pytest.raises(ValueError, match="^fhrp_mixed_context_target$"):
        validate(run, result, protocol)
    assert calls == []


@pytest.mark.parametrize("protocol", ["version", "vrrp"])
def test_named_root_production_is_once_and_writer_failures_publish_no_result(tmp_path, monkeypatch, protocol):
    run = stage(tmp_path)
    owner, _, _, prefix = selected(run, protocol)
    assert owner.canonical_rows(run.all_outputs) if protocol == "version" else owner.canonical_rows()
    freeze(monkeypatch, writers=False)
    original, stores = FactWriter.write, []
    def writing(self, **kwargs):
        stores.append(self.store)
        if len(stores) == 2:
            raise ValueError("planted_writer")
        return original(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^planted_writer$"):
        finish(run, protocol)
    assert owner.production_attempted and owner.production is owner.completed is None
    assert len(stores) == 2 and stores[0] is stores[1] and len(stores[0].values) == 1
    with pytest.raises(ValueError, match="^" + prefix + "_production_once$"):
        finish(run, protocol)


def test_old_named_profiles_and_proof_indexes_do_not_silently_admit_root9_owners(tmp_path, monkeypatch):
    with monkeypatch.context() as temporary:
        _, index, _ = legacy_closed(tmp_path / "legacy", temporary)
    run = production(tmp_path / "root9", monkeypatch)
    for protocol in ("version", "vrrp"):
        _, inputs, _, _ = selected(run, protocol)
        new, old = (vo.RootMixedGlobalVersionOwner, vo.MixedGlobalVersionOwner) if protocol == "version" else (vr.RootMixedVRRPOwner, vr.MixedVRRPOwner)
        for cls, envelope in ((new, run.old), (old, run.envelope)):
            with pytest.raises(ValueError, match="^fhrp_mixed_context_registration$"):
                cls(envelope, run.budgets, inputs.domains, inputs.version.requests if protocol == "version" else inputs.requests)
    with pytest.raises(ValueError, match="^p4_projection_store$"):
        index.close_protocol_version(run.version_result, reader(run.version_result), run.version)
    with pytest.raises(ValueError, match="^vrrp_proofs_owner$"):
        LocalVRRPProofIndex(owner=run.vrrp, result=run.vrrp_result, reader=reader(run.vrrp_result, rp.REPORTED_VRRP_STATE))
