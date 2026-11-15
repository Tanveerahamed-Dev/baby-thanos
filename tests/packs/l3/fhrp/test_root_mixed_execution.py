"""Fresh/current Root9 parser execution only; test-owned Stores do not grant product Store closure."""
from dataclasses import fields, replace
from enum import StrEnum

import pytest
from test_mixed_execution_current import freeze, produced
from test_peer_execution import forbidden
from test_root_mixed_inputs import root_folder
from test_state_owner import LIMITS

from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import mixed_execution as fresh


def execute(root, mode="normal"):
    root_folder(root, mode)
    return fresh.execute_root_mixed_inputs(root, replace(LIMITS))


def validate(source):
    return fresh.validate_root_mixed_execution(source, source.budgets)


@pytest.fixture
def case(tmp_path, monkeypatch):
    source = execute(tmp_path)
    assert validate(source) is None
    freeze(monkeypatch)
    return source


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "zero_vrrp"])
def test_fresh_root9_admits_one_saved_folder_prepares_three_packs_then_one_five_handler_batch(tmp_path, monkeypatch, mode):
    _, _, files = root_folder(tmp_path, mode)
    admission, dispatch = fresh.pipeline.p4.admit_folder, fresh.pipeline.execute_parsers
    admitted, prepared, batches = [], [], []
    def admitting(*args, **kwargs):
        value = admission(*args, **kwargs)
        admitted.append(value)
        return value
    monkeypatch.setattr(fresh.pipeline.p4, "admit_folder", admitting)
    for cls in (fresh.stp.RootObservationPack, fresh.SummaryPack, fresh.RootMixedFhrpPack):
        original = cls.prepare
        def preparing(self, envelope, original=original):
            assert not batches
            if type(self) is fresh.stp.RootObservationPack:
                self.own_execution = forbidden
            value = original(self, envelope)
            prepared.append((self, envelope))
            return value
        monkeypatch.setattr(cls, "prepare", preparing)
    def dispatching(declarations, handlers, requests):
        assert len(prepared) == 3 and not batches
        batches.append((declarations, handlers, requests))
        return dispatch(declarations, handlers, requests)
    monkeypatch.setattr(fresh.pipeline, "execute_parsers", dispatching)
    monkeypatch.setattr(FactStore, "__init__", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    source = fresh.execute_root_mixed_inputs(tmp_path, replace(LIMITS))
    envelope, pack = source.execution.envelope, source.fhrp
    assert type(source) is fresh.RootMixedExecution and admitted == [envelope]
    assert tuple(item[0] for item in prepared) == (source.tree, source.channel, pack)
    assert all(item[1] is envelope for item in prepared) and len(batches) == 1
    declarations, handlers, requests = batches[0]
    assert declarations == fresh.root_mixed_profile.DECLARATIONS and len(handlers) == 5
    assert sum(len(declaration.facts) for declaration in declarations) == 9
    assert source.tree.declaration() is fresh.stp.root_declaration() and source.tree.producer.roots is True
    assert len(source.execution.executed) == len(requests) == len(envelope.captures)
    for output in source.execution.executed:
        request = next(request for request in requests if request.capture.id == output.receipt.capture.id)
        member = next(member for member in envelope.captures if member.id == output.receipt.capture.id)
        assert output.receipt.capture is request.capture and request.capture.raw is member.raw
        assert output.receipt.owner == member.target.owner and output.receipt.registration_sha256 == envelope.registration_sha256
        assert output.receipt.parse is output.value.parse
    assert not pack.vrrp_owner.running and pack.vrrp_owner.executed is source.vrrp_executed
    assert pack.version.production is pack.vrrp_owner.production is None and not pack.state.finished
    assert len(pack.hsrp.domains) == (0 if mode == "only_vrrp" else 2)
    assert len(pack.vrrp_inputs.subjects) == (0 if mode == "zero_vrrp" else 2)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("stores", [False, True])
def test_current_root9_revalidation_is_read_only_after_zero_or_five_test_owned_store_finishes(tmp_path, monkeypatch, stores):
    source = execute(tmp_path)
    results = produced(source) if stores else ()
    batch = source.vrrp_executed
    cells = tuple(tuple(result.store.values.items()) for result in results)
    if stores:
        assert len({id(result.store) for result in results}) == 5
        assert set().union(*(set(result.store.owners) for result in results)) == {
            fact.id for declaration in fresh.root_mixed_profile.DECLARATIONS for fact in declaration.facts}
    receipts = tuple((out.receipt, out.value) for out in source.execution.executed)
    freeze(monkeypatch)
    initial, assignments = fresh.RootMixedVRRPOwner.__setattr__, []
    def setting(self, name, value):
        if name == "executed":
            assignments.append(value)
        return initial(self, name, value)
    monkeypatch.setattr(fresh.RootMixedVRRPOwner, "__setattr__", setting)
    for _ in range(3):
        assert validate(source) is None and source.fhrp.vrrp_owner.executed is source.vrrp_executed is batch
        assert all(out.receipt is receipt and out.value is value for out, (receipt, value) in zip(source.execution.executed, receipts, strict=True))
        assert all(len(result.store.values) == len(saved) and all(result.store.values[ref] is value for ref, value in saved)
            for result, saved in zip(results, cells, strict=True))
    assert assignments == []


@pytest.mark.parametrize("operation,cache", [(fresh.stp.stp.OP, "fhrp_mixed_execution_cache"),
    (fresh.ec.parse_summary.OP, "etherchannel_global_value"), (fresh.brief.OP, "hsrp_global_value"),
    (fresh.all_hsrp.OP, "hsrp_version_cache"), (fresh.vrrp.OP, "fhrp_mixed_execution_output")])
@pytest.mark.parametrize("plant", ["value", "capture", "parse", "owner", "raw", "scope"])
def test_every_original_root9_operation_recloses_cache_capture_bytes_and_flat_scope(case, operation, cache, plant):
    output = next(output for output in case.execution.executed if output.receipt.capture.operation == operation)
    source, code = case, "fhrp_mixed_execution_output"
    if plant == "scope":
        capture = output.receipt.capture
        object.__setattr__(capture, "metadata", replace(capture.resolved_metadata, scope=replace(capture.scope, vrf="blue")))
        code = "fhrp_mixed_execution_scope"
    elif plant == "raw":
        object.__setattr__(output.receipt.capture, "raw", bytes(bytearray(output.receipt.capture.raw)))
    else:
        receipt = replace(output.receipt)
        if plant == "owner":
            object.__setattr__(receipt, "owner", StrEnum("Alias", {"VALUE": receipt.owner}).VALUE)
        elif plant in ("capture", "parse"):
            receipt = replace(receipt, **{plant: replace(getattr(receipt, plant))})
        changed = replace(output, value=replace(output.value)) if plant == "value" else replace(output, receipt=receipt)
        source = replace(case, execution=replace(case.execution,
            executed=tuple(changed if item is output else item for item in case.execution.executed)))
        code = cache if plant == "value" else code
    with pytest.raises(ValueError, match="^" + code + "$"):
        validate(source)


@pytest.mark.parametrize("field", ["budget_object", "budget_leaf", "limits", "catalogue", "registration", "hash", "hash_alias", "root_literal"])
def test_root9_budget_compiled_snapshot_and_fixed_root_literal_remain_current(case, field):
    source, budgets = case, case.budgets
    if field == "budget_object":
        budgets = replace(budgets)
    elif field == "budget_leaf":
        object.__setattr__(budgets, "artifacts", budgets.artifacts + 1)
    elif field == "limits":
        source = replace(source, limits=([], *source.limits[1:]))
    elif field == "root_literal":
        source.tree.producer = replace(source.tree.producer, roots=False, declaration=fresh.stp.DECLARATION, step=fresh.stp.STEP)
    else:
        name = "catalogue_bytes" if field == "catalogue" else "registration_bytes" if field == "registration" else "registration_sha256"
        value = StrEnum("Alias", {"VALUE": source.compiled.registration_sha256}).VALUE if field == "hash_alias" else (
            "0" * 64 if field == "hash" else bytearray(getattr(source.compiled, name)))
        source = replace(source, compiled=replace(source.compiled, **{name: value}))
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        fresh.validate_root_mixed_execution(source, budgets)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_invalid_root9_budget_values_refuse_before_compilation_or_admission(tmp_path, monkeypatch, field):
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, False)
    monkeypatch.setattr(fresh.root_mixed_profile, "compile_root_mixed_profile", forbidden)
    monkeypatch.setattr(fresh.pipeline.p4, "admit_folder", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_budget$"):
        fresh.execute_root_mixed_inputs(tmp_path, budgets)


@pytest.mark.parametrize("phase", ["prepare", "preflight", "parse"])
def test_failures_clear_armed_running_state_and_consume_only_the_attempted_pack_without_a_carrier(tmp_path, monkeypatch, phase):
    root_folder(tmp_path)
    original, packs = fresh.RootMixedFhrpPack.prepare, []
    def preparing(self, envelope):
        packs.append((self, envelope))
        value = original(self, envelope)
        return replace(value, targets=value.targets[:-1]) if phase == "preflight" else value
    monkeypatch.setattr(fresh.RootMixedFhrpPack, "prepare", preparing)
    monkeypatch.setattr(fresh, "RootMixedExecution", forbidden)
    def refusing(*args, **kwargs):
        raise ValueError("planted_" + phase)
    if phase == "prepare":
        monkeypatch.setattr(fresh.global_parse, "prepare_root_mixed_hsrp_inputs", refusing)
    elif phase == "parse":
        monkeypatch.setattr(fresh.vrrp, "parse_capture", refusing)
    with pytest.raises(ValueError, match="^" + ("p4_pipeline_target_claims" if phase == "preflight" else "planted_" + phase) + "$"):
        fresh.execute_root_mixed_inputs(tmp_path, replace(LIMITS))
    pack, envelope = packs[0]
    assert pack.attempted
    if phase == "prepare":
        assert pack.state is pack.version is pack.vrrp_owner is None
    else:
        assert pack.vrrp_owner.attempted and not pack.vrrp_owner.running
        assert pack.vrrp_owner.executed is pack.vrrp_owner.production is pack.version.production is None
    with pytest.raises(ValueError, match="^fhrp_mixed_pack_once$"):
        original(pack, envelope)


def test_both_public_entry_points_reject_wrong_classes_and_coherent_seven_nine_carrier_swaps(tmp_path, monkeypatch):
    root_folder(tmp_path)
    root9, old = fresh.execute_root_mixed_inputs(tmp_path, replace(LIMITS)), fresh.execute_mixed_inputs(tmp_path, replace(LIMITS))
    assert validate(root9) is fresh.validate_mixed_execution(old, old.budgets) is None
    freeze(monkeypatch)
    for source, cls, checking in ((root9, fresh.MixedExecution, fresh.validate_mixed_execution),
            (old, fresh.RootMixedExecution, fresh.validate_root_mixed_execution)):
        with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
            checking(source, source.budgets)
        forged = cls(**{field.name: getattr(source, field.name) for field in fields(source)})
        with pytest.raises(ValueError, match="^fhrp_mixed_execution_owner$"):
            checking(forged, forged.budgets)


def test_typed_copies_preserve_data_and_unbound_root_stp_validation_ignores_instance_shadow(case):
    source = replace(case, compiled=replace(case.compiled), limits=tuple(case.limits))
    assert source is not case and source.compiled is not case.compiled and validate(source) is None
    source.tree.own_execution = forbidden
    assert validate(source) is None


@pytest.mark.parametrize("value", [None, [], "not-a-path"])
def test_invalid_root_argument_refuses_before_compilation_or_admission(monkeypatch, value):
    monkeypatch.setattr(fresh.root_mixed_profile, "compile_root_mixed_profile", forbidden)
    monkeypatch.setattr(fresh.pipeline.p4, "admit_folder", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_input$"):
        fresh.execute_root_mixed_inputs(value, replace(LIMITS))


@pytest.mark.parametrize("owner", ["tree", "channel", "state", "version", "vrrp"])
def test_all_five_current_root9_caches_reject_extra_capture_population(case, owner):
    cache = {"tree": case.tree.produced, "channel": case.channel.owner.produced, "state": case.fhrp.state.produced,
        "version": case.fhrp.version.inputs.produced, "vrrp": case.fhrp.vrrp_owner.produced}[owner]
    cache["cap:extra"] = next(iter(cache.values()))
    code = "hsrp_version_cache" if owner == "version" else "vrrp_owner_cache" if owner == "vrrp" else "fhrp_mixed_execution_cache"
    with pytest.raises(ValueError, match="^" + code + "$"):
        validate(case)


@pytest.mark.parametrize("family", ["tree", "channel", "state"])
def test_root9_current_declared_population_is_not_inferred_from_surviving_caches(case, family):
    plan = case.tree.plan if family == "tree" else case.channel.owner.plan if family == "channel" else case.fhrp.state.plan
    plan.indexed.clear()
    with pytest.raises(ValueError, match="^" + ("hsrp_state_version_population" if family == "state" else "fhrp_mixed_execution_current") + "$"):
        validate(case)
