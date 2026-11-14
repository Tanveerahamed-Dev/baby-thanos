"""Current mixed source/cache comparison; not Store-value admission or an execution-origin seal."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_context import admitted
from test_peer_execution import forbidden
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import mixed_execution as current


def freeze(monkeypatch):
    for module in (current.stp.stp, current.ec.parse_summary, current.brief, current.all_hsrp, current.vrrp):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    monkeypatch.setattr(current.pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(current.pipeline, "execute_p4_folder", forbidden)
    monkeypatch.setattr(current.pipeline.p4, "admit_folder", forbidden)
    monkeypatch.setattr(FactStore, "__init__", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)


def produced(source):
    pack, execution = source.fhrp, source.execution
    state = tuple(out for out in execution.executed if out.receipt.capture.operation == current.brief.OP)
    version = tuple(out for out in execution.executed if out.receipt.capture.operation == current.all_hsrp.OP)
    return (source.tree.finish(execution), source.channel.finish(execution), pack.state.finish(state),
        pack.version.finish(version), pack.vrrp_owner.finish())


@pytest.fixture
def case(tmp_path, monkeypatch):
    admitted(tmp_path)
    source = current.execute_mixed_inputs(tmp_path, LIMITS)
    assert current.validate_mixed_execution(source, LIMITS) is None
    freeze(monkeypatch)
    return source


@pytest.mark.parametrize("stores", [False, True])
def test_repeated_validation_is_read_only_before_and_after_real_five_store_production(tmp_path, monkeypatch, stores):
    admitted(tmp_path)
    source = current.execute_mixed_inputs(tmp_path, LIMITS)
    results = produced(source) if stores else ()
    original_batch = source.vrrp_executed
    pointers = tuple((out.receipt, out.value, out.receipt.capture, out.receipt.capture.raw) for out in source.execution.executed)
    cells = tuple(tuple((ref.fact, ref.subject, value) for ref, value in result.store.values.items()) for result in results)
    freeze(monkeypatch)
    initial_setattr, assignments = current.MixedVRRPOwner.__setattr__, []
    def setting(self, name, value):
        if name == "executed":
            assignments.append(value)
        return initial_setattr(self, name, value)
    monkeypatch.setattr(current.MixedVRRPOwner, "__setattr__", setting)
    for _ in range(3):
        assert current.validate_mixed_execution(source, LIMITS) is None
        assert source.vrrp_executed is source.fhrp.vrrp_owner.executed is original_batch
        assert all(out.receipt is receipt and out.value is value and out.receipt.capture is capture and capture.raw is raw
            for out, (receipt, value, capture, raw) in zip(source.execution.executed, pointers, strict=True))
        assert all(len(result.store.values) == len(saved) and all(
            result.store.values[k.FactRef(fact=fact, subject=subject)] is value for fact, subject, value in saved)
            for result, saved in zip(results, cells, strict=True))
    assert assignments == []
    assert set(source.fhrp.version.inputs.owned) == set(source.fhrp.version.inputs.source.expected)


def test_equal_typed_snapshot_and_shallow_carrier_copies_are_data_not_origin_tokens(case):
    source = replace(case, limits=tuple(value for value in case.limits), compiled=replace(case.compiled))
    assert source is not case and source.compiled is not case.compiled
    assert current.validate_mixed_execution(source, LIMITS) is None
    assert source.vrrp_executed is case.vrrp_executed is case.fhrp.vrrp_owner.executed


@pytest.mark.parametrize("field", ["source", "tree", "channel", "fhrp"])
def test_wrong_top_level_carrier_or_pack_class_refuses_before_field_access(case, field):
    source = object() if field == "source" else replace(case, **{field: object()})
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_" + ("current" if field == "source" else "owner") + "$"):
        current.validate_mixed_execution(source, LIMITS)


@pytest.mark.parametrize("field", ["budget_object", "limits", "compiled_type", "catalogue", "registration", "hash", "hash_alias"])
def test_current_budget_and_closed_compiled_metadata_are_finite_and_exact(case, field):
    source, budgets = case, LIMITS
    if field == "budget_object":
        budgets = replace(LIMITS)
    elif field == "limits":
        source = replace(source, limits=([], *source.limits[1:]))
    elif field == "compiled_type":
        source = replace(source, compiled=object())
    else:
        compiled = replace(source.compiled)
        name = "catalogue_bytes" if field == "catalogue" else "registration_bytes" if field == "registration" else "registration_sha256"
        value = StrEnum("Alias", {"VALUE": compiled.registration_sha256}).VALUE if field == "hash_alias" else (
            "0" * 64 if name.endswith("sha256") else bytearray(getattr(compiled, name)))
        object.__setattr__(compiled, name, value)
        source = replace(source, compiled=compiled)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        current.validate_mixed_execution(source, budgets)


@pytest.mark.parametrize("owner,plant", [(owner, plant) for owner in ("tree", "channel", "state", "version", "vrrp")
    for plant in ("extra", "alias") if (owner, plant) != ("version", "alias")])
def test_every_original_produced_cache_has_plain_exact_capture_census(case, owner, plant):
    cache = {"tree": case.tree.produced, "channel": case.channel.owner.produced, "state": case.fhrp.state.produced,
        "version": case.fhrp.version.inputs.produced, "vrrp": case.fhrp.vrrp_owner.produced}[owner]
    key, value = next(iter(cache.items()))
    cache["cap:extra" if plant == "extra" else StrEnum("Alias", {"VALUE": key}).VALUE] = value
    if plant == "alias":
        # Equal enum keys preserve an existing dict key; rebuild to retain the planted key object.
        entries = tuple(cache.items())
        cache.clear()
        cache.update({StrEnum("Alias", {"VALUE": old}).VALUE if old == key else old: item for old, item in entries})
    code = "hsrp_version_cache" if owner == "version" else "vrrp_owner_cache" if owner == "vrrp" else "fhrp_mixed_execution_cache"
    with pytest.raises(ValueError, match="^" + code + "$"):
        current.validate_mixed_execution(case, LIMITS)


@pytest.mark.parametrize("family", ["tree", "channel"])
@pytest.mark.parametrize("plant", ["drop", "domain_copy", "key_alias", "proof_drop", "proof_alias", "ref_field"])
def test_raw_bound_declared_domains_and_finite_proofs_are_independent_of_current_plan(case, family, plant):
    plan = case.tree.plan if family == "tree" else case.channel.owner.plan
    key, domain = next(iter(plan.indexed.items()))
    if plant == "drop":
        plan.indexed.clear()
    elif plant == "domain_copy":
        plan.indexed[key] = replace(domain, node=replace(domain.node))
    elif plant == "key_alias":
        entries = tuple(plan.indexed.items())
        plan.indexed.clear()
        plan.indexed.update({(StrEnum("Alias", {"VALUE": old[0]}).VALUE, *old[1:]): value for old, value in entries})
    elif plant == "proof_drop":
        plan.proofs.clear()
    elif plant == "proof_alias":
        key, refs = next(iter(plan.proofs.items()))
        object.__setattr__(plan, "proofs", {(StrEnum("Alias", {"VALUE": key[0]}).VALUE, *key[1:]): refs})
    else:
        object.__setattr__(next(iter(plan.proofs.values()))[0], "table", [])
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        current.validate_mixed_execution(case, LIMITS)


@pytest.mark.parametrize("family", ["hsrp", "state"])
def test_normalized_state_population_stays_bound_to_raw_hsrp_declarations(case, family):
    if family == "hsrp":
        object.__setattr__(case.fhrp.hsrp, "domains", ())
        code = "fhrp_mixed_execution_current"
    else:
        case.fhrp.state.plan.indexed.clear()
        code = "hsrp_state_version_population"
    with pytest.raises(ValueError, match="^" + code + "$"):
        current.validate_mixed_execution(case, LIMITS)


@pytest.mark.parametrize("field", ["tree_registration", "channel_registration", "channel_owner_registration", "root_profile"])
def test_fixed_legacy_stp_and_each_retained_registration_cannot_drift(case, field):
    if field == "root_profile":
        case.tree.producer = replace(case.tree.producer, roots=True, declaration=current.stp.ROOT_DECLARATION,
            step=current.stp.ROOT_STEP)
    else:
        owner, name = (case.tree, "registration") if field == "tree_registration" else (
            (case.channel.run, "registration") if field == "channel_registration" else (case.channel.owner, "registration"))
        object.__setattr__(owner, name, StrEnum("Alias", {"VALUE": getattr(owner, name)}).VALUE)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        current.validate_mixed_execution(case, LIMITS)


@pytest.mark.parametrize("plant,code", [("ledger_only", "fhrp_mixed_execution_output"), ("coherent", "vrrp_owner_cache"),
    ("batch_copy", "fhrp_mixed_execution_output")])
def test_vrrp_ledger_comparison_and_coherent_bad_cache_are_distinct_refusal_paths(case, plant, code):
    original = case.vrrp_executed
    if plant == "batch_copy":
        source = replace(case, vrrp_executed=tuple(out for out in original))
    else:
        output = next(out for out in case.execution.executed if out.receipt.capture.operation == current.vrrp.OP)
        changed = replace(output, value=replace(output.value))
        execution = replace(case.execution, executed=tuple(changed if out is output else out for out in case.execution.executed))
        source = replace(case, execution=execution)
        if plant == "coherent":
            batch = (current.Executed(receipt=changed.receipt, value=changed.value),)
            case.fhrp.vrrp_owner.executed = batch
            source = replace(source, vrrp_executed=batch)
    expected = source.vrrp_executed if plant == "coherent" else original
    with pytest.raises(ValueError, match="^" + code + "$"):
        current.validate_mixed_execution(source, LIMITS)
    assert case.fhrp.vrrp_owner.executed is expected


@pytest.mark.parametrize("field", ["capture_copy", "raw_copy", "parse_copy", "receipt_alias"])
def test_current_original_capture_raw_parse_and_receipt_types_reclose(case, field):
    output = case.execution.executed[0]
    receipt = replace(output.receipt)
    if field == "raw_copy":
        object.__setattr__(receipt.capture, "raw", bytes(bytearray(receipt.capture.raw)))
    elif field == "capture_copy":
        receipt = replace(receipt, capture=replace(receipt.capture))
    elif field == "parse_copy":
        receipt = replace(receipt, parse=replace(receipt.parse))
    else:
        object.__setattr__(receipt, "registration_sha256", StrEnum("Alias", {"VALUE": receipt.registration_sha256}).VALUE)
    changed = replace(output, receipt=receipt)
    source = replace(case, execution=replace(case.execution,
        executed=tuple(changed if out is output else out for out in case.execution.executed)))
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_output$"):
        current.validate_mixed_execution(source, LIMITS)


@pytest.mark.parametrize("owner", ["vrrp", "version"])
def test_public_revalidation_still_executes_both_canonical_closures_without_rebinding(case, monkeypatch, owner):
    original = case.fhrp.vrrp_owner.executed
    def refusing(*args):
        raise ValueError("planted_canonical")
    monkeypatch.setattr(current.VRRPOwner if owner == "vrrp" else current.MixedGlobalVersionOwner, "canonical_rows", refusing)
    with pytest.raises(ValueError, match="^planted_canonical$"):
        current.validate_mixed_execution(case, LIMITS)
    assert case.fhrp.vrrp_owner.executed is original


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_same_original_budget_object_cannot_change_after_fresh_execution(tmp_path, monkeypatch, field):
    admitted(tmp_path)
    budgets = replace(LIMITS)
    source = current.execute_mixed_inputs(tmp_path, budgets)
    assert current.validate_mixed_execution(source, budgets) is None
    object.__setattr__(budgets, field, getattr(budgets, field) + 1)
    freeze(monkeypatch)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        current.validate_mixed_execution(source, budgets)


@pytest.mark.parametrize("family,code", [("tree", "invalid_stp_vlans"), ("channel", "invalid_etherchannel_population")])
def test_equal_alias_domain_leaves_still_run_the_owning_target_constructor(case, family, code):
    target = next(iter((case.tree.plan if family == "tree" else case.channel.owner.plan).indexed.values()))
    object.__setattr__(target, "vlans" if family == "tree" else "groups",
        (True,) if family == "tree" else (StrEnum("Alias", {"VALUE": target.groups[0]}).VALUE,))
    with pytest.raises(ValueError, match="^" + code + "$"):
        current.validate_mixed_execution(case, LIMITS)


@pytest.mark.parametrize("mode", ["none", "only_vrrp", "cold_vrrp"])
def test_missing_capture_and_empty_other_pack_populations_survive_public_metadata_reconstruction(tmp_path, monkeypatch, mode):
    admitted(tmp_path, mode)
    source = current.execute_mixed_inputs(tmp_path, LIMITS)
    results = produced(source)
    batch = source.vrrp_executed
    counts = tuple(len(result.rows) for result in results)
    freeze(monkeypatch)
    assert current.validate_mixed_execution(source, LIMITS) is None
    assert source.fhrp.vrrp_owner.executed is source.vrrp_executed is batch
    assert tuple(len(result.rows) for result in results) == counts
    assert counts == ((0, 0, 0, 0, 2) if mode == "only_vrrp" else (1, 1, 5, 5, 2))


@pytest.mark.parametrize("field", ["state", "version", "vrrp_owner"])
def test_each_named_fhrp_owner_class_is_closed_before_population_access(case, field):
    setattr(case.fhrp, field, object())
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_owner$"):
        current.validate_mixed_execution(case, LIMITS)


@pytest.mark.parametrize("field,code", [("envelope", "current"), ("execution", "output")])
def test_equal_foreign_envelope_and_malformed_execution_records_do_not_supply_original_context(case, field, code):
    execution = replace(case.execution, envelope=replace(case.execution.envelope)) if field == "envelope" else object()
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_" + code + "$"):
        current.validate_mixed_execution(replace(case, execution=execution), LIMITS)
