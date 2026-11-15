"""Fresh retained current-value access; mutable records are not execution-origin or post-return seals."""
from copy import copy
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_component import FIELDS, spec
from test_mixed_context import admitted
from test_peer_execution import forbidden
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import mixed_component as current

FACTS = (("tree", current.stp.ROOT_GUARD, "value"), ("tree", current.stp.REPORTED_ROLE, "role"),
    ("channel", current.ec.REPORTED_PROTOCOL, "value"), ("channel", current.ec.REPORTED_MEMBER_TOKENS, "member_tokens"),
    ("state", current.build.REPORTED_STATE, "value"), ("version", current.version_profile.REPORTED_PROTOCOL_VERSION, "value"),
    ("vrrp", current.vrrp_profile.REPORTED_VRRP_STATE, "value"))


def freeze(monkeypatch):
    for module in (current.stp.stp, current.ec.parse_summary, current.build.hsrp,
            current.version_profile.parser, current.vrrp_profile.parser):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    for cls in (current.stp.RootGuardPack, current.SummaryPack, current.build.StateOwner,
            current.execution.MixedGlobalVersionOwner, current.execution.MixedVRRPOwner):
        monkeypatch.setattr(cls, "finish", forbidden)
    monkeypatch.setattr(current.execution, "execute_mixed_inputs", forbidden)
    monkeypatch.setattr(current.execution.pipeline, "execute_p4_folder", forbidden)
    monkeypatch.setattr(current.execution.pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(current.execution.pipeline.p4, "admit_folder", forbidden)
    monkeypatch.setattr(FactStore, "__init__", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)


@pytest.fixture
def source(tmp_path, monkeypatch):
    admitted(tmp_path)
    run = current.build_mixed_source(tmp_path, LIMITS)
    assert run.current_component() is run.result and run.retained.component is run.result
    freeze(monkeypatch)
    return run


def refused(run, code):
    accepted, retained = run.result, run.retained
    with pytest.raises(ValueError, match="^" + code + "$"):
        run.current_component()
    assert run.result is accepted and run.retained is retained and run.attempted
    with pytest.raises(ValueError, match="^fhrp_mixed_component_once$"):
        run.build()


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp"])
def test_current_access_reuses_original_component_cells_and_source_without_any_production(tmp_path, monkeypatch, mode):
    admitted(tmp_path, mode)
    run = current.build_mixed_source(tmp_path, LIMITS)
    accepted, retained, batch = run.result, run.retained, run.source.vrrp_executed
    snapshots = tuple((getattr(accepted, field).store, getattr(accepted, field).rows,
        tuple((ref.fact, ref.subject, value) for ref, value in getattr(accepted, field).store.values.items())) for field in FIELDS)
    freeze(monkeypatch)
    for _ in range(3):
        assert run.current_component() is accepted and run.retained is retained
        assert run.source.vrrp_executed is run.source.fhrp.vrrp_owner.executed is batch
        for field, (store, rows, cells) in zip(FIELDS, snapshots, strict=True):
            result = getattr(accepted, field)
            assert result is getattr(run, field) and result.store is store and result.rows is rows
            assert len(store.values) == len(cells) and all(store.values[k.FactRef(fact=fact, subject=subject)] is value
                for fact, subject, value in cells)
    assert sum(len(spec(field).produces) for field in FIELDS) == 7
    assert len({id(store) for store, _, _ in snapshots}) == 5


@pytest.mark.parametrize("field,fact,name", FACTS)
@pytest.mark.parametrize("plant", ["store_cell", "coherent_pair"])
def test_each_of_seven_current_cells_keeps_original_pointer_even_for_equal_values(source, field, fact, name, plant):
    result = getattr(source.result, field)
    row = result.rows[0]
    original = getattr(row, name)
    replacement = replace(original)
    assert replacement == original and replacement is not original
    ref = k.FactRef(fact=fact, subject=row.subject)
    result.store.values[ref] = replacement
    if plant == "coherent_pair":
        object.__setattr__(row, name, replacement)
    refused(source, "fhrp_mixed_component_cell")
    result.store.values[ref] = original
    if plant == "coherent_pair":
        object.__setattr__(row, name, original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("plant", ["store", "rows"])
def test_actual_store_and_rowtuple_copies_refuse_while_original_history_is_retained(source, field, plant):
    result = getattr(source.result, field)
    attribute = "store" if plant == "store" else "rows"
    original = getattr(result, attribute)
    object.__setattr__(result, attribute, copy(original) if plant == "store" else tuple(row for row in original))
    refused(source, "fhrp_mixed_component_store")
    object.__setattr__(result, attribute, original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("plant", ["missing", "extra", "owner", "fact_alias", "unhashable"])
def test_live_store_coordinates_and_ownership_cannot_change_or_evade_finite_checks(source, field, plant):
    store = getattr(source.result, field).store
    owners, values = dict(store.owners), dict(store.values)
    ref = next(iter(store.values))
    if plant == "missing":
        store.values.pop(ref)
    elif plant == "extra":
        store.values[k.FactRef(fact=ref.fact, subject="fhrp_local:foreign")] = store.values[ref]
    elif plant == "owner":
        store.owners[ref.fact] = StrEnum("Alias", {"VALUE": store.owners[ref.fact]}).VALUE
    elif plant == "fact_alias":
        alias = k.FactRef(fact=ref.fact, subject=ref.subject)
        object.__setattr__(alias, "fact", StrEnum("Alias", {"VALUE": ref.fact}).VALUE)
        store.values = {alias if key == ref else key: value for key, value in store.values.items()}
    else:
        original_fact = ref.fact
        object.__setattr__(ref, "fact", [])
    refused(source, "fhrp_mixed_component_store" if plant == "owner" else "fhrp_mixed_component_population")
    if plant == "unhashable":
        object.__setattr__(ref, "fact", original_fact)
    store.owners, store.values = owners, values
    assert source.current_component() is source.result


@pytest.mark.parametrize("field", FIELDS)
def test_equal_plain_store_maps_and_keys_remain_valid_data(source, field):
    result = getattr(source.result, field)
    result.store.owners = dict(result.store.owners)
    result.store.values = {k.FactRef(fact=ref.fact, subject=ref.subject): value for ref, value in result.store.values.items()}
    assert source.current_component() is source.result


def test_equal_typed_retention_container_copies_preserve_original_component_and_cells(source):
    original = source.retained
    held = tuple((store, rows, tuple((fact, subject, value) for fact, subject, value in cells))
        for store, rows, cells in original.held)
    subjects = tuple(tuple(value for value in group) for group in original.subjects)
    source.retained = replace(original, held=held, subjects=subjects)
    assert source.retained is not original and source.current_component() is original.component


@pytest.mark.parametrize("plant", ["subjects_alias", "subject_drop", "held_alias", "held_shape"])
def test_retained_snapshot_scope_is_finite_and_cannot_redefine_declared_population(source, plant):
    original = source.retained
    if plant.startswith("subject"):
        groups = list(original.subjects)
        groups[0] = groups[0][:-1] if plant == "subject_drop" else (StrEnum("Alias", {"VALUE": groups[0][0]}).VALUE,)
        source.retained = replace(original, subjects=tuple(groups))
    else:
        held = list(original.held)
        store, rows, cells = held[0]
        held[0] = (store, rows, ()) if plant == "held_shape" else (store, rows,
            ((StrEnum("Alias", {"VALUE": cells[0][0]}).VALUE, cells[0][1], cells[0][2]), *cells[1:]))
        source.retained = replace(original, held=tuple(held))
    code = "fhrp_mixed_component_population" if plant == "subject_drop" else "fhrp_mixed_component_cell" if plant == "held_shape" else "fhrp_mixed_component_source"
    refused(source, code)
    source.retained = original
    assert source.current_component() is source.result


@pytest.mark.parametrize("field", ["source", "result", *FIELDS])
def test_original_run_and_component_field_bindings_cannot_be_swapped(source, field):
    original = getattr(source, field)
    setattr(source, field, replace(original))
    with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
        source.current_component()
    assert getattr(source, field) is not original
    setattr(source, field, original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("plant", ["unbuilt", "foreign", "failed"])
def test_unaccepted_or_foreign_retention_never_becomes_a_current_component(tmp_path, monkeypatch, plant):
    admitted(tmp_path)
    run = current.MixedComponentRun(tmp_path, LIMITS)
    if plant == "foreign":
        run.build()
        run.retained = object()
    elif plant == "failed":
        def refusing(*args):
            raise ValueError("planted_finish")
        monkeypatch.setattr(current.execution.MixedGlobalVersionOwner, "finish", refusing)
        with pytest.raises(ValueError, match="^planted_finish$"):
            run.build()
        assert run.source is not None and run.tree is not None and run.state is not None
        assert run.version is run.vrrp is run.result is run.retained is None
    with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
        run.current_component()
    if plant != "unbuilt":
        with pytest.raises(ValueError, match="^fhrp_mixed_component_once$"):
            run.build()


@pytest.mark.parametrize("field", FIELDS)
def test_each_owning_reader_value_validator_runs_on_every_current_access(source, monkeypatch, field):
    cls, name = {"tree": (current.stp.RootGuardPack, "validate_root_guard_values"),
        "channel": (current.ec.ProtocolOwner, "validate_reported_protocol_values"),
        "state": (current.build.StateOwner, "validate_gateway_source_values"),
        "version": (current.execution.MixedGlobalVersionOwner, "validate_values"),
        "vrrp": (current.execution.MixedVRRPOwner, "validate_values")}[field]
    def refusing(self, *args):
        raise ValueError("planted_current_value")
    monkeypatch.setattr(cls, name, refusing)
    refused(source, "planted_current_value")


@pytest.mark.parametrize("field,fact,name", FACTS)
def test_in_place_primitive_fact_changes_require_canonical_values_not_only_cell_identity(source, field, fact, name):
    result = getattr(source.result, field)
    row = next(row for row in result.rows if type(getattr(row, name)) is k.Known)
    value = getattr(row, name)
    original = value.value
    object.__setattr__(value, "value", not original if type(original) is bool else "unmodelled")
    code = "stp_root_guard_source_value" if field == "tree" else "etherchannel_protocol_source_value" if field == "channel" else (
        "hsrp_gateway_source_value" if field == "state" else "hsrp_version_value_cell" if field == "version" else "vrrp_owner_value_cell")
    refused(source, code)
    object.__setattr__(value, "value", original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("which", ["first", "last"])
def test_current_access_rechecks_current_source_before_and_after_all_reader_closures(source, monkeypatch, which):
    original, calls = current.execution.validate_mixed_execution, []
    def validating(*args):
        calls.append(args[0])
        if len(calls) == (1 if which == "first" else 2):
            raise ValueError("planted_current_source")
        return original(*args)
    monkeypatch.setattr(current.execution, "validate_mixed_execution", validating)
    refused(source, "planted_current_source")
    assert calls and all(value is source.source for value in calls)


def test_repeated_fresh_source_builds_share_input_values_but_no_owned_store_instances(tmp_path, monkeypatch):
    admitted(tmp_path)
    first = current.build_mixed_source(tmp_path, LIMITS)
    second = current.build_mixed_source(tmp_path, LIMITS)
    assert first is not second and first.source is not second.source and first.result is not second.result
    assert all(getattr(first.result, field).store is not getattr(second.result, field).store
        and getattr(first.result, field).store.values == getattr(second.result, field).store.values for field in FIELDS)
    freeze(monkeypatch)
    assert first.current_component() is first.result and second.current_component() is second.result


@pytest.mark.parametrize("extra", [{"component": object()}, {"source": object()}, {"retained": object()}, {"profile": "other"}])
def test_fresh_entry_has_no_prepared_carrier_or_caller_profile_front_door(tmp_path, monkeypatch, extra):
    monkeypatch.setattr(current.MixedComponentRun, "build", forbidden)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        current.build_mixed_source(tmp_path, LIMITS, **extra)


@pytest.mark.parametrize("plant", ["budget_copy", "source_copy", "attempt_flag"])
def test_current_run_context_and_attempt_state_are_still_bound_to_original_ownership(source, plant):
    if plant == "budget_copy":
        original = source.budgets
        source.budgets = replace(original)
        code = "fhrp_mixed_execution_current"
    elif plant == "source_copy":
        original = source.source
        source.source = replace(original)
        code = "fhrp_mixed_component_source"
    else:
        original = source.attempted
        source.attempted = 1
        code = "fhrp_mixed_component_source"
    with pytest.raises(ValueError, match="^" + code + "$"):
        source.current_component()
    setattr(source, {"budget_copy": "budgets", "source_copy": "source", "attempt_flag": "attempted"}[plant], original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("operation", ["iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary",
    "iosxe.show_standby_brief", "iosxe.show_standby_all", "iosxe.show_vrrp"])
@pytest.mark.parametrize("dimension", ["vrf", "context", "instance", "vdc", "tenant", "afi", "plane"])
def test_current_actual_capture_scope_stays_flat_exec_for_every_operation(source, operation, dimension):
    receipt = next(out.receipt for out in source.source.execution.executed if out.receipt.capture.operation == operation)
    capture, metadata = receipt.capture, receipt.capture.metadata
    assert capture.scope.plane == "exec" and all(getattr(capture.scope, name) is None
        for name in ("vrf", "context", "instance", "vdc", "tenant", "afi"))
    assert source.current_component() is source.result
    changed = replace(capture.resolved_metadata, scope=replace(capture.scope,
        **{dimension: "admin" if dimension == "plane" else "blue"}))
    object.__setattr__(capture, "metadata", changed)
    request = current.execution.receipts.CaptureRequest(capture=capture, context=receipt.context)
    assert current.execution.validate_fhrp_request_graph(request) is None
    refused(source, "fhrp_mixed_execution_scope")
    object.__setattr__(capture, "metadata", metadata)
    assert source.current_component() is source.result
