"""Fresh Root9 current cells and semantic bytes; no deep origin, post-return seal or rollback claim."""
import json
from copy import copy
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_mixed_component import FIELDS
from test_mixed_source import FACTS, freeze
from test_peer_execution import forbidden
from test_root_mixed_inputs import root_folder
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import mixed_component as current

ROOT_FACTS = (*FACTS, ("tree", current.stp.REPORTED_ROOT_PRIORITY, "root_priority"),
    ("tree", current.stp.REPORTED_ROOT_MAC, "root_mac"))
MAC = "aBcD.EF01.2345"


def folder(root, mode="normal"):
    _, _, files = root_folder(root, mode)
    if "tree.txt" in files:
        files["tree.txt"] += f"   Designated root has priority 32769, address {MAC}\n".encode()
        side = json.loads(files["p4.json"])
        next(row for row in side["captures"] if row["path"] == "tree.txt")["sha256"] = sha256(files["tree.txt"]).hexdigest()
        files["p4.json"] = canonical(side)
        for name, raw in files.items():
            (root / name).write_bytes(raw)
    return files


def frozen(monkeypatch):
    freeze(monkeypatch)
    for cls in (current.stp.RootObservationPack, current.RootMixedGlobalVersionOwner, current.RootMixedVRRPOwner):
        monkeypatch.setattr(cls, "finish", forbidden)
    monkeypatch.setattr(current.execution, "execute_root_mixed_inputs", forbidden)


@pytest.fixture
def source(tmp_path, monkeypatch):
    folder(tmp_path)
    run = current.build_root_mixed_source(tmp_path, replace(LIMITS))
    assert run.current_component() is run.result
    frozen(monkeypatch)
    return run


def refused(run, code):
    result, retained = run.result, run.retained
    with pytest.raises(ValueError, match="^" + code + "$"):
        run.current_component()
    assert run.result is result and run.retained is retained
    with pytest.raises(ValueError, match="^fhrp_mixed_component_once$"):
        run.build()


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "zero_vrrp", "no_all_capture", "no_all_target"])
def test_genuine_fresh_root9_keeps_nine_facts_five_stores_original_cells_and_known_root_types(tmp_path, monkeypatch, mode):
    files = folder(tmp_path, mode)
    run = current.build_root_mixed_source(tmp_path, replace(LIMITS))
    result, batch = run.result, run.source.vrrp_executed
    assert type(result) is current.RootMixedComponent and result is run.retained.component
    assert len({id(getattr(result, field).store) for field in FIELDS}) == 5
    expected = (0, 0, 0, 0, 2) if mode == "only_vrrp" else (1, 1, 5, 5, 0 if mode == "zero_vrrp" else 1 if mode in ("no_all_capture", "no_all_target") else 2)
    assert tuple(len(getattr(result, field).rows) for field in FIELDS) == expected
    assert set().union(*(set(getattr(result, field).store.owners) for field in FIELDS)) == {fact for _, fact, _ in ROOT_FACTS}
    if mode in ("normal", "cold_vrrp", "zero_vrrp", "no_all_capture", "no_all_target"):
        row = result.tree.rows[0]
        assert type(row.root_priority) is k.Known and type(row.root_priority.value) is int and row.root_priority.value == 32769
        assert row.root_priority.raw == "32769" and row.root_mac.value == row.root_mac.raw == MAC
        assert type(row.value.value) is bool and row.value.value is True and row.role.value == "designated"
    if mode == "zero_vrrp":
        assert run.source.fhrp.vrrp_inputs.subjects == () and result.vrrp.rows == () and result.vrrp.store.values == {}
    if mode in ("no_all_capture", "no_all_target"):
        known = {row.subject for row in result.state.rows if type(row.value) is k.Known}
        assert known and known <= {row.subject for row in result.version.rows}
        for row in result.version.rows:
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
            assert row.value.next_evidence == (k.EvidenceNeed(node=row.target.node.key,
                operation=current.version_profile.parser.OP, params=(("group", row.group), ("interface", row.interface)),
                resolves=(current.version_profile.REPORTED_PROTOCOL_VERSION,), reruns=(str(current.version_profile.STEP.id),),
                after_s=None, unprintable=("explicit_reported_protocol_version",)),)
    snapshots = tuple((getattr(result, field).store, getattr(result, field).rows, tuple(getattr(result, field).store.values.items())) for field in FIELDS)
    frozen(monkeypatch)
    assigning, binding, assigned, readers = current.RootMixedVRRPOwner.__setattr__, current.bind_reader, [], []
    def setting(self, name, value):
        if name == "executed":
            assigned.append(value)
        return assigning(self, name, value)
    def reading(store, *, step):
        readers.append((store, step.reads))
        return binding(store, step=step)
    monkeypatch.setattr(current.RootMixedVRRPOwner, "__setattr__", setting)
    monkeypatch.setattr(current, "bind_reader", reading)
    for _ in range(3):
        assert run.current_component() is result and run.source.vrrp_executed is run.source.fhrp.vrrp_owner.executed is batch
        for field, (store, rows, cells) in zip(FIELDS, snapshots, strict=True):
            assert getattr(run, field) is getattr(result, field) and getattr(result, field).store is store and getattr(result, field).rows is rows
            assert len(store.values) == len(cells) and all(store.values[ref] is value for ref, value in cells)
    assert assigned == [] and len(readers) == 15
    assert all(reads == tuple(sorted(store.owners)) for store, reads in readers)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("field,fact,name", ROOT_FACTS)
@pytest.mark.parametrize("plant", ["pair", "store", "missing", "alias"])
def test_all_nine_fact_cells_keep_original_pointers_and_exact_plain_coordinates_with_restoration(source, field, fact, name, plant):
    result = getattr(source.result, field)
    row, values = result.rows[0], dict(result.store.values)
    original = getattr(row, name)
    reference = k.FactRef(fact=fact, subject=row.subject)
    if plant in ("pair", "store"):
        replacement = replace(original)
        assert replacement == original and replacement is not original
        result.store.values[reference] = replacement
        if plant == "pair":
            object.__setattr__(row, name, replacement)
        code = "fhrp_mixed_component_cell"
    elif plant == "missing":
        result.store.values.pop(reference)
        code = "fhrp_mixed_component_population"
    else:
        alias = k.FactRef(fact=fact, subject=row.subject)
        object.__setattr__(alias, "fact", StrEnum("Alias", {"VALUE": fact}).VALUE)
        result.store.values = {alias if ref == reference else ref: value for ref, value in result.store.values.items()}
        code = "fhrp_mixed_component_population"
    refused(source, code)
    object.__setattr__(row, name, original)
    result.store.values = values
    assert source.current_component() is source.result


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("plant", ["store", "rows", "owner"])
def test_each_original_root9_store_rowtuple_and_owner_map_is_retained(source, field, plant):
    result = getattr(source.result, field)
    if plant == "owner":
        original = dict(result.store.owners)
        result.store.owners[next(iter(original))] = "l3.fhrp/other"
    else:
        original = getattr(result, plant)
        object.__setattr__(result, plant, copy(original) if plant == "store" else tuple(row for row in original))
    refused(source, "fhrp_mixed_component_store")
    if plant == "owner":
        result.store.owners = original
    else:
        object.__setattr__(result, plant, original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("name,value", [("root_priority", True), ("value", 1), ("root_mac", "0000.0000.0000"), ("role", "root")])
def test_original_root_semantics_refuse_priority_bool_guard_integer_mac_and_role_forgeries(source, name, value):
    state = getattr(source.tree.rows[0], name)
    original = state.value
    assert type(state) is k.Known
    object.__setattr__(state, "value", value)
    refused(source, "stp_root_observation_value")
    object.__setattr__(state, "value", original)
    assert source.current_component() is source.result


@pytest.mark.parametrize("which", ["version", "vrrp"])
def test_later_writer_failure_retains_prior_returned_results_and_consumes_run_without_retention(tmp_path, monkeypatch, which):
    folder(tmp_path)
    run = current.RootMixedComponentRun(tmp_path, replace(LIMITS))
    original, stores = FactWriter.write, []
    fact = current.version_profile.REPORTED_PROTOCOL_VERSION if which == "version" else current.vrrp_profile.REPORTED_VRRP_STATE
    def writing(self, **kwargs):
        if kwargs["fact"] == fact:
            stores.append(self.store)
            if len(stores) == 2:
                raise ValueError("planted_writer")
        return original(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^planted_writer$"):
        run.build()
    index = FIELDS.index(which)
    assert run.source is not None and all(getattr(run, field) is not None for field in FIELDS[:index])
    assert all(getattr(run, field) is None for field in FIELDS[index:]) and run.result is run.retained is None
    assert len(stores) == 2 and stores[0] is stores[1] and len(stores[0].values) == 1
    refused(run, "fhrp_mixed_component_source")


@pytest.mark.parametrize("field", ["source", "result", *FIELDS])
def test_current_run_fields_cannot_be_replaced_even_with_equal_copies(source, field):
    original = getattr(source, field)
    setattr(source, field, replace(original))
    with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
        source.current_component()
    setattr(source, field, original)
    assert source.current_component() is source.result


def test_typed_retention_container_copies_preserve_data_but_old_and_root_run_gates_remain_distinct(tmp_path, monkeypatch):
    folder(tmp_path)
    root = current.build_root_mixed_source(tmp_path, replace(LIMITS))
    old = current.build_mixed_source(tmp_path, replace(LIMITS))
    original = root.retained
    root.retained = replace(original, subjects=tuple(tuple(group) for group in original.subjects),
        held=tuple((store, rows, tuple(cells)) for store, rows, cells in original.held))
    frozen(monkeypatch)
    with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
        current.RootMixedComponentRun(tmp_path, replace(LIMITS)).current_component()
    assert root.current_component() is original.component and old.current_component() is old.result
    for run, foreign, cls in ((root, old, current.MixedComponentRun), (old, root, current.RootMixedComponentRun)):
        with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
            cls.current_component(run)
        saved = run.retained
        run.retained = foreign.retained
        with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
            run.current_component()
        run.retained = saved
        monkeypatch.setattr(current.execution, "execute_mixed_inputs" if cls is current.MixedComponentRun else "execute_root_mixed_inputs", lambda *args, value=run.source: value)
        with pytest.raises(ValueError, match="^fhrp_mixed_component_source$"):
            cls(tmp_path, run.budgets).build()


@pytest.mark.parametrize("which", ["budget", "profile", "capture_scope"])
def test_current_source_budget_profile_and_scope_are_rechecked_before_owning_cells(source, which):
    if which == "budget":
        object.__setattr__(source.budgets, "artifacts", source.budgets.artifacts + 1)
        code = "fhrp_mixed_execution_current"
    elif which == "profile":
        object.__setattr__(source.source, "compiled", replace(source.source.compiled, registration_sha256="0" * 64))
        code = "fhrp_mixed_execution_current"
    else:
        capture = source.source.execution.executed[0].receipt.capture
        object.__setattr__(capture, "metadata", replace(capture.resolved_metadata, scope=replace(capture.scope, vrf="blue")))
        code = "fhrp_mixed_execution_scope"
    refused(source, code)
