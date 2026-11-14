"""Fresh five-Store production and retained failure evidence; no global proof or origin seal."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_context import admitted
from test_peer_execution import forbidden
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import mixed_component as component

FIELDS = ("tree", "channel", "state", "version", "vrrp")


def spec(field):
    return {"tree": component.stp.STEP, "channel": component.ec.STEP, "state": component.build.STEP,
        "version": component.version_profile.STEP, "vrrp": component.vrrp_profile.STEP}[field]


def finish_class(field):
    return {"tree": component.stp.RootGuardPack, "channel": component.SummaryPack,
        "state": component.build.StateOwner, "version": component.execution.MixedGlobalVersionOwner,
        "vrrp": component.execution.MixedVRRPOwner}[field]


def fact(field):
    return {"tree": component.stp.ROOT_GUARD, "channel": component.ec.REPORTED_PROTOCOL,
        "state": component.build.REPORTED_STATE, "version": component.version_profile.REPORTED_PROTOCOL_VERSION,
        "vrrp": component.vrrp_profile.REPORTED_VRRP_STATE}[field]


def started(tmp_path):
    admitted(tmp_path)
    return component.MixedComponentRun(tmp_path, LIMITS)


def late(monkeypatch, run, action):
    original = component.execution.MixedVRRPOwner.finish
    def finishing(self):
        result = original(self)
        action(run, result)
        return result
    monkeypatch.setattr(component.execution.MixedVRRPOwner, "finish", finishing)


def refused(run, code):
    with pytest.raises(ValueError, match="^" + code + "$"):
        run.build()
    assert run.attempted and run.source is not None and run.result is None
    with pytest.raises(ValueError, match="^fhrp_mixed_component_once$"):
        run.build()


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp"])
def test_actual_five_stores_keep_independent_declared_populations_readers_and_original_cells(tmp_path, monkeypatch, mode):
    admitted(tmp_path, mode)
    run = component.MixedComponentRun(tmp_path, LIMITS)
    readers, parses, stores = [], [], []
    init, write, validate = FactStore.__init__, FactWriter.write, component.execution.validate_mixed_execution
    validated = []
    def initializing(self):
        init(self)
        stores.append(self)
    def validating(*args):
        result = validate(*args)
        validated.append((args[0], len(stores)))
        return result
    def writing(self, **kwargs):
        assert len(validated) >= 2 and validated[0][1] == validated[1][1] == 0
        return write(self, **kwargs)
    monkeypatch.setattr(FactStore, "__init__", initializing)
    monkeypatch.setattr(FactWriter, "write", writing)
    monkeypatch.setattr(component.execution, "validate_mixed_execution", validating)
    for module in (component.stp.stp, component.ec.parse_summary, component.build.hsrp,
            component.version_profile.parser, component.vrrp_profile.parser):
        original = module.parse_capture
        def parsing(capture, *args, original=original):
            result = original(capture, *args)
            parses.append(capture)
            return result
        monkeypatch.setattr(module, "parse_capture", parsing)
    for field, name in zip(FIELDS, ("validate_root_guard_values", "validate_reported_protocol_values",
            "validate_gateway_source_values", "validate_values", "validate_values"), strict=True):
        cls, original = (component.ec.ProtocolOwner if field == "channel" else finish_class(field)), None
        original = getattr(cls, name)
        def reading(self, result, reader, *args, field=field, original=original):
            assert all(getattr(run, name) is not None for name in FIELDS)
            assert reader.store is result.store and reader.step.reads == spec(field).produces and not reader.step.produces
            readers.append(field)
            return original(self, result, reader, *args)
        monkeypatch.setattr(cls, name, reading)
    result = run.build()
    assert type(result) is component.MixedComponent and result is run.result and result.source is run.source
    assert readers == list(FIELDS) and len(stores) == 5 and len({id(store) for store in stores}) == 5
    assert len(parses) == len(result.source.execution.executed) and all(source is result.source for source, _ in validated)
    expected = (0, 0, 0, 0, 2) if mode == "only_vrrp" else (1, 1, 5, 5, 2)
    assert tuple(len(getattr(result, field).rows) for field in FIELDS) == expected
    for field in FIELDS:
        owned = getattr(result, field)
        assert owned is getattr(run, field) and owned.store.owners == {value: spec(field).id for value in spec(field).produces}
        assert set(owned.store.values) == {k.FactRef(fact=value, subject=row.subject) for row in owned.rows for value in spec(field).produces}
    assert set(row.subject for row in result.state.rows) == set(row.subject for row in result.version.rows)
    assert not set(row.subject for row in result.state.rows) & set(row.subject for row in result.vrrp.rows)
    monkeypatch.setattr(component.execution, "execute_mixed_inputs", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_component_once$"):
        run.build()


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("plant", ["missing", "extra", "alias", "cross_protocol", "owner"])
def test_each_store_has_exact_declared_fact_subject_keys_and_plain_ownership(tmp_path, monkeypatch, field, plant):
    run = started(tmp_path)
    def changing(attempt, current):
        result = current if field == "vrrp" else getattr(attempt, field)
        ref = next(iter(result.store.values))
        if plant == "missing":
            result.store.values.pop(ref)
        elif plant == "extra":
            result.store.values[k.FactRef(fact=ref.fact, subject="fhrp_local:extra")] = result.store.values[ref]
        elif plant == "alias":
            alias = k.FactRef(fact=ref.fact, subject=ref.subject)
            object.__setattr__(alias, "fact", StrEnum("Alias", {"VALUE": ref.fact}).VALUE)
            result.store.values = {alias if key == ref else key: value for key, value in result.store.values.items()}
        elif plant == "cross_protocol":
            result.store.values[k.FactRef(fact=component.vrrp_profile.REPORTED_VRRP_STATE if field != "vrrp" else component.build.REPORTED_STATE,
                subject=ref.subject)] = result.store.values[ref]
        else:
            result.store.owners[ref.fact] = "l3.fhrp/other"
    late(monkeypatch, run, changing)
    refused(run, "fhrp_mixed_component_store" if plant == "owner" else "fhrp_mixed_component_population")
    assert all(getattr(run, name) is not None for name in FIELDS)


@pytest.mark.parametrize("field", FIELDS)
def test_coherently_shrunken_returned_rows_and_store_do_not_redefine_expected_subjects(tmp_path, monkeypatch, field):
    run = started(tmp_path)
    cls, original = finish_class(field), finish_class(field).finish
    def finishing(self, *args):
        result = original(self, *args)
        rows = result.rows[:-1]
        subjects = {row.subject for row in rows}
        object.__setattr__(result, "rows", rows)
        result.store.values = {ref: value for ref, value in result.store.values.items() if ref.subject in subjects}
        return result
    monkeypatch.setattr(cls, "finish", finishing)
    refused(run, "fhrp_mixed_component_population")


@pytest.mark.parametrize("field", ["tree", "channel", "state"])
@pytest.mark.parametrize("plant", ["equal_cell", "store_copy", "rows_copy"])
def test_earlier_real_store_rows_and_cells_are_snapshotted_before_later_finishes(tmp_path, monkeypatch, field, plant):
    run = started(tmp_path)
    def changing(attempt, current):
        result = getattr(attempt, field)
        if plant == "store_copy":
            copy = FactStore()
            copy.owners, copy.values = dict(result.store.owners), dict(result.store.values)
            object.__setattr__(result, "store", copy)
        elif plant == "rows_copy":
            object.__setattr__(result, "rows", tuple(row for row in result.rows))
        else:
            row = result.rows[0]
            value = replace(row.value)
            assert value == row.value and value is not row.value
            object.__setattr__(row, "value", value)
            result.store.values[k.FactRef(fact=fact(field), subject=row.subject)] = value
    late(monkeypatch, run, changing)
    refused(run, "fhrp_mixed_component_cell" if plant == "equal_cell" else "fhrp_mixed_component_store")


@pytest.mark.parametrize("field", FIELDS)
def test_each_public_owning_value_validator_is_required_before_accepting_component(tmp_path, monkeypatch, field):
    run = started(tmp_path)
    name = "validate_root_guard_values" if field == "tree" else "validate_reported_protocol_values" if field == "channel" else "validate_gateway_source_values" if field == "state" else "validate_values"
    cls = component.ec.ProtocolOwner if field == "channel" else finish_class(field)
    def refusing(self, *args):
        assert all(getattr(run, name) is not None for name in FIELDS)
        raise ValueError("planted_value")
    monkeypatch.setattr(cls, name, refusing)
    refused(run, "planted_value")
    assert all(getattr(run, name) is not None for name in FIELDS)


@pytest.mark.parametrize("field", FIELDS)
def test_writer_failure_retains_only_source_and_prior_returned_stores_without_rollback_claim(tmp_path, monkeypatch, field):
    run = started(tmp_path)
    original, seen = FactWriter.write, []
    def writing(self, **kwargs):
        if kwargs["fact"] in spec(field).produces:
            seen.append(self.store)
            if len(seen) == 2:
                raise ValueError("planted_writer")
        return original(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    refused(run, "planted_writer")
    index = FIELDS.index(field)
    assert all(getattr(run, name) is not None for name in FIELDS[:index])
    assert all(getattr(run, name) is None for name in FIELDS[index:])
    assert len(seen) == 2 and seen[0] is seen[1] and len(seen[0].values) == 1


@pytest.mark.parametrize("plant", ["store", "step", "type"])
def test_reader_factory_must_return_the_actual_store_and_exact_narrow_step(tmp_path, monkeypatch, plant):
    run = started(tmp_path)
    original = component.bind_reader
    def binding(store, *, step):
        value = original(store, step=step)
        return object() if plant == "type" else replace(value, store=FactStore()) if plant == "store" else replace(value, step=replace(step))
    monkeypatch.setattr(component, "bind_reader", binding)
    refused(run, "fhrp_mixed_component_reader")


@pytest.mark.parametrize("phase", ["before_writer", "after_finishes", "final"])
def test_current_source_validation_remains_required_at_every_component_boundary(tmp_path, monkeypatch, phase):
    run = started(tmp_path)
    original, calls = component.execution.validate_mixed_execution, []
    def validating(source, budgets):
        calls.append(source)
        if len(calls) == {"before_writer": 2, "after_finishes": 3, "final": 4}[phase]:
            raise ValueError("planted_source")
        return original(source, budgets)
    monkeypatch.setattr(component.execution, "validate_mixed_execution", validating)
    refused(run, "planted_source")
    assert all(getattr(run, field) is None for field in FIELDS) if phase == "before_writer" else all(getattr(run, field) is not None for field in FIELDS)


@pytest.mark.parametrize("field,code", [("tree", "stp_root_guard_source_value"), ("channel", "etherchannel_protocol_source_value"),
    ("state", "hsrp_gateway_source_value"), ("version", "hsrp_version_value_cell"), ("vrrp", "vrrp_owner_value_cell")])
def test_in_place_original_cell_mutation_requires_each_owning_semantic_check(tmp_path, monkeypatch, field, code):
    run = started(tmp_path)
    def changing(attempt, current):
        result = current if field == "vrrp" else getattr(attempt, field)
        row = next(row for row in result.rows if type(row.value) is k.Known)
        object.__setattr__(row.value, "value", not row.value.value if field == "tree" else "unmodelled")
    late(monkeypatch, run, changing)
    refused(run, code)


@pytest.mark.parametrize("field,code", [("tree", "fhrp_mixed_execution_cache"), ("channel", "fhrp_mixed_execution_cache"),
    ("state", "fhrp_mixed_execution_cache"), ("version", "hsrp_version_cache"), ("vrrp", "vrrp_owner_cache")])
def test_every_current_original_source_cache_closes_before_first_store(tmp_path, monkeypatch, field, code):
    baseline = started(tmp_path / "baseline").build()
    assert baseline.vrrp.rows
    run = started(tmp_path / "bad")
    original = component.execution.execute_mixed_inputs
    def executing(*args):
        source = original(*args)
        cache = {"tree": source.tree.produced, "channel": source.channel.owner.produced,
            "state": source.fhrp.state.produced, "version": source.fhrp.version.inputs.produced,
            "vrrp": source.fhrp.vrrp_owner.produced}[field]
        cache.clear()
        return source
    monkeypatch.setattr(component.execution, "execute_mixed_inputs", executing)
    monkeypatch.setattr(FactStore, "__init__", forbidden)
    refused(run, code)
    assert all(getattr(run, name) is None for name in FIELDS)
