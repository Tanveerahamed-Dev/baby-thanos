"""Retained production/Reader falsification; closed cells are not general admission proof."""
from copy import deepcopy
from dataclasses import replace
from enum import StrEnum

import pytest
from test_reported_state_build import B
from test_version_finish import item, request

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactReader, FactStore, FactWriter, bind_reader
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import version_inputs as inputs
from atlas_brain.packs.l3.fhrp import version_owner as owner
from atlas_brain.runner import pack_runtime

FACT, STEP = "l3.fhrp.reported_protocol_version", "l3.fhrp/parse_hsrp_all_version"


def alias(value):
    return StrEnum("Alias", {"VALUE": value}).VALUE


def reader_for(store, name="l3.fhrp/arbitrary_reader"):
    step = StepSpec(id=StepId(name), pack=build.PACK, kind="check", scope="estate",
                    reads=(FACT,), produces=(), evaluator="l3.fhrp.inspect_values")
    return bind_reader(store, step=step)


def production(empty=False):
    first, cold = deepcopy(item()), deepcopy(item(node=B))
    execution = owner.execute_local_version_inputs(() if empty else (first, cold), () if empty else (request(first),))
    result = execution.owner.finish(execution.executed)
    return execution.owner, result, reader_for(result.store)


def known_row(result):
    return next(row for row in result.rows if type(row.value) is k.Known)


def unknown_row(result, cold=False):
    reason = k.UnknownReason.NOT_COLLECTED if cold else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    return next(row for row in result.rows if type(row.value) is k.Unknown and row.value.reason is reason)


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("name", ["l3.fhrp/not_a_credential", "l3.fhrp/another_reader"])
def test_actual_retained_production_and_declared_reader_validate_without_parser_or_writer_replay(monkeypatch, empty, name):
    actual, result, _ = production(empty)
    reader = reader_for(result.store, name)
    reads, original = [], FactReader.read
    def reading(self, **kwargs):
        value = original(self, **kwargs)
        reads.append((kwargs["subject"], value))
        return value
    def forbidden(*args, **kwargs):
        pytest.fail("value validation replayed parser, dispatcher or Writer")
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(owner.parser, "parse_capture", forbidden)
    monkeypatch.setattr(owner, "execute_parsers", forbidden)
    monkeypatch.setattr(pack_runtime, "execute_parsers", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    assert actual.validate_values(result, reader) is None
    assert len(reads) == len(result.rows) and {subject for subject, _ in reads} == {row.subject for row in result.rows}
    assert all(value is result.store.values[k.FactRef(fact=FACT, subject=subject)] for subject, value in reads)
    assert actual.validate_values(result, replace(reader)) is None


@pytest.mark.parametrize("field", ["result_copy", "store_copy", "rows_copy", "executed_copy", "registration"])
def test_typed_carrier_and_equal_metadata_copies_are_not_the_actual_completed_production(field):
    actual, result, reader = production()
    if field == "result_copy":
        result = replace(result)
    elif field == "store_copy":
        store = FactStore()
        store.owners.update(result.store.owners)
        store.values.update(result.store.values)
        object.__setattr__(result, "store", store)
        reader = reader_for(store)
    elif field == "rows_copy":
        object.__setattr__(result, "rows", tuple(list(result.rows)))
    elif field == "executed_copy":
        object.__setattr__(result, "executed", tuple(list(result.executed)))
    else:
        object.__setattr__(result, "registration_sha256", "0" * 64)
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("field", ["drop", "extra", "wrong_fact", "cell_copy", "owner", "extra_owner",
                                    "owner_fact_alias", "owner_step_alias", "reference_fact_alias", "reference_subject_alias"])
def test_complete_store_population_original_cells_and_plain_key_types_are_closed(field):
    actual, result, reader = production()
    row = known_row(result)
    reference = k.FactRef(fact=FACT, subject=row.subject)
    if field == "drop":
        result.store.values.pop(k.FactRef(fact=FACT, subject=unknown_row(result, True).subject))
    elif field == "extra":
        result.store.values[k.FactRef(fact=FACT, subject="fhrp_local:synthetic_extra")] = row.value
    elif field == "wrong_fact":
        result.store.values[k.FactRef(fact=build.REPORTED_STATE, subject=row.subject)] = result.store.values.pop(reference)
    elif field == "cell_copy":
        result.store.values[reference] = replace(row.value)
    elif field == "owner":
        result.store.owners[FACT] = "l3.fhrp/other"
    elif field == "extra_owner":
        result.store.owners[build.REPORTED_STATE] = build.STEP.id
    elif field == "owner_fact_alias":
        step = result.store.owners.pop(FACT)
        result.store.owners[alias(FACT)] = step
    elif field == "owner_step_alias":
        result.store.owners[FACT] = alias(STEP)
    else:
        copied = replace(reference)
        object.__setattr__(copied, "fact" if field == "reference_fact_alias" else "subject",
                           alias(FACT if field == "reference_fact_alias" else row.subject))
        result.store.values.pop(reference)
        result.store.values[copied] = row.value
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("field", ["value", "raw", "both", "integer", "enum", "raw_enum", "basis", "capture", "role", "span", "span_bool", "hash", "evidence_order"])
def test_in_place_known_forgeries_cannot_survive_canonical_recomputation(field):
    actual, result, reader = production()
    value = known_row(result).value
    if field in ("value", "raw", "both"):
        for name in (("value", "raw") if field == "both" else (field,)):
            object.__setattr__(value, name, "1")
    elif field in ("integer", "enum"):
        object.__setattr__(value, "value", 2 if field == "integer" else alias("2"))
    elif field == "raw_enum":
        object.__setattr__(value, "raw", alias("2"))
    elif field == "basis":
        object.__setattr__(value, "basis", k.Basis.DECLARED)
    elif field == "evidence_order":
        object.__setattr__(value, "evidence", tuple(reversed(value.evidence)))
    else:
        original = next(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
        change = {"capture": {"capture": k.CaptureId("cap:other")}, "role": {"role": k.EvidenceRole.WITNESS},
            "span": {"locator": k.ByteSpan(start=original.locator.start + 1, end=original.locator.end)},
            "hash": {"excerpt_sha256": "0" * 64}, "span_bool": {}}[field]
        if field == "span_bool":
            copied = replace(original.locator)
            assert copied.start == 0
            object.__setattr__(copied, "start", False)
            change = {"locator": copied}
        changed = replace(original, **change)
        object.__setattr__(value, "evidence", tuple(changed if ref is original else ref for ref in value.evidence))
        if field == "span_bool":
            assert len(actual.canonical_rows(actual.completed.executed)) == len(result.rows)
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("cold", [False, True])
@pytest.mark.parametrize("field", ["reason", "detail", "needs", "params", "reruns", "candidates"])
def test_all_unknown_states_and_collection_needs_remain_exact_including_cold_participants(cold, field):
    actual, result, reader = production()
    value = unknown_row(result, cold).value
    if field == "reason":
        object.__setattr__(value, "reason", k.UnknownReason.PARSE_PARTIAL)
    elif field == "detail":
        object.__setattr__(value, "detail", "synthetic_other")
    elif field == "needs":
        object.__setattr__(value, "next_evidence", ())
    elif field == "candidates":
        object.__setattr__(value, "candidates", ("node:synthetic:other",))
    else:
        need, = value.next_evidence
        changed = replace(need, **({"params": (("group", "9"), ("interface", "Vlan10"))} if field == "params"
                                  else {"reruns": ("l3.fhrp/other",)}))
        object.__setattr__(value, "next_evidence", (changed,))
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("field", ["target", "interface", "group", "subject", "coherent_cell"])
def test_original_row_subject_mapping_and_coordinated_row_store_replacements_are_not_canonical(field):
    actual, result, reader = production()
    row = known_row(result)
    if field == "target":
        object.__setattr__(row, "target", replace(row.target))
    elif field in ("interface", "group", "subject"):
        object.__setattr__(row, field, "other")
    else:
        forged = replace(row.value, value="1", raw="1")
        object.__setattr__(row, "value", forged)
        result.store.values[k.FactRef(fact=FACT, subject=row.subject)] = forged
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("field", ["no_grant", "extra_read", "produces", "foreign_pack", "foreign_store", "enum_grant"])
def test_reader_is_exactly_bound_to_original_store_and_sole_fact_grant_even_when_empty(empty, field):
    actual, result, reader = production(empty)
    if field == "foreign_store":
        other = FactStore()
        other.owners.update(result.store.owners)
        other.values.update(result.store.values)
        reader = reader_for(other)
    elif field == "foreign_pack":
        reader = bind_reader(result.store, step=StepSpec(id=StepId("l2.stp/reader"), pack=k.PackId("l2.stp"),
            kind="check", scope="estate", reads=(FACT,), produces=(), evaluator="l2.stp.reader"))
    else:
        step = replace(reader.step)
        change = {"no_grant": {"reads": ()}, "extra_read": {"reads": (FACT, build.REPORTED_STATE)},
                  "produces": {"produces": (FACT,)}, "enum_grant": {"reads": (alias(FACT),)}}[field]
        for name, value in change.items():
            object.__setattr__(step, name, value)
        reader = bind_reader(result.store, step=step)
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


def test_reader_returning_an_equal_state_copy_is_not_the_original_cell(monkeypatch):
    actual, result, reader = production()
    original = FactReader.read
    monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(original(self, **kwargs)))
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("failure", ["before_finish", "refused_finish"])
def test_no_actual_successful_completion_record_means_no_value_source(failure):
    target = deepcopy(item())
    execution = owner.execute_local_version_inputs((target,), (request(target),))
    if failure == "refused_finish":
        with pytest.raises(ValueError):
            execution.owner.finish(())
    fabricated = owner.VersionResult(store=FactStore(), rows=(), executed=execution.executed,
                                     registration_sha256=execution.owner.inputs.registration_sha256)
    with pytest.raises(ValueError):
        execution.owner.validate_values(fabricated, reader_for(fabricated.store))


def test_public_graph_helper_is_only_shape_and_not_canonical_version_authority():
    _, result, _ = production()
    declared = known_row(result).target.node.declaration
    nonversion = k.Known(value="synthetic_nonversion", raw="synthetic_nonversion", basis=k.Basis.DECLARED,
                        evidence=declared.evidence)
    assert inputs.validate_version_state_graph(nonversion) is None
    object.__setattr__(nonversion, "value", [])
    with pytest.raises(ValueError):
        inputs.validate_version_state_graph(nonversion)


@pytest.mark.parametrize("field", ["capture", "owner", "context", "registration", "parse", "value", "pop_cold"])
def test_held_execution_and_original_input_census_remain_authoritative_for_this_result(field):
    actual, result, reader = production()
    output = result.executed[0]
    if field == "pop_cold":
        cold = next(row.target for row in result.rows if type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED)
        actual.inputs.source.indexed.pop((cold.context, cold.node.key))
    elif field == "value":
        object.__setattr__(output, "value", replace(output.value))
    else:
        name = {"capture": "capture", "owner": "owner", "context": "context",
                "registration": "registration_sha256", "parse": "parse"}[field]
        value = {"capture": replace(output.receipt.capture), "owner": "l3.fhrp/other", "context": "other",
                 "registration": "0" * 64, "parse": replace(output.receipt.parse)}[field]
        object.__setattr__(output.receipt, name, value)
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("field", ["known_locator", "unknown_params", "unknown_evidence"])
def test_malformed_current_state_graphs_refuse_without_traversing_the_cell_snapshot(monkeypatch, field):
    actual, result, reader = production()
    value = known_row(result).value if field == "known_locator" else unknown_row(result).value
    if field == "known_locator":
        ref = next(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
        changed = replace(ref, locator=replace(ref.locator))
        object.__setattr__(changed.locator, "start", [])
        object.__setattr__(value, "evidence", tuple(changed if old is ref else old for old in value.evidence))
    elif field == "unknown_params":
        object.__setattr__(value.next_evidence[0], "params", [])
    else:
        object.__setattr__(value, "evidence", [])
    snapshot = owner.asdict
    def snapshotting(current):
        if current is value:
            pytest.fail("traversed malformed production state before its graph guard")
        return snapshot(current)
    monkeypatch.setattr(owner, "asdict", snapshotting)
    with pytest.raises(ValueError):
        actual.validate_values(result, reader)


@pytest.mark.parametrize("empty", [False, True])
def test_untyped_reader_is_not_a_grant_even_when_the_production_is_empty(empty):
    actual, result, _ = production(empty)
    with pytest.raises(ValueError):
        actual.validate_values(result, object())


def test_writer_failure_never_creates_an_actual_completion_record(monkeypatch):
    target = deepcopy(item())
    execution = owner.execute_local_version_inputs((target,), (request(target),))
    def writing(*args, **kwargs):
        raise RuntimeError("synthetic_write_failure")
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(RuntimeError, match="synthetic_write_failure"):
        execution.owner.finish(execution.executed)
    assert execution.owner.completed is None
    fabricated = owner.VersionResult(store=FactStore(), rows=(), executed=execution.executed,
                                     registration_sha256=execution.owner.inputs.registration_sha256)
    with pytest.raises(ValueError):
        execution.owner.validate_values(fabricated, reader_for(fabricated.store))
