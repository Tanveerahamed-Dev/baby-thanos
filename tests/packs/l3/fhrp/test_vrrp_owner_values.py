"""Actual local VRRP value closure; returned data is not admission or an origin credential."""
from dataclasses import asdict, replace
from enum import StrEnum

import pytest
from test_parse_vrrp import BODY
from test_peer_execution import forbidden
from test_vrrp_owner import supplied

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactReader, FactStore, FactWriter, bind_reader
from atlas_brain.packs.l3.fhrp import vrrp_owner as owner
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.runner import pack_runtime

FACT = profile.REPORTED_VRRP_STATE


def alias(value):
    return StrEnum("Alias", {"VALUE": value}).VALUE


def reader_for(store, name="l3.fhrp/read_vrrp"):
    return bind_reader(store, step=StepSpec(id=name, pack=profile.PACK, kind="check", scope="estate",
        reads=(FACT,), produces=(), evaluator="l3.fhrp.read_vrrp"))


def actual(monkeypatch, mode="normal"):
    raw = BODY + b"unrecognized\n" if mode == "partial" else BODY + BODY if mode == "duplicate" else BODY
    targets, requests = supplied(raw, missing=mode == "missing")
    execution = owner.execute_local_vrrp_inputs(() if mode == "zero" else targets, () if mode == "zero" else requests)
    result = execution.result
    foreign = FactStore()
    foreign.owners, foreign.values = dict(result.store.owners), dict(result.store.values)
    reader = reader_for(result.store)
    assert execution.owner.validate_values(result, reader) is None
    assert execution.owner.canonical_rows() == result.rows
    for module, name in ((owner.parser, "parse_capture"), (owner, "execute_parsers"), (pack_runtime, "execute_parsers"),
            (owner, "bind_writer"), (FactWriter, "write"), (FactStore, "__init__")):
        monkeypatch.setattr(module, name, forbidden)
    assert execution.owner.validate_values(result, reader) is None
    return execution.owner, result, reader, foreign


@pytest.mark.parametrize("mode", ["normal", "missing", "partial", "duplicate", "zero"])
def test_canonical_rows_and_actual_original_reader_close_repeatedly_without_execution(monkeypatch, mode):
    actual_owner, result, reader, _ = actual(monkeypatch, mode)
    reads, original = [], FactReader.read
    def reading(self, **kwargs):
        value = original(self, **kwargs)
        reads.append((self, kwargs["subject"], value))
        return value
    monkeypatch.setattr(FactReader, "read", reading)
    assert actual_owner.canonical_rows() == actual_owner.canonical_rows() == result.rows
    assert actual_owner.validate_values(result, replace(reader)) is None
    assert len(reads) == len(result.rows)
    assert all(view.store is result.store and value is result.store.values[k.FactRef(fact=FACT, subject=subject)]
        for view, subject, value in reads)
    assert actual_owner.production is result and result.store.owners == {FACT: profile.STEP.id}
    assert {row.subject for row in result.rows} == {ref.subject for ref in result.store.values}
    if mode == "normal":
        assert sum(type(row.value) is k.Known for row in result.rows) == 1
        assert {row.value.reason for row in result.rows if type(row.value) is k.Unknown} == {
            k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE, k.UnknownReason.NOT_COLLECTED}


@pytest.mark.parametrize("map_copy", [False, True])
def test_equal_plain_owner_maps_and_factref_keys_preserve_actual_cells_and_are_not_origin_tokens(monkeypatch, map_copy):
    actual_owner, result, reader, _ = actual(monkeypatch)
    originals = tuple(result.store.values.items())
    result.store.owners = dict(result.store.owners)
    result.store.values = {replace(ref) if map_copy else ref: value for ref, value in originals}
    assert actual_owner.validate_values(result, reader) is None
    assert all(result.store.values[k.FactRef(fact=ref.fact, subject=ref.subject)] is value for ref, value in originals)


@pytest.mark.parametrize("field", ["result", "store", "rows", "executed", "owner_batch", "registration", "production", "attempted"])
def test_only_actual_completed_result_store_rows_and_batch_are_value_source(monkeypatch, field):
    actual_owner, result, reader, foreign = actual(monkeypatch)
    if field == "result":
        result = replace(result)
    elif field == "store":
        object.__setattr__(result, "store", foreign)
        reader = reader_for(foreign)
    elif field in ("rows", "executed"):
        object.__setattr__(result, field, tuple(item for item in getattr(result, field)))
    elif field == "owner_batch":
        actual_owner.executed = tuple(item for item in actual_owner.executed)
    elif field == "registration":
        object.__setattr__(result, "registration_sha256", "0" * 64)
    elif field == "attempted":
        actual_owner.production_attempted = False
    else:
        actual_owner.production = replace(result)
    with pytest.raises(ValueError, match="^vrrp_owner_value_source$"):
        actual_owner.validate_values(result, reader)


@pytest.mark.parametrize("fault", ["missing", "extra", "wrong_fact", "copy", "owners", "extra_owner", "owner_alias",
    "fact_alias", "subject_alias", "fact_deep", "subject_deep"])
def test_all_store_owners_and_cells_include_absent_and_cold_subjects_before_reads(monkeypatch, fault):
    actual_owner, result, reader, _ = actual(monkeypatch)
    row = next(row for row in result.rows if row.target.node.id == "b")
    reference = k.FactRef(fact=FACT, subject=row.subject)
    if fault == "missing":
        result.store.values.pop(reference)
    elif fault == "extra":
        result.store.values[k.FactRef(fact=FACT, subject="extra:subject")] = row.value
    elif fault == "wrong_fact":
        result.store.values[k.FactRef(fact="l3.fhrp.reported_state", subject=row.subject)] = result.store.values.pop(reference)
    elif fault == "copy":
        result.store.values[reference] = replace(row.value)
    elif fault in ("owners", "extra_owner", "owner_alias"):
        result.store.owners[FACT if fault != "extra_owner" else "l3.fhrp.other"] = alias(profile.STEP.id) if fault == "owner_alias" else "l3.fhrp/other"
    else:
        original = next(ref for ref in result.store.values if ref == reference)
        name = "fact" if fault.startswith("fact_") else "subject"
        object.__setattr__(original, name, [] if fault.endswith("deep") else alias(getattr(original, name)))
    with pytest.raises(ValueError, match="^vrrp_owner_" + ("value_reader" if fault == "copy" else "value_store") + "$"):
        actual_owner.validate_values(result, reader)


@pytest.mark.parametrize("field", ["value", "raw", "both", "alias", "basis", "hash", "role", "order", "cycle"])
def test_actual_known_cell_payload_cannot_change_in_place_or_donate_evidence(monkeypatch, field):
    actual_owner, result, reader, _ = actual(monkeypatch)
    row = next(row for row in result.rows if type(row.value) is k.Known)
    value = row.value
    if field in ("value", "raw", "both"):
        for name in ("value", "raw") if field == "both" else (field,):
            object.__setattr__(value, name, "Master" if field == "both" and name == "raw" else "master")
    elif field == "alias":
        object.__setattr__(value, "value", alias(value.value))
    elif field == "basis":
        object.__setattr__(value, "basis", k.Basis.DECLARED)
    elif field == "order":
        object.__setattr__(value, "evidence", tuple(reversed(value.evidence)))
    elif field == "cycle":
        object.__setattr__(value, "value", value)
    else:
        ref = next(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
        change = {"excerpt_sha256": "0" * 64} if field == "hash" else {"role": k.EvidenceRole.WITNESS}
        object.__setattr__(value, "evidence", tuple(replace(ref, **change) if item is ref else item for item in value.evidence))
    assert result.store.values[k.FactRef(fact=FACT, subject=row.subject)] is value
    with pytest.raises(ValueError, match="^" + ("hsrp_version_inputs_state" if field in ("alias", "cycle") else "vrrp_owner_value_cell") + "$"):
        actual_owner.validate_values(result, reader)


@pytest.mark.parametrize("cold", [False, True])
@pytest.mark.parametrize("field", ["reason", "detail", "candidates", "needs", "node", "params", "resolves", "reruns", "deep", "cycle"])
def test_unknown_absent_and_cold_values_and_needs_remain_canonical(monkeypatch, cold, field):
    actual_owner, result, reader, _ = actual(monkeypatch)
    row = next(row for row in result.rows if type(row.value) is k.Unknown and (row.target.node.id == "b") is cold)
    value = row.value
    if field in ("node", "params", "resolves", "reruns", "deep"):
        need, = value.next_evidence
        changes = {"node": "node:other", "params": (("group", "other"),), "resolves": ("other.fact",),
            "reruns": ("l3.fhrp/other",), "deep": ([],)}
        object.__setattr__(need, "resolves" if field == "deep" else field, changes[field])
    else:
        changes = {"reason": k.UnknownReason.PARSE_PARTIAL, "detail": "other", "candidates": ("synthetic:other",),
            "needs": (), "cycle": (value,)}
        object.__setattr__(value, "next_evidence" if field == "needs" else "candidates" if field == "cycle" else field, changes[field])
    assert result.store.values[k.FactRef(fact=FACT, subject=row.subject)] is value
    code = "hsrp_version_inputs_need" if field == "deep" else "hsrp_version_inputs_unknown" if field == "cycle" else "vrrp_owner_value_cell"
    with pytest.raises(ValueError, match="^" + code + "$"):
        actual_owner.validate_values(result, reader)


@pytest.mark.parametrize("field", ["target", "interface", "group", "subject", "coherent", "neighbor"])
def test_actual_row_store_subject_binding_and_neighbor_donation_are_closed(monkeypatch, field):
    actual_owner, result, reader, _ = actual(monkeypatch)
    row = next(row for row in result.rows if type(row.value) is k.Known)
    if field in ("coherent", "neighbor"):
        value = next(other.value for other in result.rows if other.target.node.id == "b") if field == "neighbor" else replace(row.value, value="master", raw="Master")
        object.__setattr__(row, "value", value)
        result.store.values[k.FactRef(fact=FACT, subject=row.subject)] = value
    elif field == "target":
        object.__setattr__(row, "target", replace(row.target))
    else:
        object.__setattr__(row, field, "synthetic-other")
    with pytest.raises(ValueError, match="^vrrp_owner_" + ("value_population" if field == "subject" else "value_cell") + "$"):
        actual_owner.validate_values(result, reader)


@pytest.mark.parametrize("mode,fault", [(mode, fault) for mode in ("normal", "zero")
    for fault in ("foreign_store", "no_read", "extra_read", "produces", "foreign_pack", "alias", "reader_type", "copy")
    if mode != "zero" or fault != "copy"])
def test_reader_requires_actual_store_same_pack_sole_plain_grant_and_original_cells(monkeypatch, mode, fault):
    actual_owner, result, reader, foreign = actual(monkeypatch, mode)
    if fault == "foreign_store":
        reader = reader_for(foreign)
    elif fault == "reader_type":
        reader = object()
    else:
        step = replace(reader.step)
        changes = {"no_read": {"reads": ()}, "extra_read": {"reads": (FACT, "l3.fhrp.other")}, "produces": {"produces": (FACT,)},
            "foreign_pack": {"pack": "l2.stp"}, "alias": {"reads": (alias(FACT),)}, "copy": {}}
        for name, value in changes[fault].items():
            object.__setattr__(step, name, value)
        reader = bind_reader(result.store, step=step)
        if fault == "copy":
            read = FactReader.read
            monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)))
    with pytest.raises(ValueError, match="^vrrp_owner_" + ("value_reader" if fault == "copy" else "reader") + "$"):
        actual_owner.validate_values(result, reader)


@pytest.mark.parametrize("fault", ["cache", "parse", "receipt", "coverage", "rawclaim", "input", "snapshot", "profile", "registration"])
def test_current_canonical_batch_is_revalidated_after_success_without_replay(monkeypatch, fault):
    actual_owner, result, reader, _ = actual(monkeypatch)
    output = result.executed[0]
    key = output.receipt.capture.id
    if fault == "cache":
        actual_owner.produced[key] = replace(output.value)
    elif fault == "parse":
        actual_owner.parsed[key] = replace(output.value.parse)
    elif fault == "receipt":
        object.__setattr__(output.receipt, "owner", "l3.fhrp/other")
    elif fault == "coverage":
        actual_owner.executed = ()
    elif fault == "rawclaim":
        object.__setattr__(output.value.rows[0].state, "value", owner.parser.VRRPState.MASTER)
        actual_owner.snapshots[key] = asdict(output.value)
    elif fault == "input":
        object.__setattr__(actual_owner.inputs.targets[0].node, "ports", ("Gi1/0/1", "Gi1/0/2"))
    elif fault == "profile":
        monkeypatch.setattr(profile, "REPORTED_VRRP_STATE", alias(FACT))
    elif fault == "registration":
        actual_owner.registration = (b"changed", *actual_owner.registration[1:])
    else:
        actual_owner.snapshots[key] = {"self": actual_owner.snapshots}
    code = "vrrp_profile" if fault == "profile" else "vrrp_owner_registration" if fault == "registration" else (
        "vrrp_owner_receipt" if fault == "receipt" else "vrrp_owner_batch" if fault == "coverage" else "vrrp_claims_state" if fault == "rawclaim"
        else "vrrp_inputs_target" if fault == "input" else "vrrp_owner_cache")
    with pytest.raises(ValueError, match="^" + code + "$"):
        actual_owner.canonical_rows()
    with pytest.raises(ValueError, match="^" + ("vrrp_owner_value_source" if fault == "coverage" else code) + "$"):
        actual_owner.validate_values(result, reader)


def test_unexecuted_owner_has_no_canonical_batch_or_actual_value_source(monkeypatch):
    targets, requests = supplied()
    good = owner.execute_local_vrrp_inputs(targets, requests)
    reader = reader_for(good.result.store)
    fresh = owner.VRRPOwner(targets, requests)
    for module, name in ((owner.parser, "parse_capture"), (owner, "execute_parsers"), (owner, "bind_writer"), (FactWriter, "write"), (FactStore, "__init__")):
        monkeypatch.setattr(module, name, forbidden)
    with pytest.raises(ValueError, match="^vrrp_owner_batch$"):
        fresh.canonical_rows()
    with pytest.raises(ValueError, match="^vrrp_owner_value_source$"):
        fresh.validate_values(good.result, reader)
    with pytest.raises(TypeError):
        fresh.canonical_rows(good.result.executed)


def test_writer_failure_leaves_canonical_diagnostic_data_but_no_completed_value_source(monkeypatch):
    targets, requests = supplied()
    good = owner.execute_local_vrrp_inputs(targets, requests)
    reader = reader_for(good.result.store)
    constructor, held = owner.VRRPOwner, []
    def constructing(*args):
        actual_owner = constructor(*args)
        held.append(actual_owner)
        return actual_owner
    def writing(*args, **kwargs):
        raise RuntimeError("planted_writer")
    monkeypatch.setattr(owner, "VRRPOwner", constructing)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(RuntimeError, match="^planted_writer$"):
        owner.execute_local_vrrp_inputs(targets, requests)
    actual_owner = held[0]
    assert actual_owner.production is actual_owner.completed is None and actual_owner.production_attempted
    for module, name in ((owner.parser, "parse_capture"), (owner, "execute_parsers"), (owner, "bind_writer"), (FactStore, "__init__")):
        monkeypatch.setattr(module, name, forbidden)
    assert len(actual_owner.canonical_rows()) == 4 and len(actual_owner.produced) == 1
    with pytest.raises(ValueError, match="^vrrp_owner_value_source$"):
        actual_owner.validate_values(good.result, reader)
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        actual_owner.finish()


@pytest.mark.parametrize("name", ["l3.fhrp/not_a_credential", "l3.fhrp/other_consumer"])
def test_valid_samepack_consumer_names_are_permissions_not_origin_tokens(monkeypatch, name):
    actual_owner, result, _, _ = actual(monkeypatch)
    reader = reader_for(result.store, name)
    assert actual_owner.validate_values(result, reader) is None


@pytest.mark.parametrize("known", [False, True])
def test_coherent_equal_row_and_store_copy_is_not_the_independently_retained_cell(monkeypatch, known):
    actual_owner, result, reader, _ = actual(monkeypatch)
    row = next(row for row in result.rows if type(row.value) is k.Known) if known else next(
        row for row in result.rows if row.target.node.id == "b")
    canonical, original = actual_owner.canonical_rows(), row.value
    copied = replace(original)
    assert copied == original and copied is not original
    object.__setattr__(row, "value", copied)
    result.store.values[k.FactRef(fact=FACT, subject=row.subject)] = copied
    assert actual_owner.canonical_rows() == canonical and result.store.values[k.FactRef(fact=FACT, subject=row.subject)] is row.value
    with pytest.raises(ValueError, match="^vrrp_owner_value_cell$"):
        actual_owner.validate_values(result, reader)
