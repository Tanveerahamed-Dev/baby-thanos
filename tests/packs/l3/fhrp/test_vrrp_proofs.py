"""Local VRRP leaf proofs retain actual bytes and unexpanded declarations, not root admission."""
from dataclasses import asdict, replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_vrrp import BODY, block
from test_peer_execution import forbidden
from test_vrrp_owner import supplied
from test_vrrp_owner_values import reader_for

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import vrrp_owner as owning
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.packs.l3.fhrp import vrrp_proofs as proofs
from atlas_brain.runner import pack_runtime

FACT = profile.REPORTED_VRRP_STATE


def alias(value):
    return StrEnum("Alias", {"VALUE": value}).VALUE


def actual(monkeypatch, mode="normal"):
    raw = BODY + block("Vl61", "101", "Backup") if mode == "two" else b"" if mode == "empty" else (
        BODY + BODY if mode == "duplicate" else BODY + b"unrecognized\n" if mode == "partial" else BODY)
    targets, requests = supplied(raw, missing=mode == "missing")
    if mode == "contexts":
        targets += (replace(targets[0], context="other"),)
        requests += (replace(requests[0], context="other", capture=replace(requests[0].capture, id="cap:other")),)
    execution = owning.execute_local_vrrp_inputs(() if mode == "zero" else targets, () if mode == "zero" else requests)
    reader = reader_for(execution.result.store)
    foreign = FactStore()
    foreign.owners, foreign.values = dict(execution.result.store.owners), dict(execution.result.store.values)
    index = proofs.LocalVRRPProofIndex(owner=execution.owner, result=execution.result, reader=reader)
    for module, name in ((owning.parser, "parse_capture"), (owning, "execute_parsers"), (pack_runtime, "execute_parsers"),
            (owning, "bind_writer"), (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)
    assert index.validate() is None
    for row in execution.result.rows:
        assert index.resolve(k.FactRef(fact=FACT, subject=row.subject)).state is row.value
    return index, foreign


@pytest.mark.parametrize("mode", ["normal", "two", "contexts", "empty", "duplicate", "partial", "missing", "zero"])
def test_actual_rows_return_only_original_scoped_byte_leaves_and_unexpanded_registry_refs(monkeypatch, mode):
    index, _ = actual(monkeypatch, mode)
    if not index.result.rows:
        with pytest.raises(ValueError, match="^vrrp_proofs_reference$"):
            index.resolve(k.FactRef(fact=FACT, subject="outside:subject"))
    for row in index.result.rows:
        reference = k.FactRef(fact=FACT, subject=row.subject)
        result = index.resolve(reference)
        assert result.reference is reference and result.state is row.value
        assert result.unexpanded_registry_refs == row.target.node.declaration.evidence
        assert all(ref is original for ref, original in zip(result.unexpanded_registry_refs, row.target.node.declaration.evidence, strict=True))
        assert tuple(leaf.reference for leaf in result.capture_leaves) == tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        request = next((request for request in index.owner.inputs.requests if request.context == row.target.context and request.capture.source == row.target.node.key), None)
        assert bool(result.capture_leaves) is (request is not None)
        for leaf in result.capture_leaves:
            ref, capture = leaf.reference, leaf.capture
            assert capture is request.capture and ref.capture == capture.id
            assert any(ref is original for original in row.value.evidence)
            assert leaf.capture_sha256 == capture.bytes_sha256 == sha256(capture.raw).hexdigest()
            assert leaf.raw == (capture.raw[ref.locator.start:ref.locator.end] if type(ref.locator) is k.ByteSpan else capture.raw)
            assert sha256(leaf.raw).hexdigest() == ref.excerpt_sha256
            assert ref.role is (k.EvidenceRole.SUBJECT if type(row.value) is k.Known else k.EvidenceRole.WITNESS)
            assert type(ref.locator) is k.ByteSpan if type(row.value) is k.Known else type(ref.locator) in (k.ByteSpan, k.WholeCapture)
            assert not hasattr(leaf, "path") and not hasattr(leaf, "target") and not hasattr(leaf, "registry_raw")
        if type(row.value) is k.Unknown:
            assert result.next_evidence is row.value.next_evidence and not row.value.candidates
            need, = result.next_evidence
            assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (
                row.target.node.key, "iosxe.show_vrrp", (("group", row.group), ("interface", row.interface)), (FACT,), (profile.STEP.id,))
            if request is None:
                assert result.capture_leaves == ()
        else:
            assert not result.next_evidence and result.capture_leaves
            assert all(b"Authentication" not in leaf.raw for leaf in result.capture_leaves)
        with pytest.raises(AttributeError):
            result.state = None
        assert index.resolve(replace(reference)) == result


@pytest.mark.parametrize("field", ["owner", "result", "store", "reader"])
def test_constructor_closes_actual_local_production_and_reader_before_any_proof(monkeypatch, field):
    index, foreign = actual(monkeypatch)
    result = index.result
    arguments = {"owner": index.owner, "result": result, "reader": index.reader}
    if field == "owner":
        arguments["owner"] = object()
    elif field == "result":
        arguments["result"] = replace(result)
    elif field == "store":
        object.__setattr__(result, "store", foreign)
    else:
        arguments["reader"] = reader_for(foreign)
    code = "vrrp_proofs_owner" if field == "owner" else "vrrp_owner_reader" if field == "reader" else "vrrp_owner_value_source"
    with pytest.raises(ValueError, match="^" + code + "$"):
        proofs.LocalVRRPProofIndex(**arguments)


def test_copied_plain_references_and_valid_readers_are_data_without_new_origin_or_scope_claims(monkeypatch):
    index, _ = actual(monkeypatch)
    other = replace(index, reader=replace(index.reader))
    for row in index.result.rows:
        reference = k.FactRef(fact=FACT, subject=row.subject)
        assert other.resolve(replace(reference)) == index.resolve(reference)
    assert set(proofs.LocalVRRPProof.__dataclass_fields__) == {
        "reference", "state", "unexpanded_registry_refs", "capture_leaves", "next_evidence"}


@pytest.mark.parametrize("plant", ["object", "hsrp", "version", "outside", "fact_alias", "subject_alias", "fact_deep", "subject_deep"])
def test_reference_is_exact_plain_owned_vrrp_and_never_cross_protocol_or_recursive(monkeypatch, plant):
    index, _ = actual(monkeypatch)
    row = index.result.rows[0]
    reference = k.FactRef(fact=FACT, subject=row.subject)
    if plant == "object":
        reference = object()
    elif plant in ("hsrp", "version", "outside"):
        reference = replace(reference, **({"subject": "outside:subject"} if plant == "outside" else {
            "fact": "l3.fhrp.reported_state" if plant == "hsrp" else "l3.fhrp.reported_protocol_version"}))
    else:
        field = "fact" if plant.startswith("fact_") else "subject"
        object.__setattr__(reference, field, [] if plant.endswith("deep") else alias(getattr(reference, field)))
    with pytest.raises(ValueError, match="^vrrp_proofs_reference$"):
        index.resolve(reference)


@pytest.mark.parametrize("plant", ["hash", "role", "span", "whole", "capture", "registry", "recursive", "rich_row"])
def test_actual_known_evidence_mutation_is_reclosed_before_leaf_resolution(monkeypatch, plant):
    index, _ = actual(monkeypatch)
    row = next(row for row in index.result.rows if type(row.value) is k.Known)
    reference = k.FactRef(fact=FACT, subject=row.subject)
    original = index.resolve(reference)
    if plant == "recursive":
        evidence = row.value.evidence + (reference,)
    elif plant == "rich_row":
        output = index.result.executed[0]
        rich = next(item for item in output.value.rows if item.interface.raw == row.interface and item.group.raw == row.group)
        point, capture = rich.span, output.receipt.capture
        evidence = row.value.evidence + (k.EvidenceRef(capture=capture.id, locator=point, role=k.EvidenceRole.SUBJECT,
            excerpt_sha256=sha256(capture.raw[point.start:point.end]).hexdigest()),)
    else:
        selected = next(ref for ref in row.value.evidence if type(ref) is (k.RegistryRef if plant == "registry" else k.EvidenceRef))
        changes = {"locator": k.ByteSpan(start=selected.locator.start + 1, end=selected.locator.end)} if plant == "span" else {
            "hash": {"excerpt_sha256": "0" * 64}, "role": {"role": k.EvidenceRole.WITNESS},
            "whole": {"locator": k.WholeCapture()}, "capture": {"capture": "cap:foreign"},
            "registry": {"table_digest": "0" * 64}}[plant]
        changed = replace(selected, **changes)
        evidence = tuple(changed if ref is selected else ref for ref in row.value.evidence)
    object.__setattr__(row.value, "evidence", evidence)
    with pytest.raises(ValueError, match="^vrrp_owner_value_cell$"):
        index.resolve(reference)
    assert original.state is row.value


@pytest.mark.parametrize("cold", [False, True])
@pytest.mark.parametrize("plant", ["need", "candidates", "reason", "evidence", "copy"])
def test_absent_and_cold_unknown_needs_and_cells_reclose_including_unrequested_subjects(monkeypatch, cold, plant):
    index, _ = actual(monkeypatch)
    row = next(row for row in index.result.rows if type(row.value) is k.Unknown and (row.target.node.id == "b") is cold)
    requested = next(row for row in index.result.rows if type(row.value) is k.Known)
    reference = k.FactRef(fact=FACT, subject=requested.subject)
    if plant == "copy":
        index.result.store.values[k.FactRef(fact=FACT, subject=row.subject)] = replace(row.value)
    elif plant == "need":
        object.__setattr__(row.value.next_evidence[0], "reruns", ("l3.fhrp/other",))
    elif plant == "candidates":
        object.__setattr__(row.value, "candidates", ("synthetic:other",))
    elif plant == "reason":
        object.__setattr__(row.value, "reason", k.UnknownReason.PARSE_PARTIAL)
    else:
        object.__setattr__(row.value, "evidence", (replace(row.value.evidence[0], table_digest="0" * 64), *row.value.evidence[1:]))
    with pytest.raises(ValueError, match="^vrrp_owner_" + ("value_reader" if plant == "copy" else "value_cell") + "$"):
        index.resolve(reference)


@pytest.mark.parametrize("plant", ["neighbor", "equal_copy", "owner", "row", "batch", "profile", "rawclaim"])
def test_every_resolve_rechecks_current_owner_cells_and_same_capture_neighbor_scope(monkeypatch, plant):
    index, _ = actual(monkeypatch, "two")
    first, second = tuple(row for row in index.result.rows if type(row.value) is k.Known)
    reference = k.FactRef(fact=FACT, subject=first.subject)
    assert index.resolve(reference).capture_leaves and index.resolve(k.FactRef(fact=FACT, subject=second.subject)).capture_leaves
    if plant in ("neighbor", "equal_copy"):
        assert first.value.value == second.value.value
        copied = second.value if plant == "neighbor" else replace(first.value)
        object.__setattr__(first, "value", copied)
        index.result.store.values[reference] = copied
    elif plant == "owner":
        index.result.store.owners[FACT] = "l3.fhrp/other"
    elif plant == "row":
        object.__setattr__(first, "target", replace(first.target))
    elif plant == "batch":
        index.owner.executed = tuple(item for item in index.owner.executed)
    elif plant == "profile":
        monkeypatch.setattr(profile, "REPORTED_VRRP_STATE", alias(FACT))
    else:
        output = index.result.executed[0]
        object.__setattr__(output.value.rows[0].state, "value", owning.parser.VRRPState.MASTER)
        index.owner.snapshots[output.receipt.capture.id] = asdict(output.value)
    code = "vrrp_owner_value_store" if plant == "owner" else "vrrp_owner_value_source" if plant == "batch" else (
        "vrrp_profile" if plant == "profile" else "vrrp_claims_state" if plant == "rawclaim" else "vrrp_owner_value_cell")
    with pytest.raises(ValueError, match="^" + code + "$"):
        index.resolve(reference)


def test_derived_noop_validate_cannot_bypass_inherited_constructor_or_resolve(monkeypatch):
    index, _ = actual(monkeypatch)
    calls = []
    class Derived(proofs.LocalVRRPProofIndex):
        def validate(self):
            calls.append("bypassed")
    arguments = {"owner": index.owner, "result": index.result, "reader": index.reader}
    with pytest.raises(ValueError, match="^vrrp_proofs_owner$"):
        Derived(**arguments)
    assert not calls
    forged = object.__new__(Derived)
    for name, value in arguments.items():
        object.__setattr__(forged, name, value)
    row = index.result.rows[0]
    with pytest.raises(ValueError, match="^vrrp_proofs_owner$"):
        proofs.LocalVRRPProofIndex.resolve(forged, k.FactRef(fact=FACT, subject=row.subject))
    assert not calls


def test_constructor_validate_and_each_reference_reclose_actual_owner_before_reference_checks(monkeypatch):
    index, _ = actual(monkeypatch)
    original, calls = owning.VRRPOwner.validate_values, []
    def validating(self, result, reader):
        calls.append((self, result, reader))
        return original(self, result, reader)
    monkeypatch.setattr(owning.VRRPOwner, "validate_values", validating)
    second = replace(index)
    row = next(row for row in index.result.rows if type(row.value) is k.Known)
    assert second.resolve(k.FactRef(fact=FACT, subject=row.subject)).state is row.value
    assert calls == [(index.owner, index.result, index.reader)] * 2
    cold = next(row for row in index.result.rows if row.target.node.id == "b")
    index.result.store.values.pop(k.FactRef(fact=FACT, subject=cold.subject))
    with pytest.raises(ValueError, match="^vrrp_owner_value_store$"):
        second.resolve(object())
    assert len(calls) == 3


@pytest.mark.parametrize("field", ["owners_alias", "key_alias", "inputs", "reader", "metadata_error", "registry_ref"])
def test_current_input_registry_metadata_and_store_mutation_refuse_even_when_requesting_other_cell(monkeypatch, field):
    index, foreign = actual(monkeypatch)
    row = next(row for row in index.result.rows if type(row.value) is k.Known)
    reference = k.FactRef(fact=FACT, subject=row.subject)
    if field == "owners_alias":
        index.result.store.owners[FACT] = alias(profile.STEP.id)
    elif field == "key_alias":
        key = next(iter(index.result.store.values))
        object.__setattr__(key, "fact", alias(FACT))
    elif field == "inputs":
        node = index.owner.inputs.targets[0].node
        object.__setattr__(node, "ports", node.ports + ("Gi1/0/2",))
    elif field == "reader":
        object.__setattr__(index, "reader", reader_for(foreign))
    elif field == "metadata_error":
        capture = index.owner.inputs.requests[0].capture
        object.__setattr__(capture, "metadata", replace(capture.resolved_metadata, error=ErrorKind.TIMEOUT))
    else:
        ref = index.owner.inputs.targets[0].node.declaration.evidence[0]
        object.__setattr__(ref, "table_digest", "1" * 64)
    code = "vrrp_owner_value_store" if field in ("owners_alias", "key_alias") else "vrrp_owner_reader" if field == "reader" else (
        "vrrp_inputs_request" if field == "metadata_error" else "vrrp_inputs_target")
    with pytest.raises(ValueError, match="^" + code + "$"):
        index.resolve(reference)
