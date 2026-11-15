"""Root9 current leaf proofs and bounded bulk work; no persistent cache, grants or origin seal."""
import json
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_mixed_proofs import custody
from test_peer_execution import forbidden
from test_root_mixed_component import ROOT_FACTS, folder, frozen
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.runner import p4_mixed_refs as proofs


def saved(root, mode="normal"):
    files = folder(root, "no_all_capture" if mode == "no_all" else mode if mode in ("none", "cold_vrrp", "only_vrrp", "no_all_target") else "normal")
    changes = {}
    if "tree.txt" in files:
        changes["tree.txt"] = files["tree.txt"].replace(b"enabled", b"disabled")
    if mode in ("empty", "partial"):
        changes["vrrp.txt"] = b"" if mode == "empty" else files["vrrp.txt"] + b"unrecognized\n"
    side = json.loads(files["p4.json"])
    for name, raw in changes.items():
        (root / name).write_bytes(raw)
        next(row for row in side["captures"] if row["path"] == name)["sha256"] = sha256(raw).hexdigest()
    (root / "p4.json").write_bytes(canonical(side))


def references(result):
    return tuple((k.FactRef(fact=fact, subject=row.subject), getattr(row, name))
        for field, fact, name in ROOT_FACTS for row in getattr(result, field).rows)


def actual(root, monkeypatch, mode="normal"):
    saved(root, mode)
    source = proofs.owning.build_root_mixed_source(root, replace(LIMITS))
    index = proofs.RootMixedProofIndex(source)
    reference, state = references(source.result)[0]
    assert index.resolve(reference).state is state and index.resolve_all()
    frozen(monkeypatch)
    return source, index


@pytest.fixture
def case(tmp_path, monkeypatch):
    return actual(tmp_path, monkeypatch)


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all", "no_all_target"])
def test_complete_root9_bulk_and_singles_preserve_actual_int_bool_text_unknown_and_all_original_leaf_custody(tmp_path, monkeypatch, mode):
    source, index = actual(tmp_path, monkeypatch, mode)
    expected = dict(references(source.result))
    bulk = index.resolve_all()
    assert type(bulk) is tuple and all(type(value) is proofs.RootMixedFactProof for value in bulk)
    assert tuple((value.reference.fact, value.reference.subject) for value in bulk) == tuple(sorted((ref.fact, ref.subject) for ref in expected))
    assert len(bulk) == len(expected) == sum(len(getattr(source.result, field).store.values) for field in ("tree", "channel", "state", "version", "vrrp"))
    for value in bulk:
        custody(source, value.reference, expected[value.reference], value)
        assert index.resolve(replace(value.reference)) == value
    if mode != "only_vrrp":
        assert {value.reference.fact for value in bulk} == {fact for _, fact, _ in ROOT_FACTS}
    if mode == "normal":
        guard = next(value for value in bulk if value.reference.fact == proofs.stp.ROOT_GUARD)
        priority = next(value for value in bulk if value.reference.fact == proofs.stp.REPORTED_ROOT_PRIORITY)
        assert guard.state.value is False and all(leaf.reference.role is k.EvidenceRole.SUBJECT for leaf in guard.capture_leaves)
        assert type(priority.state.value) is int and priority.state.value == 32769
        assert any(leaf.raw == b"32769" for leaf in priority.capture_leaves)
    if mode in ("none", "cold_vrrp", "empty"):
        selected = bulk if mode == "none" else tuple(value for value in bulk if value.reference.fact == proofs.vrrp_profile.REPORTED_VRRP_STATE)
        assert all(type(value.state) is k.Unknown and value.next_evidence is value.state.next_evidence for value in selected)
        assert all(not value.capture_leaves for value in selected) if mode != "empty" else all(
            any(type(leaf.reference.locator) is k.WholeCapture and leaf.raw == b"" for leaf in value.capture_leaves) for value in selected)
    if mode in ("no_all", "no_all_target"):
        for row in source.result.state.rows:
            if type(row.value) is k.Known:
                value = index.resolve(k.FactRef(fact=proofs.version_profile.REPORTED_PROTOCOL_VERSION, subject=row.subject))
                assert value.capture_leaves == () and len(value.registry_leaves) == (3 if mode == "no_all_target" else 4)
                assert all(need.operation == proofs.version_profile.parser.OP for need in value.next_evidence)


@pytest.mark.parametrize("field,fact,name", ROOT_FACTS)
@pytest.mark.parametrize("entry", ["single", "bulk"])
def test_every_current_original_root9_cell_is_reclosed_before_either_proof_entry(case, field, fact, name, entry):
    source, index = case
    result = getattr(source.result, field)
    row = result.rows[0]
    reference = k.FactRef(fact=fact, subject=row.subject)
    original = getattr(row, name)
    result.store.values[reference] = replace(original)
    with pytest.raises(ValueError, match="^fhrp_mixed_component_cell$"):
        index.resolve(reference) if entry == "single" else index.resolve_all()


@pytest.mark.parametrize("plant", ["object", "fact_alias", "subject_alias", "unhashable", "unknown_fact", "unknown_subject", "cross_protocol"])
def test_plain_finite_owned_references_are_required_before_hashing(case, plant):
    source, index = case
    reference = replace(references(source.result)[0][0])
    if plant == "object":
        reference = object()
    elif plant in ("fact_alias", "subject_alias", "unhashable"):
        name = "subject" if plant == "subject_alias" else "fact"
        object.__setattr__(reference, name, [] if plant == "unhashable" else StrEnum("Alias", {"VALUE": getattr(reference, name)}).VALUE)
    else:
        reference = k.FactRef(fact=proofs.vrrp_profile.REPORTED_VRRP_STATE, subject=source.result.state.rows[0].subject) if plant == "cross_protocol" else replace(reference,
            **({"fact": "l3.fhrp.reported_virtual_ip"} if plant == "unknown_fact" else {"subject": "fhrp_local:foreign"}))
    with pytest.raises(ValueError, match="^p4_mixed_proofs_reference$"):
        index.resolve(reference)


@pytest.mark.parametrize("entry", ["single", "bulk"])
@pytest.mark.parametrize("plant", ["role", "digest", "whole", "scope", "raw"])
def test_current_real_capture_evidence_roles_hashes_scope_and_byte_identity_cannot_drift(case, entry, plant):
    source, index = case
    row = source.result.tree.rows[0]
    reference = k.FactRef(fact=proofs.stp.ROOT_GUARD, subject=row.subject)
    if plant in ("role", "digest", "whole"):
        evidence = next(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        field, value = ("role", k.EvidenceRole.WITNESS) if plant == "role" else (
            ("excerpt_sha256", "0" * 64) if plant == "digest" else ("locator", k.WholeCapture()))
        object.__setattr__(evidence, field, value)
        code = "stp_root_observation_value"
    else:
        capture = index.resolve(reference).capture_leaves[0].capture
        if plant == "scope":
            object.__setattr__(capture, "metadata", replace(capture.resolved_metadata, scope=replace(capture.scope, vrf="blue")))
            code = "fhrp_mixed_execution_scope"
        else:
            object.__setattr__(capture, "raw", bytes(bytearray(capture.raw)))
            code = "fhrp_mixed_execution_output"
    with pytest.raises(ValueError, match="^" + code + "$"):
        index.resolve(reference) if entry == "single" else index.resolve_all()


@pytest.mark.parametrize("entry", ["single", "bulk"])
@pytest.mark.parametrize("plant", ["before", "after", "result_epoch", "source_swap"])
def test_source_and_result_epoch_close_before_and_after_without_publishing_partial_proof(case, monkeypatch, entry, plant):
    source, index = case
    original, calls = proofs.owning.RootMixedComponentRun.current_component, []
    def current(self):
        result = original(self)
        calls.append(result)
        if plant == "source_swap" and len(calls) == 1:
            index.source = proofs.owning.RootMixedComponentRun(source.root, source.budgets)
        if len(calls) == (1 if plant == "before" else 2):
            if plant in ("before", "after"):
                raise ValueError("planted_current")
            return replace(result) if plant == "result_epoch" else result
        return result
    monkeypatch.setattr(proofs.owning.RootMixedComponentRun, "current_component", current)
    with pytest.raises(ValueError, match="^" + ("planted_current" if plant in ("before", "after") else "p4_mixed_proofs_source") + "$"):
        index.resolve(references(source.result)[0][0]) if entry == "single" else index.resolve_all()
    assert len(calls) == (1 if plant in ("before", "source_swap") else 2)


@pytest.mark.parametrize("plant", ["derived_ctor", "derived_single", "derived_bulk", "old_source", "unbuilt", "shadow_getter"])
def test_root_index_receiver_and_unbound_getter_gates_preserve_old_profiles(case, monkeypatch, tmp_path, plant):
    source, index = case
    class Derived(proofs.RootMixedProofIndex):
        pass
    if plant == "shadow_getter":
        source.current_component = forbidden
        assert index.resolve_all()
        return
    if plant == "old_source":
        index.source = proofs.owning.MixedComponentRun(tmp_path, replace(LIMITS))
    elif plant == "unbuilt":
        index.source = proofs.owning.RootMixedComponentRun(tmp_path, replace(LIMITS))
    code = "fhrp_mixed_component_source" if plant == "unbuilt" else "p4_mixed_proofs_source"
    with pytest.raises(ValueError, match="^" + code + "$"):
        if plant == "derived_ctor":
            Derived(source)
        elif plant.startswith("derived"):
            forged = object.__new__(Derived)
            forged.source = source
            proofs.RootMixedProofIndex.resolve_all(forged) if plant == "derived_bulk" else proofs.RootMixedProofIndex.resolve(forged, references(source.result)[0][0])
        else:
            index.resolve_all()
    with pytest.raises(ValueError, match="^p4_mixed_proofs_source$"):
        proofs.MixedProofIndex(source)


@pytest.mark.parametrize("mode,swap", [("normal", False), ("normal", True), ("empty", False)])
def test_bulk_closes_twice_builds_each_map_once_and_binds_ephemeral_sha_to_actual_raw_objects(tmp_path, monkeypatch, mode, swap):
    source, index = actual(tmp_path, monkeypatch, mode)
    component, envelope = source.result, source.source.execution.envelope
    current, mapper, registries, maps = proofs.owning.RootMixedComponentRun.current_component, proofs._cell_map, proofs._registries, proofs._maps
    leaf, digest = proofs._leaves, proofs.sha256
    calls, map_results, shared, hashes = [], [], [], []
    tree_capture = next(out.receipt.capture for out in source.source.execution.executed if out.receipt.capture.operation == proofs.stp.stp.OP)
    tree_member = next(member for member in envelope.captures if member.id == tree_capture.id)
    original_raw = tree_capture.raw
    def getting(self):
        calls.append("current")
        return current(self)
    def mapping(value):
        calls.append("cells")
        return mapper(value)
    def registered(*args):
        calls.append("registry")
        return registries(*args)
    def mapped(*args):
        calls.append("maps")
        result = maps(*args)
        map_results.append(result)
        return result
    def hashing(raw):
        hashes.append(raw)
        return digest(raw)
    def leaves(*args):
        shared.append(tuple(id(value) for value in args[4:]))
        result = leaf(*args)
        if swap and args[0] is component.tree.rows[0].role:
            replacement = bytes(bytearray(tree_capture.raw))
            assert replacement == tree_capture.raw and replacement is not tree_capture.raw
            object.__setattr__(tree_capture, "raw", replacement)
            object.__setattr__(tree_member, "raw", replacement)
        return result
    monkeypatch.setattr(proofs.owning.RootMixedComponentRun, "current_component", getting)
    monkeypatch.setattr(proofs, "_cell_map", mapping)
    monkeypatch.setattr(proofs, "_registries", registered)
    monkeypatch.setattr(proofs, "_maps", mapped)
    monkeypatch.setattr(proofs, "sha256", hashing)
    monkeypatch.setattr(proofs, "_leaves", leaves)
    for _ in range(2):
        calls.clear()
        shared.clear()
        hashes.clear()
        before = tree_capture.raw
        bulk = index.resolve_all()
        assert calls.count("current") == 2 and all(calls.count(name) == 1 for name in ("cells", "registry", "maps"))
        assert len(set(shared)) == 1 and len(shared) == len(bulk)
        assert sum(raw is envelope.base.raw for raw in hashes) == sum(raw is envelope.raw for raw in hashes) == 1
        assert sum(raw is before for raw in hashes) == 1
        if swap:
            assert tree_capture.raw is not before and sum(raw is tree_capture.raw for raw in hashes) == 1
        assert all(sum(raw is out.receipt.capture.raw for raw in hashes) == 1
            for out in source.source.execution.executed if out.receipt.capture is not tree_capture)
        assert map_results[-1][3][tree_capture.id][0] is tree_capture.raw
    assert map_results[0][3] is not map_results[1][3]
    assert not swap or original_raw is not tree_capture.raw


@pytest.mark.parametrize("entry,extra", [("single", {"positive": True}), ("single", {"evidence": ()}), ("bulk", {"state": object()})])
def test_no_caller_evidence_state_or_positive_grants_are_accepted(case, entry, extra):
    source, index = case
    with pytest.raises(TypeError):
        index.resolve(references(source.result)[0][0], **extra) if entry == "single" else index.resolve_all(**extra)
