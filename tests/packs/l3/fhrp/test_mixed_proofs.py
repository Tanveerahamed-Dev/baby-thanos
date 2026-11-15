"""Actual current mixed leaf proofs; original synthetic bytes only, no execution-origin seal."""
import json
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_mixed_context import admitted
from test_mixed_source import FACTS, freeze
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.runner import p4_mixed_refs as proofs


def saved(root, mode="normal"):
    _, files = admitted(root, mode if mode in ("none", "cold_vrrp", "only_vrrp") else "normal")
    if mode not in ("false", "omitted", "empty", "partial", "no_all", "no_all_target"):
        return
    changes = {"false": ("tree.txt", files["tree.txt"].replace(b"enabled", b"disabled")),
        "omitted": ("tree.txt", files["tree.txt"].splitlines(keepends=True)[0]),
        "empty": ("vrrp.txt", b""), "partial": ("vrrp.txt", files["vrrp.txt"] + b"unrecognized\n"),
        "no_all": ("all.txt", None), "no_all_target": ("all.txt", None)}
    if mode in changes:
        name, raw = changes[mode]
        side = json.loads(files["p4.json"])
        if raw is None:
            side["captures"] = [row for row in side["captures"] if row["path"] != name]
            if mode == "no_all_target":
                side["targets"] = [row for row in side["targets"] if row["operation"] != proofs.version_profile.parser.OP]
            (root / name).unlink()
        else:
            (root / name).write_bytes(raw)
            next(row for row in side["captures"] if row["path"] == name)["sha256"] = sha256(raw).hexdigest()
        (root / "p4.json").write_bytes(canonical(side))


def references(component):
    return tuple((k.FactRef(fact=fact, subject=row.subject), getattr(row, name))
        for field, fact, name in FACTS for row in getattr(component, field).rows)


def actual(root, monkeypatch, mode="normal"):
    saved(root, mode)
    source = proofs.owning.build_mixed_source(root, LIMITS)
    index = proofs.MixedProofIndex(source)
    reference, state = references(source.result)[0]
    assert index.resolve(reference).state is state
    freeze(monkeypatch)
    return source, index


def custody(source, reference, state, result):
    envelope = source.source.execution.envelope
    assert result.reference is reference and result.state is state
    registries = tuple(ref for ref in state.evidence if type(ref) is k.RegistryRef)
    captures = tuple(ref for ref in state.evidence if type(ref) is k.EvidenceRef)
    assert len(result.registry_leaves) == len(registries) and len(result.capture_leaves) == len(captures)
    for leaf, ref in zip(result.registry_leaves, registries, strict=True):
        raw = envelope.base.raw if ref.table == "synthetic_p2.nodes" else envelope.raw
        assert leaf.reference is ref and leaf.registry_raw is raw and sha256(raw).hexdigest() == ref.table_digest
        value = json.loads(raw)
        for part in ref.citation.split("/")[1:]:
            value = value[int(part)] if type(value) is list else value[part]
        assert leaf.canonical_value == canonical(value)
        if ref.table.endswith(".nodes") or ref.table.endswith(".targets"):
            assert value["id"] == ref.row_id
        else:
            assert ref.table == "synthetic_p4.context" and value == ref.row_id == envelope.context
    for leaf, ref in zip(result.capture_leaves, captures, strict=True):
        output = next(out for out in source.source.execution.executed if out.receipt.capture.id == ref.capture)
        member = next(member for member in envelope.captures if member.id == ref.capture)
        assert leaf.member is member and leaf.receipt is output.receipt and leaf.capture is output.receipt.capture
        assert leaf.reference is ref and leaf.capture.raw is member.raw
        expected = member.raw if type(ref.locator) is k.WholeCapture else member.raw[ref.locator.start:ref.locator.end]
        assert leaf.raw == expected and leaf.capture_sha256 == sha256(member.raw).hexdigest() == member.sha256
        assert sha256(leaf.raw).hexdigest() == ref.excerpt_sha256
        assert ref.role is (k.EvidenceRole.SUBJECT if type(state) is k.Known else k.EvidenceRole.WITNESS)
        assert type(ref.locator) is k.ByteSpan if type(state) is k.Known else type(ref.locator) in (k.ByteSpan, k.WholeCapture)
    assert result.next_evidence is state.next_evidence if type(state) is k.Unknown else result.next_evidence == ()


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "false", "omitted", "empty", "partial", "no_all", "no_all_target"])
def test_all_seven_actual_fact_kinds_expand_complete_original_registry_and_capture_evidence(tmp_path, monkeypatch, mode):
    source, index = actual(tmp_path, monkeypatch, mode)
    pairs = references(source.result)
    for reference, state in pairs:
        result = index.resolve(reference)
        custody(source, reference, state, result)
        assert index.resolve(replace(reference)) == result
    if mode != "only_vrrp":
        assert {reference.fact for reference, _ in pairs} == {fact for _, fact, _ in FACTS}
    if mode == "false":
        reference, state = next(pair for pair in pairs if pair[0].fact == proofs.stp.ROOT_GUARD)
        assert type(state) is k.Known and state.value is False
        assert all(leaf.reference.role is k.EvidenceRole.SUBJECT for leaf in index.resolve(reference).capture_leaves)
    if mode in ("none", "cold_vrrp"):
        rows = pairs if mode == "none" else tuple(pair for pair in pairs if pair[0].fact == proofs.vrrp_profile.REPORTED_VRRP_STATE)
        assert all(type(state) is k.Unknown and state.reason is k.UnknownReason.NOT_COLLECTED
            and not index.resolve(reference).capture_leaves and index.resolve(reference).registry_leaves for reference, state in rows)
    if mode == "empty":
        reference, state = next(pair for pair in pairs if pair[0].fact == proofs.vrrp_profile.REPORTED_VRRP_STATE)
        result = index.resolve(reference)
        assert type(state) is k.Unknown and state.reason is k.UnknownReason.EMPTY_UNREGISTERED
        assert any(type(leaf.reference.locator) is k.WholeCapture and leaf.raw == b"" for leaf in result.capture_leaves)


@pytest.mark.parametrize("mode", ["normal", "no_all", "no_all_target"])
def test_version_and_state_share_subjects_but_version_uses_only_actual_all_capture(tmp_path, monkeypatch, mode):
    source, index = actual(tmp_path, monkeypatch, mode)
    pair = next((row, version) for row in source.result.state.rows for version in source.result.version.rows
        if row.subject == version.subject and type(row.value) is k.Known)
    state, version = pair
    brief = index.resolve(k.FactRef(fact=proofs.build.REPORTED_STATE, subject=state.subject))
    detail = index.resolve(k.FactRef(fact=proofs.version_profile.REPORTED_PROTOCOL_VERSION, subject=version.subject))
    assert brief.capture_leaves and all(leaf.capture.operation == proofs.build.hsrp.OP for leaf in brief.capture_leaves)
    assert all(leaf.capture.operation == proofs.version_profile.parser.OP for leaf in detail.capture_leaves)
    if mode != "normal":
        assert len(detail.registry_leaves) == (3 if mode == "no_all_target" else 4)
        assert type(version.value) is k.Unknown and version.value.reason is k.UnknownReason.NOT_COLLECTED
        assert detail.capture_leaves == () and detail.next_evidence is version.value.next_evidence
        assert all(need.operation == proofs.version_profile.parser.OP for need in detail.next_evidence)
    else:
        assert detail.capture_leaves and all(leaf.capture.id != brief.capture_leaves[0].capture.id for leaf in detail.capture_leaves)


@pytest.mark.parametrize("plant", ["object", "fact_alias", "subject_alias", "unhashable", "unknown_fact", "unknown_subject", "cross_protocol"])
def test_plain_finite_fact_references_are_required_before_hash_lookup(tmp_path, monkeypatch, plant):
    source, index = actual(tmp_path, monkeypatch)
    reference = replace(references(source.result)[0][0])
    if plant == "object":
        reference = object()
    elif plant in ("fact_alias", "subject_alias", "unhashable"):
        name = "fact" if plant != "subject_alias" else "subject"
        object.__setattr__(reference, name, [] if plant == "unhashable" else StrEnum("Alias", {"VALUE": getattr(reference, name)}).VALUE)
    elif plant == "cross_protocol":
        reference = k.FactRef(fact=proofs.vrrp_profile.REPORTED_VRRP_STATE, subject=source.result.state.rows[0].subject)
    else:
        reference = replace(reference, **({"fact": "l2.stp.reported_root_mac"} if plant == "unknown_fact" else {"subject": "fhrp_local:foreign"}))
    with pytest.raises(ValueError, match="^p4_mixed_proofs_reference$"):
        index.resolve(reference)


@pytest.mark.parametrize("plant", ["derived_ctor", "derived_resolve", "wrong_source", "unbuilt", "shadow_getter"])
def test_fixed_index_and_unbound_current_getter_cannot_be_bypassed(tmp_path, monkeypatch, plant):
    source, index = actual(tmp_path, monkeypatch)
    reference = references(source.result)[0][0]
    class Derived(proofs.MixedProofIndex):
        pass
    if plant == "shadow_getter":
        source.current_component = lambda: source.result
        result = source.result.tree
        ref = next(iter(result.store.values))
        result.store.values[ref] = replace(result.store.values[ref])
        code = "fhrp_mixed_component_cell"
    elif plant == "wrong_source":
        index.source = object()
        code = "p4_mixed_proofs_source"
    elif plant == "unbuilt":
        index.source = proofs.owning.MixedComponentRun(tmp_path, LIMITS)
        code = "fhrp_mixed_component_source"
    else:
        code = "p4_mixed_proofs_source"
    with pytest.raises(ValueError, match="^" + code + "$"):
        if plant == "derived_ctor":
            Derived(source)
        elif plant == "derived_resolve":
            forged = object.__new__(Derived)
            forged.source = source
            proofs.MixedProofIndex.resolve(forged, reference)
        else:
            index.resolve(reference)


@pytest.mark.parametrize("plant", ["cell_copy", "digest", "registry", "role", "whole", "scope", "raw"])
def test_current_cell_and_source_mutations_refuse_before_snapshot_proof(tmp_path, monkeypatch, plant):
    source, index = actual(tmp_path, monkeypatch)
    row = source.result.tree.rows[0]
    reference = k.FactRef(fact=proofs.stp.ROOT_GUARD, subject=row.subject)
    if plant == "cell_copy":
        source.result.tree.store.values[reference] = replace(row.value)
        code = "fhrp_mixed_component_cell"
    elif plant in ("digest", "registry", "role", "whole"):
        ref = next(ref for ref in row.value.evidence if type(ref) is (k.RegistryRef if plant == "registry" else k.EvidenceRef))
        if plant == "registry":
            original, ref = ref, replace(ref)
            object.__setattr__(row.value, "evidence", tuple(ref if item is original else item for item in row.value.evidence))
        name, value = ("citation", "/targets/999") if plant == "registry" else ("excerpt_sha256", "0" * 64) if plant == "digest" else (
            ("role", k.EvidenceRole.WITNESS) if plant == "role" else ("locator", k.WholeCapture()))
        object.__setattr__(ref, name, value)
        code = "stp_root_guard_source_value"
    else:
        leaf = index.resolve(reference).capture_leaves[0]
        if plant == "scope":
            object.__setattr__(leaf.capture, "metadata", replace(leaf.capture.resolved_metadata, scope=replace(leaf.capture.scope, vrf="blue")))
            code = "fhrp_mixed_execution_scope"
        else:
            object.__setattr__(leaf.capture, "raw", bytes(bytearray(leaf.capture.raw)))
            code = "fhrp_mixed_execution_output"
    with pytest.raises(ValueError, match="^" + code + "$"):
        index.resolve(reference)


@pytest.mark.parametrize("extra", [{"evidence": ()}, {"positive": True}, {"state": object()}])
def test_resolve_accepts_no_caller_grants_or_replacement_values(tmp_path, monkeypatch, extra):
    source, index = actual(tmp_path, monkeypatch)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        index.resolve(references(source.result)[0][0], **extra)


def test_all_proof_records_are_snapshots_and_frozen_data_not_admission_tokens(tmp_path, monkeypatch):
    source, index = actual(tmp_path, monkeypatch)
    reference, state = references(source.result)[0]
    result = index.resolve(reference)
    assert replace(result) == result and result.state is state
    with pytest.raises(AttributeError):
        result.state = None
    with pytest.raises(AttributeError):
        result.registry_leaves[0].canonical_value = b"changed"
    assert result.capture_leaves
    with pytest.raises(AttributeError):
        result.capture_leaves[0].raw = b"changed"


@pytest.mark.parametrize("registry,code", [("p2", "fhrp_mixed_context_registry"), ("p4", "hsrp_folder_declaration")])
def test_current_original_registry_bytes_cannot_drift_after_index_creation(tmp_path, monkeypatch, registry, code):
    source, index = actual(tmp_path, monkeypatch)
    envelope = source.source.execution.envelope
    owner = envelope.base if registry == "p2" else envelope
    original = owner.raw
    object.__setattr__(owner, "raw", original + b"\n")
    with pytest.raises(ValueError, match="^" + code + "$"):
        index.resolve(references(source.result)[0][0])
    object.__setattr__(owner, "raw", original)
    assert index.resolve(references(source.result)[0][0]).state is references(source.result)[0][1]
