"""Root9 context and input correspondence only; no production, origin or admission claim."""
import json
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_context import admitted, freeze
from test_mixed_hsrp_inputs import customized
from test_mixed_vrrp_inputs import configured
from test_peer_execution import forbidden
from test_state_owner import LIMITS

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import mixed_vrrp_inputs as mv
from atlas_brain.packs.l3.fhrp import root_mixed_profile as profile
from atlas_brain.packs.l3.fhrp import version_inputs as vi
from atlas_brain.packs.l3.fhrp import vrrp_inputs as vr


def root_folder(root, mode="normal"):
    old, files = configured(root, "zero") if mode == "zero_vrrp" else customized(root, mode) if mode.startswith("no_") else admitted(root, mode)
    envelope = gp.p4.admit_folder(root, LIMITS, declarations=profile.DECLARATIONS)
    assert old.registration_sha256 != envelope.registration_sha256
    return envelope, old, files


def entries(hsrp, vrrp):
    return (gp.validate_root_mixed_context, gp.prepare_root_mixed_hsrp_inputs,
        lambda env, limits: gp.validate_root_mixed_hsrp_correspondence(env, limits, hsrp.version),
        mv.prepare_root_mixed_vrrp_inputs,
        lambda env, limits: mv.validate_root_mixed_vrrp_correspondence(env, limits, vrrp.vrrp))


def check(envelope, hsrp, vrrp):
    compiled = profile.compile_root_mixed_profile()
    assert gp.validate_root_mixed_context(envelope, LIMITS) == compiled
    for result in (hsrp, vrrp):
        assert result.envelope is envelope and result.budgets is LIMITS and result.compiled == compiled
        for domain in result.domains:
            assert any(domain.node is node for node in envelope.base.nodes) and domain.context == envelope.context
        for request in result.requests + (hsrp.version.requests if result is hsrp else ()):
            member = next(member for member in envelope.captures if member.id == request.capture.id)
            assert request.capture.raw is member.raw and request.capture.bytes_sha256 == member.sha256
            assert request.capture.source == member.target.node.key and request.context == envelope.context
            assert request.capture.operation == member.target.operation
    assert hsrp.version.targets is hsrp.domains and vrrp.vrrp.targets is vrrp.domains
    assert vrrp.vrrp.requests is vrrp.requests and vrrp.vrrp.registration_sha256 != compiled.registration_sha256
    for result, operation in ((hsrp, gp.hsrp.OP), (vrrp, mv.profile.parser.OP)):
        expected = tuple(target for target in envelope.targets if target.operation == operation)
        assert len(result.domains) == len(expected) and set(result.declarations) == {(domain.context, domain.node.key) for domain in result.domains}
        for domain in result.domains:
            target = next(target for target in expected if target.node is domain.node)
            assert any(target is original for original in result.targets)
            assert domain.groups == tuple(sorted(map(tuple, json.loads(target.params)["groups"])))
            refs = domain.node.declaration.evidence + envelope.declaration.evidence + target.declaration.evidence
            if result is hsrp:
                detail = next((target for target in result.targets if target.node is domain.node and target.operation == gp.all_hsrp.OP), None)
                refs += () if detail is None else detail.declaration.evidence
            actual = result.declarations[domain.context, domain.node.key]
            assert len(actual) == len(refs) and all(a is b for a, b in zip(actual, refs, strict=True))
    expected_subjects = tuple(sorted(vr.subject(domain, interface, group) for domain in vrrp.domains for interface, group in domain.groups))
    assert vrrp.subjects == expected_subjects and len(expected_subjects) == sum(len(domain.groups) for domain in vrrp.domains)
    assert gp.validate_root_mixed_hsrp_correspondence(envelope, LIMITS, hsrp.version) == hsrp.declarations
    assert mv.validate_root_mixed_vrrp_correspondence(envelope, LIMITS, vrrp.vrrp) == vrrp.declarations


def prepared(root, monkeypatch, mode="normal"):
    freeze(monkeypatch)
    monkeypatch.setattr(gp.p4_pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(gp.build.StateOwner, "__init__", forbidden)
    envelope, old, files = root_folder(root, mode)
    monkeypatch.setattr(gp.p4, "admit_folder", forbidden)
    hsrp, vrrp = gp.prepare_root_mixed_hsrp_inputs(envelope, LIMITS), mv.prepare_root_mixed_vrrp_inputs(envelope, LIMITS)
    check(envelope, hsrp, vrrp)
    return envelope, hsrp, vrrp, old, files


@pytest.fixture
def case(tmp_path, monkeypatch):
    return prepared(tmp_path, monkeypatch)


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "zero_vrrp", "multi_tree", "no_all_target", "no_all_capture", "no_brief_capture", "no_captures"])
def test_fixed_root9_preparations_keep_original_declarations_independent_populations_and_raw_members(tmp_path, monkeypatch, mode):
    envelope, hsrp, vrrp, old, files = prepared(tmp_path, monkeypatch, mode)
    assert len(hsrp.domains) == (0 if mode == "only_vrrp" else 2)
    assert sum(len(domain.groups) for domain in hsrp.domains) == (0 if mode == "only_vrrp" else 5)
    assert len(vrrp.subjects) == (0 if mode == "zero_vrrp" else 1 if mode.startswith("no_") else 2)
    assert len(hsrp.version.requests) == (0 if mode in ("none", "only_vrrp", "no_all_target", "no_all_capture", "no_captures") else 1)
    assert len(hsrp.requests) == (0 if mode in ("none", "only_vrrp", "no_brief_capture", "no_captures") else 1)
    assert len(vrrp.requests) == (0 if mode in ("none", "cold_vrrp", "zero_vrrp") else 1)
    assert gp.validate_mixed_context(old, LIMITS) == gp.mixed_profile.compile_mixed_profile()
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files
    for call in (gp.validate_mixed_context, gp.prepare_mixed_hsrp_inputs, mv.prepare_mixed_vrrp_inputs):
        with pytest.raises(ValueError, match="^fhrp_mixed_context_registration$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("selection", ["mixed7", "root4", "old_report", "peer4", "foreign", "alias"])
def test_old_and_malformed_registration_labels_cannot_select_the_root9_path(case, selection):
    envelope, hsrp, vrrp, old, _ = case
    hashes = {"mixed7": old.registration_sha256,
        "root4": profile.compile_packs((profile.stp.root_declaration(),)).registration_sha256,
        "old_report": profile.compile_packs((profile.stp.root_declaration(), profile.ec.DECLARATION, profile.hsrp.DECLARATION)).registration_sha256,
        "peer4": gp.peer_profile.compile_peer_state_version_profile().registration_sha256, "foreign": "0" * 64,
        "alias": StrEnum("Alias", {"VALUE": envelope.registration_sha256}).VALUE}
    changed = replace(envelope, registration_sha256=hashes[selection])
    code = "hsrp_state_version_graph" if selection == "alias" else "fhrp_mixed_context_registration"
    for call in entries(hsrp, vrrp):
        with pytest.raises(ValueError, match="^" + code + "$"):
            call(changed, LIMITS)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_current_budget_leaves_refuse_before_root_compilation_or_detached_snapshots(case, monkeypatch, field):
    envelope, hsrp, vrrp, _, _ = case
    limits = replace(LIMITS)
    object.__setattr__(limits, field, False)
    monkeypatch.setattr(profile, "compile_root_mixed_profile", forbidden)
    monkeypatch.setattr(gp, "strict_json", forbidden)
    for call in entries(hsrp, vrrp):
        with pytest.raises(ValueError, match="^hsrp_state_version_budget$"):
            call(envelope, limits)


@pytest.mark.parametrize("field", ["artifacts", "artifact_bytes", "bundle_bytes"])
def test_whole_raw_material_limits_include_two_manifests_and_precede_the_root_compiler(case, monkeypatch, field):
    envelope, hsrp, vrrp, _, _ = case
    raws = (envelope.base.raw, envelope.raw) + tuple(capture.raw for capture in envelope.base.captures) + tuple(member.raw for member in envelope.captures)
    exact = {"artifacts": len(raws), "artifact_bytes": max(map(len, raws)), "bundle_bytes": sum(map(len, raws))}
    assert gp.validate_root_mixed_context(envelope, replace(LIMITS, **exact)) == hsrp.compiled
    monkeypatch.setattr(profile, "compile_root_mixed_profile", forbidden)
    for call in entries(hsrp, vrrp):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
            call(envelope, replace(LIMITS, **{field: exact[field] - 1}))
        assert caught.value.member == "fhrp_mixed_context_raw_budget"


@pytest.mark.parametrize("field", ["targets", "captures", "operation_alias"])
def test_finite_current_graph_refuses_before_root_profile_compilation(case, monkeypatch, field):
    envelope, hsrp, vrrp, _, _ = case
    if field == "operation_alias":
        target = envelope.targets[0]
        object.__setattr__(target, "operation", StrEnum("Alias", {"VALUE": target.operation}).VALUE)
    else:
        object.__setattr__(envelope, field, list(getattr(envelope, field)))
    monkeypatch.setattr(profile, "compile_root_mixed_profile", forbidden)
    code = "hsrp_state_version_graph" if field == "operation_alias" else "fhrp_mixed_context_graph"
    for call in entries(hsrp, vrrp):
        with pytest.raises(ValueError, match="^" + code + "$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("operation", ["iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary",
    "iosxe.show_standby_brief", "iosxe.show_standby_all", "iosxe.show_vrrp"])
def test_each_original_operation_owner_is_closed_before_either_protocol_is_prepared(case, operation):
    envelope, hsrp, vrrp, _, _ = case
    target = next(target for target in envelope.targets if target.operation == operation)
    object.__setattr__(target, "owner", "l3.fhrp/other")
    for call in entries(hsrp, vrrp):
        with pytest.raises(ValueError, match="^fhrp_mixed_context_target$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("part", ["node", "context", "brief", "all", "vrrp"])
def test_original_node_context_and_each_protocol_target_registry_references_reject_neighbor_donors(case, part):
    envelope, hsrp, vrrp, _, _ = case
    target = next(target for target in envelope.targets if target.operation == (
        gp.all_hsrp.OP if part == "all" else mv.profile.parser.OP if part == "vrrp" else gp.hsrp.OP))
    state = target.node.declaration if part == "node" else envelope.declaration if part == "context" else target.declaration
    donor = next(node for node in envelope.base.nodes if node.id == "b").declaration
    object.__setattr__(state, "evidence", donor.evidence)
    for call in entries(hsrp, vrrp):
        with pytest.raises(ValueError, match="^hsrp_folder_declaration$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("protocol", ["hsrp", "vrrp"])
@pytest.mark.parametrize("plant", ["drop", "node_copy", "groups", "raw_copy", "snapshot"])
def test_coherent_lower_inputs_and_retained_snapshots_cannot_replace_current_root9_correspondence(case, protocol, plant):
    envelope, hsrp, vrrp, _, _ = case
    original, local, validating = (hsrp.version, vi, gp.validate_root_mixed_hsrp_correspondence) if protocol == "hsrp" else (
        vrrp.vrrp, vr, mv.validate_root_mixed_vrrp_correspondence)
    if plant == "snapshot":
        held = original.retained_requests[0]
        retained = (replace(held, value={}),) if protocol == "hsrp" else ((held[0], held[1], b"changed"),)
        changed = replace(original, retained_requests=retained)
        code = "pack_receipts_retention_mismatch" if protocol == "hsrp" else "vrrp_inputs_request"
    else:
        domains, requests = original.targets, original.requests
        if plant in ("drop", "node_copy", "groups"):
            domains = () if plant == "drop" else tuple(replace(domain, **({"node": replace(domain.node)} if plant == "node_copy" else {
                "groups": (("Vl99", "9"),) if protocol == "hsrp" else (("Vlan61", "101"),)})) for domain in domains)
            requests = () if plant == "drop" else requests
        else:
            request = requests[0]
            copied = bytes(bytearray(request.capture.raw))
            assert copied == request.capture.raw and copied is not request.capture.raw
            requests = (replace(request, capture=replace(request.capture, raw=copied)),)
        changed = local.retain_version_inputs(domains, requests) if protocol == "hsrp" else local.retain_vrrp_inputs(domains, requests)
        code = "fhrp_mixed_" + protocol + ("_capture" if plant == "raw_copy" else "_population")
    with pytest.raises(ValueError, match="^" + code + "$"):
        validating(envelope, LIMITS, changed)


@pytest.mark.parametrize("protocol", ["hsrp", "vrrp"])
@pytest.mark.parametrize("entry", ["prepare", "correspondence"])
@pytest.mark.parametrize("plant", ["raw_copy", "compiled"])
def test_documented_context_phases_reclose_selected_raw_bindings_and_compiled_metadata(case, monkeypatch, protocol, entry, plant):
    envelope, hsrp, vrrp, _, _ = case
    original, calls = gp.validate_root_mixed_context, []
    result = hsrp if protocol == "hsrp" else vrrp
    def validating(env, limits):
        value = original(env, limits)
        calls.append(value)
        if len(calls) == (1 if protocol == "hsrp" and entry == "correspondence" and plant == "raw_copy" else 4 if entry == "prepare" else 2):
            if plant == "compiled":
                return replace(value, registration_sha256="0" * 64)
            operation = (gp.hsrp.OP if entry == "prepare" else gp.all_hsrp.OP) if protocol == "hsrp" else mv.profile.parser.OP
            member = next(member for member in env.captures if member.target.operation == operation)
            object.__setattr__(member, "raw", bytes(bytearray(member.raw)))
        return value
    monkeypatch.setattr(gp, "validate_root_mixed_context", validating)
    call = gp.prepare_root_mixed_hsrp_inputs if protocol == "hsrp" else mv.prepare_root_mixed_vrrp_inputs
    code = "fhrp_mixed_" + protocol + ("_registration" if plant == "compiled" else "_capture")
    with pytest.raises(ValueError, match="^" + code + "$"):
        call(envelope, LIMITS) if entry == "prepare" else (
            gp.validate_root_mixed_hsrp_correspondence(envelope, LIMITS, result.version) if protocol == "hsrp" else
            mv.validate_root_mixed_vrrp_correspondence(envelope, LIMITS, result.vrrp))
    assert len(calls) == (1 if protocol == "hsrp" and entry == "correspondence" and plant == "raw_copy" else 4 if entry == "prepare" else 2)


def test_permuted_lower_models_and_typed_data_copies_are_comparison_data_not_origin_tokens(case):
    envelope, hsrp, vrrp, _, _ = case
    permuted = replace(envelope, targets=tuple(reversed(envelope.targets)), captures=tuple(reversed(envelope.captures)))
    check(permuted, gp.prepare_root_mixed_hsrp_inputs(permuted, LIMITS), mv.prepare_root_mixed_vrrp_inputs(permuted, LIMITS))
    copied = vi.retain_version_inputs(tuple(replace(domain) for domain in reversed(hsrp.domains)),
        tuple(replace(request, capture=replace(request.capture)) for request in hsrp.version.requests))
    assert gp.validate_root_mixed_hsrp_correspondence(replace(envelope), LIMITS, copied) == hsrp.declarations
    copied_vrrp = vr.retain_vrrp_inputs(tuple(replace(domain) for domain in vrrp.domains),
        tuple(replace(request, capture=replace(request.capture)) for request in vrrp.requests))
    assert mv.validate_root_mixed_vrrp_correspondence(replace(envelope), LIMITS, copied_vrrp) == vrrp.declarations
