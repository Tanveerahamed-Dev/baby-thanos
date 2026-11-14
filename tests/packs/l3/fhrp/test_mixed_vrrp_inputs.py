"""Declared mixed VRRP inputs and current raw correspondence; no production or origin token."""
import json
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_context import admitted, freeze
from test_parse_vrrp import BODY
from test_peer_execution import forbidden
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.packs.l3.fhrp import mixed_vrrp_inputs as mixed
from atlas_brain.packs.l3.fhrp import vrrp_inputs as local
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile


def frozen(monkeypatch):
    freeze(monkeypatch)
    monkeypatch.setattr(mixed.context.p4_pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(mixed.context.build.StateOwner, "__init__", forbidden)


def check(envelope, result):
    assert result.envelope is envelope and result.budgets is LIMITS
    assert result.compiled == mixed.context.mixed_profile.compile_mixed_profile()
    assert result.vrrp.registration_sha256 == profile.compile_vrrp_profile().registration_sha256
    assert result.vrrp.registration_sha256 != result.compiled.registration_sha256
    assert result.vrrp.targets is result.domains and result.vrrp.requests is result.requests
    assert result.targets == tuple(target for target in envelope.targets if target.operation == profile.parser.OP)
    assert len(result.domains) == len(result.targets)
    for domain, target in zip(result.domains, result.targets, strict=True):
        assert domain.node is target.node and domain.context == envelope.context
        assert domain.groups == tuple(sorted(map(tuple, json.loads(target.params)["groups"])))
        refs = domain.node.declaration.evidence + envelope.declaration.evidence + target.declaration.evidence
        actual = result.declarations[domain.context, domain.node.key]
        assert len(actual) == 3 and all(a is b for a, b in zip(actual, refs, strict=True))
    expected = tuple(sorted(local.subject(domain, interface, group) for domain in result.domains for interface, group in domain.groups))
    assert result.subjects == expected and len(result.subjects) == sum(len(domain.groups) for domain in result.domains)
    for request in result.requests:
        member = next(member for member in envelope.captures if member.id == request.capture.id)
        assert member.target in result.targets and request.capture.raw is member.raw
        assert request.capture.bytes_sha256 == member.sha256 and request.capture.source == member.target.node.key
        assert request.context == envelope.context and request.capture.operation == profile.parser.OP
        assert request.capture.rendered == profile.parser.COMMAND
    assert mixed.validate_mixed_vrrp_correspondence(envelope, LIMITS, result.vrrp) == result.declarations


@pytest.fixture
def case(tmp_path, monkeypatch):
    frozen(monkeypatch)
    envelope, _ = admitted(tmp_path)
    result = mixed.prepare_mixed_vrrp_inputs(envelope, LIMITS)
    check(envelope, result)
    return envelope, result


def configured(root, mode="normal", groups=None):
    def changing(side, files):
        if mode == "zero":
            return
        side["targets"].append({"id": "vrrp", "node": "b" if mode == "cold_node" else "a",
            "operation": profile.parser.OP, "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]} if groups is None else groups})
        if mode == "both_nodes":
            side["targets"].append({"id": "vrrp-b", "node": "b", "operation": profile.parser.OP,
                "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]}})
        if mode == "duplicate_target":
            side["targets"].append({"id": "second-vrrp", "node": "a", "operation": profile.parser.OP,
                "params": {"groups": [["Vl62", "101"]]}})
        if mode not in ("cold", "cold_node", "duplicate_target"):
            files["vrrp.txt"] = b"show clock\n" if groups is not None else BODY
            side["captures"].append({"target": "vrrp", "path": "vrrp.txt"})
        if mode == "duplicate_capture":
            files["second-vrrp.txt"] = BODY
            side["captures"].append({"target": "vrrp", "path": "second-vrrp.txt"})
    files = folder(root, change=changing)
    envelope = mixed.p4.admit_folder(root, LIMITS, declarations=mixed.context.mixed_profile.DECLARATIONS)
    assert mixed.context.validate_mixed_context(envelope, LIMITS) == mixed.context.mixed_profile.compile_mixed_profile()
    return envelope, files


@pytest.mark.parametrize("mode", ["normal", "only_vrrp", "none", "cold_vrrp", "multi_tree"])
def test_real_mixed_admission_returns_original_local_models_and_independent_declared_subjects(tmp_path, monkeypatch, mode):
    frozen(monkeypatch)
    envelope, files = admitted(tmp_path, mode)
    monkeypatch.setattr(mixed.p4, "admit_folder", forbidden)
    result = mixed.prepare_mixed_vrrp_inputs(envelope, LIMITS)
    check(envelope, result)
    assert len(result.subjects) == 2 and len(result.domains) == 1
    assert len(result.requests) == (0 if mode in ("none", "cold_vrrp") else 1)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("mode", ["zero", "cold", "cold_node", "both_nodes"])
def test_zero_vrrp_and_unobserved_original_nodes_are_valid_without_fabricated_captures(case, tmp_path, mode):
    envelope, _ = configured(tmp_path / "population", mode)
    result = mixed.prepare_mixed_vrrp_inputs(envelope, LIMITS)
    check(envelope, result)
    assert len(result.requests) == (1 if mode == "both_nodes" else 0)
    assert len(result.subjects) == (0 if mode == "zero" else 4 if mode == "both_nodes" else 2)
    if mode == "zero":
        assert result.targets == result.domains == () and result.declarations == {}
    if mode == "cold_node":
        assert result.domains[0].node is next(node for node in envelope.base.nodes if node.id == "b")


def test_permutations_plain_map_copies_and_new_local_carriers_preserve_data_not_origin(case):
    envelope, result = case
    permuted = replace(envelope, targets=tuple(reversed(envelope.targets)), captures=tuple(reversed(envelope.captures)))
    check(permuted, mixed.prepare_mixed_vrrp_inputs(permuted, LIMITS))
    copied = local.retain_vrrp_inputs(tuple(replace(domain) for domain in result.domains),
        tuple(replace(request, capture=replace(request.capture)) for request in result.requests))
    assert mixed.validate_mixed_vrrp_correspondence(replace(envelope), LIMITS, copied) == result.declarations


@pytest.mark.parametrize("params,code", [({}, "invalid_record_fields"), ({"groups": [], "other": []}, "invalid_record_fields"),
    *[({"groups": value}, "fhrp_mixed_vrrp_groups") for value in ([], "100", {}, [["Vlan61"]], [["Vlan61", 100]], [["Vlan61", "100"]] * 129)],
    *[({"groups": value}, "vrrp_inputs_population") for value in ([["Vlan61", "200"]], [["bad interface", "100"]],
        [["Vlan61", "100"], ["Vlan61", "100"]])]])
def test_exact_bounded_groups_schema_and_synthetic_floor_refuse_before_any_bad_frame(case, tmp_path, monkeypatch, params, code):
    envelope, _ = configured(tmp_path / "groups", groups=params)
    monkeypatch.setattr(local, "prepare_vrrp_request", forbidden)
    monkeypatch.setattr(mixed, "MixedVRRPInputs", forbidden)
    with pytest.raises(ValueError, match="^" + code + "$"):
        mixed.prepare_mixed_vrrp_inputs(envelope, LIMITS)


@pytest.mark.parametrize("mode,code", [("duplicate_target", "target"), ("duplicate_capture", "capture")])
def test_multiple_target_or_capture_per_node_refuses_before_frame_preparation_even_when_cold(case, tmp_path, monkeypatch, mode, code):
    envelope, _ = configured(tmp_path / "duplicate", mode)
    monkeypatch.setattr(local, "prepare_vrrp_request", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_vrrp_" + code + "$"):
        mixed.prepare_mixed_vrrp_inputs(envelope, LIMITS)


@pytest.mark.parametrize("plant", ["input", "target_drop", "node_copy", "groups", "request_drop", "raw_copy",
    "id", "source", "context", "local_hash", "snapshot", "capture_copy", "deep_groups"])
def test_coherent_lower_graphs_snapshots_and_population_cannot_replace_original_mixed_bindings(case, plant):
    envelope, result = case
    value = result.vrrp
    code = "fhrp_mixed_vrrp_input"
    if plant == "input":
        value = []
    elif plant in ("target_drop", "node_copy", "groups"):
        domains = () if plant == "target_drop" else tuple(replace(domain, **(
            {"node": replace(domain.node)} if plant == "node_copy" else {"groups": (("Vlan61", "101"),)})) for domain in value.targets)
        value = local.retain_vrrp_inputs(domains, () if plant == "target_drop" else value.requests)
        code = "fhrp_mixed_vrrp_population"
    elif plant in ("request_drop", "raw_copy", "id"):
        requests = ()
        if plant != "request_drop":
            request = value.requests[0]
            sample = replace(request.capture, **({"raw": bytes(bytearray(request.capture.raw))} if plant == "raw_copy" else {"id": "cap:foreign"}))
            requests = (replace(request, capture=sample),)
        value = local.retain_vrrp_inputs(value.targets, requests)
        code = "fhrp_mixed_vrrp_capture"
    elif plant == "local_hash":
        value = replace(value, registration_sha256=result.compiled.registration_sha256)
        code = "vrrp_inputs_input"
    elif plant == "snapshot":
        held = value.retained_requests[0]
        value = replace(value, retained_requests=((held[0], held[1], b"changed"),))
        code = "vrrp_inputs_request"
    elif plant == "capture_copy":
        object.__setattr__(value.requests[0], "capture", replace(value.requests[0].capture))
        code = "vrrp_inputs_request"
    elif plant == "deep_groups":
        object.__setattr__(value.targets[0], "groups", (("Vlan61", []),))
        code = "vrrp_inputs_population"
    else:
        request = value.requests[0]
        object.__setattr__(request.capture if plant == "source" else request, plant,
            "node:foreign:b" if plant == "source" else "other")
        code = "vrrp_inputs_population"
    with pytest.raises(ValueError, match="^" + code + "$"):
        mixed.validate_mixed_vrrp_correspondence(envelope, LIMITS, value)


@pytest.mark.parametrize("operation", ["iosxe.show_standby_brief", "iosxe.show_standby_all",
    "iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary", "iosxe.show_vrrp", "registration"])
@pytest.mark.parametrize("field", ["owner", "alias"])
def test_all_five_operations_and_outer_registration_are_currently_owned_plain_and_closed(case, operation, field):
    envelope, result = case
    target = envelope if operation == "registration" else next(target for target in envelope.targets if target.operation == operation)
    name = "registration_sha256" if operation == "registration" else "owner" if field == "owner" else "operation"
    object.__setattr__(target, name, (result.vrrp.registration_sha256 if operation == "registration" else "l3.fhrp/other")
        if field == "owner" else StrEnum("Alias", {"VALUE": getattr(target, name)}).VALUE)
    code = "hsrp_state_version_graph" if field == "alias" else "fhrp_mixed_context_registration" if operation == "registration" else "fhrp_mixed_context_target"
    for call in (mixed.prepare_mixed_vrrp_inputs, lambda env, limits: mixed.validate_mixed_vrrp_correspondence(env, limits, result.vrrp)):
        with pytest.raises(ValueError, match="^" + code + "$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("part", ["node", "context", "target"])
def test_registry_donors_do_not_replace_original_declared_node_context_or_vrrp_target(case, part):
    envelope, result = case
    state = result.domains[0].node.declaration if part == "node" else envelope.declaration if part == "context" else result.targets[0].declaration
    donor = next(node for node in envelope.base.nodes if node.id == "b").declaration
    object.__setattr__(state, "evidence", donor.evidence)
    with pytest.raises(ValueError, match="^hsrp_folder_declaration$"):
        mixed.validate_mixed_vrrp_correspondence(envelope, LIMITS, result.vrrp)


@pytest.mark.parametrize("field", ["id", "sha256", "raw", "equal_raw", "target_copy"])
def test_current_vrrp_member_census_hashes_ids_and_raw_identity_are_not_detached(case, field):
    envelope, result = case
    member = next(member for member in envelope.captures if member.target is result.targets[0])
    name, value = ("raw", bytes(bytearray(member.raw))) if field == "equal_raw" else ("target", replace(member.target)) if field == "target_copy" else (
        field, "cap:foreign" if field == "id" else "0" * 64 if field == "sha256" else member.raw + b"\n")
    object.__setattr__(member, name, value)
    code = "fhrp_mixed_vrrp_capture" if field == "equal_raw" else "hsrp_state_version_graph" if field == "target_copy" else "hsrp_folder_member"
    with pytest.raises(ValueError, match="^" + code + "$"):
        mixed.validate_mixed_vrrp_correspondence(envelope, LIMITS, result.vrrp)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_every_current_budget_leaf_is_rechecked_before_detached_vrrp_snapshots(case, monkeypatch, field):
    envelope, result = case
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, False)
    monkeypatch.setattr(local, "asdict", forbidden)
    for call in (mixed.prepare_mixed_vrrp_inputs, lambda env, limits: mixed.validate_mixed_vrrp_correspondence(env, limits, result.vrrp)):
        with pytest.raises(ValueError, match="^hsrp_state_version_budget$"):
            call(envelope, budgets)


@pytest.mark.parametrize("entry", ["prepare", "correspondence"])
@pytest.mark.parametrize("plant", ["raw_copy", "declaration", "node_snapshot", "budget", "compiled"])
def test_current_context_budgets_and_final_bindings_still_refuse_before_publication(case, monkeypatch, entry, plant):
    envelope, result = case
    limits = replace(LIMITS)
    original, calls = mixed.context.validate_mixed_context, []
    def validating(env, budgets):
        value = original(env, budgets)
        calls.append(value)
        if len(calls) == (1 if plant == "budget" else 4 if entry == "prepare" else 2):
            if plant == "budget":
                object.__setattr__(budgets, "artifact_bytes", 1)
            elif plant == "compiled":
                return replace(value, registration_sha256="0" * 64)
            elif plant == "raw_copy":
                member = next(member for member in env.captures if member.target is result.targets[0])
                object.__setattr__(member, "raw", bytes(bytearray(member.raw)))
            elif plant == "declaration":
                object.__setattr__(env, "declaration", next(node for node in env.base.nodes if node.id == "b").declaration)
            else:
                object.__setattr__(result.domains[0].node, "ports", result.domains[0].node.ports + ("Gi1/0/2",))
        return value
    monkeypatch.setattr(mixed.context, "validate_mixed_context", validating)
    monkeypatch.setattr(mixed, "MixedVRRPInputs", forbidden)
    code = "budget_exceeded" if plant == "budget" else "fhrp_mixed_vrrp_registration" if plant == "compiled" else "fhrp_mixed_vrrp_capture" if plant == "raw_copy" else "fhrp_mixed_vrrp_declaration" if plant == "declaration" else "vrrp_inputs_target"
    with pytest.raises(BudgetExceeded if plant == "budget" else ValueError, match="^" + code + "$") as caught:
        mixed.prepare_mixed_vrrp_inputs(envelope, limits) if entry == "prepare" else mixed.validate_mixed_vrrp_correspondence(envelope, limits, result.vrrp)
    if plant == "budget":
        assert caught.value.member == "fhrp_mixed_context_raw_budget"


def test_initial_selected_target_identity_is_retained_across_final_context_revalidation(case, monkeypatch):
    envelope, result = case
    original, calls = mixed.context.validate_mixed_context, []
    def validating(env, budgets):
        value = original(env, budgets)
        calls.append(value)
        if len(calls) == 4:
            old = result.targets[0]
            new = replace(old)
            object.__setattr__(env, "targets", tuple(new if target is old else target for target in env.targets))
            for member in env.captures:
                if member.target is old:
                    object.__setattr__(member, "target", new)
        return value
    monkeypatch.setattr(mixed.context, "validate_mixed_context", validating)
    monkeypatch.setattr(mixed, "MixedVRRPInputs", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_vrrp_target$"):
        mixed.prepare_mixed_vrrp_inputs(envelope, LIMITS)
