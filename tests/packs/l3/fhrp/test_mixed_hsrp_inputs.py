"""Current mixed HSRP input correspondence; no execution, admission, origin or VRRP population claim."""
import json
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_context import admitted, freeze
from test_parse_vrrp import BODY as VRRP
from test_peer_execution import forbidden
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import mixed_profile, peer_profile
from atlas_brain.packs.l3.fhrp import version_inputs as vi


def frozen(monkeypatch):
    freeze(monkeypatch)
    monkeypatch.setattr(gp.p4_pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(gp.build.StateOwner, "__init__", forbidden)


def check(envelope, result):
    assert result.envelope is envelope and result.budgets is LIMITS
    assert result.compiled == mixed_profile.compile_mixed_profile()
    assert result.version.targets is result.domains
    assert result.targets == tuple(target for operation in (gp.hsrp.OP, gp.all_hsrp.OP)
        for target in envelope.targets if target.operation == operation)
    assert len(result.domains) == sum(target.operation == gp.hsrp.OP for target in envelope.targets)
    for domain in result.domains:
        brief = next(target for target in result.targets if target.node is domain.node and target.operation == gp.hsrp.OP)
        assert domain.context == envelope.context and domain.groups == tuple(sorted(map(tuple, json.loads(brief.params)["groups"])))
        refs = domain.node.declaration.evidence + envelope.declaration.evidence + brief.declaration.evidence
        detail = next((target for target in result.targets if target.node is domain.node and target.operation == gp.all_hsrp.OP), None)
        if detail is not None:
            refs += detail.declaration.evidence
        actual = result.declarations[domain.context, domain.node.key]
        assert len(refs) == len(actual) and all(a is b for a, b in zip(actual, refs, strict=True))
    assert set(result.declarations) == {(target.context, target.node.key) for target in result.domains}
    for request in result.requests + result.version.requests:
        member = next(member for member in envelope.captures if member.id == request.capture.id)
        assert request.capture.raw is member.raw and request.capture.bytes_sha256 == member.sha256
        assert request.capture.source == member.target.node.key and request.context == envelope.context
        assert request.capture.operation == member.target.operation
        assert request.capture.rendered == (gp.hsrp.COMMAND if member.target.operation == gp.hsrp.OP else gp.all_hsrp.COMMAND)
    assert gp.validate_mixed_hsrp_correspondence(envelope, LIMITS, result.version) == result.declarations


@pytest.fixture
def case(tmp_path, monkeypatch):
    frozen(monkeypatch)
    envelope, files = admitted(tmp_path)
    result = gp.prepare_mixed_hsrp_inputs(envelope, LIMITS)
    check(envelope, result)
    return envelope, result, files


def customized(root, mode="normal", plant=None):
    def changing(side, files):
        side["targets"].append({"id": "vrrp", "node": "a", "operation": "iosxe.show_vrrp",
            "params": {"groups": [["Vlan61", "100"]]}})
        files["vrrp.txt"] = VRRP
        side["captures"].append({"target": "vrrp", "path": "vrrp.txt"})
        if plant == "orphan":
            side["targets"] = [row for row in side["targets"] if row["id"] != "brief-a"]
            side["captures"] = [row for row in side["captures"] if row["target"] != "brief-a"]
            files.pop("brief.txt")
        elif plant == "groups":
            next(row for row in side["targets"] if row["id"] == "all-a")["params"]["groups"][0][0] = "Vlan20"
        elif plant == "duplicate_all":
            side["targets"].append({"id": "extra-all", "node": "a", "operation": gp.all_hsrp.OP,
                "params": {"groups": [["Vl20", "9"]]}})
        elif plant == "duplicate_capture":
            files["second-all.txt"] = files["all.txt"]
            side["captures"].append({"target": "all-a", "path": "second-all.txt"})
        if plant in ("orphan", "groups", "duplicate_all") and "all.txt" in files:
            files["all.txt"] = b"show clock\n"
    files = folder(root, mode=mode, change=changing)
    for name in ("brief.txt", "all.txt"):
        if name not in files:
            (root / name).unlink(missing_ok=True)
    envelope = gp.p4.admit_folder(root, LIMITS, declarations=mixed_profile.DECLARATIONS)
    assert gp.validate_mixed_context(envelope, LIMITS) == mixed_profile.compile_mixed_profile()
    return envelope, files


@pytest.mark.parametrize("mode", ["normal", "only_vrrp", "none", "cold_vrrp", "multi_tree", "opaque_params"])
def test_actual_fixed_mixed_context_prepares_only_hsrp_and_keeps_all_original_objects(tmp_path, monkeypatch, mode):
    frozen(monkeypatch)
    envelope, files = admitted(tmp_path, mode)
    monkeypatch.setattr(gp.p4, "admit_folder", forbidden)
    result = gp.prepare_mixed_hsrp_inputs(envelope, LIMITS)
    check(envelope, result)
    assert all(request.capture.operation in (gp.hsrp.OP, gp.all_hsrp.OP) for request in result.requests + result.version.requests)
    if mode == "only_vrrp":
        assert result.targets == result.domains == result.requests == result.version.requests == ()
        assert result.declarations == result.version.indexed == result.version.expected == {}
    if mode == "none":
        assert result.domains and not result.requests and not result.version.requests
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files
    with pytest.raises(ValueError, match="^fhrp_peer_registration$"):
        gp.prepare_peer_state_version_inputs(envelope, LIMITS)


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "no_captures", "unselected_b"])
def test_missing_captures_or_all_declarations_never_reduce_the_independent_brief_denominator(case, tmp_path, mode):
    envelope, files = customized(tmp_path / "missing", mode)
    result = gp.prepare_mixed_hsrp_inputs(envelope, LIMITS)
    check(envelope, result)
    assert len(result.domains) == (1 if mode == "unselected_b" else 2)
    assert sum(len(domain.groups) for domain in result.domains) == (4 if mode == "unselected_b" else 5)
    assert len(result.version.requests) == (0 if mode.startswith("no_all") or mode == "no_captures" else 1)
    assert len(result.requests) == (0 if mode in ("no_brief_capture", "no_captures") else 1)
    assert all(len(refs) == (3 if mode == "no_all" or mode == "no_all_target" and key[1].endswith(":a") else 4)
        for key, refs in result.declarations.items())
    assert {path.name: path.read_bytes() for path in (tmp_path / "missing").iterdir()} == files


def test_permutations_and_coherent_lower_data_copies_are_not_origin_tokens(case):
    envelope, result, _ = case
    permuted = replace(envelope, targets=tuple(reversed(envelope.targets)), captures=tuple(reversed(envelope.captures)))
    check(permuted, gp.prepare_mixed_hsrp_inputs(permuted, LIMITS))
    requests = tuple(replace(request, capture=replace(request.capture)) for request in reversed(result.version.requests))
    copied = vi.retain_version_inputs(tuple(replace(domain) for domain in reversed(result.domains)), requests)
    assert gp.validate_mixed_hsrp_correspondence(replace(envelope), LIMITS, copied) == result.declarations
    assert gp.validate_mixed_hsrp_correspondence(envelope, LIMITS,
        replace(result.version, indexed=dict(result.version.indexed), expected=dict(result.version.expected))) == result.declarations


def test_old_four_operation_envelope_remains_valid_only_for_its_original_peer_gate(case, tmp_path):
    folder(tmp_path / "old")
    envelope = gp.p4.admit_folder(tmp_path / "old", LIMITS, declarations=peer_profile.DECLARATIONS)
    assert len(gp.prepare_peer_state_version_inputs(envelope, LIMITS).compiled.operations) == 4
    for call in (gp.prepare_mixed_hsrp_inputs, lambda env, budgets: gp.validate_mixed_hsrp_correspondence(env, budgets, case[1].version)):
        with pytest.raises(ValueError, match="^fhrp_mixed_context_registration$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("plant", ["orphan", "groups", "duplicate_all"])
def test_all_selector_faults_refuse_before_bad_all_framing_or_preparation(case, tmp_path, monkeypatch, plant):
    envelope, _ = customized(tmp_path / "selector", plant=plant)
    monkeypatch.setattr(gp, "prepare_version_request", forbidden)
    monkeypatch.setattr(gp, "StateVersionInputs", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_hsrp_target$"):
        gp.prepare_mixed_hsrp_inputs(envelope, LIMITS)


def test_two_actual_all_captures_for_one_original_node_refuse_without_last_wins(case, tmp_path):
    envelope, _ = customized(tmp_path / "duplicate", plant="duplicate_capture")
    with pytest.raises(ValueError, match="^hsrp_version_inputs_population$"):
        gp.prepare_mixed_hsrp_inputs(envelope, LIMITS)


@pytest.mark.parametrize("plant", ["input", "indexed_container", "indexed_key", "indexed_shape", "expected_key",
    "cold_index", "expected_drop", "target_drop", "node_copy", "groups", "domain_context", "request_drop",
    "capture_id", "source", "raw_copy", "request_context"])
def test_coherent_and_malformed_lower_inputs_cannot_replace_current_owned_population(case, plant):
    envelope, result, _ = case
    version = result.version
    code = "fhrp_mixed_hsrp_input"
    if plant == "input":
        version = []
    elif plant in ("indexed_container", "indexed_key", "indexed_shape", "expected_key"):
        if plant == "indexed_container":
            class MappingAlias(dict):
                pass
            version = replace(version, indexed=MappingAlias(version.indexed))
        elif plant == "expected_key":
            request = version.requests[0]
            version = replace(version, expected={StrEnum("Alias", {"VALUE": request.capture.id}).VALUE: request})
        else:
            key, value = next(iter(version.indexed.items()))
            key = (StrEnum("Alias", {"VALUE": key[0]}).VALUE, key[1]) if plant == "indexed_key" else (key[0],)
            version = replace(version, indexed={key: value})
    elif plant in ("cold_index", "expected_drop"):
        version = replace(version, indexed={} if plant == "cold_index" else dict(version.indexed),
            expected={} if plant == "expected_drop" else dict(version.expected))
        code = "hsrp_version_inputs_population"
    elif plant in ("target_drop", "node_copy", "groups", "domain_context"):
        domains = version.targets[:-1] if plant == "target_drop" else tuple(replace(domain, **(
            {"node": replace(domain.node)} if plant == "node_copy" else {"groups": (("Vl99", "9"),)}
            if plant == "groups" else {"context": "other"})) for domain in version.targets)
        requests = () if plant in ("target_drop", "domain_context") else version.requests
        version = vi.retain_version_inputs(domains, requests)
        code = "fhrp_mixed_hsrp_population"
    else:
        requests = ()
        if plant != "request_drop":
            original = version.requests[0]
            if plant == "request_context":
                request = replace(original, context="other")
                version = replace(version, requests=(request,), expected={request.capture.id: request},
                    retained_requests=vi.custody.retain_requests((request,)))
            else:
                sample = original.capture
                changes = {"id": "cap:foreign"} if plant == "capture_id" else {"source": result.domains[-1].node.key} if plant == "source" else {"raw": bytes(bytearray(sample.raw))}
                request = replace(original, capture=replace(sample, **changes))
                requests = (request,)
        if plant != "request_context":
            version = vi.retain_version_inputs(version.targets, requests)
        code = "fhrp_mixed_hsrp_capture"
    with pytest.raises(ValueError, match="^" + code + "$"):
        gp.validate_mixed_hsrp_correspondence(envelope, LIMITS, version)


@pytest.mark.parametrize("operation", ["iosxe.show_standby_brief", "iosxe.show_standby_all",
    "iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary", "iosxe.show_vrrp"])
@pytest.mark.parametrize("field", ["owner", "operation_alias"])
def test_every_fixed_mixed_operation_stays_owned_and_plain_before_hsrp_selector_work(case, operation, field):
    envelope, result, _ = case
    target = next(target for target in envelope.targets if target.operation == operation)
    object.__setattr__(target, "owner" if field == "owner" else "operation",
        "l3.fhrp/other" if field == "owner" else StrEnum("Alias", {"VALUE": target.operation}).VALUE)
    code = "fhrp_mixed_context_target" if field == "owner" else "hsrp_state_version_graph"
    for call in (gp.prepare_mixed_hsrp_inputs, lambda env, budgets: gp.validate_mixed_hsrp_correspondence(env, budgets, result.version)):
        with pytest.raises(ValueError, match="^" + code + "$"):
            call(envelope, LIMITS)


@pytest.mark.parametrize("part", ["node", "context", "brief", "all"])
def test_original_registry_declarations_cannot_be_replaced_by_neighbor_donors(case, part):
    envelope, result, _ = case
    target = next(target for target in envelope.targets if target.node.id == "a" and target.operation == (gp.all_hsrp.OP if part == "all" else gp.hsrp.OP))
    state = target.node.declaration if part == "node" else envelope.declaration if part == "context" else target.declaration
    donor = next(domain.node.declaration for domain in result.domains if domain.node.id == "b")
    object.__setattr__(state, "evidence", donor.evidence)
    with pytest.raises(ValueError, match="^hsrp_folder_declaration$"):
        gp.validate_mixed_hsrp_correspondence(envelope, LIMITS, result.version)


@pytest.mark.parametrize("field", ["id", "hash", "raw", "target_copy", "equal_raw"])
def test_all_member_metadata_and_original_raw_identity_are_reclosed(case, field):
    envelope, result, _ = case
    member = next(member for member in envelope.captures if member.target.operation == gp.all_hsrp.OP)
    name, value = {"id": ("id", "cap:foreign"), "hash": ("sha256", "0" * 64),
        "raw": ("raw", member.raw + b"\n"), "target_copy": ("target", replace(member.target)),
        "equal_raw": ("raw", bytes(bytearray(member.raw)))}[field]
    object.__setattr__(member, name, value)
    code = "hsrp_state_version_graph" if field == "target_copy" else "fhrp_mixed_hsrp_capture" if field == "equal_raw" else "hsrp_folder_member"
    with pytest.raises(ValueError, match="^" + code + "$"):
        gp.validate_mixed_hsrp_correspondence(envelope, LIMITS, result.version)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_current_budgets_refuse_before_any_detached_snapshot(case, monkeypatch, field):
    envelope, result, _ = case
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, False)
    monkeypatch.setattr(vi, "asdict", forbidden)
    with pytest.raises(ValueError, match="^hsrp_state_version_budget$"):
        gp.validate_mixed_hsrp_correspondence(envelope, budgets, result.version)
    with pytest.raises(ValueError, match="^hsrp_state_version_budget$"):
        gp.prepare_mixed_hsrp_inputs(envelope, budgets)


@pytest.mark.parametrize("field", ["artifacts", "artifact_bytes", "bundle_bytes"])
def test_all_raw_material_budget_is_still_enforced_through_both_new_entry_points(case, field):
    envelope, result, _ = case
    budgets = replace(LIMITS, **{field: 1})
    for call in (gp.prepare_mixed_hsrp_inputs, lambda env, limits: gp.validate_mixed_hsrp_correspondence(env, limits, result.version)):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
            call(envelope, budgets)
        assert caught.value.member == "fhrp_mixed_context_raw_budget"


@pytest.mark.parametrize("plant", ["id", "source", "context", "raw_copy", "member_copy", "rendered"])
def test_late_original_brief_requests_and_member_data_refuse_before_carrier_publication(case, monkeypatch, plant):
    envelope, baseline, _ = case
    original_validate, original_prepare, seen = gp.validate_brief_request, gp.prepare_version_request, []
    def validating(request):
        original_validate(request)
        seen.append(request)
    def preparing(**kwargs):
        result = original_prepare(**kwargs)
        request = seen[0]
        sample = request.capture
        if plant == "member_copy":
            member = next(member for member in envelope.captures if member.id == sample.id)
            object.__setattr__(member, "raw", bytes(bytearray(member.raw)))
        elif plant == "context":
            object.__setattr__(request, "context", "other")
        else:
            name, value = {"id": ("id", "cap:foreign"), "source": ("source", baseline.domains[-1].node.key),
                "raw_copy": ("raw", bytes(bytearray(sample.raw))), "rendered": ("rendered", "show clock")}[plant]
            object.__setattr__(sample, name, value)
        return result
    monkeypatch.setattr(gp, "validate_brief_request", validating)
    monkeypatch.setattr(gp, "prepare_version_request", preparing)
    monkeypatch.setattr(gp, "StateVersionInputs", forbidden)
    with pytest.raises(ValueError, match="^" + ("hsrp_state_version_request" if plant == "rendered" else "fhrp_mixed_hsrp_capture") + "$"):
        gp.prepare_mixed_hsrp_inputs(envelope, LIMITS)


@pytest.mark.parametrize("entry", ["prepare", "correspondence"])
@pytest.mark.parametrize("phase", ["first", "last"])
@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_initial_and_final_mixed_compiled_identity_drift_never_publishes_partial_results(case, monkeypatch, entry, phase, field):
    envelope, result, _ = case
    original, calls = gp.validate_mixed_context, []
    def validating(env, budgets):
        value = original(env, budgets)
        calls.append(value)
        if len(calls) == (1 if phase == "first" else 4 if entry == "prepare" else 2):
            return replace(value, **{field: "0" * 64 if field == "registration_sha256" else b"changed"})
        return value
    monkeypatch.setattr(gp, "validate_mixed_context", validating)
    monkeypatch.setattr(gp, "StateVersionInputs", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_hsrp_registration$"):
        gp.prepare_mixed_hsrp_inputs(envelope, LIMITS) if entry == "prepare" else gp.validate_mixed_hsrp_correspondence(envelope, LIMITS, result.version)
