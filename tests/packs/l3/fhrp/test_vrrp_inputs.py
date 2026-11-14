"""VRRP metadata and retained comparison inputs; no admission, producer or field qualification."""
import json
from copy import deepcopy
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_vrrp import capture
from test_peer_execution import forbidden
from test_reported_state_build import A, B

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.packs.l3.fhrp import version_profile as old
from atlas_brain.packs.l3.fhrp import vrrp_inputs as inputs
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    for module, name in ((profile.parser, "parse_capture"), (pack_runtime, "execute_parsers"),
            (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


def fixture():
    first = inputs.VRRPTarget(context="round", node=deepcopy(A), groups=(("Vlan61", "100"), ("Vl61", "101")))
    cold = replace(first, node=deepcopy(B))
    sample = replace(capture(), source=first.node.key)
    metadata = sample.resolved_metadata
    need = k.EvidenceNeed(node=first.node.key, operation=profile.BINDING.operation, params=(),
        resolves=(profile.REPORTED_VRRP_STATE,), reruns=(profile.STEP.id,), after_s=2 ** 80, unprintable=())
    sample = replace(sample, metadata=replace(metadata, collected_utc=replace(metadata.collected_utc, next_evidence=(need,))))
    request = CaptureRequest(context=first.context, capture=sample)
    retained = inputs.retain_vrrp_inputs((first, cold), (request,))
    assert inputs.validate_vrrp_inputs(retained) is None
    return first, cold, request, retained


def test_fixed_profile_bytes_old_profiles_and_distinct_vrrp_subjects_are_metadata_only():
    prior = tuple(getattr(old.compile_version_profile(), field) for field in ("catalogue_bytes", "registration_bytes", "registration_sha256"))
    compiled = profile.compile_vrrp_profile()
    assert compiled == compile_packs((profile.DECLARATION,)) and compiled is not profile.compile_vrrp_profile()
    assert compiled.steps == (profile.STEP,) and compiled.operations == (profile.BINDING,)
    assert (profile.PACK, profile.REPORTED_VRRP_STATE, profile.STEP.id, profile.BINDING.operation) == (
        "l3.fhrp", "l3.fhrp.reported_vrrp_state", "l3.fhrp/parse_vrrp", "iosxe.show_vrrp")
    assert (profile.DECLARATION.entity_kinds[0].id, profile.DECLARATION.facts[0].subject) == ("fhrp_local", "fhrp_local")
    assert compiled.registration_sha256 == sha256(compiled.registration_bytes).hexdigest()
    assert prior == tuple(getattr(old.compile_version_profile(), field) for field in ("catalogue_bytes", "registration_bytes", "registration_sha256"))
    first, _, _, _ = fixture()
    legacy = hsrp.Target(context=first.context, node=first.node, groups=first.groups)
    subject = inputs.subject(first, "Vlan61", "100")
    assert subject == "fhrp_local:" + sha256(canonical(("atlas-brain.vrrp-local/1", "round", first.node.key, "Vlan61", "ipv4", "vrrp", "100"))).hexdigest()
    assert subject != hsrp.subject(legacy, "Vlan61", "100") and subject != inputs.subject(first, "Vl61", "101")
    with pytest.raises(ValueError, match="^duplicate_pack$"):
        compile_packs((profile.DECLARATION, hsrp.DECLARATION))


@pytest.mark.parametrize("empty", [False, True])
def test_original_denominator_immutable_snapshots_and_valid_copy_semantics(empty):
    first, cold, request, original = fixture()
    held = inputs.retain_vrrp_inputs((first, cold), () if empty else (request,))
    assert held.targets == (first, cold) and held.requests == (() if empty else (request,))
    assert all(row[0] is target and row[1] is target.node and row[2] is target.node.declaration and type(row[3]) is bytes
        for row, target in zip(held.retained_targets, held.targets, strict=True))
    assert inputs.validate_vrrp_inputs(replace(held, targets=tuple(item for item in held.targets))) is None
    assert inputs.validate_vrrp_inputs(deepcopy(held)) is None
    assert original.retained_requests[0][0] is request and original.retained_requests[0][1] is request.capture
    snapshot = original.retained_requests[0][2]
    raw = dict(dict(json.loads(snapshot))["capture"])
    assert raw["raw"] == ["bytes_sha256", sha256(request.capture.raw).hexdigest()]
    assert dict(dict(raw["lines"][0])["span"])["start"] == ["integer", "0"]
    assert b'"integer","1208925819614629174706176"' in snapshot
    with pytest.raises(AttributeError):
        held.registration_sha256 = "other"


@pytest.mark.parametrize("field", ["PACK", "REPORTED_VRRP_STATE", "STEP", "BINDING", "DECLARATION", "OP", "COMMAND", "SYNTHETIC_GROUPS", "root", "nested_alias", "coherent"])
def test_live_captured_and_equal_alias_metadata_never_replace_literal_profile(monkeypatch, field):
    profile.compile_vrrp_profile()
    if field in ("OP", "COMMAND", "SYNTHETIC_GROUPS"):
        current = getattr(profile.parser, field)
        value = ("101",) if field == "SYNTHETIC_GROUPS" else StrEnum("Alias", {"VALUE": current}).VALUE
        monkeypatch.setattr(profile.parser, field, value)
    elif field in ("PACK", "REPORTED_VRRP_STATE"):
        monkeypatch.setattr(profile, field, StrEnum("Alias", {"VALUE": getattr(profile, field)}).VALUE)
    elif field in ("STEP", "BINDING"):
        monkeypatch.setattr(profile, field, replace(getattr(profile, field), **({"evaluator": "l3.fhrp.other"} if field == "STEP" else {"operation": "iosxe.show_other"})))
    else:
        declaration = profile.DECLARATION
        if field in ("root", "nested_alias"):
            kind = replace(declaration.entity_kinds[0])
            object.__setattr__(kind, "root" if field == "root" else "id", 0 if field == "root" else StrEnum("Alias", {"VALUE": kind.id}).VALUE)
            declaration = replace(declaration, entity_kinds=(kind,))
        elif field == "coherent":
            step = replace(profile.STEP, evaluator="l3.fhrp.other")
            monkeypatch.setattr(profile, "STEP", step)
            declaration = replace(declaration, steps=(step,))
        else:
            declaration = old.DECLARATION
        monkeypatch.setattr(profile, "DECLARATION", declaration)
    with pytest.raises(TypeError if field == "nested_alias" else ValueError, match="^non_json_type$" if field == "nested_alias" else "^vrrp_profile$"):
        profile.compile_vrrp_profile()


@pytest.mark.parametrize("phase", [1, 2, 3])
@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_each_compiler_identity_closes_against_the_other_two(monkeypatch, phase, field):
    profile.compile_vrrp_profile()
    compiler, calls = profile.compile_packs, []
    def compiling(declarations):
        result = compiler(declarations)
        calls.append(result)
        return replace(result, **{field: "0" * 64 if field.endswith("sha256") else b"changed"}) if len(calls) == phase else result
    monkeypatch.setattr(profile, "compile_packs", compiling)
    with pytest.raises(ValueError, match="^vrrp_profile$"):
        profile.compile_vrrp_profile()
    assert len(calls) == 3


@pytest.mark.parametrize("plant", ["target_duplicate", "request_duplicate", "capture_duplicate", "foreign", "context", "command", "operation", "scope"])
def test_population_and_exact_request_command_flat_scope_refuse_after_good_baseline(plant):
    first, cold, request, _ = fixture()
    targets, requests = (first, cold), (request,)
    if plant == "target_duplicate":
        targets += (replace(first),)
    elif plant in ("request_duplicate", "capture_duplicate"):
        requests += (request if plant == "request_duplicate" else replace(request, capture=replace(request.capture, source=cold.node.key, metadata=None)),)
    elif plant in ("foreign", "context"):
        if plant == "context":
            request = replace(request, context="other")
        else:
            sample = request.capture
            request = replace(request, capture=replace(sample, source="node:foreign:a",
                metadata=replace(sample.metadata, scope=replace(sample.scope, node="node:foreign:a"))))
        requests = (request,)
    else:
        sample = request.capture
        changed = replace(sample, **({"rendered": "show standby brief"} if plant == "command" else {"operation": hsrp.hsrp.OP}
            if plant == "operation" else {"metadata": replace(sample.metadata, scope=replace(sample.scope, vrf="other"))}))
        requests = (replace(request, capture=changed),)
    with pytest.raises(ValueError, match="^vrrp_inputs_" + ("request" if plant in ("command", "operation", "scope") else "population") + "$"):
        inputs.retain_vrrp_inputs(targets, requests)


@pytest.mark.parametrize("field", ["context", "node_id", "ports", "declaration", "registry", "groups", "group", "raw", "offsets", "scope", "candidates", "need"])
def test_finite_graph_refusal_precedes_snapshot_traversal_and_identifier_hashes(monkeypatch, field):
    first, cold, request, _ = fixture()
    obj, name = {"context": (first, "context"), "node_id": (first.node, "id"), "ports": (first.node, "ports"),
        "declaration": (first.node.declaration, "value"), "registry": (first.node.declaration.evidence[0], "table_digest"),
        "groups": (first, "groups"), "group": (first, "groups"), "raw": (request.capture, "raw"),
        "offsets": (request.capture.lines[0], "offsets"), "scope": (request.capture.metadata.scope, "vrf"),
        "candidates": (request.capture.metadata.collected_utc, "candidates"),
        "need": (request.capture.metadata.collected_utc.next_evidence[0], "resolves")}[field]
    object.__setattr__(obj, name, (("Vlan61", []),) if field == "group" else ([],) if field in ("offsets", "candidates", "need") else [])
    monkeypatch.setattr(inputs, "asdict", forbidden)
    with pytest.raises(ValueError):
        inputs.retain_vrrp_inputs((first, cold), (request,))


@pytest.mark.parametrize("plant", ["target_copy", "node_copy", "declaration_copy", "request_copy", "capture_copy", "ports", "digest",
    "raw", "metadata_copy", "target_snapshot", "request_snapshot", "targets", "requests", "registration"])
def test_postretention_pointer_value_snapshot_and_census_changes_are_detected(plant):
    first, cold, request, held = fixture()
    code = "request" if plant in ("request_copy", "capture_copy", "raw", "request_snapshot") else "input" if plant == "registration" else "target"
    if plant == "target_copy":
        held = replace(held, targets=(replace(first), cold))
    elif plant in ("node_copy", "declaration_copy", "ports", "digest"):
        obj, name, value = (first, "node", replace(first.node)) if plant == "node_copy" else (
            (first.node, "declaration", replace(first.node.declaration)) if plant == "declaration_copy" else
            (first.node, "ports", first.node.ports + ("Gi1/0/2",)) if plant == "ports" else
            (first.node.declaration.evidence[0], "table_digest", "1" * 64))
        object.__setattr__(obj, name, value)
    elif plant == "request_copy":
        held = replace(held, requests=(replace(request),))
    elif plant == "capture_copy":
        object.__setattr__(request, "capture", replace(request.capture))
    elif plant == "raw":
        changed = replace(request.capture, raw=(raw := request.capture.raw + b"\n"), lines=text_lines(raw, "utf-8"), metadata=None)
        for name in ("raw", "lines", "metadata"):
            object.__setattr__(request.capture, name, getattr(changed, name))
    elif plant == "metadata_copy":
        object.__setattr__(request.capture, "metadata", replace(request.capture.metadata))
        assert inputs.validate_vrrp_inputs(held) is None
        return
    else:
        name = "retained_targets" if plant in ("target_snapshot", "targets") else "retained_requests" if plant in ("request_snapshot", "requests") else "registration_sha256"
        value = "0" * 64 if plant == "registration" else () if plant in ("targets", "requests") else (
            (*held.retained_targets[0][:3], b"changed"), *held.retained_targets[1:]) if plant == "target_snapshot" else ((request, request.capture, b"changed"),)
        held = replace(held, **{name: value})
        code = "input" if plant in ("targets", "requests", "registration") else code
    with pytest.raises(ValueError, match="^vrrp_inputs_" + code + "$"):
        inputs.validate_vrrp_inputs(held)
