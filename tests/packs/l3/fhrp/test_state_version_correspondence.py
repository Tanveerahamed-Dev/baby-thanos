"""Real fixed FHRP admission/correspondence; carriers grant no parser or production authority."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_all import block
from test_parse_hsrp_brief import BODY as BRIEF
from test_reported_state_build import DISCOVERY, GROUPS, REGISTRY
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import version_inputs as vi
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner import pack_runtime

DETAIL = block(interface="Vl20") + block("1", "Vl10", "1") + block("2", "BD3329", "129")


def folder(root, detail=DETAIL, mode="normal", change=None):
    root.mkdir(parents=True, exist_ok=True)
    base = canonical(REGISTRY)
    targets = [
        {"id": "brief-a", "node": "a", "operation": b.hsrp.OP, "params": {"groups": [list(pair) for pair in GROUPS]}},
        {"id": "brief-b", "node": "b", "operation": b.hsrp.OP, "params": {"groups": [["Vl30", "2"]]}},
        {"id": "all-a", "node": "a", "operation": gp.all_hsrp.OP, "params": {"groups": [list(pair) for pair in GROUPS]}},
        {"id": "all-b", "node": "b", "operation": gp.all_hsrp.OP, "params": {"groups": [["Vl30", "2"]]}},
    ]
    files = {"p2.json": base, "discovery.txt": DISCOVERY, "brief.txt": BRIEF, "all.txt": detail}
    captures = [{"target": "brief-a", "path": "brief.txt"}, {"target": "all-a", "path": "all.txt"}]
    if mode == "no_all_target":
        targets = [row for row in targets if row["id"] != "all-a"]
    elif mode == "no_all":
        targets = [row for row in targets if row["operation"] != gp.all_hsrp.OP]
    if mode in ("no_all_target", "no_all_capture", "no_all"):
        captures = [row for row in captures if row["target"] != "all-a"]
        files.pop("all.txt")
    if mode == "no_brief_capture":
        captures = [row for row in captures if row["target"] != "brief-a"]
        files.pop("brief.txt")
    if mode == "no_captures":
        captures = []
        files.pop("brief.txt", None)
        files.pop("all.txt", None)
    if mode == "unselected_b":
        targets = [row for row in targets if row["node"] != "b"]
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "round",
        "base_sha256": sha256(base).hexdigest(), "targets": targets, "captures": captures}
    if change is not None:
        change(side, files)
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files



def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("input preparation executed a parser, owner, dispatcher or Store")
    for module, names in ((b.hsrp, ("parse_capture",)), (gp.all_hsrp, ("parse_capture",)),
        (pack_runtime, ("execute_parsers",)), (FactStore, ("__init__",)),
        (b.StateOwner, ("__init__",)), (FactWriter, ("write",)), (b, ("bind_writer",))):
        for name in names:
            monkeypatch.setattr(module, name, forbidden)


def admitted_inputs(root):
    envelope = gp.p4.admit_folder(root, LIMITS, declarations=(profile.STATE_VERSION_DECLARATION,))
    domains = tuple(b.Target(context=envelope.context, node=target.node,
        groups=tuple(tuple(pair) for pair in json.loads(target.params)["groups"]))
        for target in envelope.targets if target.operation == b.hsrp.OP)
    requests = tuple(vi.prepare_version_request(capture_id=member.id, source=member.target.node.key,
        context=envelope.context, raw=member.raw) for member in envelope.captures if member.target.operation == gp.all_hsrp.OP)
    return envelope, vi.retain_version_inputs(domains, requests)


def test_current_correspondence_preserves_exact_original_registry_witnesses_and_population(tmp_path, monkeypatch):
    files = folder(tmp_path)
    envelope, version = admitted_inputs(tmp_path)
    forbid_execution(monkeypatch)
    result = gp.validate_state_version_correspondence(envelope, LIMITS, version)
    assert len(result) == len(version.targets) == 2 and sum(len(target.groups) for target in version.targets) == 5
    for domain in version.targets:
        brief = next(target for target in envelope.targets if target.node is domain.node and target.operation == b.hsrp.OP)
        detail = next(target for target in envelope.targets if target.node is domain.node and target.operation == gp.all_hsrp.OP)
        refs = domain.node.declaration.evidence + envelope.declaration.evidence + brief.declaration.evidence + detail.declaration.evidence
        assert result[domain.context, domain.node.key] == refs
        assert all(type(ref) is k.RegistryRef and ref.table_digest == sha256(
            files["p2.json"] if ref.table == "synthetic_p2.nodes" else files["p4.json"]).hexdigest() for ref in refs)
    assert gp.validate_state_version_correspondence(replace(envelope), LIMITS, replace(version)) == result


@pytest.mark.parametrize("part", ["cold_index", "expected", "target_groups", "request_context", "capture_copy", "member_equal_raw", "context_ref", "all_params"])
def test_current_correspondence_rejects_derived_census_and_equal_pointer_forgery(tmp_path, part):
    folder(tmp_path)
    envelope, version = admitted_inputs(tmp_path)
    if part == "cold_index":
        version.indexed.pop(next(key for key, target in version.indexed.items() if target.node.id == "b"))
    elif part == "expected":
        version.expected.clear()
    elif part == "target_groups":
        object.__setattr__(version.targets[-1], "groups", (("Vl30", "3"),))
    elif part in ("request_context", "capture_copy"):
        request = version.requests[0]
        object.__setattr__(request, "context" if part == "request_context" else "capture", "other" if part == "request_context" else replace(request.capture))
    elif part == "member_equal_raw":
        member = next(member for member in envelope.captures if member.target.operation == gp.all_hsrp.OP)
        object.__setattr__(member, "raw", bytes(bytearray(member.raw)))
    elif part == "context_ref":
        ref, = envelope.declaration.evidence
        object.__setattr__(envelope.declaration, "evidence", (replace(ref, citation="/wrong"),))
    else:
        target = next(target for target in envelope.targets if target.operation == gp.all_hsrp.OP)
        object.__setattr__(target, "params", b"{}")
    with pytest.raises(ValueError):
        gp.validate_state_version_correspondence(envelope, LIMITS, version)


@pytest.mark.parametrize("plant", ["root_alias", "evaluator", "coherent_owner", "operation", "extra_fact"])
def test_fixed_compound_profile_closes_canonical_metadata_not_only_equal_dataclasses(monkeypatch, plant):
    declaration = profile.STATE_VERSION_DECLARATION
    expected = profile.compile_state_version_profile()
    assert expected == compile_packs((declaration,)) and expected == profile.compile_state_version_profile()
    state, version = declaration.steps
    if plant == "root_alias":
        entity, = declaration.entity_kinds
        entity = replace(entity)
        object.__setattr__(entity, "root", 0)
        changed = replace(declaration, entity_kinds=(entity,))
    elif plant == "evaluator":
        changed = replace(declaration, steps=(replace(state, evaluator="l3.fhrp.other"), version))
    elif plant == "coherent_owner":
        new_state = replace(state, id="l3.fhrp/other")
        changed = replace(declaration, steps=(new_state, version),
            facts=(replace(declaration.facts[0], step=new_state.id), declaration.facts[1]),
            operations=(replace(declaration.operations[0], step=new_state.id), declaration.operations[1]))
    elif plant == "operation":
        changed = replace(declaration, operations=(replace(declaration.operations[0], operation="iosxe.show_clock"), declaration.operations[1]))
    else:
        changed = replace(declaration, facts=declaration.facts + b.VIP_DECLARATION.facts[-1:])
    monkeypatch.setattr(profile, "STATE_VERSION_DECLARATION", changed)
    with pytest.raises(ValueError):
        profile.compile_state_version_profile()


@pytest.mark.parametrize("field", ["envelope_raw", "node_ports", "node_declaration", "member_raw", "targets", "discovery_span"])
def test_direct_current_envelope_graph_refuses_before_detached_comparison(tmp_path, monkeypatch, field):
    folder(tmp_path)
    envelope, version = admitted_inputs(tmp_path)
    if field == "envelope_raw":
        object.__setattr__(envelope, "raw", [])
    elif field == "node_ports":
        object.__setattr__(envelope.base.nodes[0], "ports", [])
    elif field == "node_declaration":
        object.__setattr__(envelope.base.nodes[0].declaration, "value", [])
    elif field == "member_raw":
        object.__setattr__(envelope.captures[0], "raw", bytearray(envelope.captures[0].raw))
    elif field == "targets":
        object.__setattr__(envelope, "targets", list(envelope.targets))
    else:
        object.__setattr__(envelope.base.captures[0].lines[0].span, "start", [])
    monkeypatch.setattr(vi, "asdict", lambda *args: pytest.fail("invalid envelope reached detached comparison"))
    monkeypatch.setattr(vi.custody, "asdict", lambda *args: pytest.fail("invalid envelope reached detached comparison"))
    with pytest.raises(ValueError):
        gp.validate_state_version_correspondence(envelope, LIMITS, version)


def test_direct_budget_boolean_alias_refuses_before_detached_comparison(tmp_path, monkeypatch):
    folder(tmp_path)
    envelope, version = admitted_inputs(tmp_path)
    budgets = replace(LIMITS)
    object.__setattr__(budgets, "bundle_bytes", False)
    monkeypatch.setattr(vi, "asdict", lambda *args: pytest.fail("invalid budget reached detached comparison"))
    with pytest.raises(ValueError):
        gp.validate_state_version_correspondence(envelope, budgets, version)


def test_coherent_wrong_step_and_all_target_owners_cannot_replace_the_closed_profile(tmp_path, monkeypatch):
    folder(tmp_path)
    envelope, version = admitted_inputs(tmp_path)
    wrong = replace(profile.STEP, id="l3.fhrp/wrong_version_owner")
    monkeypatch.setattr(profile, "STEP", wrong)
    for target in envelope.targets:
        if target.operation == gp.all_hsrp.OP:
            object.__setattr__(target, "owner", wrong.id)
    with pytest.raises(ValueError):
        gp.validate_state_version_correspondence(envelope, LIMITS, version)


def test_coherent_wrong_live_state_step_and_brief_owners_cannot_replace_the_closed_profile(tmp_path, monkeypatch):
    folder(tmp_path)
    envelope, version = admitted_inputs(tmp_path)
    wrong = replace(b.STEP, id="l3.fhrp/wrong_state_owner")
    monkeypatch.setattr(b, "STEP", wrong)
    for target in envelope.targets:
        if target.operation == b.hsrp.OP:
            object.__setattr__(target, "owner", wrong.id)
    with pytest.raises(ValueError):
        gp.validate_state_version_correspondence(envelope, LIMITS, version)


@pytest.mark.parametrize("part", ["binding", "declaration_evaluator", "declaration_root_alias"])
def test_live_state_binding_and_declaration_are_closed_even_when_captured_profile_is_unchanged(monkeypatch, part):
    if part == "binding":
        monkeypatch.setattr(b, "BINDING", replace(b.BINDING, operation="iosxe.show_clock"))
    elif part == "declaration_evaluator":
        step, = b.DECLARATION.steps
        monkeypatch.setattr(b, "DECLARATION", replace(b.DECLARATION, steps=(replace(step, evaluator="l3.fhrp.other"),)))
    else:
        entity, = b.DECLARATION.entity_kinds
        entity = replace(entity)
        object.__setattr__(entity, "root", 0)
        monkeypatch.setattr(b, "DECLARATION", replace(b.DECLARATION, entity_kinds=(entity,)))
    with pytest.raises(ValueError):
        profile.compile_state_version_profile()
