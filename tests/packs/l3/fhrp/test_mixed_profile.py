"""One fixed mixed metadata profile; compiled data is not execution or source admission."""
import json
from copy import deepcopy
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_peer_execution import forbidden

from atlas_brain.model.pack_registration import CompiledPackSet, compile_packs
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.packs.l3.fhrp import mixed_profile as mixed
from atlas_brain.packs.l3.fhrp import peer_profile as peer
from atlas_brain.packs.l3.fhrp import version_profile as version
from atlas_brain.packs.l3.fhrp import vrrp_profile as vrrp
from atlas_brain.runner import pack_runtime

FACTS = {"l2.stp.reported_role", "l2.stp.root_guard", "l2.etherchannel.reported_member_tokens",
    "l2.etherchannel.reported_protocol", "l3.fhrp.reported_state", "l3.fhrp.reported_protocol_version", "l3.fhrp.reported_vrrp_state"}
OPERATIONS = {"iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary",
    "iosxe.show_standby_brief", "iosxe.show_standby_all", "iosxe.show_vrrp"}


def alias(value):
    return StrEnum("Alias", {"VALUE": value}).VALUE


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    for module, name in ((stp.stp, "parse_capture"), (ec.parse_summary, "parse_capture"), (hsrp.hsrp, "parse_capture"),
            (version.parser, "parse_capture"), (vrrp.parser, "parse_capture"), (pack_runtime, "execute_parsers"),
            (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


def old_profiles():
    return (peer.compile_peer_state_version_profile(), vrrp.compile_vrrp_profile(), version.compile_version_profile(),
        version.compile_state_version_profile(), compile_packs((hsrp.DECLARATION,)), compile_packs((hsrp.VIP_DECLARATION,)),
        compile_packs((stp.ROOT_DECLARATION, ec.DECLARATION, hsrp.DECLARATION)))


def test_exact_seven_fact_five_operation_three_pack_contract_is_metadata_only_and_preserves_old_profiles():
    before = old_profiles()
    first, second = mixed.compile_mixed_profile(), mixed.compile_mixed_profile()
    assert type(first) is CompiledPackSet and first == second and first is not second
    assert mixed.DECLARATIONS == (stp.DECLARATION, ec.DECLARATION, mixed.FHRP_DECLARATION)
    assert tuple(item.pack for item in mixed.DECLARATIONS) == ("l2.stp", "l2.etherchannel", "l3.fhrp")
    catalogue = json.loads(first.catalogue_bytes)
    registration = json.loads(first.registration_bytes)
    assert catalogue["schema"] == 1 and registration["schema"] == "atlas-brain.pack-registration/1"
    assert {row["fact"] for row in catalogue["facts"]} == FACTS and len(catalogue["facts"]) == 7
    assert len(catalogue["entity_kinds"]) == 3 and sum(row["entity_kind"] == "fhrp_local" for row in catalogue["entity_kinds"]) == 1
    assert not catalogue["relations"] and len(first.steps) == len(first.operations) == 5
    assert {row.operation for row in first.operations} == OPERATIONS
    assert all(step.kind == "parse_build" and step.scope == "device" and not step.reads for step in first.steps)
    assert set().union(*(set(step.produces) for step in first.steps)) == FACTS
    assert registration["packs"] == ["l2.etherchannel", "l2.stp", "l3.fhrp"]
    assert registration["catalogue_sha256"] == sha256(first.catalogue_bytes).hexdigest()
    assert first.registration_sha256 == sha256(first.registration_bytes).hexdigest()
    assert old_profiles() == before and first.registration_sha256 not in {item.registration_sha256 for item in before}
    fhrp = mixed.FHRP_DECLARATION
    assert len(fhrp.facts) == len(fhrp.steps) == len(fhrp.operations) == 3 and len(fhrp.entity_kinds) == 1
    assert all(fact.pack == "l3.fhrp" and fact.subject == "fhrp_local" and fact.value_type == "text" for fact in fhrp.facts)
    assert first == compile_packs(mixed.DECLARATIONS)
    for extra in (vrrp.DECLARATION, version.STATE_VERSION_DECLARATION):
        with pytest.raises(ValueError, match="^duplicate_pack$"):
            compile_packs(mixed.DECLARATIONS + (extra,))


@pytest.mark.parametrize("argument", ["positional", "profile", "declarations", "include_vrrp", "mode", "callback"])
def test_named_compiler_accepts_no_caller_profile_selection_or_callback(monkeypatch, argument):
    mixed.compile_mixed_profile()
    monkeypatch.setattr(mixed, "compile_packs", forbidden)
    monkeypatch.setattr(peer, "compile_peer_state_version_profile", forbidden)
    monkeypatch.setattr(vrrp, "compile_vrrp_profile", forbidden)
    with pytest.raises(TypeError):
        mixed.compile_mixed_profile(mixed.DECLARATIONS) if argument == "positional" else mixed.compile_mixed_profile(**{argument: mixed.DECLARATIONS})


@pytest.mark.parametrize("pack", ["stp", "ec", "hsrp", "version", "state_version", "vrrp", "combined"])
@pytest.mark.parametrize("field", ["pack", "kinds_type", "kind_id", "kind_root", "fact_id", "fact_subject",
    "step_id", "step_reads", "step_produces", "binding_operation", "binding_step"])
def test_every_live_nested_declaration_is_finite_plain_and_closed_before_any_compiler(monkeypatch, pack, field):
    mixed.compile_mixed_profile()
    module, name = {"stp": (stp, "DECLARATION"), "ec": (ec, "DECLARATION"), "hsrp": (hsrp, "DECLARATION"),
        "version": (version, "DECLARATION"), "state_version": (version, "STATE_VERSION_DECLARATION"),
        "vrrp": (vrrp, "DECLARATION"), "combined": (mixed, "FHRP_DECLARATION")}[pack]
    declaration = deepcopy(getattr(module, name))
    if field == "pack":
        object.__setattr__(declaration, "pack", alias(declaration.pack))
    elif field == "kinds_type":
        object.__setattr__(declaration, "entity_kinds", list(declaration.entity_kinds))
    else:
        obj, attribute = {"kind_id": (declaration.entity_kinds[0], "id"), "kind_root": (declaration.entity_kinds[0], "root"),
            "fact_id": (declaration.facts[0], "id"), "fact_subject": (declaration.facts[0], "subject"),
            "step_id": (declaration.steps[0], "id"), "step_reads": (declaration.steps[0], "reads"),
            "step_produces": (declaration.steps[0], "produces"),
            "binding_operation": (declaration.operations[0], "operation"), "binding_step": (declaration.operations[0], "step")}[field]
        current = getattr(obj, attribute)
        value = 0 if field == "kind_root" else ([],) if field in ("step_reads", "step_produces") else [] if field in ("fact_subject", "binding_step") else alias(current)
        object.__setattr__(obj, attribute, value)
    monkeypatch.setattr(module, name, declaration)
    monkeypatch.setattr(mixed, "compile_packs", forbidden)
    monkeypatch.setattr(peer, "compile_peer_state_version_profile", forbidden)
    monkeypatch.setattr(vrrp, "compile_vrrp_profile", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_profile$"):
        mixed.compile_mixed_profile()


@pytest.mark.parametrize("module", [stp, ec, hsrp, version, vrrp])
@pytest.mark.parametrize("kind", ["step", "binding"])
def test_current_runtime_step_and_binding_are_checked_independently_of_captured_declarations(monkeypatch, module, kind):
    mixed.compile_mixed_profile()
    name = "STEP" if kind == "step" else "BINDING"
    item = deepcopy(getattr(module, name))
    object.__setattr__(item, "produces" if kind == "step" else "operation", ([],) if kind == "step" else [])
    monkeypatch.setattr(module, name, item)
    monkeypatch.setattr(mixed, "compile_packs", forbidden)
    monkeypatch.setattr(peer, "compile_peer_state_version_profile", forbidden)
    monkeypatch.setattr(vrrp, "compile_vrrp_profile", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_profile$"):
        mixed.compile_mixed_profile()


@pytest.mark.parametrize("selector", ["list", "count", "duplicate", "reordered", "old_peer", "separate_vrrp"])
def test_exact_captured_pack_selector_is_not_a_dynamic_or_double_fhrp_profile(monkeypatch, selector):
    mixed.compile_mixed_profile()
    choices = {"list": list(mixed.DECLARATIONS), "count": mixed.DECLARATIONS[:-1],
        "duplicate": (stp.DECLARATION, ec.DECLARATION, ec.DECLARATION), "reordered": tuple(reversed(mixed.DECLARATIONS)),
        "old_peer": peer.DECLARATIONS, "separate_vrrp": (stp.DECLARATION, ec.DECLARATION, vrrp.DECLARATION)}
    monkeypatch.setattr(mixed, "DECLARATIONS", choices[selector])
    with pytest.raises(ValueError, match="^fhrp_mixed_profile$"):
        mixed.compile_mixed_profile()


@pytest.mark.parametrize("drift", ["evaluator", "operation", "missing_fact"])
def test_well_formed_changed_captured_fhrp_is_compilable_but_cannot_replace_fixed_literal(monkeypatch, drift):
    mixed.compile_mixed_profile()
    original = mixed.FHRP_DECLARATION
    if drift == "evaluator":
        changed = replace(original, steps=(replace(original.steps[0], evaluator="l3.fhrp.other"), *original.steps[1:]))
    elif drift == "operation":
        changed = replace(original, operations=(replace(original.operations[0], operation="iosxe.show_other"), *original.operations[1:]))
    else:
        changed = replace(original, facts=original.facts[:-1], steps=original.steps[:-1], operations=original.operations[:-1])
    compiled = compile_packs((stp.DECLARATION, ec.DECLARATION, changed))
    assert compiled != compile_packs(mixed.DECLARATIONS)
    monkeypatch.setattr(mixed, "FHRP_DECLARATION", changed)
    monkeypatch.setattr(mixed, "DECLARATIONS", (stp.DECLARATION, ec.DECLARATION, changed))
    with pytest.raises(ValueError, match="^fhrp_mixed_profile$"):
        mixed.compile_mixed_profile()


@pytest.mark.parametrize("phase", [1, 2, 3])
def test_actual_runtime_and_literal_compilations_use_real_different_metadata_as_counterexamples(monkeypatch, phase):
    mixed.compile_mixed_profile()
    compiler, calls = mixed.compile_packs, []
    def compiling(declarations):
        calls.append(declarations)
        if len(calls) == phase:
            declaration = declarations[2]
            changed = replace(declaration, steps=(replace(declaration.steps[0], evaluator="l3.fhrp.other"), *declaration.steps[1:]))
            return compiler((*declarations[:2], changed))
        return compiler(declarations)
    monkeypatch.setattr(mixed, "compile_packs", compiling)
    with pytest.raises(ValueError, match="^fhrp_mixed_profile$"):
        mixed.compile_mixed_profile()
    assert len(calls) == 3


@pytest.mark.parametrize("phase", [1, 2, 3])
@pytest.mark.parametrize("field", ["class", "catalogue_bytes", "registration_bytes", "registration_sha256", "steps", "operations", "reordered_steps"])
def test_full_compiled_record_types_and_step_order_are_not_just_equal_digest_labels(monkeypatch, phase, field):
    mixed.compile_mixed_profile()
    compiler, calls = mixed.compile_packs, []
    def compiling(declarations):
        result = compiler(declarations)
        calls.append(result)
        if len(calls) != phase:
            return result
        if field == "class":
            return object()
        return replace(result, **{"catalogue_bytes": bytearray(result.catalogue_bytes)} if field == "catalogue_bytes" else
            {"registration_bytes": bytearray(result.registration_bytes)} if field == "registration_bytes" else
            {"registration_sha256": alias(result.registration_sha256)} if field == "registration_sha256" else
            {"steps": tuple(reversed(result.steps))} if field == "reordered_steps" else {field: list(getattr(result, field))})
    monkeypatch.setattr(mixed, "compile_packs", compiling)
    with pytest.raises(ValueError, match="^fhrp_mixed_profile$"):
        mixed.compile_mixed_profile()
    assert len(calls) == 3


@pytest.mark.parametrize("selector", ["stp_pack", "ec_pack", "hsrp_pack", "version_pack", "vrrp_pack",
    "hsrp_fact", "version_fact", "vrrp_fact", "brief_operation", "brief_command"])
@pytest.mark.parametrize("mode", ["alias", "drift"])
def test_current_public_pack_fact_and_hsrp_selector_exports_remain_exact(monkeypatch, selector, mode):
    mixed.compile_mixed_profile()
    module, name = {"stp_pack": (stp, "PACK"), "ec_pack": (ec, "PACK"), "hsrp_pack": (hsrp, "PACK"),
        "version_pack": (version, "PACK"), "vrrp_pack": (vrrp, "PACK"),
        "hsrp_fact": (hsrp, "REPORTED_STATE"), "version_fact": (version, "REPORTED_PROTOCOL_VERSION"),
        "vrrp_fact": (vrrp, "REPORTED_VRRP_STATE"), "brief_operation": (hsrp.hsrp, "OP"), "brief_command": (hsrp.hsrp, "COMMAND")}[selector]
    current = getattr(module, name)
    monkeypatch.setattr(module, name, alias(current) if mode == "alias" else "synthetic.other")
    code = "hsrp_version_profile" if selector.startswith("version_") else "vrrp_profile" if selector.startswith("vrrp_") else "fhrp_mixed_profile"
    with pytest.raises(ValueError, match="^" + code + "$"):
        mixed.compile_mixed_profile()
