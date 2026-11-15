"""Fixed Root9 metadata only; no Root9 execution, admission, census or R11 claim."""
import json
from copy import deepcopy
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_mixed_profile import FACTS, OPERATIONS
from test_peer_execution import forbidden

from atlas_brain.contract.canonical import canonical
from atlas_brain.model.pack_registration import CompiledPackSet, compile_packs
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.packs.l3.fhrp import mixed_profile as mixed
from atlas_brain.packs.l3.fhrp import root_mixed_profile as root
from atlas_brain.runner import pack_runtime

ROOT_FACTS = {"l2.stp.reported_root_priority": "integer", "l2.stp.reported_root_mac": "text"}
STEPS = {"l2.stp/parse_root_guard", "l2.etherchannel/parse_protocol", "l3.fhrp/parse_hsrp_brief",
    "l3.fhrp/parse_hsrp_all_version", "l3.fhrp/parse_vrrp"}


def alias(value):
    return StrEnum("Alias", {"VALUE": value}).VALUE


@pytest.fixture(autouse=True)
def metadata_only(monkeypatch):
    for module, name in ((stp.stp, "parse_capture"), (ec.parse_summary, "parse_capture"),
            (hsrp.hsrp, "parse_capture"), (mixed.version.parser, "parse_capture"), (mixed.vrrp.parser, "parse_capture"),
            (pack_runtime, "execute_parsers"), (stp, "execute_parsers"), (stp.p4_pipeline, "execute_parsers"),
            (stp.p4_admission, "admit_folder"),
            (stp.p4_pipeline, "execute_p4_folder"), (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


def previous():
    return (mixed.compile_mixed_profile(), compile_packs((stp.root_declaration(),)),
        compile_packs((stp.root_declaration(), ec.DECLARATION, hsrp.DECLARATION)))


def test_fixed_nine_fact_profile_is_canonical_deterministic_and_preserves_three_old_profiles():
    before = previous()
    first, second = root.compile_root_mixed_profile(), root.compile_root_mixed_profile()
    assert type(first) is CompiledPackSet and first == second and first is not second
    assert root.FHRP_DECLARATION is mixed.FHRP_DECLARATION
    assert root.DECLARATIONS == (stp.root_declaration(), ec.DECLARATION, mixed.FHRP_DECLARATION)
    assert root.DECLARATIONS[0] is stp.ROOT_DECLARATION and stp.DECLARATION not in root.DECLARATIONS
    assert first == compile_packs(root.DECLARATIONS) and previous() == before
    assert first.registration_sha256 not in {item.registration_sha256 for item in before}
    catalogue, registration = json.loads(first.catalogue_bytes), json.loads(first.registration_bytes)
    assert canonical(catalogue) == first.catalogue_bytes and canonical(registration) == first.registration_bytes
    assert catalogue["schema"] == 1 and registration["schema"] == "atlas-brain.pack-registration/1"
    assert first.registration_sha256 == sha256(first.registration_bytes).hexdigest()
    assert registration["catalogue_sha256"] == sha256(first.catalogue_bytes).hexdigest()
    assert registration["packs"] == ["l2.etherchannel", "l2.stp", "l3.fhrp"]
    assert len(catalogue["facts"]) == 9 and {row["fact"] for row in catalogue["facts"]} == FACTS | ROOT_FACTS.keys()
    assert not catalogue["relations"] and len(catalogue["entity_kinds"]) == 3
    assert {row["entity_kind"] for row in catalogue["entity_kinds"]} == {"stp_port_vlan", "etherchannel_group", "fhrp_local"}
    assert all(row["root"] is False for row in catalogue["entity_kinds"])
    assert {step.id for step in first.steps} == STEPS and len(first.steps) == 5
    assert {binding.operation for binding in first.operations} == OPERATIONS and len(first.operations) == 5
    assert all(step.kind == "parse_build" and step.scope == "device" and step.reads == () for step in first.steps)
    assert set().union(*(set(step.produces) for step in first.steps)) == FACTS | ROOT_FACTS.keys()
    expected = {fact.id: fact for declaration in root.DECLARATIONS for fact in declaration.facts}
    for row in catalogue["facts"]:
        fact = expected[row["fact"]]
        assert row == fact.row() and fact.step in STEPS
        assert fact.pack == fact.step.partition("/")[0]
        assert fact.subject == {"l2.stp": "stp_port_vlan", "l2.etherchannel": "etherchannel_group", "l3.fhrp": "fhrp_local"}[fact.pack]
        assert fact.value_type == (ROOT_FACTS | {"l2.stp.root_guard": "boolean"}).get(fact.id, "text")
        if fact.id in ROOT_FACTS:
            assert fact.value_type == ROOT_FACTS[fact.id] and fact.subject == "stp_port_vlan"
            assert fact.step == "l2.stp/parse_root_guard"
    assert next(step for step in first.steps if step.pack == "l2.stp") is stp.ROOT_STEP
    assert registration["operations"] == [{"operation": item.operation, "step": item.step} for item in first.operations]
    assert tuple(len(json.loads(item.catalogue_bytes)["facts"]) for item in before) == (7, 4, 7)


@pytest.mark.parametrize("argument", ["positional", "profile", "declarations", "roots", "mode", "callback"])
def test_no_caller_profile_flags_or_callback_front_door(monkeypatch, argument):
    root.compile_root_mixed_profile()
    monkeypatch.setattr(mixed, "compile_mixed_profile", forbidden)
    with pytest.raises(TypeError):
        root.compile_root_mixed_profile(root.DECLARATIONS) if argument == "positional" else root.compile_root_mixed_profile(**{argument: root.DECLARATIONS})


@pytest.mark.parametrize("selector", ["list", "count", "duplicate", "reversed", "legacy_stp", "mixed7", "local_root", "old_report"])
def test_captured_composition_is_exact_and_cannot_select_an_old_profile(monkeypatch, selector):
    root.compile_root_mixed_profile()
    original = root.DECLARATIONS
    options = {"list": list(original), "count": original[:-1], "duplicate": (original[0], original[1], original[1]),
        "reversed": tuple(reversed(original)), "legacy_stp": (stp.DECLARATION, *original[1:]),
        "mixed7": mixed.DECLARATIONS, "local_root": (original[0],),
        "old_report": (original[0], original[1], hsrp.DECLARATION)}
    monkeypatch.setattr(root, "DECLARATIONS", options[selector])
    with pytest.raises(ValueError, match="^fhrp_root_mixed_profile$"):
        root.compile_root_mixed_profile()


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("field", ["pack", "kinds", "kind_id", "kind_root", "facts", "fact_id", "fact_subject",
    "fact_type", "steps", "step_id", "step_reads", "step_produces", "bindings", "binding_operation", "binding_step"])
def test_every_captured_nested_metadata_graph_is_finite_plain_before_new_profile_compilation(monkeypatch, position, field):
    root.compile_root_mixed_profile()
    declaration = deepcopy(root.DECLARATIONS[position])
    if field in ("pack", "kinds", "facts", "steps", "bindings"):
        name = {"kinds": "entity_kinds", "bindings": "operations"}.get(field, field)
        object.__setattr__(declaration, name, alias(declaration.pack) if field == "pack" else list(getattr(declaration, name)))
    else:
        item, name = {"kind_id": (declaration.entity_kinds[0], "id"), "kind_root": (declaration.entity_kinds[0], "root"),
            "fact_id": (declaration.facts[0], "id"), "fact_subject": (declaration.facts[0], "subject"),
            "fact_type": (declaration.facts[0], "value_type"), "step_id": (declaration.steps[0], "id"),
            "step_reads": (declaration.steps[0], "reads"), "step_produces": (declaration.steps[0], "produces"),
            "binding_operation": (declaration.operations[0], "operation"), "binding_step": (declaration.operations[0], "step")}[field]
        value = 0 if field == "kind_root" else ([],) if field in ("step_reads", "step_produces") else [] if field in ("fact_subject", "binding_step") else alias(getattr(item, name))
        object.__setattr__(item, name, value)
    declarations = list(root.DECLARATIONS)
    declarations[position] = declaration
    monkeypatch.setattr(root, "DECLARATIONS", tuple(declarations))
    compiler, calls = root.compile_packs, []
    def compiling(items):
        calls.append(items)
        return compiler(items)
    monkeypatch.setattr(root, "compile_packs", compiling)
    with pytest.raises(ValueError, match="^fhrp_root_mixed_profile$"):
        root.compile_root_mixed_profile()
    assert tuple(len(items) for items in calls) == (1, 3)


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("drift", ["evaluator", "operation"])
def test_well_formed_compilable_captured_changes_still_cannot_replace_current_named_metadata(monkeypatch, position, drift):
    root.compile_root_mixed_profile()
    declaration = root.DECLARATIONS[position]
    changed = replace(declaration, **{"steps": (replace(declaration.steps[0], evaluator=declaration.pack + ".other"), *declaration.steps[1:])}
        if drift == "evaluator" else {"operations": (replace(declaration.operations[0], operation="iosxe.show_other"), *declaration.operations[1:])})
    declarations = list(root.DECLARATIONS)
    declarations[position] = changed
    assert compile_packs(tuple(declarations)) != compile_packs(root.DECLARATIONS)
    monkeypatch.setattr(root, "DECLARATIONS", tuple(declarations))
    with pytest.raises(ValueError, match="^fhrp_root_mixed_profile$"):
        root.compile_root_mixed_profile()


@pytest.mark.parametrize("drift", ["evaluator", "missing_priority", "priority_type"])
def test_root_owner_literal_gate_remains_a_required_current_prerequisite(monkeypatch, drift):
    root.compile_root_mixed_profile()
    declaration = stp.ROOT_DECLARATION
    if drift == "evaluator":
        step = replace(stp.ROOT_STEP, evaluator="l2.stp.other")
        changed = replace(declaration, steps=(step,))
        monkeypatch.setattr(stp, "ROOT_STEP", step)
    elif drift == "missing_priority":
        facts = tuple(fact for fact in declaration.facts if fact.id != stp.REPORTED_ROOT_PRIORITY)
        step = replace(stp.ROOT_STEP, produces=tuple(fact.id for fact in sorted(facts, key=lambda fact: fact.id)))
        changed = replace(declaration, facts=facts, steps=(step,))
        monkeypatch.setattr(stp, "ROOT_STEP", step)
    else:
        changed = replace(declaration, facts=tuple(replace(fact, value_type="text") if fact.id == stp.REPORTED_ROOT_PRIORITY else fact for fact in declaration.facts))
    monkeypatch.setattr(stp, "ROOT_DECLARATION", changed)
    assert compile_packs((changed,)) != compile_packs((declaration,))
    with pytest.raises(ValueError, match="^stp_root_observation_metadata$"):
        root.compile_root_mixed_profile()


@pytest.mark.parametrize("phase", [1, 2, 3, 4, 5, 6])
def test_every_historical_expected_actual_and_repeat_compile_is_compared_using_real_changed_metadata(monkeypatch, phase):
    root.compile_root_mixed_profile()
    compiler, calls = root.compile_packs, []
    def compiling(declarations):
        calls.append(declarations)
        if len(calls) == phase:
            declaration = declarations[0]
            changed = replace(declaration, steps=(replace(declaration.steps[0], evaluator="l2.stp.other"),))
            return compiler((changed, *declarations[1:]))
        return compiler(declarations)
    monkeypatch.setattr(root, "compile_packs", compiling)
    with pytest.raises(ValueError, match="^fhrp_root_mixed_profile$"):
        root.compile_root_mixed_profile()
    assert len(calls) == (4 if phase in (3, 4) else 6)


@pytest.mark.parametrize("phase,field", [(phase, field) for phase in (1, 2, 3, 4) for field in
    ("class", "catalogue_bytes", "registration_bytes", "registration_sha256", "steps", "operations", "step_order")
    if field != "step_order" or phase != 1])
def test_full_compiled_record_shape_and_order_are_checked_in_addition_to_hash_labels(monkeypatch, phase, field):
    root.compile_root_mixed_profile()
    compiler, calls = root.compile_packs, []
    def compiling(declarations):
        result = compiler(declarations)
        calls.append(result)
        if len(calls) != phase:
            return result
        if field == "class":
            return object()
        name = "steps" if field == "step_order" else field
        value = bytearray(getattr(result, name)) if field.endswith("_bytes") else alias(result.registration_sha256) if field == "registration_sha256" else tuple(reversed(result.steps)) if field == "step_order" else list(getattr(result, name))
        return replace(result, **{name: value})
    monkeypatch.setattr(root, "compile_packs", compiling)
    with pytest.raises(ValueError, match="^fhrp_root_mixed_profile$"):
        root.compile_root_mixed_profile()
    assert len(calls) == (6 if field == "step_order" and phase in (1, 2) else 4)


@pytest.mark.parametrize("phase", [1, 2])
def test_mixed7_prerequisite_is_checked_before_and_after_using_real_semantic_drift(monkeypatch, phase):
    root.compile_root_mixed_profile()
    compiler, calls = mixed.compile_mixed_profile, []
    def compiling():
        result = compiler()
        calls.append(result)
        declaration = mixed.FHRP_DECLARATION
        changed = replace(declaration, steps=(replace(declaration.steps[0], evaluator="l3.fhrp.other"), *declaration.steps[1:]))
        return compile_packs((stp.DECLARATION, ec.DECLARATION, changed)) if len(calls) == phase else result
    monkeypatch.setattr(mixed, "compile_mixed_profile", compiling)
    with pytest.raises(ValueError, match="^fhrp_root_mixed_profile$"):
        root.compile_root_mixed_profile()
    assert len(calls) == 2

@pytest.mark.parametrize("extra", [stp.DECLARATION, mixed.FHRP_DECLARATION, mixed.vrrp.DECLARATION])
def test_root9_cannot_be_composed_with_a_duplicate_stp_or_fhrp_namespace(extra):
    actual = root.compile_root_mixed_profile()
    assert len(actual.steps) == 5
    with pytest.raises(ValueError, match="^duplicate_pack$"):
        compile_packs(root.DECLARATIONS + (extra,))


def test_equal_canonical_data_copies_remain_comparison_data_without_origin_tokens(monkeypatch):
    original = root.compile_root_mixed_profile()
    monkeypatch.setattr(root, "DECLARATIONS", deepcopy(root.DECLARATIONS))
    monkeypatch.setattr(root, "FHRP_DECLARATION", deepcopy(root.FHRP_DECLARATION))
    assert root.compile_root_mixed_profile() == original
