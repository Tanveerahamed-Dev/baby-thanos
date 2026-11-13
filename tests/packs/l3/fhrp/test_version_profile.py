"""Closed registration metadata only; synthetic grant fixtures do not prove parser execution."""
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_reported_state_build import target

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, FactWriter, bind_reader, bind_writer
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner import pack_runtime

FACT, OWNER = "l3.fhrp.reported_protocol_version", "l3.fhrp/parse_hsrp_all_version"


class Text(StrEnum):
    FACT = "l3.fhrp.reported_protocol_version"
    KIND = "fhrp_local"


def forbid_writes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("profile compilation wrote a fact")
    monkeypatch.setattr(FactWriter, "write", forbidden)


def test_fresh_literal_compiles_pin_exact_owner_bytes_and_deterministic_registration_without_execution(monkeypatch):
    compile_packs, calls = profile.compile_packs, []
    def compiling(declarations):
        result = compile_packs(declarations)
        calls.append((declarations, result))
        return result
    def forbidden(*args, **kwargs):
        pytest.fail("metadata compilation executed a parser or dispatcher")
    monkeypatch.setattr(profile, "compile_packs", compiling)
    monkeypatch.setattr(profile.parser, "parse_capture", forbidden)
    monkeypatch.setattr(pack_runtime, "execute_parsers", forbidden)
    forbid_writes(monkeypatch)
    first, second = profile.compile_version_profile(), profile.compile_version_profile()
    assert len(calls) == 4 and calls[0][0] == calls[1][0] == calls[2][0] == calls[3][0] == (profile.DECLARATION,)
    assert calls[0][0][0] is calls[2][0][0] is profile.DECLARATION
    assert calls[1][0][0] is not profile.DECLARATION and calls[1][0][0] is not calls[3][0][0]
    assert first is calls[0][1] and second is calls[2][1] and first is not second
    assert type(first) is registration.CompiledPackSet
    assert (profile.PACK, profile.REPORTED_PROTOCOL_VERSION) == ("l3.fhrp", FACT)
    assert type(profile.PACK) is type(profile.REPORTED_PROTOCOL_VERSION) is str
    assert (profile.STEP.id, profile.STEP.pack, profile.STEP.kind, profile.STEP.scope) == (OWNER, "l3.fhrp", "parse_build", "device")
    assert (profile.STEP.reads, profile.STEP.produces, profile.STEP.evaluator) == ((), (FACT,), "l3.fhrp.build_reported_version")
    assert (profile.BINDING.operation, profile.BINDING.step) == ("iosxe.show_standby_all", OWNER)
    declaration = profile.DECLARATION
    spec, = declaration.facts
    kind, = declaration.entity_kinds
    assert (declaration.pack, declaration.relations, declaration.steps, declaration.operations) == ("l3.fhrp", (), (profile.STEP,), (profile.BINDING,))
    assert (kind.id, kind.pack, kind.root) == ("fhrp_local", "l3.fhrp", False) and type(kind.root) is bool
    assert (spec.id, spec.pack, spec.subject, spec.value_type, spec.step) == (FACT, "l3.fhrp", "fhrp_local", "text", OWNER)
    assert first.steps == second.steps == (profile.STEP,) and first.operations == second.operations == (profile.BINDING,)
    expected = registration.compile_packs((declaration,))
    assert first.catalogue_bytes == second.catalogue_bytes == expected.catalogue_bytes
    assert first.registration_bytes == second.registration_bytes == canonical({
        "schema": "atlas-brain.pack-registration/1", "catalogue_sha256": sha256(first.catalogue_bytes).hexdigest(),
        "packs": ["l3.fhrp"], "operations": [{"operation": "iosxe.show_standby_all", "step": OWNER}]})
    assert first.registration_sha256 == second.registration_sha256 == sha256(first.registration_bytes).hexdigest()


def test_declared_reader_and_writer_grants_are_mechanical_metadata_not_source_admission():
    compiled = profile.compile_version_profile()
    declared = target(groups=(("Vlan10", "0"),))
    subject = build.subject(declared, "Vlan10", "0")
    value = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="synthetic_profile_only",
                      evidence=declared.node.declaration.evidence, candidates=(), next_evidence=())
    store = FactStore()
    writer = bind_writer(store, step=compiled.steps[0])
    writer.write(fact=FACT, subject=subject, value=value)
    assert store.owners == {FACT: OWNER}
    reader = StepSpec(id=StepId("l3.fhrp/test_profile"), pack=profile.PACK, kind="check", scope="device",
                      reads=(FACT,), produces=(), evaluator="l3.fhrp.test_profile")
    assert bind_reader(store, step=reader).read(fact=FACT, subject=subject) is value
    with pytest.raises(ValueError, match="undeclared_read"):
        bind_reader(store, step=build.SOURCE_STEP).read(fact=FACT, subject=subject)
    with pytest.raises(ValueError):
        writer.write(fact=build.REPORTED_STATE, subject=subject, value=value)


@pytest.mark.parametrize("field", ["fact", "step", "declaration", "operation", "command"])
def test_fixed_application_profile_cannot_be_replaced_by_inspectable_metadata(monkeypatch, field):
    if field in ("operation", "command"):
        monkeypatch.setattr(profile.parser, "OP" if field == "operation" else "COMMAND", "other")
    else:
        name, value = {"fact": ("REPORTED_PROTOCOL_VERSION", "l3.fhrp.other"),
            "step": ("STEP", build.STEP), "declaration": ("DECLARATION", build.VIP_DECLARATION)}[field]
        monkeypatch.setattr(profile, name, value)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        profile.compile_version_profile()


@pytest.mark.parametrize("alias", ["root_integer", "nested_string_enum", "public_string_enum"])
def test_equal_valued_metadata_aliases_do_not_bypass_exact_json_types(monkeypatch, alias):
    if alias == "public_string_enum":
        monkeypatch.setattr(profile, "REPORTED_PROTOCOL_VERSION", Text.FACT)
    else:
        kind = replace(profile.DECLARATION.entity_kinds[0])
        object.__setattr__(kind, "root" if alias == "root_integer" else "id", 0 if alias == "root_integer" else Text.KIND)
        monkeypatch.setattr(profile, "DECLARATION", replace(profile.DECLARATION, entity_kinds=(kind,)))
    forbid_writes(monkeypatch)
    with pytest.raises((ValueError, TypeError)):
        profile.compile_version_profile()


@pytest.mark.parametrize("drift", ["evaluator", "owner", "operation"])
def test_coherent_valid_metadata_drift_still_refuses_the_fixed_literal_contract(monkeypatch, drift):
    step, binding, declaration = profile.STEP, profile.BINDING, profile.DECLARATION
    if drift in ("evaluator", "owner"):
        step = replace(step, evaluator="l3.fhrp.other", **({"id": StepId("l3.fhrp/other_version")} if drift == "owner" else {}))
        binding = replace(binding, step=step.id)
        declaration = replace(declaration, steps=(step,), operations=(binding,),
                              facts=(replace(declaration.facts[0], step=step.id),))
    else:
        binding = replace(binding, operation="iosxe.other")
        declaration = replace(declaration, operations=(binding,))
        monkeypatch.setattr(profile.parser, "OP", "iosxe.other")
    monkeypatch.setattr(profile, "STEP", step)
    monkeypatch.setattr(profile, "BINDING", binding)
    monkeypatch.setattr(profile, "DECLARATION", declaration)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        profile.compile_version_profile()


@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_each_compiled_byte_and_digest_field_must_match_the_separate_literal_compile(monkeypatch, field):
    compile_packs, calls = profile.compile_packs, []
    def compiling(declarations):
        result = compile_packs(declarations)
        calls.append(result)
        changed = "0" * 64 if field == "registration_sha256" else b"synthetic mismatch"
        return replace(result, **{field: changed}) if len(calls) == 1 else result
    monkeypatch.setattr(profile, "compile_packs", compiling)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        profile.compile_version_profile()
    assert len(calls) == 2


def test_callers_cannot_supply_a_declaration_or_compiled_carrier_as_a_profile():
    compiled = profile.compile_version_profile()
    for supplied in (profile.DECLARATION, compiled, replace(compiled)):
        with pytest.raises(TypeError):
            profile.compile_version_profile(supplied)
