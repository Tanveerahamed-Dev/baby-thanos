"""Closed local VERSION registration; compiled carriers are not source admission."""
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    CompiledPackSet,
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser

PACK = k.PackId("l3.fhrp")
REPORTED_PROTOCOL_VERSION = k.FactId("l3.fhrp.reported_protocol_version")
STEP = StepSpec(id=StepId("l3.fhrp/parse_hsrp_all_version"), pack=PACK, kind="parse_build", scope="device",
    reads=(), produces=(REPORTED_PROTOCOL_VERSION,), evaluator="l3.fhrp.build_reported_version")
BINDING = OperationBinding(operation=parser.OP, step=STEP.id)
DECLARATION = PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="fhrp_local", pack=PACK, root=False),),
    facts=(FactSpec(id=REPORTED_PROTOCOL_VERSION, pack=PACK, subject="fhrp_local", value_type="text", step=STEP.id),),
    relations=(), steps=(STEP,), operations=(BINDING,))


def compile_version_profile() -> CompiledPackSet:
    """Compile the fixed owner contract afresh; callers cannot provide a profile."""
    step = StepSpec(id=StepId("l3.fhrp/parse_hsrp_all_version"), pack=k.PackId("l3.fhrp"), kind="parse_build",
        scope="device", reads=(), produces=(k.FactId("l3.fhrp.reported_protocol_version"),), evaluator="l3.fhrp.build_reported_version")
    binding = OperationBinding(operation="iosxe.show_standby_all", step=step.id)
    declaration = PackDeclaration(pack=k.PackId("l3.fhrp"),
        entity_kinds=(EntityKindSpec(id="fhrp_local", pack=k.PackId("l3.fhrp"), root=False),),
        facts=(FactSpec(id=k.FactId("l3.fhrp.reported_protocol_version"), pack=k.PackId("l3.fhrp"),
                       subject="fhrp_local", value_type="text", step=step.id),), relations=(), steps=(step,), operations=(binding,))
    k.require(STEP == step and BINDING == binding and DECLARATION == declaration and type(PACK) is str and PACK == "l3.fhrp"
          and type(REPORTED_PROTOCOL_VERSION) is str and REPORTED_PROTOCOL_VERSION == "l3.fhrp.reported_protocol_version"
          and type(parser.OP) is str and type(parser.COMMAND) is str
          and parser.OP == "iosxe.show_standby_all" and parser.COMMAND == "show standby all", "hsrp_version_profile")
    actual = compile_packs((DECLARATION,))
    expected = compile_packs((declaration,))
    k.require(actual.catalogue_bytes == expected.catalogue_bytes
              and actual.registration_bytes == expected.registration_bytes
              and actual.registration_sha256 == expected.registration_sha256, "hsrp_version_profile")
    return actual


STATE_VERSION_DECLARATION = PackDeclaration(pack=PACK, entity_kinds=DECLARATION.entity_kinds,
    facts=build.DECLARATION.facts + DECLARATION.facts, relations=(),
    steps=build.DECLARATION.steps + DECLARATION.steps, operations=build.DECLARATION.operations + DECLARATION.operations)


def compile_state_version_profile() -> CompiledPackSet:
    """Compile only this fixed FHRP subset; the application supplies the fixed peer composition."""
    compile_version_profile()
    state = StepSpec(id=StepId("l3.fhrp/parse_hsrp_brief"), pack=PACK, kind="parse_build", scope="device",
        reads=(), produces=(k.FactId("l3.fhrp.reported_state"),), evaluator="l3.fhrp.build_reported_state")
    expected = PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="fhrp_local", pack=PACK, root=False),),
        facts=(FactSpec(id=k.FactId("l3.fhrp.reported_state"), pack=PACK, subject="fhrp_local", value_type="text", step=state.id),) + DECLARATION.facts,
        relations=(), steps=(state, STEP), operations=(OperationBinding(operation="iosxe.show_standby_brief", step=state.id), BINDING))
    state_declaration = PackDeclaration(pack=PACK, entity_kinds=expected.entity_kinds, facts=expected.facts[:1],
        relations=(), steps=(state,), operations=(expected.operations[0],))
    k.require(type(build.STEP) is StepSpec and type(build.BINDING) is OperationBinding
              and type(build.DECLARATION) is PackDeclaration and build.STEP == state
              and build.BINDING == expected.operations[0] and build.DECLARATION == state_declaration, "hsrp_state_version_profile")
    runtime_state = PackDeclaration(pack=build.DECLARATION.pack, entity_kinds=build.DECLARATION.entity_kinds,
        facts=build.DECLARATION.facts, relations=build.DECLARATION.relations, steps=(build.STEP,), operations=(build.BINDING,))
    claimed_state, actual_state, literal_state = (compile_packs((build.DECLARATION,)),
        compile_packs((runtime_state,)), compile_packs((state_declaration,)))
    k.require(claimed_state.catalogue_bytes == actual_state.catalogue_bytes == literal_state.catalogue_bytes
              and claimed_state.registration_bytes == actual_state.registration_bytes == literal_state.registration_bytes
              and claimed_state.registration_sha256 == actual_state.registration_sha256 == literal_state.registration_sha256,
              "hsrp_state_version_profile")
    actual, literal = compile_packs((STATE_VERSION_DECLARATION,)), compile_packs((expected,))
    k.require(actual.catalogue_bytes == literal.catalogue_bytes and actual.registration_bytes == literal.registration_bytes
              and actual.registration_sha256 == literal.registration_sha256, "hsrp_state_version_profile")
    return actual
