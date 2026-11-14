"""Closed synthetic VRRP-state metadata; compilation is not admission or production."""
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    CompiledPackSet,
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.packs.l3.fhrp import parse_vrrp as parser

PACK = k.PackId("l3.fhrp")
REPORTED_VRRP_STATE = k.FactId("l3.fhrp.reported_vrrp_state")


def _literal() -> PackDeclaration:
    step = StepSpec(id=StepId("l3.fhrp/parse_vrrp"), pack=k.PackId("l3.fhrp"), kind="parse_build",
        scope="device", reads=(), produces=(k.FactId("l3.fhrp.reported_vrrp_state"),), evaluator="l3.fhrp.build_reported_vrrp_state")
    return PackDeclaration(pack=k.PackId("l3.fhrp"),
        entity_kinds=(EntityKindSpec(id="fhrp_local", pack=k.PackId("l3.fhrp"), root=False),),
        facts=(FactSpec(id=k.FactId("l3.fhrp.reported_vrrp_state"), pack=k.PackId("l3.fhrp"),
            subject="fhrp_local", value_type="text", step=step.id),), relations=(), steps=(step,),
        operations=(OperationBinding(operation="iosxe.show_vrrp", step=step.id),))


DECLARATION = _literal()
STEP = DECLARATION.steps[0]
BINDING = DECLARATION.operations[0]


def compile_vrrp_profile() -> CompiledPackSet:
    """Compile only the fixed VRRP prerequisite; callers cannot supply a profile."""
    literal = _literal()
    k.require(type(PACK) is str and PACK == "l3.fhrp" and type(REPORTED_VRRP_STATE) is str
        and REPORTED_VRRP_STATE == "l3.fhrp.reported_vrrp_state" and type(STEP) is StepSpec
        and type(BINDING) is OperationBinding and type(DECLARATION) is PackDeclaration
        and STEP == literal.steps[0] and BINDING == literal.operations[0] and DECLARATION == literal
        and type(parser.OP) is str and parser.OP == "iosxe.show_vrrp"
        and type(parser.COMMAND) is str and parser.COMMAND == "show vrrp"
        and type(parser.SYNTHETIC_GROUPS) is tuple and parser.SYNTHETIC_GROUPS == ("100", "101")
        and all(type(group) is str for group in parser.SYNTHETIC_GROUPS), "vrrp_profile")
    runtime = PackDeclaration(pack=DECLARATION.pack, entity_kinds=DECLARATION.entity_kinds, facts=DECLARATION.facts,
        relations=DECLARATION.relations, steps=(STEP,), operations=(BINDING,))
    claimed, actual, expected = (compile_packs((DECLARATION,)), compile_packs((runtime,)), compile_packs((literal,)))
    identities = tuple((item.catalogue_bytes, item.registration_bytes, item.registration_sha256)
                       for item in (claimed, actual, expected))
    k.require(identities[0] == identities[1] == identities[2], "vrrp_profile")
    return claimed
