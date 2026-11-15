"""Fixed Root4/EC/HSRP STATE+VERSION/VRRP metadata; no source, census or coverage claim."""
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    CompiledPackSet,
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepSpec
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.packs.l3.fhrp import mixed_profile as mixed


def _need(condition: bool) -> None:
    k.require(condition, "fhrp_root_mixed_profile")


def _closed(value: PackDeclaration) -> None:
    _need(type(value) is PackDeclaration and type(value.pack) is str and all(type(items) is tuple for items in
        (value.entity_kinds, value.facts, value.relations, value.steps, value.operations)) and not value.relations)
    for kind in value.entity_kinds:
        _need(type(kind) is EntityKindSpec and type(kind.id) is str and type(kind.pack) is str and type(kind.root) is bool)
        EntityKindSpec(id=kind.id, pack=kind.pack, root=kind.root)
    for fact in value.facts:
        _need(type(fact) is FactSpec and all(type(item) is str for item in
            (fact.id, fact.pack, fact.subject, fact.value_type, fact.step)))
        FactSpec(id=fact.id, pack=fact.pack, subject=fact.subject, value_type=fact.value_type, step=fact.step)
    for step in value.steps:
        _need(type(step) is StepSpec and all(type(item) is str for item in
            (step.id, step.pack, step.kind, step.scope, step.evaluator)) and type(step.reads) is tuple
            and type(step.produces) is tuple and all(type(fact) is str for fact in step.reads + step.produces))
        StepSpec(id=step.id, pack=step.pack, kind=step.kind, scope=step.scope,
            reads=step.reads, produces=step.produces, evaluator=step.evaluator)
    for binding in value.operations:
        _need(type(binding) is OperationBinding and type(binding.operation) is str and type(binding.step) is str)
        OperationBinding(operation=binding.operation, step=binding.step)
    PackDeclaration(pack=value.pack, entity_kinds=value.entity_kinds, facts=value.facts,
        relations=value.relations, steps=value.steps, operations=value.operations)


FHRP_DECLARATION = mixed.FHRP_DECLARATION
DECLARATIONS = (stp.ROOT_DECLARATION, ec.DECLARATION, FHRP_DECLARATION)


def compile_root_mixed_profile() -> CompiledPackSet:
    """Compile only this named nine-fact profile; metadata is comparison data, never admission."""
    previous = mixed.compile_mixed_profile()
    root = stp.root_declaration()
    old = compile_packs((root,)), compile_packs((root, ec.DECLARATION, hsrp.DECLARATION))
    _need(type(DECLARATIONS) is tuple and len(DECLARATIONS) == 3)
    for declaration in (root, ec.DECLARATION, FHRP_DECLARATION, *DECLARATIONS):
        _closed(declaration)
    _need(FHRP_DECLARATION == mixed.FHRP_DECLARATION
        and DECLARATIONS == (root, ec.DECLARATION, mixed.FHRP_DECLARATION))
    expected = compile_packs((root, ec.DECLARATION, mixed.FHRP_DECLARATION))
    actual = compile_packs(DECLARATIONS)
    _need(all(type(item) is CompiledPackSet and type(item.catalogue_bytes) is bytes
        and type(item.registration_bytes) is bytes and type(item.registration_sha256) is str
        and type(item.steps) is tuple and type(item.operations) is tuple for item in (actual, expected, previous, *old)))
    facts = tuple(fact for declaration in DECLARATIONS for fact in declaration.facts)
    kinds = tuple(kind for declaration in DECLARATIONS for kind in declaration.entity_kinds)
    _need(len(facts) == 9 and len(kinds) == 3 and len(actual.steps) == len(actual.operations) == 5
        and tuple(sorted(kind.id for kind in kinds)) == ("etherchannel_group", "fhrp_local", "stp_port_vlan")
        and tuple(sorted(declaration.pack for declaration in DECLARATIONS)) == ("l2.etherchannel", "l2.stp", "l3.fhrp"))
    _need(actual == expected and actual.registration_sha256 not in
        (previous.registration_sha256, old[0].registration_sha256, old[1].registration_sha256)
        and previous == mixed.compile_mixed_profile() and root == stp.root_declaration()
        and old == (compile_packs((stp.root_declaration(),)),
                    compile_packs((stp.root_declaration(), ec.DECLARATION, hsrp.DECLARATION))))
    return actual
