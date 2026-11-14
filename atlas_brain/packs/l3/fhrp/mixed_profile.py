"""Fixed STP/EC/HSRP STATE+VERSION/VRRP metadata; no admission, execution or coverage claim."""
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    CompiledPackSet,
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.packs.l3.fhrp import peer_profile as peer
from atlas_brain.packs.l3.fhrp import version_profile as version
from atlas_brain.packs.l3.fhrp import vrrp_profile as vrrp


def _need(condition: bool) -> None:
    k.require(condition, "fhrp_mixed_profile")


def _step(value: StepSpec) -> None:
    _need(type(value) is StepSpec and all(type(item) is str for item in
          (value.id, value.pack, value.kind, value.scope, value.evaluator))
          and type(value.reads) is tuple and type(value.produces) is tuple
          and all(type(item) is str for item in value.reads + value.produces))
    StepSpec(id=value.id, pack=value.pack, kind=value.kind, scope=value.scope,
             reads=value.reads, produces=value.produces, evaluator=value.evaluator)


def _binding(value: OperationBinding) -> None:
    _need(type(value) is OperationBinding and type(value.operation) is str and type(value.step) is str)
    OperationBinding(operation=value.operation, step=value.step)


def _declaration(value: PackDeclaration) -> None:
    _need(type(value) is PackDeclaration and type(value.pack) is str
          and all(type(items) is tuple for items in
              (value.entity_kinds, value.facts, value.relations, value.steps, value.operations)) and not value.relations)
    for kind in value.entity_kinds:
        _need(type(kind) is EntityKindSpec and type(kind.id) is str and type(kind.pack) is str and type(kind.root) is bool)
        EntityKindSpec(id=kind.id, pack=kind.pack, root=kind.root)
    for fact in value.facts:
        _need(type(fact) is FactSpec and all(type(item) is str for item in
              (fact.id, fact.pack, fact.subject, fact.value_type, fact.step)))
        FactSpec(id=fact.id, pack=fact.pack, subject=fact.subject, value_type=fact.value_type, step=fact.step)
    for step in value.steps:
        _step(step)
    for binding in value.operations:
        _binding(binding)
    PackDeclaration(pack=value.pack, entity_kinds=value.entity_kinds, facts=value.facts,
        relations=value.relations, steps=value.steps, operations=value.operations)


def _literal() -> PackDeclaration:
    pack = k.PackId("l3.fhrp")
    rows = (
        ("l3.fhrp/parse_hsrp_brief", "l3.fhrp.reported_state", "iosxe.show_standby_brief", "l3.fhrp.build_reported_state"),
        ("l3.fhrp/parse_hsrp_all_version", "l3.fhrp.reported_protocol_version", "iosxe.show_standby_all", "l3.fhrp.build_reported_version"),
        ("l3.fhrp/parse_vrrp", "l3.fhrp.reported_vrrp_state", "iosxe.show_vrrp", "l3.fhrp.build_reported_vrrp_state"),
    )
    steps = tuple(StepSpec(id=StepId(row[0]), pack=pack, kind="parse_build", scope="device",
        reads=(), produces=(k.FactId(row[1]),), evaluator=row[3]) for row in rows)
    return PackDeclaration(pack=pack, entity_kinds=(EntityKindSpec(id="fhrp_local", pack=pack, root=False),),
        facts=tuple(FactSpec(id=step.produces[0], pack=pack, subject="fhrp_local", value_type="text", step=step.id) for step in steps),
        relations=(), steps=steps,
        operations=tuple(OperationBinding(operation=row[2], step=step.id) for row, step in zip(rows, steps, strict=True)))


FHRP_DECLARATION = PackDeclaration(pack=version.STATE_VERSION_DECLARATION.pack,
    entity_kinds=version.STATE_VERSION_DECLARATION.entity_kinds,
    facts=version.STATE_VERSION_DECLARATION.facts + vrrp.DECLARATION.facts, relations=(),
    steps=version.STATE_VERSION_DECLARATION.steps + vrrp.DECLARATION.steps,
    operations=version.STATE_VERSION_DECLARATION.operations + vrrp.DECLARATION.operations)
DECLARATIONS = (stp.DECLARATION, ec.DECLARATION, FHRP_DECLARATION)


def compile_mixed_profile() -> CompiledPackSet:
    """Compile one named five-operation profile; metadata objects grant no source authority."""
    _need(type(DECLARATIONS) is tuple and len(DECLARATIONS) == 3)
    for value in (stp.DECLARATION, ec.DECLARATION, hsrp.DECLARATION, version.DECLARATION,
                  version.STATE_VERSION_DECLARATION, vrrp.DECLARATION, FHRP_DECLARATION, *DECLARATIONS):
        _declaration(value)
    for step in (stp.STEP, ec.STEP, hsrp.STEP, version.STEP, vrrp.STEP):
        _step(step)
    for binding in (stp.BINDING, ec.BINDING, hsrp.BINDING, version.BINDING, vrrp.BINDING):
        _binding(binding)
    old_peer, old_vrrp = peer.compile_peer_state_version_profile(), vrrp.compile_vrrp_profile()
    literal = _literal()
    packs = (stp.PACK, ec.PACK, hsrp.PACK, version.PACK, vrrp.PACK)
    _need(all(type(pack) is str for pack in packs)
          and packs == ("l2.stp", "l2.etherchannel", "l3.fhrp", "l3.fhrp", "l3.fhrp"))
    facts = (hsrp.REPORTED_STATE, version.REPORTED_PROTOCOL_VERSION, vrrp.REPORTED_VRRP_STATE)
    _need(all(type(fact) is str for fact in facts) and facts == tuple(step.produces[0] for step in literal.steps)
          and type(hsrp.hsrp.OP) is str and hsrp.hsrp.OP == literal.operations[0].operation
          and type(hsrp.hsrp.COMMAND) is str and hsrp.hsrp.COMMAND == "show standby brief")
    runtime_fhrp = PackDeclaration(pack=version.PACK, entity_kinds=version.STATE_VERSION_DECLARATION.entity_kinds,
        facts=hsrp.DECLARATION.facts + version.DECLARATION.facts + vrrp.DECLARATION.facts, relations=(),
        steps=(hsrp.STEP, version.STEP, vrrp.STEP), operations=(hsrp.BINDING, version.BINDING, vrrp.BINDING))
    _need(FHRP_DECLARATION == runtime_fhrp == literal
          and DECLARATIONS == (stp.DECLARATION, ec.DECLARATION, FHRP_DECLARATION))
    actual = compile_packs(DECLARATIONS)
    runtime = compile_packs((stp.DECLARATION, ec.DECLARATION, runtime_fhrp))
    expected = compile_packs((stp.DECLARATION, ec.DECLARATION, literal))
    _need(all(type(item) is CompiledPackSet and type(item.catalogue_bytes) is bytes
              and type(item.registration_bytes) is bytes and type(item.registration_sha256) is str
              and type(item.steps) is tuple and type(item.operations) is tuple for item in (actual, runtime, expected)))
    _need(actual == runtime == expected and actual.registration_sha256 not in
          (old_peer.registration_sha256, old_vrrp.registration_sha256)
          and old_peer == peer.compile_peer_state_version_profile() and old_vrrp == vrrp.compile_vrrp_profile())
    return actual
