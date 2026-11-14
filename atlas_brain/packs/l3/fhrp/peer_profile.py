"""Fixed ordinary-protocol STP/EC/FHRP STATE+VERSION metadata; never source admission."""
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
from atlas_brain.packs.l3.fhrp import version_profile as version

DECLARATIONS = (stp.DECLARATION, ec.DECLARATION, version.STATE_VERSION_DECLARATION)


def _closed(actual: PackDeclaration, step: StepSpec, binding: OperationBinding, literal: PackDeclaration) -> None:
    k.require(type(step) is StepSpec and type(binding) is OperationBinding and actual == literal
              and step == literal.steps[0] and binding == literal.operations[0], "fhrp_peer_profile")
    runtime = PackDeclaration(pack=actual.pack, entity_kinds=actual.entity_kinds, facts=actual.facts,
        relations=actual.relations, steps=(step,), operations=(binding,))
    recorded, current, expected = compile_packs((actual,)), compile_packs((runtime,)), compile_packs((literal,))
    k.require(recorded.catalogue_bytes == current.catalogue_bytes == expected.catalogue_bytes
              and recorded.registration_bytes == current.registration_bytes == expected.registration_bytes
              and recorded.registration_sha256 == current.registration_sha256 == expected.registration_sha256, "fhrp_peer_profile")


def compile_peer_state_version_profile() -> CompiledPackSet:
    """Compile only the named four-operation composition; no supplied declaration or mode."""
    version.compile_state_version_profile()
    tree = StepSpec(id=StepId("l2.stp/parse_root_guard"), pack=k.PackId("l2.stp"), kind="parse_build", scope="device",
        reads=(), produces=(k.FactId("l2.stp.reported_role"), k.FactId("l2.stp.root_guard")), evaluator="l2.stp.build_root_guard")
    channel = StepSpec(id=StepId("l2.etherchannel/parse_protocol"), pack=k.PackId("l2.etherchannel"), kind="parse_build",
        scope="device", reads=(), produces=(k.FactId("l2.etherchannel.reported_member_tokens"),
        k.FactId("l2.etherchannel.reported_protocol")), evaluator="l2.etherchannel.build_reported_protocol")
    tree_decl = PackDeclaration(pack=tree.pack, entity_kinds=(EntityKindSpec(id="stp_port_vlan", pack=tree.pack, root=False),),
        facts=(FactSpec(id=tree.produces[1], pack=tree.pack, subject="stp_port_vlan", value_type="boolean", step=tree.id),
               FactSpec(id=tree.produces[0], pack=tree.pack, subject="stp_port_vlan", value_type="text", step=tree.id)),
        relations=(), steps=(tree,), operations=(OperationBinding(operation="iosxe.show_spanning_tree_interface_detail", step=tree.id),))
    channel_decl = PackDeclaration(pack=channel.pack,
        entity_kinds=(EntityKindSpec(id="etherchannel_group", pack=channel.pack, root=False),),
        facts=tuple(FactSpec(id=fact, pack=channel.pack, subject="etherchannel_group", value_type="text", step=channel.id)
                    for fact in channel.produces), relations=(), steps=(channel,),
        operations=(OperationBinding(operation="iosxe.show_etherchannel_summary", step=channel.id),))
    _closed(stp.DECLARATION, stp.STEP, stp.BINDING, tree_decl)
    _closed(ec.DECLARATION, ec.STEP, ec.BINDING, channel_decl)
    facts = (stp.REPORTED_ROLE, stp.ROOT_GUARD, ec.REPORTED_MEMBER_TOKENS, ec.REPORTED_PROTOCOL)
    k.require(all(type(fact) is str for fact in facts) and facts == tree.produces + channel.produces
              and all(type(value) is str for value in (stp.stp.OP, ec.parse_summary.OP, ec.parse_summary.COMMAND))
              and stp.stp.OP == "iosxe.show_spanning_tree_interface_detail"
              and ec.parse_summary.OP == "iosxe.show_etherchannel_summary"
              and ec.parse_summary.COMMAND == "show etherchannel summary", "fhrp_peer_profile")
    actual = compile_packs(DECLARATIONS)
    expected = compile_packs((tree_decl, channel_decl, version.STATE_VERSION_DECLARATION))
    k.require(DECLARATIONS == (stp.DECLARATION, ec.DECLARATION, version.STATE_VERSION_DECLARATION)
              and actual.catalogue_bytes == expected.catalogue_bytes
              and actual.registration_bytes == expected.registration_bytes
              and actual.registration_sha256 == expected.registration_sha256, "fhrp_peer_profile")
    return actual
