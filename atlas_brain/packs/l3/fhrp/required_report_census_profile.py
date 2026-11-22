"""Explicit static required-report profile for the synthetic HSRP census grammar."""
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census
from atlas_brain.packs.l3.fhrp import required_report_profile as required


def declaration() -> registration.PackDeclaration:
    """Extend the single FHRP declaration. No parser dispatch or fact production."""
    base = required.declaration()
    operation = census.OP
    k.require(type(operation) is str and operation == "synthetic.hsrp_ipv4_interface_census",
              "fhrp_census_operation")
    step = StepSpec(
        id=StepId("l3.fhrp/parse_hsrp_census"),
        pack=base.pack,
        kind="parse_build",
        scope="device",
        reads=(),
        produces=(),
        evaluator="l3.fhrp.parse_hsrp_census",
    )
    result = registration.PackDeclaration(
        pack=base.pack,
        entity_kinds=base.entity_kinds,
        facts=base.facts,
        relations=base.relations,
        steps=(*base.steps, step),
        operations=(*base.operations, registration.OperationBinding(operation=operation, step=step.id)),
    )
    registration.compile_packs((result,))
    return result
