"""Fixed required-report metadata; no dynamic profile or evaluator loading."""
from dataclasses import dataclass

from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.packs.l3.fhrp import gateway_policy as policy

PACK = k.PackId("l3.fhrp")
PRESENCE = k.FactId("l3.fhrp.reported_group_present")
MISSING = k.FactId("l3.fhrp.required_report_missing")
STEP = StepSpec(id=StepId("l3.fhrp/check_required_reports"),pack=PACK,kind="check",scope="estate",
    reads=(PRESENCE,),produces=(MISSING,),evaluator="l3.fhrp.check_required_reports")
PROJECT = StepSpec(id=StepId("l3.fhrp/project_required_reports"),pack=PACK,kind="derive",scope="estate",
    reads=(MISSING,),produces=(),evaluator="l3.fhrp.project_required_reports")


@dataclass(frozen=True,slots=True,kw_only=True)
class Inputs:
    policies: tuple[policy.GatewayPolicy,...]
    baseline_raw: bytes | None


def _step(actual: StepSpec,expected: StepSpec) -> None:
    k.require(type(actual) is StepSpec and all(type(value) is str for value in
        (actual.id,actual.pack,actual.kind,actual.scope,actual.evaluator))
        and type(actual.reads) is tuple and type(actual.produces) is tuple
        and all(type(value) is str for value in (*actual.reads,*actual.produces))
        and actual==expected,"fhrp_required_profile")


def declaration() -> registration.PackDeclaration:
    """Build the exact required-report declaration; compile against actual peer packs."""
    pack=k.PackId("l3.fhrp")
    state=k.FactId("l3.fhrp.reported_state")
    presence=k.FactId("l3.fhrp.reported_group_present")
    missing=k.FactId("l3.fhrp.required_report_missing")
    parse=StepSpec(id=StepId("l3.fhrp/parse_hsrp_brief"),pack=pack,kind="parse_build",scope="device",
        reads=(),produces=(state,),evaluator="l3.fhrp.build_reported_state")
    derive=StepSpec(id=StepId("l3.fhrp/derive_reported_presence"),pack=pack,kind="derive",scope="device",
        reads=(state,),produces=(presence,),evaluator="l3.fhrp.build_reported_presence")
    check=StepSpec(id=StepId("l3.fhrp/check_required_reports"),pack=pack,kind="check",scope="estate",
        reads=(presence,),produces=(missing,),evaluator="l3.fhrp.check_required_reports")
    project=StepSpec(id=StepId("l3.fhrp/project_required_reports"),pack=pack,kind="derive",scope="estate",
        reads=(missing,),produces=(),evaluator="l3.fhrp.project_required_reports")
    k.require(type(PACK) is str and PACK==pack and type(PRESENCE) is str and PRESENCE==presence
        and type(MISSING) is str and MISSING==missing,"fhrp_required_profile")
    _step(STEP,check)
    _step(PROJECT,project)
    result=registration.PackDeclaration(pack=pack,entity_kinds=(
        EntityKindSpec(id="fhrp_local",pack=pack,root=False),
        EntityKindSpec(id="fhrp_requirement",pack=pack,root=False)),facts=(
        FactSpec(id=state,pack=pack,subject="fhrp_local",value_type="text",step=parse.id),
        FactSpec(id=presence,pack=pack,subject="fhrp_local",value_type="boolean",step=derive.id),
        FactSpec(id=missing,pack=pack,subject="fhrp_requirement",value_type="boolean",step=check.id)),
        relations=(),steps=(parse,derive,check,project),
        operations=(registration.OperationBinding(operation="iosxe.show_standby_brief",step=parse.id),))
    registration.compile_packs((result,))
    return result
