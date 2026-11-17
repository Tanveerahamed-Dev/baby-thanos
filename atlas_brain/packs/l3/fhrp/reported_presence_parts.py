"""Fixed positive metadata, carriers and Store comparisons; none admit supplied Source or origin."""
from dataclasses import dataclass

from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model import store as storage
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.packs.l3.fhrp import build as state


def _need(condition: bool) -> None:
    k.require(condition,"hsrp_presence_source")


def positive_contract(fact_id: k.FactId,derive_step: StepSpec,declaration: registration.PackDeclaration) -> registration.PackDeclaration:
    """Recompile the fixed producer declaration; no default-profile registration."""
    parse=StepSpec(id=StepId("l3.fhrp/parse_hsrp_brief"),pack=k.PackId("l3.fhrp"),kind="parse_build",scope="device",
        reads=(),produces=(k.FactId("l3.fhrp.reported_state"),),evaluator="l3.fhrp.build_reported_state")
    derive=StepSpec(id=StepId("l3.fhrp/derive_reported_presence"),pack=parse.pack,kind="derive",scope="device",
        reads=parse.produces,produces=(k.FactId("l3.fhrp.reported_group_present"),),evaluator="l3.fhrp.build_reported_presence")
    _need(type(fact_id) is str and type(state.REPORTED_STATE) is str and fact_id==derive.produces[0]
        and state.REPORTED_STATE==parse.produces[0] and type(state.STEP) is StepSpec and type(derive_step) is StepSpec
        and type(state.BINDING) is registration.OperationBinding and type(declaration) is registration.PackDeclaration)
    _need(type(declaration.pack) is str and type(declaration.entity_kinds) is tuple
        and type(declaration.facts) is tuple and type(declaration.steps) is tuple
        and type(declaration.relations) is tuple and type(declaration.operations) is tuple)
    for step in (state.STEP,derive_step,*declaration.steps):
        _need(type(step) is StepSpec and all(type(item) is str for item in
            (step.id,step.pack,step.kind,step.scope,step.evaluator))
            and type(step.reads) is tuple and type(step.produces) is tuple
            and all(type(item) is str for item in (*step.reads,*step.produces)))
    for fact in declaration.facts:
        _need(type(fact) is FactSpec and all(type(item) is str for item in
            (fact.id,fact.pack,fact.subject,fact.value_type,fact.step)))
    for kind in declaration.entity_kinds:
        _need(type(kind) is EntityKindSpec and type(kind.id) is str and type(kind.pack) is str and type(kind.root) is bool)
    for binding in (state.BINDING,*declaration.operations):
        _need(type(binding) is registration.OperationBinding and type(binding.operation) is str and type(binding.step) is str)
    _need(not declaration.relations)
    _need(state.STEP==parse and derive_step==derive and state.BINDING==registration.OperationBinding(operation="iosxe.show_standby_brief",step=parse.id)
        and declaration==registration.PackDeclaration(pack=parse.pack,entity_kinds=(EntityKindSpec(id="fhrp_local",pack=parse.pack,root=False),),
            facts=(FactSpec(id=parse.produces[0],pack=parse.pack,subject="fhrp_local",value_type="text",step=parse.id),
                FactSpec(id=fact_id,pack=parse.pack,subject="fhrp_local",value_type="boolean",step=derive.id)),
            relations=(),steps=(parse,derive),operations=(state.BINDING,)))
    registration.compile_packs((declaration,))
    return declaration



@dataclass(frozen=True,slots=True,kw_only=True)
class Row:
    source: state.Row
    value: k.Known[bool] | k.Unknown


@dataclass(frozen=True,slots=True,kw_only=True)
class Result:
    source: state.Result
    store: storage.FactStore
    rows: tuple[Row,...]


def compare_store(store: storage.FactStore, fact: k.FactId, step: StepId,
           cells: tuple[tuple[k.EntityKey,object],...], maps: tuple[object,object]) -> None:
    _need(type(store) is storage.FactStore and type(store.owners) is dict and type(store.values) is dict
        and store.owners is maps[0] and store.values is maps[1])
    _need(all(type(key) is str and type(value) is str for key,value in store.owners.items())
        and all(type(ref) is k.FactRef and type(ref.fact) is str and type(ref.subject) is str for ref in store.values))
    _need(store.owners=={fact:step} and len(store.values)==len(cells)
        and all(store.values.get(k.FactRef(fact=fact,subject=subject)) is value for subject,value in cells))


def validate_positive_value(value: k.Known[bool] | k.Unknown,source: k.Known[str] | k.Unknown,subject: k.EntityKey) -> None:
    """Close fixed positive semantics only after the caller's actual original Source closure."""
    if type(source) is k.Unknown:_need(value is source)
    else:
        _need(type(value) is k.Known and type(value.value) is bool and value.value is True
            and value.raw is None and value.basis is k.Basis.DERIVED and type(value.evidence) is tuple
            and len(value.evidence)==1 and type(value.evidence[0]) is k.FactRef
            and type(value.evidence[0].fact) is str and type(value.evidence[0].subject) is str
            and value.evidence[0].fact==state.REPORTED_STATE and value.evidence[0].subject==subject)
