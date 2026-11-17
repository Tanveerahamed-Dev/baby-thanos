"""Real qualified model/compiler contracts and pure comparison data; no positive runtime exists here."""
from dataclasses import FrozenInstanceError, replace

import pytest

from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model import store
from atlas_brain.model.specs import FactSpec, StepId, StepSpec
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_parts as parts

FACT=k.FactId("l3.fhrp.reported_group_present")


def metadata():
    step=StepSpec(id=StepId("l3.fhrp/derive_reported_presence"),pack=state.PACK,kind="derive",scope="device",
        reads=(state.REPORTED_STATE,),produces=(FACT,),evaluator="l3.fhrp.build_reported_presence")
    declared=registration.PackDeclaration(pack=state.PACK,entity_kinds=state.DECLARATION.entity_kinds,
        facts=state.DECLARATION.facts+(FactSpec(id=FACT,pack=state.PACK,subject="fhrp_local",value_type="boolean",step=step.id),),
        relations=(),steps=(state.STEP,step),operations=(state.BINDING,))
    return step,declared


def stored():
    source=store.FactStore()
    value=k.Known(value="unit",raw="unit",basis=k.Basis.DECLARED,
        evidence=(k.RegistryRef(table="unit",row_id="unit",table_digest="0"*64,citation="/unit"),))
    subject=k.EntityKey("unit:subject")
    store.bind_writer(source,step=state.STEP).write(fact=state.REPORTED_STATE,subject=subject,value=value)
    return source,subject,value


def test_fixed_contract_recompiles_real_metadata_and_produces_actual_model_permissions(monkeypatch):
    step,declared=metadata()
    compile=registration.compile_packs
    calls=[]
    def compiling(declarations):
        calls.append(declarations)
        return compile(declarations)
    monkeypatch.setattr(registration,"compile_packs",compiling)
    assert parts.positive_contract(FACT,step,declared) is declared
    assert parts.positive_contract(FACT,step,declared) is declared and len(calls)==2
    source,subject,value=stored()
    assert store.bind_reader(source,step=step).read(fact=state.REPORTED_STATE,subject=subject) is value
    output=store.FactStore()
    true=k.Known(value=True,raw=None,basis=k.Basis.DERIVED,evidence=(k.FactRef(fact=state.REPORTED_STATE,subject=subject),))
    store.bind_writer(output,step=step).write(fact=FACT,subject=subject,value=true)
    assert output.values[k.FactRef(fact=FACT,subject=subject)] is true


@pytest.mark.parametrize("fault",["fact","reads","produces","value_type","declaration","opaque_leaf"])
def test_every_fixed_contract_guard_survives_extraction_without_foreign_hooks(fault):
    step,declared=metadata()
    fact=FACT
    calls=[]
    class Text(str):
        def __eq__(self,_other):calls.append("equality");raise AssertionError
        def __hash__(self):calls.append("hash");raise AssertionError
    if fault=="fact":fact=k.FactId("l3.fhrp.foreign")
    elif fault=="reads":step=replace(step,reads=())
    elif fault=="produces":step=replace(step,produces=())
    elif fault=="value_type":declared=replace(declared,facts=(declared.facts[0],replace(declared.facts[1],value_type="text")))
    elif fault=="declaration":declared=replace(declared,facts=declared.facts[:1])
    else:object.__setattr__(step,"id",Text(step.id))
    with pytest.raises(ValueError):parts.positive_contract(fact,step,declared)
    assert calls==[]


@pytest.mark.parametrize("fault",["owners","values","owner","cell","extra","key"])
def test_whole_store_comparison_retains_all_original_bindings_and_value_identities(fault):
    source,subject,value=stored()
    maps=(source.owners,source.values)
    cells=((subject,value),)
    parts.compare_store(source,state.REPORTED_STATE,state.STEP.id,cells,maps)
    if fault=="owners":source.owners=dict(source.owners)
    elif fault=="values":source.values=dict(source.values)
    elif fault=="owner":source.owners[state.REPORTED_STATE]=StepId("l3.fhrp/foreign")
    elif fault=="cell":source.values[k.FactRef(fact=state.REPORTED_STATE,subject=subject)]=replace(value)
    elif fault=="extra":source.values[k.FactRef(fact=state.REPORTED_STATE,subject=k.EntityKey("extra"))]=value
    else:object.__setattr__(next(iter(source.values)),"subject",False)
    with pytest.raises(ValueError):parts.compare_store(source,state.REPORTED_STATE,state.STEP.id,cells,maps)


def test_frozen_carriers_remain_inspectable_comparison_data_without_source_admission():
    source,subject,value=stored()
    carrier=state.Result(store=source,rows=(),executed=())
    result=parts.Result(source=carrier,store=source,rows=())
    assert result.source is carrier and result.rows==() and source.values[k.FactRef(fact=state.REPORTED_STATE,subject=subject)] is value
    with pytest.raises(FrozenInstanceError):result.rows=()


@pytest.mark.parametrize("field,changed",[("value",False),("raw","forged"),("basis",k.Basis.DECLARED),("evidence",())])
def test_fixed_positive_value_is_exact_true_and_exact_original_unknown(field,changed):
    _store,subject,source=stored()
    value=k.Known(value=True,raw=None,basis=k.Basis.DERIVED,evidence=(k.FactRef(fact=state.REPORTED_STATE,subject=subject),))
    parts.validate_positive_value(value,source,subject)
    object.__setattr__(value,field,changed)
    with pytest.raises(ValueError):parts.validate_positive_value(value,source,subject)
    unknown=k.Unknown(reason=k.UnknownReason.NOT_COLLECTED,detail="unit",evidence=(),candidates=(),next_evidence=())
    parts.validate_positive_value(unknown,unknown,subject)
    with pytest.raises(ValueError):parts.validate_positive_value(replace(unknown),unknown,subject)
