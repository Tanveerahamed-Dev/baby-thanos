"""Real pre-all-Writer HSRP comparisons; original run and Source remain caller-owned."""
from copy import copy
from dataclasses import replace

import pytest
from test_gateway_source import LIMITS, folder

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4_pipeline


class CapturingPack(StandbyBriefPack):
    def prepare(self,envelope):
        batch=super().prepare(envelope)
        self.plan_bindings=custody.retain_plan(self.owner,envelope,self.budgets)
        return batch
    def finish(self,execution):
        custody.close_execution(self.execution_bindings,self.owner,execution,self.budgets)
        return super().finish(execution)


def parsed(root,missing=None):
    folder(root,missing)
    limits=replace(LIMITS)
    tree,channel,pack=stp.RootGuardPack(limits),SummaryPack(limits),CapturingPack(limits)
    execution=p4_pipeline.execute_p4_folder(root,limits,packs=(tree,channel,pack))
    pack.execution_bindings=custody.retain_execution(pack.plan_bindings,pack.owner,execution,limits)
    tree.finish(execution);channel.finish(execution)
    return pack,execution


def close(pack,execution):
    owned=custody.close_execution(pack.execution_bindings,pack.owner,execution,pack.budgets)
    return state.StateOwner.reclose_current_rows(pack.owner,execution.envelope,pack.budgets,owned)


@pytest.mark.parametrize("missing",[None,"hsrp","both"])
def test_public_bridge_recloses_exact_original_rows_proofs_unknowns_without_callbacks(tmp_path,monkeypatch,missing):
    root=tmp_path/"inputs";pack,execution=parsed(root,missing);source=pack.finish(execution)
    before={p.name:p.read_bytes() for p in root.iterdir()}
    facts=tuple((row,row.value) for row in source.rows)
    monkeypatch.setattr(FactReader,"read",lambda *_a,**_k:pytest.fail("Reader in pure closure"))
    monkeypatch.setattr(FactWriter,"write",lambda *_a,**_k:pytest.fail("Writer in pure closure"))
    monkeypatch.setattr(state.hsrp,"parse_capture",lambda *_a,**_k:pytest.fail("parser in pure closure"))
    rows=close(pack,execution)
    assert graph.source_rows_bytes(rows,pack.owner.plan.indexed,pack.plan_bindings.targets)==graph.source_rows_bytes(source.rows,pack.owner.plan.indexed,pack.plan_bindings.targets)
    assert all(row.value is value for row,value in facts) and len(rows)==6
    assert any(type(row.value) is k.Unknown for row in source.rows)
    assert close(pack,execution)==rows
    assert {p.name:p.read_bytes() for p in root.iterdir()}==before


@pytest.mark.parametrize("phase",["reader","writer"])
@pytest.mark.parametrize("fault",[
    "owner","plan","requests","expected","indexed","proof_map","proof_value","registration",
    "produced_map","produced_value","parse","execution","outputs","receipt","value","capture",
    "receipt_parse","envelope","target","node","declaration","raw","context","capture_bytes",
    "opaque_produced","opaque_request","opaque_proof","opaque_value",
    "target_operation","envelope_targets","envelope_members","base_nodes","base_captures",
    "base_container","member_copy","base_bytes","member_bytes","budget","opaque_budget","budget_copy","member_target",
    "capture_string","unsupported_metadata","opaque_leaf",
    "plan_class_accept","plan_class_refuse","own_shadow","finish_shadow","bridge_shadow",
])
def test_final_real_reader_or_writer_cannot_substitute_any_original_binding(tmp_path,monkeypatch,phase,fault):
    pack,execution=parsed(tmp_path/"inputs");current=[execution];owner=pack.owner;plan=owner.plan
    expected={state.subject(target,interface,group) for target in plan.indexed.values() for interface,group in target.groups}
    output=next(out for out in execution.executed if out.receipt.capture.operation==state.hsrp.OP)
    key=output.receipt.capture.id;target=next(iter(plan.indexed.values()));request=plan.expected[key]
    metadata=next(item for item in execution.envelope.targets if item.operation==state.hsrp.OP)
    calls=[];hit=[];seen=set()
    class Equal(str):
        def __eq__(self,_other):calls.append("equality");return True
        def __hash__(self):calls.append("hash");raise AssertionError
        def __deepcopy__(self,_memo):calls.append("deepcopy");raise AssertionError
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
    class ForeignDict(dict):
        def __iter__(self):calls.append("iteration");raise AssertionError
        def __getitem__(self,_key):calls.append("getitem");raise AssertionError
        def __contains__(self,_key):calls.append("contains");raise AssertionError
    class ForeignTuple(tuple):
        def __iter__(self):calls.append("iteration");raise AssertionError
    class PlanHook(type(plan)):
        __slots__=()
        def __getattribute__(self,name):
            calls.append("plan_class")
            if fault=="plan_class_refuse":raise AssertionError("plan attribute hook")
            return object.__getattribute__(self,name)
    def shadow(*args,**kwargs):
        calls.append("method")
        source.store.values.clear()
    def mutate():
        hit.append(True)
        if fault=="owner":object.__setattr__(pack.run,"owner",copy(owner))
        elif fault=="plan":owner.plan=replace(plan)
        elif fault in ("plan_class_accept","plan_class_refuse"):object.__setattr__(plan,"__class__",PlanHook)
        elif fault=="own_shadow":owner.own=shadow
        elif fault=="finish_shadow":owner.finish=shadow
        elif fault=="bridge_shadow":owner.reclose_current_rows=shadow
        elif fault=="requests":object.__setattr__(plan,"requests",(*plan.requests,))
        elif fault=="expected":object.__setattr__(plan,"expected",dict(plan.expected))
        elif fault=="indexed":object.__setattr__(plan,"indexed",dict(plan.indexed))
        elif fault=="proof_map":object.__setattr__(plan,"proofs",dict(plan.proofs))
        elif fault=="proof_value":object.__setattr__(next(iter(plan.proofs.values()))[0],"citation","/wrong")
        elif fault=="registration":owner.registration="0"*64
        elif fault=="produced_map":owner.produced=dict(owner.produced)
        elif fault=="produced_value":owner.produced[key]=replace(owner.produced[key])
        elif fault=="parse":object.__setattr__(owner.produced[key],"parse",replace(owner.produced[key].parse))
        elif fault=="execution":current[0]=replace(execution)
        elif fault=="outputs":object.__setattr__(execution,"executed",(*execution.executed,))
        elif fault=="receipt":object.__setattr__(output,"receipt",replace(output.receipt))
        elif fault=="value":object.__setattr__(output,"value",replace(output.value))
        elif fault=="capture":object.__setattr__(output.receipt,"capture",replace(output.receipt.capture))
        elif fault=="receipt_parse":object.__setattr__(output.receipt,"parse",replace(output.receipt.parse))
        elif fault=="envelope":object.__setattr__(execution,"envelope",replace(execution.envelope))
        elif fault=="target":plan.indexed[target.context,target.node.key]=replace(target)
        elif fault=="node":object.__setattr__(target,"node",replace(target.node))
        elif fault=="declaration":object.__setattr__(target.node,"declaration",replace(target.node.declaration))
        elif fault=="raw":object.__setattr__(execution.envelope,"raw",execution.envelope.raw+b" ")
        elif fault=="context":object.__setattr__(request,"context","foreign")
        elif fault=="capture_bytes":object.__setattr__(request.capture,"raw",request.capture.raw+b"changed\n")
        elif fault=="opaque_produced":owner.produced=ForeignDict(owner.produced)
        elif fault=="opaque_request":object.__setattr__(request,"context",Equal(request.context))
        elif fault=="opaque_proof":plan.proofs[next(iter(plan.proofs))]=ForeignTuple(next(iter(plan.proofs.values())))
        elif fault=="opaque_value":owner.produced[key]=Foreign()
        elif fault=="capture_string":object.__setattr__(request.capture,"raw",request.capture.raw.hex())
        elif fault=="unsupported_metadata":object.__setattr__(request.capture,"metadata",Foreign())
        elif fault=="opaque_leaf":object.__setattr__(output.value.rows[0].interface,"value",Equal(output.value.rows[0].interface.value))
        elif fault=="target_operation":object.__setattr__(metadata,"operation",Equal(metadata.operation))
        elif fault=="envelope_targets":object.__setattr__(execution.envelope,"targets",ForeignTuple(execution.envelope.targets))
        elif fault=="envelope_members":object.__setattr__(execution.envelope,"captures",ForeignTuple(execution.envelope.captures))
        elif fault=="base_nodes":object.__setattr__(execution.envelope.base,"nodes",ForeignTuple(execution.envelope.base.nodes))
        elif fault=="base_captures":object.__setattr__(execution.envelope.base,"captures",ForeignTuple(execution.envelope.base.captures))
        elif fault=="base_container":object.__setattr__(execution.envelope,"base",replace(execution.envelope.base))
        elif fault=="member_copy":object.__setattr__(execution.envelope,"captures",tuple(replace(item) for item in execution.envelope.captures))
        elif fault=="base_bytes":object.__setattr__(execution.envelope.base,"raw",execution.envelope.base.raw+b" ")
        elif fault=="member_bytes":object.__setattr__(execution.envelope.captures[0],"raw",execution.envelope.captures[0].raw+b"changed\n")
        elif fault=="budget":object.__setattr__(pack.budgets,"nesting_depth",pack.budgets.nesting_depth+1)
        elif fault=="opaque_budget":object.__setattr__(pack.budgets,"nesting_depth",Equal("64"))
        elif fault=="budget_copy":pack.budgets=replace(pack.budgets)
        else:object.__setattr__(execution.envelope.captures[0],"target",replace(execution.envelope.captures[0].target))
    read,write=FactReader.read,FactWriter.write
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is state.SOURCE_STEP:
            seen.add(kw["subject"])
            if seen==expected:mutate()
        return value
    def writing(self,**kw):
        value=write(self,**kw)
        if self.step is state.STEP:
            seen.add(kw["subject"])
            if seen==expected:mutate()
        return value
    if phase=="writer":monkeypatch.setattr(FactWriter,"write",writing)
    source=pack.finish(execution)
    if phase=="reader":
        subjects=tuple(sorted(row.subject for row in source.rows))
        reader=bind_reader(source.store,step=state.SOURCE_STEP)
        monkeypatch.setattr(FactReader,"read",reading)
        for subject in subjects:reader.read(fact=state.REPORTED_STATE,subject=subject)
    if fault in ("own_shadow","finish_shadow","bridge_shadow"):
        close(pack,current[0])
    else:
        with pytest.raises(ValueError):close(pack,current[0])
    assert hit==[True] and calls==[] and len(source.store.values)==len(expected)


def test_semantically_equal_result_clone_has_no_original_execution_authority(tmp_path):
    pack,execution=parsed(tmp_path/"inputs");pack.finish(execution)
    output=next(out for out in execution.executed if out.receipt.capture.operation==state.hsrp.OP)
    copied=replace(output.value)
    pack.owner.produced[output.receipt.capture.id]=copied
    object.__setattr__(output,"value",copied)
    with pytest.raises(ValueError):close(pack,execution)


def test_repeated_closure_rechecks_mutation_after_previous_success(tmp_path):
    pack,execution=parsed(tmp_path/"inputs");pack.finish(execution);close(pack,execution)
    first=next(iter(pack.owner.produced.values()))
    object.__setattr__(first.rows[0].interface,"value","foreign")
    with pytest.raises(ValueError):close(pack,execution)


@pytest.mark.parametrize("peer",["stp","channel"])
@pytest.mark.parametrize("plant",["clone","shadow"])
def test_earlier_peer_writer_cannot_rebase_parse_custody_or_dispatch_callbacks(tmp_path,monkeypatch,peer,plant):
    captured={};hit=[];calls=[]
    retain,write=custody.retain_execution,FactWriter.write
    def retaining(plan,owner,execution,budgets):
        held=retain(plan,owner,execution,budgets)
        captured.update(owner=owner,execution=execution)
        return held
    def shadow(*args,**kwargs):calls.append("method");raise AssertionError("instance dispatch")
    def writing(self,**kw):
        value=write(self,**kw)
        if captured and self.step.id.startswith("l2.stp/" if peer=="stp" else "l2.etherchannel/") and not hit:
            hit.append(True);owner=captured["owner"]
            output=next(out for out in captured["execution"].executed if out.receipt.capture.operation==state.hsrp.OP)
            if plant=="clone":
                clone=replace(output.value)
                owner.produced[output.receipt.capture.id]=clone
                object.__setattr__(output,"value",clone)
            else:owner.own=owner.finish=owner.reclose_current_rows=shadow
        return value
    monkeypatch.setattr(custody,"retain_execution",retaining)
    monkeypatch.setattr(FactWriter,"write",writing)
    pack,execution=parsed(tmp_path/"inputs")
    if plant=="clone":
        with pytest.raises(ValueError):pack.finish(execution)
    else:
        source=pack.finish(execution)
        assert len(close(pack,execution))==len(source.rows)==6
    assert hit==[True] and calls==[]
