"""Test-only owning-run fixtures and plants; no unpublished producer import."""
import json
from copy import copy
from dataclasses import replace
from hashlib import sha256

from test_gateway_source import folder

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack

PRESENCE_FACT = k.FactId("l3.fhrp.reported_group_present")
PHASES = ("stp_writer","channel_writer","source_writer","source_reader","derived_writer")
CUSTODY_FAULTS = (
    "run","pack_class","execution_class","owner","plan","expected","indexed","proofs","produced","parse","receipt","capture",
    "context","raw","envelope","budget","budget_copy","registration","declaration","plan_class",
    "own_shadow","finish_shadow","bridge_shadow","metadata","member","outputs","produced_value",
    "envelope_bytes","base_bytes","target","node","proof_value","target_operation","opaque_leaf",
)
SOURCE_FAULTS = ("store","owners","values","rows","cell","executed","unknown_need","reader_store","reader_step","reader_clone")


def inputs(root,mode="normal"):
    files=folder(root,mode if mode in ("hsrp","both") else None)
    if mode in ("partial","error","truncated","conflict"):
        raw=files["hsrp.txt"]
        files["hsrp.txt"]=raw+b"unmodelled row\n" if mode=="partial" else b"% Command failed\n" if mode=="error" else raw+b"[truncated]\n" if mode=="truncated" else raw+next(line for line in raw.splitlines(keepends=True) if line.startswith(b"Vl10 "))
        side=json.loads(files["p4.json"])
        for row in side["captures"]:
            row["sha256"]=sha256(files[row["path"]]).hexdigest()
        files["p4.json"]=canonical(side)
        for name,raw in files.items():
            (root/name).write_bytes(raw)
    return files


def capture(monkeypatch,pack_type):
    seen={}
    prepare,retain,finish=pack_type.prepare,custody.retain_execution,StandbyBriefPack.finish
    def preparing(self,envelope):
        batch=prepare(self,envelope)
        seen["pack"]=self
        return batch
    def retaining(plan,owner,execution,budgets):
        held=retain(plan,owner,execution,budgets)
        seen.update(execution=execution,held=held)
        return held
    def finishing(self,execution):
        source=finish(self,execution)
        seen["source"]=source
        return source
    monkeypatch.setattr(pack_type,"prepare",preparing)
    monkeypatch.setattr(custody,"retain_execution",retaining)
    monkeypatch.setattr(StandbyBriefPack,"finish",finishing)
    return seen


def mutate_custody(seen,fault,monkeypatch,declaration_module,calls):
    class Foreign:
        def __getattribute__(self,name):
            calls.append(name)
            raise AssertionError
    def shadow(*_args,**_kwargs):
        calls.append("method")
        raise AssertionError
    pack=seen["pack"]
    owner=pack.owner
    plan=owner.plan
    execution=seen["execution"]
    output=next(out for out in execution.executed if out.receipt.capture.operation==state.hsrp.OP)
    key=output.receipt.capture.id
    request=plan.expected[key]
    target=next(iter(plan.indexed.values()))
    class PlanHook(type(plan)):
        __slots__=()
        def __getattribute__(self,name):
            calls.append(name)
            raise AssertionError
    class PackHook(type(pack)):
        __slots__=()
        __getattribute__=Foreign.__getattribute__
    class ExecutionHook(type(execution)):
        __slots__=()
        __getattribute__=Foreign.__getattribute__
    if fault=="run":
        pack.run=replace(pack.run)
    elif fault=="pack_class":
        object.__setattr__(pack,"__class__",PackHook)
    elif fault=="execution_class":
        object.__setattr__(execution,"__class__",ExecutionHook)
    elif fault=="owner":
        object.__setattr__(pack.run,"owner",copy(owner))
    elif fault=="plan":
        owner.plan=replace(plan)
    elif fault=="expected":
        object.__setattr__(plan,"expected",dict(plan.expected))
    elif fault=="indexed":
        object.__setattr__(plan,"indexed",dict(plan.indexed))
    elif fault=="proofs":
        object.__setattr__(plan,"proofs",dict(plan.proofs))
    elif fault=="produced":
        owner.produced=dict(owner.produced)
    elif fault=="parse":
        object.__setattr__(output.value,"parse",replace(output.value.parse))
    elif fault=="receipt":
        object.__setattr__(output,"receipt",replace(output.receipt))
    elif fault=="capture":
        object.__setattr__(output.receipt,"capture",replace(output.receipt.capture))
    elif fault=="context":
        object.__setattr__(request,"context","foreign")
    elif fault=="raw":
        object.__setattr__(request.capture,"raw",request.capture.raw+b"changed\n")
    elif fault=="envelope":
        object.__setattr__(execution,"envelope",replace(execution.envelope))
    elif fault=="budget":
        object.__setattr__(pack.budgets,"nesting_depth",pack.budgets.nesting_depth+1)
    elif fault=="budget_copy":
        pack.budgets=replace(pack.budgets)
    elif fault=="registration":
        owner.registration="0"*64
    elif fault=="declaration":
        monkeypatch.setattr(declaration_module,"DECLARATION",replace(declaration_module.DECLARATION,facts=declaration_module.DECLARATION.facts[:1]))
    elif fault=="plan_class":
        object.__setattr__(plan,"__class__",PlanHook)
    elif fault=="own_shadow":
        owner.own=shadow
    elif fault=="finish_shadow":
        owner.finish=shadow
    elif fault=="bridge_shadow":
        owner.reclose_current_rows=shadow
    elif fault=="metadata":
        object.__setattr__(request.capture,"metadata",Foreign())
    elif fault=="member":
        object.__setattr__(execution.envelope.captures[0],"target",replace(execution.envelope.captures[0].target))
    elif fault=="outputs":
        object.__setattr__(execution,"executed",tuple(item for item in execution.executed))
    elif fault=="produced_value":
        clone=replace(output.value)
        owner.produced[key]=clone
        object.__setattr__(output,"value",clone)
    elif fault=="envelope_bytes":
        object.__setattr__(execution.envelope,"raw",execution.envelope.raw+b" ")
    elif fault=="base_bytes":
        object.__setattr__(execution.envelope.base,"raw",execution.envelope.base.raw+b" ")
    elif fault=="target_operation":
        object.__setattr__(execution.envelope.targets[0],"operation",Foreign())
    elif fault=="opaque_leaf":
        object.__setattr__(output.value.rows[0].interface,"value",Foreign())
    elif fault=="target":
        plan.indexed[target.context,target.node.key]=replace(target)
    elif fault=="node":
        object.__setattr__(target,"node",replace(target.node))
    elif fault=="proof_value":
        object.__setattr__(next(iter(plan.proofs.values()))[0],"citation","/wrong")
    else:
        raise ValueError("presence_test_fault")


def mutate_source(seen,handle,value,fault):
    source=seen["source"]
    row=next(row for row in source.rows if type(row.value) is k.Unknown)
    if fault=="store":
        object.__setattr__(source,"store",FactStore())
    elif fault=="owners":
        source.store.owners=dict(source.store.owners)
    elif fault=="values":
        source.store.values=dict(source.store.values)
    elif fault=="rows":
        object.__setattr__(source,"rows",tuple(item for item in source.rows))
    elif fault=="cell":
        clone=replace(row.value)
        object.__setattr__(row,"value",clone)
        source.store.values[k.FactRef(fact=state.REPORTED_STATE,subject=row.subject)]=clone
    elif fault=="executed":
        object.__setattr__(source,"executed",tuple(item for item in source.executed))
    elif fault=="unknown_need":
        object.__setattr__(row.value,"next_evidence",())
    elif fault=="reader_store":
        object.__setattr__(handle,"store",FactStore())
    elif fault=="reader_step":
        object.__setattr__(handle,"step",replace(handle.step))
    elif fault=="reader_clone":
        return replace(value)
    else:
        raise ValueError("presence_test_fault")
    return value
