"""Trusted built-in HSRP finish dispatch preserves every owning phase."""
from copy import copy
from dataclasses import replace

import pytest
from test_gateway_source import LIMITS, folder

from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import brief_execution_graph as brief
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack, VirtualIpPack
from atlas_brain.runner import p4_pipeline


def parsed(root,vip=False,missing=None):
    files=folder(root,missing)
    budgets=replace(LIMITS)
    tree,channel=stp.RootGuardPack(budgets),SummaryPack(budgets)
    standby=VirtualIpPack(budgets) if vip else StandbyBriefPack(budgets)
    execution=p4_pipeline.execute_p4_folder(root,budgets,packs=(tree,channel,standby))
    return tree,channel,standby,execution,budgets,files


@pytest.mark.parametrize("vip",[False,True])
@pytest.mark.parametrize("missing",[None,"hsrp","both"])
def test_public_finish_preserves_original_rows_vip_prelude_and_source_assignment(tmp_path,monkeypatch,vip,missing):
    writes=[];write=FactWriter.write
    def writing(self,**kw):
        writes.append((self.step.id,kw["fact"],kw["subject"]))
        return write(self,**kw)
    monkeypatch.setattr(FactWriter,"write",writing)
    tree,channel,pack,execution,budgets,files=parsed(tmp_path/"inputs",vip,missing)
    assert writes==[]
    original=tuple(out for out in execution.executed if out.receipt.capture.operation==state.hsrp.OP)
    assert all(pack.owner.produced[out.receipt.capture.id] is out.value for out in original)
    brief.validate_brief_execution_graph(execution.executed)
    targets=graph.retain_targets(pack.owner.plan.indexed)
    prelude=[];method=state.VirtualIpOwner.virtual_ip_originals
    def originals(self,outputs):
        prelude.append(tuple(outputs))
        return method(self,outputs)
    monkeypatch.setattr(state.VirtualIpOwner,"virtual_ip_originals",originals)
    monkeypatch.setattr(state.hsrp,"parse_capture",lambda *_:pytest.fail("finish parsed again"))
    tree.finish(execution);channel.finish(execution)
    result=StandbyBriefPack.finish(pack,execution)
    assert len(result.rows)==len(result.store.values)==6 and pack.owner.finished
    assert all(a.receipt is b.receipt and a.value is b.value for a,b in zip(result.executed,original,strict=True))
    assert prelude==([original] if vip else [])
    if vip:assert pack.owner.source is result
    monkeypatch.setattr(FactReader,"read",lambda *_a,**_k:pytest.fail("Reader in comparison bridge"))
    monkeypatch.setattr(FactWriter,"write",lambda *_a,**_k:pytest.fail("Writer in comparison bridge"))
    rows=state.StateOwner.reclose_current_rows(pack.owner,execution.envelope,budgets,result.executed)
    assert graph.source_rows_bytes(rows,pack.owner.plan.indexed,targets)==graph.source_rows_bytes(result.rows,pack.owner.plan.indexed,targets)
    assert {p.name:p.read_bytes() for p in (tmp_path/"inputs").iterdir()}==files


@pytest.mark.parametrize("vip,shadow",[(False,"own"),(False,"finish"),(False,"reclose_current_rows"),
    (True,"own"),(True,"finish"),(True,"virtual_ip_originals")])
@pytest.mark.parametrize("peer",["stp","channel"])
def test_actual_earlier_peer_writer_cannot_invoke_instance_dispatch(tmp_path,monkeypatch,vip,shadow,peer):
    tree,channel,pack,execution,budgets,files=parsed(tmp_path/"inputs",vip)
    owner=pack.owner;calls=[];hit=[];write=FactWriter.write
    original=tuple(out for out in execution.executed if out.receipt.capture.operation==state.hsrp.OP)
    def callback(*args,**kwargs):
        calls.append("shadow")
        object.__setattr__(original[0].value.rows[0].interface,"value","forged")
        raise AssertionError("instance dispatch after peer Writer")
    def writing(self,**kw):
        value=write(self,**kw)
        if self.step.id.startswith("l2.stp/" if peer=="stp" else "l2.etherchannel/") and not hit:
            hit.append(True)
            object.__setattr__(owner,shadow,callback)
        return value
    monkeypatch.setattr(FactWriter,"write",writing)
    tree.finish(execution);channel.finish(execution)
    result=StandbyBriefPack.finish(pack,execution)
    rows=state.StateOwner.reclose_current_rows(owner,execution.envelope,budgets,result.executed)
    assert len(rows)==len(result.rows)==6 and hit==[True] and calls==[]
    assert all(a.receipt is b.receipt and a.value is b.value for a,b in zip(result.executed,original,strict=True))
    if vip:assert owner.source is result and state.VirtualIpOwner.virtual_ip_originals(owner,result.executed) is not None
    assert {p.name:p.read_bytes() for p in (tmp_path/"inputs").iterdir()}==files


def test_unsupported_current_owner_type_refuses_before_any_owner_attribute(tmp_path):
    _tree,_channel,pack,execution,_budgets,_files=parsed(tmp_path/"inputs")
    owner=copy(pack.owner);calls=[]
    class Unsupported(type(owner)):
        __slots__=()
        def __getattribute__(self,name):
            calls.append(name)
            raise AssertionError("unsupported owner attribute")
    object.__setattr__(owner,"__class__",Unsupported)
    object.__setattr__(pack.run,"owner",owner)
    with pytest.raises(ValueError,match="^hsrp_global_owner$"):
        StandbyBriefPack.finish(pack,execution)
    assert calls==[]
