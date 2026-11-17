"""Shared plants run against the qualified ordinary pipeline before producer activation."""
from dataclasses import replace

import pytest
from presence_test_support import (
    CUSTODY_FAULTS,
    SOURCE_FAULTS,
    capture,
    inputs,
    mutate_custody,
    mutate_source,
)
from test_gateway_source import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4_pipeline


class OriginalPack(StandbyBriefPack):
    def prepare(self,envelope):
        prepared=super().prepare(envelope)
        self.bindings=custody.retain_plan(self.owner,envelope,self.budgets)
        return prepared


def ordinary(root,monkeypatch,mode="normal"):
    files=inputs(root,mode)
    limits=replace(LIMITS)
    seen=capture(monkeypatch,OriginalPack)
    tree,channel,pack=stp.RootGuardPack(limits),SummaryPack(limits),OriginalPack(limits)
    execution=p4_pipeline.execute_p4_folder(root,limits,packs=(tree,channel,pack))
    held=custody.retain_execution(pack.bindings,pack.owner,execution,limits)
    seen.update(run=pack.run,limits=limits,declaration=state.DECLARATION)
    rows=state.StateOwner.reclose_current_rows(pack.owner,execution.envelope,limits,
        custody.close_execution(held,pack.owner,execution,limits))
    expected=graph.source_rows_bytes(rows,held.plan.indexed,held.plan.targets)
    tree.finish(execution)
    channel.finish(execution)
    source=StandbyBriefPack.finish(pack,execution)
    assert seen["source"] is source
    seen.update(source_store=source.store,source_rows=source.rows,source_outputs=source.executed,
        source_maps=(source.store.owners,source.store.values),cells=tuple((row,row.value) for row in source.rows))
    return seen,files,expected


def close(seen):
    pack,execution=seen["pack"],seen["execution"]
    k.require(type(pack) is OriginalPack and type(execution) is p4_pipeline.Result,"support_graph")
    k.require(pack.run is seen["run"] and pack.budgets is seen["limits"]
        and state.DECLARATION is seen["declaration"],"support_original")
    held=seen["held"]
    outputs=custody.close_execution(held,pack.owner,execution,seen["limits"])
    rows=state.StateOwner.reclose_current_rows(pack.owner,execution.envelope,seen["limits"],outputs)
    wanted=graph.source_rows_bytes(rows,held.plan.indexed,held.plan.targets)
    source=seen["source"]
    k.require(source.store is seen["source_store"] and source.rows is seen["source_rows"]
        and source.executed is seen["source_outputs"] and source.store.owners is seen["source_maps"][0]
        and source.store.values is seen["source_maps"][1],"support_source")
    k.require(graph.source_rows_bytes(source.rows,held.plan.indexed,held.plan.targets)==wanted
        and all(row is original and row.value is value for row,(original,value) in zip(source.rows,seen["cells"],strict=True)),
        "support_source")
    return wanted


@pytest.mark.parametrize("mode",["normal","hsrp","both","partial","error","truncated","conflict"])
def test_shared_input_modes_use_actual_admission_execution_and_original_rows(tmp_path,monkeypatch,mode):
    root=tmp_path/"inputs"
    seen,files,expected=ordinary(root,monkeypatch,mode)
    assert close(seen)==expected
    assert graph.source_rows_bytes(seen["source"].rows,seen["held"].plan.indexed,seen["held"].plan.targets)==expected
    assert len(seen["source"].rows)==6
    assert any(type(row.value) is k.Unknown for row in seen["source"].rows)
    assert {p.name:p.read_bytes() for p in root.iterdir()}==files


@pytest.mark.parametrize("fault",CUSTODY_FAULTS)
def test_every_shared_custody_plant_reaches_real_owned_execution_and_original_binding(tmp_path,monkeypatch,fault):
    seen,_files,expected=ordinary(tmp_path/"inputs",monkeypatch)
    calls=[]
    mutate_custody(seen,fault,monkeypatch,state,calls)
    if fault.endswith("_shadow"):assert close(seen)==expected
    else:
        with pytest.raises(ValueError):close(seen)
    assert calls==[]


@pytest.mark.parametrize("fault",SOURCE_FAULTS)
def test_shared_source_plants_reach_the_last_actual_source_reader(tmp_path,monkeypatch,fault):
    seen,_files,_expected=ordinary(tmp_path/"inputs",monkeypatch)
    source=seen["source"]
    reader=bind_reader(source.store,step=state.SOURCE_STEP)
    original=tuple((row.subject,row.value) for row in source.rows)
    found=[]
    for index,(subject,_value) in enumerate(original):
        value=reader.read(fact=state.REPORTED_STATE,subject=subject)
        if index==len(original)-1:value=mutate_source(seen,reader,value,fault)
        found.append(value)
    with pytest.raises(ValueError):
        close(seen)
        k.require(reader.store is seen["source_store"] and reader.step is state.SOURCE_STEP
            and all(value is actual for value,(_subject,actual) in zip(found,original,strict=True)),"support_reader")
