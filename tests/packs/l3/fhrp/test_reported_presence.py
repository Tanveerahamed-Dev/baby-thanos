"""Real owning producer regressions; shared plants preserve every original control."""
from dataclasses import replace

import first_use_support as first_use
import pytest
from presence_test_support import (
    CUSTODY_FAULTS,
    PHASES,
    SOURCE_FAULTS,
    capture,
    inputs,
    mutate_custody,
    mutate_source,
)
from test_gateway_source import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence as present
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack


@pytest.mark.parametrize("mode",["normal","hsrp","both","partial","error","truncated","conflict"])
def test_owning_folder_preserves_originals_full_population_true_refs_and_exact_unknowns(tmp_path,monkeypatch,mode):
    root=tmp_path/"inputs";files=inputs(root,mode);seen=capture(monkeypatch,present.PresencePack)
    read,write=FactReader.read,FactWriter.write;reads=[];writes=[]
    def reading(self,**kw):
        if self.step is present.STEP:reads.append(kw["subject"])
        return read(self,**kw)
    def writing(self,**kw):
        assert "held" in seen
        if kw["fact"]==present.FACT:
            assert len(reads)==6
            writes.append(kw["subject"])
        return write(self,**kw)
    monkeypatch.setattr(FactReader,"read",reading);monkeypatch.setattr(FactWriter,"write",writing)
    result=present.build_reported_presence(root,replace(LIMITS))
    assert result.source is seen["source"] and len(result.rows)==len(result.store.values)==6
    assert result.store.owners=={present.FACT:present.STEP.id} and len(reads)==len(writes)==6
    assert set(reads)==set(writes)=={row.source.subject for row in result.rows}
    for row in result.rows:
        assert result.store.values[k.FactRef(fact=present.FACT,subject=row.source.subject)] is row.value
        if type(row.source.value) is k.Known:
            assert type(row.value) is k.Known and type(row.value.value) is bool and row.value.value is True
            assert row.value.raw is None and row.value.basis is k.Basis.DERIVED
            assert row.value.evidence==(k.FactRef(fact=state.REPORTED_STATE,subject=row.source.subject),)
        else:assert type(row.value) is k.Unknown and row.value is row.source.value
    assert any(type(row.value) is k.Unknown for row in result.rows)
    assert {p.name:p.read_bytes() for p in root.iterdir()}==files


@pytest.mark.parametrize("phase",PHASES)
@pytest.mark.parametrize("fault",CUSTODY_FAULTS)
def test_actual_callbacks_cannot_replace_original_custody_or_dispatch_instance_shadows(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs";inputs(root);seen=capture(monkeypatch,present.PresencePack);hit=[];calls=[];subjects=set()
    def mutate():
        hit.append(True)
        mutate_custody(seen,fault,monkeypatch,present,calls)
    def event(handle,kw,kind):
        if phase!=kind:return
        subjects.add(kw["subject"])
        if (len(subjects)==6 or phase in ("stp_writer","channel_writer")) and not hit:mutate()
    read,write=FactReader.read,FactWriter.write
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is present.STEP:event(self,kw,"source_reader")
        return value
    def writing(self,**kw):
        value=write(self,**kw)
        if kw["fact"]==state.REPORTED_STATE:event(self,kw,"source_writer")
        elif kw["fact"]==present.FACT:event(self,kw,"derived_writer")
        elif kw["fact"].startswith("l2.stp."):event(self,kw,"stp_writer")
        elif kw["fact"].startswith("l2.etherchannel."):event(self,kw,"channel_writer")
        return value
    monkeypatch.setattr(FactReader,"read",reading);monkeypatch.setattr(FactWriter,"write",writing)
    if fault.endswith("_shadow"):assert len(present.build_reported_presence(root,replace(LIMITS)).rows)==6
    else:
        with pytest.raises(ValueError):present.build_reported_presence(root,replace(LIMITS))
    assert hit==[True] and calls==[]


@pytest.mark.parametrize("phase",["source_reader","derived_writer"])
@pytest.mark.parametrize("fault",SOURCE_FAULTS)
def test_last_callback_cannot_rebase_source_cells_stores_population_or_reader(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs";inputs(root);seen=capture(monkeypatch,present.PresencePack);hit=[];subjects=set()
    read,write=FactReader.read,FactWriter.write
    def plant(handle,value,subject):
        subjects.add(subject)
        if len(subjects)!=6 or hit:return value
        hit.append(True)
        return mutate_source(seen,handle,value,fault)
    def reading(self,**kw):
        value=read(self,**kw)
        return plant(self,value,kw["subject"]) if phase=="source_reader" and self.step is present.STEP else value
    def writing(self,**kw):
        value=write(self,**kw)
        if phase=="derived_writer" and kw["fact"]==present.FACT:
            changed=plant(self,kw["value"],kw["subject"])
            if changed is not kw["value"]:self.store.values[k.FactRef(fact=kw["fact"],subject=kw["subject"])]=changed
        return value
    monkeypatch.setattr(FactReader,"read",reading);monkeypatch.setattr(FactWriter,"write",writing)
    with pytest.raises(ValueError):present.build_reported_presence(root,replace(LIMITS))
    assert hit==[True]


@pytest.mark.parametrize("fact",[state.REPORTED_STATE,present.FACT])
@pytest.mark.parametrize("field,changed",[("value",False),("raw","forged"),("basis",k.Basis.DECLARED),("evidence",())])
def test_final_writer_cannot_mutate_an_earlier_already_written_value(tmp_path,monkeypatch,fact,field,changed):
    root=tmp_path/"inputs";inputs(root);write=FactWriter.write;seen=set();hit=[]
    def writing(self,**kw):
        value=write(self,**kw)
        if kw["fact"]==fact:
            seen.add(kw["subject"])
            if len(seen)==6:
                target=next(value for ref,value in self.store.values.items() if ref.subject!=kw["subject"] and type(value) is k.Known)
                hit.append(True);object.__setattr__(target,field,changed)
        return value
    monkeypatch.setattr(FactWriter,"write",writing)
    with pytest.raises(ValueError):present.build_reported_presence(root,replace(LIMITS))
    assert hit==[True]


@pytest.mark.parametrize("fault",["step","fact","declaration","value_type"])
def test_fixed_declaration_refuses_drift_before_any_parser(tmp_path,monkeypatch,fault):
    root=tmp_path/"inputs";inputs(root)
    if fault=="step":monkeypatch.setattr(present,"STEP",replace(present.STEP,reads=()))
    elif fault=="fact":monkeypatch.setattr(present,"FACT","l3.fhrp.foreign")
    elif fault=="value_type":monkeypatch.setattr(present,"DECLARATION",replace(present.DECLARATION,facts=(present.DECLARATION.facts[0],replace(present.DECLARATION.facts[1],value_type="text"))))
    else:monkeypatch.setattr(present,"DECLARATION",replace(present.DECLARATION,facts=present.DECLARATION.facts[:1]))
    monkeypatch.setattr(state.hsrp,"parse_capture",lambda *_:pytest.fail("parse before fixed declaration"))
    with pytest.raises(ValueError):present.build_reported_presence(root,replace(LIMITS))


@pytest.mark.parametrize("fault",[None,"result_clone","source_clone","store_clone","labels","cell","run_class"])
def test_live_factory_recloses_original_result_without_reparse_readers_or_writers(tmp_path,monkeypatch,fault):
    root=tmp_path/"inputs";inputs(root);parsed=[];parse=state.hsrp.parse_capture
    def parsing(capture):
        parsed.append(capture.id)
        return parse(capture)
    monkeypatch.setattr(state.hsrp,"parse_capture",parsing)
    live=present.PresenceRun.open_folder(root,replace(LIMITS))
    assert len(parsed)==len(set(parsed))==2
    monkeypatch.setattr(state.hsrp,"parse_capture",lambda *_:pytest.fail("reparsed live run"))
    monkeypatch.setattr(FactReader,"read",lambda *_a,**_k:pytest.fail("Reader in pure closure"))
    monkeypatch.setattr(FactWriter,"write",lambda *_a,**_k:pytest.fail("Writer in pure closure"))
    assert present.PresenceRun.close(live) is live.result
    assert present.PresenceRun.source_rows(live) is live.result.source.rows
    assert present.PresenceRun.presence_rows(live) is live.result.rows
    if fault is None:return
    if fault=="result_clone":live.result=replace(live.result)
    elif fault=="source_clone":object.__setattr__(live.result,"source",replace(live.result.source))
    elif fault=="store_clone":object.__setattr__(live.result,"store",state.FactStore())
    elif fault=="labels":live.labels=()
    elif fault=="cell":object.__setattr__(next(row.value for row in live.result.rows if type(row.value) is k.Known),"value",False)
    else:
        class Hook(type(live)):
            __slots__=()
            def __getattribute__(self,_name):pytest.fail("live carrier attribute hook")
        object.__setattr__(live,"__class__",Hook)
    with pytest.raises(ValueError):present.PresenceRun.close(live)


@pytest.mark.parametrize("phase,fault",[(phase,fault) for phase in ("reader","writer") for fault in first_use.HANDLE_FAULTS+first_use.DATA_FAULTS]+[("writer","value_class")])
def test_first_actual_source_operation_checks_next_handle_and_uses_frozen_arguments(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs";inputs(root);seen=capture(monkeypatch,present.PresencePack)
    read,write=FactReader.read,FactWriter.write
    ops,calls=[],[]
    def operation(self,**kw):
        writing="value" in kw
        returned=(write if writing else read)(self,**kw)
        if self.step is present.STEP and writing==(phase=="writer"):
            ops.append(kw["subject"])
            if len(ops)==1:
                if fault in first_use.HANDLE_FAULTS:first_use.poison_handle(self,fault,calls)
                else:
                    rows=seen["pack"].factory.original_presence_rows if writing else seen["pack"].factory.original_rows
                    if fault=="value_class":first_use.poison_value_class(rows[1].value,calls)
                    else:first_use.poison_data(rows,fault,calls)
        return returned
    monkeypatch.setattr(FactReader,"read",operation)
    monkeypatch.setattr(FactWriter,"write",operation)
    step,original_reads=present.STEP,present.STEP.reads
    try:
        with pytest.raises(ValueError):present.PresenceRun.open_folder(root,replace(LIMITS))
    finally:
        object.__setattr__(step,"reads",original_reads)
    assert len(ops)==(1 if fault in first_use.HANDLE_FAULTS or fault=="value_class" else 6) and calls==[]


@pytest.mark.parametrize("plant", ["original", "open", "subclass", "after_snapshot"])
def test_actual_brief_prepare_requires_private_plan_shape_before_retention(tmp_path, monkeypatch, plant):
    root = tmp_path / "inputs"
    inputs(root)
    prepare = StandbyBriefPack.prepare
    snapshot = custody.capture_context
    owners, hits, calls = [], [], []

    class OpenPlan:
        def __getattribute__(self, name):
            calls.append(name)
            pytest.fail("opened an unchecked BRIEF plan")

    def open_as_subclass(owner):
        class PlanSubclass(type(owner.plan)):
            __slots__ = ()
            __getattribute__ = OpenPlan.__getattribute__

        object.__setattr__(owner.plan, "__class__", PlanSubclass)

    def preparing(self, envelope):
        batch = prepare(self, envelope)
        owner = batch.handlers[0].parser
        owners.append(owner)
        if plant == "open":
            owner.plan = OpenPlan()
        elif plant == "subclass":
            open_as_subclass(owner)
        return batch

    def snapshotting(envelope, budgets):
        values = snapshot(envelope, budgets)
        if plant == "after_snapshot":
            open_as_subclass(owners[0])
        hits.append(True)
        return values

    monkeypatch.setattr(StandbyBriefPack, "prepare", preparing)
    monkeypatch.setattr(custody, "capture_context", snapshotting)
    if plant == "original":
        result = present.build_reported_presence(root, LIMITS)
        targets = tuple(owners[0].plan.indexed.values())
        assert len(result.rows) == 6
        assert all(any(row.target is member for member in targets) for row in result.source.rows)
    else:
        monkeypatch.setattr(state.hsrp, "parse_capture", lambda *_: pytest.fail("parsed before the plan check"))
        with pytest.raises(ValueError, match="^hsrp_presence_custody$"):
            present.build_reported_presence(root, LIMITS)
        assert hits == [True]
    assert len(owners) == 1 and hits and calls == []
