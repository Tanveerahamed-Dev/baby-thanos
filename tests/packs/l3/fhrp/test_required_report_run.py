"""One actual required-report folder run, original premises and final callback regressions."""
from copy import copy
from dataclasses import replace

import pytest
from presence_test_support import CUSTODY_FAULTS, capture, mutate_custody
from required_report_cases import budget_inputs, forbid_observations, original_inputs
from test_gateway_source import LIMITS

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model import store
from atlas_brain.packs.l3.fhrp import reported_presence as presence
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp import required_report_run as required


@pytest.mark.parametrize("case,reason",[
    ("ready",None),("permission",None),("baseline",k.UnknownReason.NO_BASELINE),("unmatched",k.UnknownReason.NO_BASELINE),
    ("population",k.UnknownReason.DENOMINATOR_OPEN),("domain",k.UnknownReason.JOIN_UNPROVEN),("binding",k.UnknownReason.JOIN_UNPROVEN),
    ("baseline_domain",k.UnknownReason.NO_BASELINE),("population_domain",k.UnknownReason.DENOMINATOR_OPEN),
    ("baseline_missing",k.UnknownReason.NO_BASELINE),("missing",k.UnknownReason.NOT_COLLECTED),("both",k.UnknownReason.NOT_COLLECTED),
    ("partial",k.UnknownReason.PARSE_PARTIAL),("error",k.UnknownReason.CAPTURE_ERROR),
    ("truncated",k.UnknownReason.CAPTURE_TRUNCATED),("conflict",k.UnknownReason.CONFLICTING_EVIDENCE),
    ("header",k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE),
])
def test_actual_single_admission_parse_complete_reads_primary_identity_and_secondary_premises(tmp_path,monkeypatch,case,reason):
    root=tmp_path/"inputs"
    _envelope,policies,raw,files=original_inputs(root,case)
    read,parse,admit=store.FactReader.read,presence.state.hsrp.parse_capture,p4.admit_folder
    reads,parsed,admitted=[],[],[]
    def reading(self,**kw):
        if self.step is profile.STEP:reads.append(kw["subject"])
        return read(self,**kw)
    def parsing(capture):
        parsed.append(capture.id)
        return parse(capture)
    def admitting(*args,**kwargs):
        admitted.append(True)
        return admit(*args,**kwargs)
    monkeypatch.setattr(store.FactReader,"read",reading)
    monkeypatch.setattr(presence.state.hsrp,"parse_capture",parsing)
    monkeypatch.setattr(p4,"admit_folder",admitting)
    run=required.RequiredReportRun(root,replace(LIMITS),policies,raw)
    result=required.RequiredReportRun.close(run)
    row,=result.rows
    with pytest.raises(ValueError):required.RequiredReportRun.read_presence(run)
    wanted_parses=0 if case=="both" else 1 if "missing" in case else 2
    assert admitted==[True] and len(parsed)==len(set(parsed))==wanted_parses
    assert len(reads)==len(set(reads))==6 and len(result.store.values)==1 and row.requirement is run.baseline.rows[0]
    if reason is None:
        assert type(row.value) is k.Known and type(row.value.value) is bool and row.value.value is False
        assert row.value.raw is None and row.value.basis is k.Basis.DERIVED
        assert row.value.evidence==row.requirement.baseline.evidence+row.requirement.population.evidence+row.requirement.binding.evidence+tuple(
            k.FactRef(fact=profile.PRESENCE,subject=operand.source.subject) for operand in row.operands)
        assert any(type(actual.value) is k.Unknown for actual in run.live.result.rows)
    else:
        assert type(row.value) is k.Unknown and row.value.reason is reason
        primary=row.requirement.primary_gap
        assert row.value is (primary if primary is not None else next(operand.value for operand in row.operands if type(operand.value) is k.Unknown))
    held=run.live.original_premises.cells[0]
    assert all(value is original for value,original in zip(
        (row.requirement.baseline,row.requirement.population,row.requirement.binding),held[2:5],strict=True))
    assert {p.name:p.read_bytes() for p in root.iterdir()}==files


@pytest.mark.parametrize("phase",["presence_reader","predicate_writer"])
@pytest.mark.parametrize("fault",CUSTODY_FAULTS)
def test_final_real_callbacks_preserve_every_original_custody_control(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root)
    seen=capture(monkeypatch,presence.PresencePack)
    read,write=store.FactReader.read,store.FactWriter.write
    hit,calls,subjects=[],[],set()
    def plant(subject):
        subjects.add(subject)
        if hit or phase=="presence_reader" and len(subjects)!=6:return
        hit.append(True)
        mutate_custody(seen,fault,monkeypatch,presence,calls)
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is profile.STEP:plant(kw["subject"])
        return value
    def writing(self,**kw):
        value=write(self,**kw)
        if phase=="predicate_writer" and kw["fact"]==profile.MISSING:plant(kw["subject"])
        return value
    if phase=="presence_reader":monkeypatch.setattr(store.FactReader,"read",reading)
    monkeypatch.setattr(store.FactWriter,"write",writing)
    if fault.endswith("_shadow"):assert len(required.RequiredReportRun(root,replace(LIMITS),policies,raw).result.rows)==1
    else:
        with pytest.raises(ValueError):required.RequiredReportRun(root,replace(LIMITS),policies,raw)
    assert hit==[True] and calls==[]


@pytest.mark.parametrize("phase",["presence_reader","predicate_writer"])
@pytest.mark.parametrize("fault",["policy","raw","primary","population","binding","unselected_unknown","reader_store","reader_step","clone",
    "run_class","live_clone","baseline_clone","label"])
def test_final_actual_reads_and_writes_reclose_declared_secondary_and_unselected_graphs(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root,"baseline" if fault=="primary" else "ready")
    reading_stage=required.RequiredReportRun.read_presence
    read,write=store.FactReader.read,store.FactWriter.write
    seen,hit,subjects={},[],set()
    def recording(self):
        seen["owner"]=self
        return reading_stage(self)
    def plant(handle,value,subject):
        subjects.add(subject)
        if hit or phase=="presence_reader" and len(subjects)!=6:return value
        hit.append(True)
        owner=seen["owner"]
        live=owner.live
        prepared=owner.baseline
        class Hook(type(owner)):
            __slots__=()
            def __getattribute__(self,_name):pytest.fail("required Run hook")
        if fault=="policy":object.__setattr__(policies[0],"vlan",11)
        elif fault=="raw":object.__setattr__(live.requirements,"baseline_raw",b"{}")
        elif fault=="primary":object.__setattr__(prepared.rows[0].primary_gap,"next_evidence",())
        elif fault=="population":object.__setattr__(prepared.rows[0].population,"raw","forged")
        elif fault=="binding":object.__setattr__(prepared.rows[0].binding,"raw","forged")
        elif fault=="unselected_unknown":object.__setattr__(next(row.value for row in live.source.rows if type(row.value) is k.Unknown),"evidence",())
        elif fault=="reader_store":object.__setattr__(handle,"store",store.FactStore())
        elif fault=="reader_step":object.__setattr__(handle,"step",replace(handle.step))
        elif fault=="clone":return replace(value)
        elif fault=="run_class":object.__setattr__(owner,"__class__",Hook)
        elif fault=="live_clone":owner.live=copy(live)
        elif fault=="baseline_clone":owner.baseline=replace(prepared)
        else:object.__setattr__(prepared.rows[0].scope,"policy_id","forged")
        return value
    def reading(self,**kw):
        value=read(self,**kw)
        return plant(self,value,kw["subject"]) if self.step is profile.STEP else value
    def writing(self,**kw):
        value=write(self,**kw)
        if phase=="predicate_writer" and kw["fact"]==profile.MISSING:
            changed=plant(self,kw["value"],kw["subject"])
            if changed is not kw["value"]:self.store.values[k.FactRef(fact=kw["fact"],subject=kw["subject"])]=changed
        return value
    monkeypatch.setattr(required.RequiredReportRun,"read_presence",recording)
    if phase=="presence_reader":monkeypatch.setattr(store.FactReader,"read",reading)
    monkeypatch.setattr(store.FactWriter,"write",writing)
    with pytest.raises(ValueError):required.RequiredReportRun(root,replace(LIMITS),policies,raw)
    assert hit==[True]


@pytest.mark.parametrize("field,changed",[("value",True),("raw","forged"),("basis",k.Basis.DECLARED),("evidence",())])
def test_last_predicate_writer_cannot_mutate_an_earlier_requirement_cell(tmp_path,monkeypatch,field,changed):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root,multiple=True)
    write=store.FactWriter.write
    hit,subjects=[],set()
    def writing(self,**kw):
        result=write(self,**kw)
        if kw["fact"]==profile.MISSING:
            subjects.add(kw["subject"])
            if len(subjects)==2:
                earlier=next(value for ref,value in self.store.values.items() if ref.subject!=kw["subject"])
                object.__setattr__(earlier,field,changed)
                hit.append(True)
        return result
    monkeypatch.setattr(store.FactWriter,"write",writing)
    with pytest.raises(ValueError):required.RequiredReportRun(root,replace(LIMITS),policies,raw)
    assert hit==[True]


@pytest.mark.parametrize("limit",["exact","bundle","count","artifact","artifact_boundary"])
def test_original_source_policy_and_baseline_budget_boundaries_before_any_parser(tmp_path,monkeypatch,limit):
    root=tmp_path/"inputs"
    if limit!="exact":forbid_observations(monkeypatch)
    limits,policies,raw=budget_inputs(root,limit)
    if limit=="exact":
        run=required.RequiredReportRun(root,limits,policies,raw)
        assert run.result.rows[0].value.value is False
    else:
        with pytest.raises(BudgetExceeded):required.RequiredReportRun(root,limits,policies,raw)
