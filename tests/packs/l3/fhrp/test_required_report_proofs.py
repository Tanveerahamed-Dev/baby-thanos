"""Original-folder literal required-report proof oracle and actual final-reader boundaries."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from presence_test_support import CUSTODY_FAULTS, capture, mutate_custody
from required_report_cases import expected_scope, literal_requirement, original_inputs
from test_gateway_source import LIMITS, literal_spans, subject

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model import store
from atlas_brain.packs.l3.fhrp import reported_presence as presence
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp import required_report_proofs as proofs


def test_literal_actual_proofs_all_source_subjects_original_external_bytes_and_no_reparse(tmp_path,monkeypatch):
    root=tmp_path/"inputs"
    envelope,policies,raw,files=original_inputs(root)
    parsed,reads=[],[]
    parse,read=presence.state.hsrp.parse_capture,store.FactReader.read
    def parsing(capture):
        parsed.append(capture.id)
        return parse(capture)
    def reading(self,**kw):
        if self.step is profile.PROJECT:reads.append(kw["subject"])
        return read(self,**kw)
    monkeypatch.setattr(presence.state.hsrp,"parse_capture",parsing)
    monkeypatch.setattr(store.FactReader,"read",reading)
    _run,_result,projected=proofs.project_folder(root,replace(LIMITS),policies,raw)
    expected=literal_requirement(envelope,raw)
    assert canonical(next(iter(projected.requirements.values())))==canonical(expected)
    assert len(parsed)==len(set(parsed))==2 and reads==[expected["subject"]]
    scope,_points=expected_scope(envelope)
    assert set(projected.inputs)=={*files.values(),scope,raw}
    assert projected.header["input_artifacts"]==len(files)+2
    raw_map={sha256(item).hexdigest():item for item in projected.inputs}
    for record,fragment in projected.registry:
        selected=json.loads(raw_map[record["raw"]])
        for part in record["pointer"].split("/")[1:]:selected=selected[int(part)] if type(selected) is list else selected[part]
        assert fragment==canonical(selected)
    assert projected.header["declared_policy"]=={"raw":sha256(scope).hexdigest(),"origin":"canonical_typed_policy_input"}
    assert projected.header["external_baseline"]=={"raw":sha256(raw).hexdigest()}
    observed={("a","Vl20"):("init","Init",("203.0.113.1",)),("a","Vl10"):("active","Active",("192.0.2.2","192.0.2.1")),
        ("a","BD3329"):("standby","Standby",("198.51.100.2","198.51.100.1")),("b","BD10"):("standby","Standby",("192.0.2.3","192.0.2.99"))}
    side=json.loads(files["p4.json"])
    wanted=set()
    for target in side["targets"]:
        if target["operation"]!="iosxe.show_standby_brief":continue
        for interface,group in target["params"]["groups"]:
            entity=subject(target["node"],interface,group)
            wanted.update(((entity,"l3.fhrp.reported_state"),(entity,"l3.fhrp.reported_group_present")))
            row=projected.local[entity,"l3.fhrp.reported_state"]
            present=projected.local[entity,"l3.fhrp.reported_group_present"]
            declared=[(ref["table"],ref["row_id"]) for ref in row["evidence"] if ref["type"]=="registry"]
            assert declared==[("synthetic_p2.nodes",target["node"]),("synthetic_p4.context","round"),("synthetic_p4.targets",target["id"])]
            assert row["local"]=={"context":"round","node":"node:demo:"+target["node"],"interface":interface,"group":group,"address_family":"ipv4","protocol":"hsrp"}
            if (target["node"],interface) in observed:
                value,raw_state,addresses=observed[target["node"],interface]
                assert row["value"]=={"state":"known","basis":"observed","value":value,"raw":raw_state}
                path=next(member["path"] for member in side["captures"] if member["target"]==target["id"])
                spans=literal_spans(files[path],interface,group,raw_state,addresses)
                identity="cap:"+sha256(canonical(("atlas-brain.synthetic-p4/1",sha256(envelope.raw).hexdigest(),
                    sha256(envelope.base.raw).hexdigest(),"round",target["id"],path,sha256(files[path]).hexdigest(),envelope.registration_sha256))).hexdigest()
                leaves=row["proof"]["captures"]
                assert all(leaf["capture"]==identity and leaf["role"]=="subject" for leaf in leaves)
                assert tuple((leaf["locator"]["start"],leaf["locator"]["end"]) for leaf in leaves)==spans
                assert all(leaf["excerpt_sha256"]==sha256(files[path][start:end]).hexdigest()
                    for leaf,(start,end) in zip(leaves,spans,strict=True))
            else:assert row["value"]["reason"]=="subject_absent_from_capture" and present["source"]["same_original_unknown"] is True
            assert present["dependencies"]==[{"fact":"l3.fhrp.reported_state","subject":entity}]
    assert set(projected.local)==wanted and len(wanted)==12
    assert projected.header["source_denominator"]=={"declared_groups":6,"reported_groups":4,"unknown_groups":2}
    assert {p.name:p.read_bytes() for p in root.iterdir()}==files


@pytest.mark.parametrize("fault",CUSTODY_FAULTS)
def test_final_projection_reader_recloses_all_original_source_custody_and_fresh_proofs(tmp_path,monkeypatch,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root)
    seen=capture(monkeypatch,presence.PresencePack)
    read=store.FactReader.read
    calls,hit=[],[]
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is profile.PROJECT:
            hit.append(True)
            mutate_custody(seen,fault,monkeypatch,presence,calls)
        return value
    monkeypatch.setattr(store.FactReader,"read",reading)
    if fault.endswith("_shadow"):assert len(proofs.project_folder(root,replace(LIMITS),policies,raw)[2].requirements)==1
    else:
        with pytest.raises(ValueError):proofs.project_folder(root,replace(LIMITS),policies,raw)
    assert hit==[True] and calls==[]


@pytest.mark.parametrize("phase,fault",
    [("early",fault) for fault in ("store","step","class","owners","values","poisoned_key","next_row_class","next_subject")]
    +[("final",fault) for fault in ("value","label","proof","result_clone","run_class","unselected_unknown","presence")])
def test_actual_projection_next_use_and_final_semantics_use_original_current_graphs(tmp_path,monkeypatch,phase,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root,multiple=True)
    read,current=store.FactReader.read,proofs.required.RequiredReportRun.close
    seen,calls,reads={},[],[]
    def closing(self):
        result=current(self)
        seen["run"]=self
        return result
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
    class Text(str):
        __hash__=str.__hash__
        def __eq__(self,_other):calls.append("equality");raise AssertionError
        def encode(self,*_args,**_kw):calls.append("encode");raise AssertionError
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is profile.PROJECT:
            reads.append(kw["subject"])
            run=seen["run"]
            if phase=="early" and len(reads)==1:
                next_row=next(row for row in run.result.rows if row.subject!=kw["subject"])
                if fault=="store":object.__setattr__(self,"store",Foreign())
                elif fault=="step":object.__setattr__(self,"step",replace(self.step))
                elif fault=="owners":self.store.owners=dict(self.store.owners)
                elif fault=="values":self.store.values=dict(self.store.values)
                elif fault=="poisoned_key":object.__setattr__(next(iter(self.store.values)),"fact",Text("l3.fhrp.required_report_missing"))
                elif fault=="next_subject":object.__setattr__(next_row,"subject",Text(next_row.subject))
                else:
                    target=self if fault=="class" else next_row
                    class Hook(type(target)):
                        __slots__=()
                        __getattribute__=Foreign.__getattribute__
                    object.__setattr__(target,"__class__",Hook)
            elif phase=="final" and len(reads)==2:
                if fault=="value":object.__setattr__(run.result.rows[0].value,"value",True)
                elif fault=="label":object.__setattr__(run.baseline.rows[0].scope,"policy_id","forged")
                elif fault=="proof":
                    ref=next(ref for row in run.live.source.rows for ref in row.value.evidence if type(ref) is k.EvidenceRef and type(ref.locator) is k.ByteSpan)
                    object.__setattr__(ref.locator,"start",ref.locator.start+1)
                elif fault=="result_clone":run.result=replace(run.result)
                elif fault=="presence":object.__setattr__(next(row.value for row in run.live.result.rows if type(row.value) is k.Known),"value",False)
                elif fault=="unselected_unknown":object.__setattr__(next(row.value for row in run.live.source.rows if type(row.value) is k.Unknown),"evidence",())
                else:
                    class Hook(type(run)):
                        __slots__=()
                        __getattribute__=Foreign.__getattribute__
                    object.__setattr__(run,"__class__",Hook)
        return value
    monkeypatch.setattr(proofs.required.RequiredReportRun,"close",closing)
    monkeypatch.setattr(store.FactReader,"read",reading)
    with pytest.raises(ValueError):proofs.project_folder(root,replace(LIMITS),policies,raw)
    expected=1 if phase=="early" and fault not in ("next_row_class","next_subject") else 2
    assert len(reads)==expected and calls==[]


@pytest.mark.parametrize("fault",["reader_class","store_copy","step_copy","owners_copy","step_reads","profile_step"])
def test_actual_projection_binder_closes_original_handle_before_first_read(tmp_path,monkeypatch,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_files=original_inputs(root)
    bind,read=store.bind_reader,store.FactReader.read
    project_step,original_reads=profile.PROJECT,profile.PROJECT.reads
    binds,reads,calls=[],[],[]
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
    def binding(data,*,step):
        reader=bind(data,step=step)
        if step is not project_step:return reader
        binds.append(reader)
        if fault=="reader_class":return Foreign()
        if fault=="store_copy":
            copied=store.FactStore()
            copied.owners,copied.values=dict(data.owners),dict(data.values)
            return bind(copied,step=step)
        if fault=="step_copy":return bind(data,step=replace(step))
        if fault=="owners_copy":data.owners=dict(data.owners)
        elif fault=="step_reads":object.__setattr__(step,"reads",())
        else:monkeypatch.setattr(profile,"PROJECT",replace(step))
        return reader
    def reading(self,**kw):
        if binds:reads.append(kw["subject"])
        return read(self,**kw)
    monkeypatch.setattr(store,"bind_reader",binding)
    monkeypatch.setattr(store.FactReader,"read",reading)
    try:
        with pytest.raises(ValueError):proofs.project_folder(root,replace(LIMITS),policies,raw)
    finally:
        object.__setattr__(project_step,"reads",original_reads)
    assert len(binds)==1 and reads==[] and calls==[]
