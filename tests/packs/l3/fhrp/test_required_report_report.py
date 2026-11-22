"""Actual canonical four-file C01 endpoint; literal record oracle, reopening, budgets and refusal."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from required_report_cases import expected_scope, literal_requirement, original_inputs
from test_gateway_source import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.model import store
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp import required_report_report as report
from atlas_brain.packs.l3.fhrp import required_report_run as required


def reopen(files):
    assert set(files)=={"result.json","facts/fhrp_local.jsonl","facts/fhrp_requirement.jsonl","MANIFEST.sha256"}
    expected=b"".join((sha256(raw).hexdigest()+"  "+name+"\n").encode("ascii")
        for name,raw in sorted(files.items()) if name!="MANIFEST.sha256")
    assert files["MANIFEST.sha256"]==expected
    result=json.loads(files["result.json"])
    raws={row["sha256"]:bytes.fromhex(row["data"]) for row in result["raws"]}
    assert all(sha256(raw).hexdigest()==digest for digest,raw in raws.items())
    for record in result["registry_records"]:
        selected=json.loads(raws[record["raw"]])
        for part in record["pointer"].split("/")[1:]:selected=selected[int(part)] if type(selected) is list else selected[part]
        assert bytes.fromhex(record["canonical"])==canonical(selected)
    return result,raws,[json.loads(line) for line in files["facts/fhrp_requirement.jsonl"].splitlines()]


@pytest.mark.parametrize("case,reason",[("ready",None),("permission",None),("baseline","no_baseline"),
    ("unmatched","no_baseline"),("population","denominator_open"),("domain","join_unproven"),("binding","join_unproven"),
    ("baseline_domain","no_baseline"),("population_domain","denominator_open"),("baseline_missing","no_baseline"),
    ("missing","not_collected"),("both","not_collected"),("partial","parse_partial"),("error","capture_error"),
    ("truncated","capture_truncated"),("conflict","conflicting_evidence"),("header","subject_absent_from_capture")])
def test_actual_endpoint_complete_files_secondary_needs_determinism_and_original_input_reopening(tmp_path,case,reason):
    root=tmp_path/"inputs"
    envelope,policies,raw,original=original_inputs(root,case)
    files=report.analyse_required_reports(root,replace(LIMITS),policies,raw)
    result,raws,rows=reopen(files)
    row,=rows
    if reason is None:assert row["value"]=={"state":"known","basis":"derived","value":False,"raw":None}
    else:assert row["value"]["state"]=="unknown" and row["value"]["reason"]==reason
    assert [premise["name"] for premise in row["premises"]]==["baseline","population","binding"]
    assert len(row["operands"])>0 and len(files["facts/fhrp_local.jsonl"].splitlines())==12
    assert all(blob in raws.values() for blob in original.values())
    assert result["health"]=="not_assessed" and result["true_missing_report"]=="not_implemented"
    scope_raw=raws[result["declared_policy"]["raw"]]
    assert json.loads(scope_raw)["gateways"][0]["id"]==policies[0].id
    assert result["external_baseline"] is None if raw is None else raws[result["external_baseline"]["raw"]]==raw
    assert result["input_artifacts"]==len(original)+1+(raw is not None)
    assert result["input_bytes"]==sum(map(len,original.values()))+len(scope_raw)+(0 if raw is None else len(raw))
    if case=="ready":
        assert files["facts/fhrp_requirement.jsonl"]==canonical(literal_requirement(envelope,raw))+b"\n"
        expected_policy,_points=expected_scope(envelope)
        assert scope_raw==expected_policy
    assert report.analyse_required_reports(root,replace(LIMITS),policies,raw)==files
    assert {path.name:path.read_bytes() for path in root.iterdir()}==original


@pytest.mark.parametrize("boundary",["exact","bundle","artifact","count"])
def test_actual_endpoint_accounts_all_original_input_and_exact_final_file_budgets(tmp_path,monkeypatch,boundary):
    root=tmp_path/"inputs"
    envelope,policies,raw,original=original_inputs(root)
    files=report.analyse_required_reports(root,replace(LIMITS),policies,raw)
    scope,_points=expected_scope(envelope)
    inputs=tuple(original.values())+(scope,raw)
    limits=replace(LIMITS,bundle_bytes=sum(map(len,inputs))+sum(map(len,files.values()))-(boundary=="bundle"),
        artifact_bytes=max(*map(len,inputs),*map(len,files.values()))-(boundary=="artifact"),
        artifacts=len(inputs)+4-(boundary=="count"))
    read=store.FactReader.read
    projected=[]
    def reading(self,**kw):
        if self.step is profile.PROJECT:projected.append(kw["subject"])
        return read(self,**kw)
    monkeypatch.setattr(store.FactReader,"read",reading)
    if boundary=="exact":assert report.analyse_required_reports(root,limits,policies,raw)==files
    else:
        with pytest.raises(BudgetExceeded):report.analyse_required_reports(root,limits,policies,raw)
    assert len(projected)==1


@pytest.mark.parametrize("fault",["early_handle","final_value","final_result_clone"])
def test_canonical_entry_never_publishes_after_actual_early_or_final_projection_mutation(tmp_path,monkeypatch,fault):
    root=tmp_path/"inputs"
    _envelope,policies,raw,_original=original_inputs(root,multiple=True)
    read,current=store.FactReader.read,required.RequiredReportRun.close
    seen,reads={},[]
    def closing(self):
        result=current(self)
        seen["run"]=self
        return result
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is profile.PROJECT:
            reads.append(kw["subject"])
            if fault=="early_handle" and len(reads)==1:object.__setattr__(self,"store",store.FactStore())
            elif fault!="early_handle" and len(reads)==2:
                if fault=="final_value":object.__setattr__(seen["run"].result.rows[0].value,"value",True)
                else:seen["run"].result=replace(seen["run"].result)
        return value
    monkeypatch.setattr(required.RequiredReportRun,"close",closing)
    monkeypatch.setattr(store.FactReader,"read",reading)
    with pytest.raises(ValueError):report.analyse_required_reports(root,replace(LIMITS),policies,raw)
    assert len(reads)==(1 if fault=="early_handle" else 2)


@pytest.mark.parametrize("fault", ["result_copy", "store_values_copy", "source_capture_raw"])
def test_endpoint_recloses_the_actual_run_after_real_wire_returns(tmp_path, monkeypatch, fault):
    root = tmp_path / "inputs"
    _, policies, raw, _ = original_inputs(root)
    close, render = required.RequiredReportRun.close, report.wire.render
    runs, rendered = [], []

    def closing(run):
        result = close(run)
        if not runs:
            runs.append(run)
        return result

    def rendering(*args):
        files = render(*args)
        rendered.append(files)
        assert len(runs) == 1
        (run,) = runs
        if fault == "result_copy":
            run.result = replace(run.result)
        elif fault == "store_values_copy":
            run.result.store.values = dict(run.result.store.values)
        else:
            capture = run.live.source.executed[0].receipt.capture
            object.__setattr__(capture, "raw", capture.raw + b"\n")
        return files

    monkeypatch.setattr(required.RequiredReportRun, "close", closing)
    monkeypatch.setattr(report.wire, "render", rendering)
    with pytest.raises(ValueError):
        report.analyse_required_reports(root, replace(LIMITS), policies, raw)
    (files,) = rendered
    _, _, (row,) = reopen(files)
    assert row["value"] == {"state": "known", "basis": "derived", "value": False, "raw": None}
