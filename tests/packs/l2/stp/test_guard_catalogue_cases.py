"""Original EI-R04 catalogue twins and canonical-byte oracle sensitivity; no runtime qualification."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_guard_cases import documents, echo, objects, policy_pins, save

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.runner import p4_guard_policy as api
from tools import p4_guard_cases as old
from tools import p4_guard_catalogue_cases as cases


def prepared(root,case):
    inputs=cases.members(case)
    root.mkdir()
    for name,raw in inputs.items():(root/name).write_bytes(raw)
    reports=api.report_guard_comparisons(root,Budgets(1000000,1000000,1000),cases.caller_policy(case))
    return inputs,reports


@pytest.mark.parametrize("case",tuple(cases.CASES))
def test_all_original_catalogue_twins_retain_complete_operands_proofs_gaps_and_denominators(tmp_path,capsys,case):
    inputs,reports=prepared(tmp_path/"inputs",case)
    value=cases.validate(reports,inputs,case)
    cases.validate_retained(value,case)
    with capsys.disabled():
        print("P4_R04_RETAINED="+canonical(value).decode("ascii"))
    assert value["catalogue"]=="baby-thanos.p4.synthetic/1" and value["alias"]=="EI-R04"
    assert value["historical_mapping"]=="UNVERIFIED" and value["generator"]=="p4_guard_catalogue_cases/1"
    assert value["denominator"]=={"declared_policies":1,"declared_participant_occurrences":2}
    assert value["coverage"]["reason"]=="denominator_open"
    finding,=value["findings"]
    assert (finding["state"],finding["reason"],finding["hops"][-1]["id"])==cases.CASES[case][2:]
    assert {point["target_id"] for point in value["policy"]["value"]["policies"][0]["participants"]}=={"left","right"}
    assert len(value["operands"])==4 and len({row["subject"] for row in value["operands"]})==2
    if case=="U03-partial":
        left_guard=next(row for row in value["operands"] if row["target"]=="left" and row["fact"]==cases.GUARD)
        right_role=next(row for row in value["operands"] if row["target"]=="right" and row["fact"]==cases.ROLE)
        assert (left_guard["state"],left_guard["reason"])==("unknown","field_not_printed")
        assert (right_role["state"],right_role["reason"])==("unknown","parse_partial")
    assert {row["fact"] for row in value["operands"]}=={cases.ROLE,cases.GUARD}
    assert all(bytes.fromhex(record["hex"])==inputs[name] and record["sha256"]==sha256(inputs[name]).hexdigest()
        for name,record in value["original_inputs"].items())
    assert all(bytes.fromhex(record["hex"])==reports[name] and record["sha256"]==sha256(reports[name]).hexdigest()
        for name,record in value["reports"].items())
    assert {p.name:p.read_bytes() for p in (tmp_path/"inputs").iterdir()}==inputs
    if case in ("U02","C01-missing"):
        side=json.loads(inputs["p4.json"])
        assert {target["id"] for target in side["targets"]}=={"left","right"}
        assert {capture["target"] for capture in side["captures"]}=={"left"} and "right.txt" not in inputs


@pytest.mark.parametrize("plant",["guard_int","scope_int","denominator_bool","secondary_need",
    "drop_subject","proof","priority","coverage"])
def test_resealed_artifacts_cannot_weaken_literal_oracle_including_secondary_state(tmp_path,plant):
    case=("C01-partial" if plant=="secondary_need" else "U03-scope-exclusion" if plant=="priority"
        else "U02" if plant=="drop_subject" else "F01")
    inputs,reports=prepared(tmp_path/"inputs",case)
    values=documents(reports)
    header,facts,finding=values["result.json"],values[old.FACTS],values[old.CHECKS][0]
    left=next(row for row in facts if row["target"]=="left" and row["fact"]==cases.GUARD)
    if plant=="guard_int":
        assert left["value"] is True
        left["value"]=1;echo(values,left)
    elif plant=="scope_int":
        assert finding["hops"][0]["state"]["value"] is True
        finding["hops"][0]["state"]["value"]=1
    elif plant=="denominator_bool":header["denominator"]["declared_policies"]=True
    elif plant=="secondary_need":
        right=next(row for row in facts if row["target"]=="right" and row["fact"]==cases.GUARD)
        assert right["state"]=="unknown" and right["reason"]=="parse_partial" and right["next_evidence"]
        right["next_evidence"]=[];echo(values,right)
    elif plant=="drop_subject":
        values[old.FACTS]=[row for row in facts if row["target"]!="right"]
        right=finding["right"]
        for item in tuple(objects(values)):
            if isinstance(item.get("evidence"),list):
                item["evidence"]=[ref for ref in item["evidence"] if ref.get("subject")!=right]
        values[old.POLICY]["policies"][0]["participants"]=values[old.POLICY]["policies"][0]["participants"][:1]
        finding["right"]=finding["left"]
        header["denominator"]["declared_participant_occurrences"]=1
        policy_pins(values)
    elif plant=="proof":
        proof=next(ref for ref in left["evidence"] if ref["kind"]=="capture")
        proof["end"]+=1;echo(values,left)
    elif plant=="priority":
        assert finding["hops"][0]["state"]["reason"]=="analysis_gap"
        finding["state"],finding["reason"]="not_applicable","role_excludes"
    else:header["coverage"]["reason"]="as_of_missing"
    save(reports,values)
    with pytest.raises(ValueError):cases.validate(reports,inputs,case)


@pytest.mark.parametrize("plant",["value","span","foreign"])
def test_public_reports_cannot_qualify_coherent_source_and_proof_substitution(tmp_path,monkeypatch,plant):
    original=api.stp.build_root_guard_global
    hit=[]
    def changed(*args,**kwargs):
        source=original(*args,**kwargs)
        row=next(row for row in source.result.rows if row.target.node.id=="a")
        value=row.value
        assert type(value) is k.Known and value.value is True
        if plant=="value":forged=replace(value,value=False,raw="disabled")
        elif plant=="foreign":
            donor=next(row.value for row in source.result.rows if row.target.node.id=="b")
            forged=replace(value,value=False,raw="disabled",evidence=donor.evidence)
        else:
            ref=next(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
            capture=next(out.receipt.capture for out in source.execution.executed if out.receipt.capture.id==ref.capture)
            span=k.ByteSpan(start=ref.locator.start+1,end=ref.locator.end+1)
            proof=replace(ref,locator=span,excerpt_sha256=sha256(capture.raw[span.start:span.end]).hexdigest())
            forged=replace(value,evidence=tuple(proof if item is ref else item for item in value.evidence))
        object.__setattr__(row,"value",forged)
        source.result.store.values[k.FactRef(fact=api.stp.ROOT_GUARD,subject=row.subject)]=forged
        hit.append(True)
        return source
    monkeypatch.setattr(api.stp,"build_root_guard_global",changed)
    with pytest.raises(ValueError):
        inputs,reports=prepared(tmp_path/"inputs","F01")
        cases.validate(reports,inputs,"F01")
    assert hit==[True]
