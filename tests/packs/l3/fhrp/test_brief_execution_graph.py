"""Source-only regressions for parser-graph closure after the final real Reader."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_gateway_source import LIMITS, folder, literal_spans

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import brief_execution_graph as graph
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack


def prepared(root,mode="normal"):
    files=folder(root,mode if mode in ("hsrp","both") else None)
    side=json.loads(files["p4.json"])
    if mode in ("partial","error","truncated","conflict","unmapped"):
        raw=files["hsrp.txt"]
        line=next(line for line in raw.splitlines(keepends=True) if line.startswith(b"Vl10 "))
        files["hsrp.txt"]=(raw+b"unmodelled row\n" if mode=="partial" else b"% Command failed\n" if mode=="error"
            else raw+b"[truncated]\n" if mode=="truncated" else raw+line if mode=="conflict"
            else raw.replace(line,line.replace(b"Active",b"Listen")))
    for row in side["captures"]:row["sha256"]=sha256(files[row["path"]]).hexdigest()
    for name,raw in files.items():(root/name).write_bytes(canonical(side) if name=="p4.json" else raw)
    channel,owner=SummaryPack(LIMITS),StandbyBriefPack(LIMITS)
    tree=stp.build_root_guard_global(root,LIMITS,peers=(channel,owner))
    channel.finish(tree.execution);source=owner.finish(tree.execution)
    return owner,source,tree.execution


def final_read(owner,source,execution,monkeypatch,mutate):
    read=FactReader.read;expected={row.subject for row in source.rows};seen=set();hit=[]
    def reading(self,**kw):
        value=read(self,**kw)
        if self.step is state.SOURCE_STEP:
            seen.add(kw["subject"])
            if seen==expected:
                hit.append(kw["subject"]);mutate()
        return value
    monkeypatch.setattr(FactReader,"read",reading)
    owner.owner.validate_gateway_source_values(source,bind_reader(source.store,step=state.SOURCE_STEP),execution.executed)
    assert len(hit)==1
    return hit


@pytest.mark.parametrize("mode",["normal","hsrp","both","partial","error","truncated","conflict","unmapped"])
def test_real_original_outputs_keep_literal_proofs_unknown_facts_and_original_input_bytes(tmp_path,mode):
    root=tmp_path/"inputs";owner,source,execution=prepared(root,mode)
    before={p.name:p.read_bytes() for p in root.iterdir()}
    facts=tuple((row,row.value) for row in source.rows)
    claims=tuple(state.reported_state_proofs(output) for output in source.executed)
    assert graph.validate_brief_execution_graph(execution.executed) is None
    assert tuple(state.reported_state_proofs(output) for output in source.executed)==claims
    assert all(row.value is value for row,value in facts) and len(facts)==6
    assert all(type(row.value) is k.Known or type(row.value) is k.Unknown for row in source.rows)
    for row in source.rows:
        if type(row.value) is k.Known:
            capture=next(output.receipt.capture for output in source.executed if output.receipt.capture.source==row.target.node.key)
            refs=tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            expected=literal_spans(capture.raw,row.interface,row.group,row.value.raw,
                ("203.0.113.1",) if row.interface=="Vl20" else ("192.0.2.2","192.0.2.1") if row.interface=="Vl10" else ("198.51.100.2","198.51.100.1") if row.interface=="BD3329" else ("192.0.2.3","192.0.2.99"))
            assert tuple((ref.locator.start,ref.locator.end) for ref in refs)==expected
            assert all(ref.capture==capture.id and ref.excerpt_sha256==sha256(capture.raw[a:z]).hexdigest()
                for ref,(a,z) in zip(refs,expected,strict=True))
        else:assert source.store.values[k.FactRef(fact=state.REPORTED_STATE,subject=row.subject)] is row.value
    assert {p.name:p.read_bytes() for p in root.iterdir()}==before
    assert owner.owner.finished


@pytest.mark.parametrize("field",[
    "operation","codec","lines","context","owner","registration","value","raw","span","span_start",
    "endpoint","endpoint_token","af","af_spans","record","record_fields","quality","tokens","accounting",
    "reason","row_reason","row","row_span","carrier","receipt","capture","result","parsed","tuple",
])
def test_final_real_reader_opaque_graphs_refuse_before_equality_hash_property_or_deepcopy(tmp_path,monkeypatch,field):
    owner,source,execution=prepared(tmp_path/"inputs");calls=[]
    output=next(item for item in execution.executed if item.receipt.capture.operation==state.hsrp.OP and item.value.rows)
    parsed=output.value;row=parsed.rows[0];fact=next(item.value for item in source.rows if type(item.value) is k.Known)
    original=fact.value
    class Opaque(str):
        def __eq__(self,_other):calls.append("equality");object.__setattr__(fact,"value","forged");return True
        def __hash__(self):calls.append("hash");raise AssertionError
        def __deepcopy__(self,_memo):calls.append("deepcopy");raise AssertionError
        def __iter__(self):calls.append("iteration");raise AssertionError
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
        def __eq__(self,_other):calls.append("equality");return True
        def __hash__(self):calls.append("hash");raise AssertionError
    class ForeignTuple(tuple):
        def __iter__(self):calls.append("iteration");raise AssertionError
    def mutate():
        if field in ("operation","codec"):object.__setattr__(output.receipt.capture,field,Opaque(getattr(output.receipt.capture,field)))
        elif field=="lines":object.__setattr__(output.receipt.capture,"lines",ForeignTuple(output.receipt.capture.lines))
        elif field in ("context","owner"):object.__setattr__(output.receipt,field,Opaque(getattr(output.receipt,field)))
        elif field=="registration":object.__setattr__(output.receipt,"registration_sha256",Opaque(output.receipt.registration_sha256))
        elif field=="value":object.__setattr__(row.interface,"value",Opaque(row.interface.value))
        elif field=="raw":object.__setattr__(row.interface,"raw",Opaque(row.interface.raw))
        elif field=="span":object.__setattr__(row.interface,"span",Foreign())
        elif field=="span_start":object.__setattr__(row.interface.span,"start",Foreign())
        elif field=="endpoint":object.__setattr__(row.active,"kind",Opaque(row.active.kind))
        elif field=="endpoint_token":object.__setattr__(row.active,"token",Foreign())
        elif field=="af":object.__setattr__(row,"address_family",Opaque(row.address_family))
        elif field=="af_spans":object.__setattr__(row,"af_spans",ForeignTuple(row.af_spans))
        elif field=="record":object.__setattr__(parsed.parse.records[0],"rule_id",Opaque(parsed.parse.records[0].rule_id))
        elif field=="record_fields":object.__setattr__(parsed.parse.records[0],"fields",ForeignTuple(parsed.parse.records[0].fields))
        elif field=="quality":object.__setattr__(parsed.parse,"quality",Opaque(parsed.parse.quality))
        elif field=="tokens":object.__setattr__(parsed.parse,"tokens",ForeignTuple(parsed.parse.tokens))
        elif field=="accounting":object.__setattr__(parsed.parse,"lines",ForeignTuple(parsed.parse.lines))
        elif field=="reason":object.__setattr__(parsed,"reason",Foreign())
        elif field=="row_reason":object.__setattr__(row,"reason",Foreign())
        elif field=="row":object.__setattr__(parsed,"rows",(Foreign(),*parsed.rows[1:]))
        elif field=="row_span":object.__setattr__(row,"span",Foreign())
        elif field=="carrier":object.__setattr__(execution,"executed",(Foreign(),*execution.executed[1:]))
        elif field=="receipt":object.__setattr__(output,"receipt",Foreign())
        elif field=="capture":object.__setattr__(output.receipt,"capture",Foreign())
        elif field=="result":object.__setattr__(output,"value",Foreign())
        elif field=="parsed":object.__setattr__(parsed,"parse",Foreign())
        else:object.__setattr__(execution,"executed",ForeignTuple(execution.executed))
    final_read(owner,source,execution,monkeypatch,mutate)
    with pytest.raises(ValueError):graph.validate_brief_execution_graph(execution.executed)
    assert calls==[] and fact.value==original


@pytest.mark.parametrize("field",["state","evidence","locator"])
def test_unmapped_state_leaf_foreign_metaclasses_refuse_without_callbacks(tmp_path,monkeypatch,field):
    owner,source,execution=prepared(tmp_path/"inputs","unmapped");calls=[]
    token=next(token for output in source.executed for row in output.value.rows
        for token in (row.state,) if type(token.value) is k.Unknown)
    class Alias(type):
        def __eq__(cls,_other):calls.append("equality");raise AssertionError
        def __hash__(cls):calls.append("hash");raise AssertionError
    class Foreign(metaclass=Alias):
        @property
        def __class__(self):calls.append("class");raise AssertionError
    def mutate():
        if field=="state":object.__setattr__(token,"value",Foreign())
        elif field=="evidence":object.__setattr__(token.value,"evidence",(Foreign(),))
        else:object.__setattr__(token.value.evidence[0],"locator",Foreign())
    final_read(owner,source,execution,monkeypatch,mutate)
    with pytest.raises(ValueError):graph.validate_brief_execution_graph(execution.executed)
    assert calls==[]


@pytest.mark.parametrize("leaf",["value","raw","operation"])
def test_late_malformed_carrier_cannot_activate_an_earlier_equal_content_hook(tmp_path,monkeypatch,leaf):
    owner,source,execution=prepared(tmp_path/"inputs");calls=[]
    output=source.executed[0];row=output.value.rows[0]
    class Equal(str):
        def __eq__(self,_other):calls.append("equality");return True
        def __hash__(self):calls.append("hash");raise AssertionError
    def mutate():
        if leaf=="operation":object.__setattr__(output.receipt.capture,"operation",Equal(output.receipt.capture.operation))
        else:object.__setattr__(row.interface,leaf,Equal(getattr(row.interface,leaf)))
        object.__setattr__(execution.executed[-1],"receipt",object())
    final_read(owner,source,execution,monkeypatch,mutate)
    with pytest.raises(ValueError):graph.validate_brief_execution_graph(execution.executed)
    assert calls==[]


@pytest.mark.parametrize("fault",["copy","foreign_parse","wrong_bytes"])
def test_structural_graphs_are_not_execution_origin_or_source_admission(tmp_path,fault):
    owner,source,_execution=prepared(tmp_path/"inputs");output=source.executed[0]
    if fault=="copy":
        # Authentic byte claims alone do not establish original parser ownership.
        copied=replace(output,value=replace(output.value))
        assert graph.validate_brief_execution_graph((copied,)) is None
        with pytest.raises(ValueError):owner.owner.own(copied)
    elif fault=="foreign_parse":
        with pytest.raises(ValueError):graph.validate_brief_execution_graph((replace(output,receipt=replace(output.receipt,parse=replace(output.value.parse))),))
    else:
        object.__setattr__(output.receipt.capture,"raw",output.receipt.capture.raw+b"changed\n")
        with pytest.raises(ValueError):graph.validate_brief_execution_graph((output,))
