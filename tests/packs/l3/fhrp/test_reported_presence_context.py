"""Closed current input comparisons; callers retain original custody separately."""
import json
from dataclasses import replace

import pytest
from test_gateway_source import LIMITS, folder

from atlas_brain.packs.l3.fhrp import reported_presence_context as context
from atlas_brain.runner import pack_receipts as receipts
from atlas_brain.runner.p4_fhrp_policy import prepare_fhrp_source


def original(root,missing=None):
    files=folder(root,missing)
    budgets=replace(LIMITS)
    prepared=prepare_fhrp_source(root,budgets)
    return prepared.execution.envelope,budgets,prepared,files


def immutable(value):
    assert any(type(value) is kind for kind in (tuple,str,int,bytes,type(None)))
    if type(value) is tuple:
        for item in value:immutable(item)


@pytest.mark.parametrize("missing",[None,"hsrp","both"])
def test_actual_context_has_detached_immutable_values_and_original_pointers(tmp_path,missing):
    envelope,budgets,prepared,files=original(tmp_path/"inputs",missing)
    pointers,values=context.capture_context(envelope,budgets)
    assert pointers[0] is envelope and pointers[1] is envelope.base and pointers[2] is budgets
    assert values[:4]==(envelope.raw,envelope.base.raw,envelope.context,envelope.registration_sha256)
    immutable(values)
    for output in prepared.source.executed:
        request=receipts.CaptureRequest(capture=output.receipt.capture,context=output.receipt.context)
        held,=context.request_values((request,))
        assert held[0]==request.capture.id and held[1] is request and held[2] is request.capture
        data=json.loads(held[3])
        assert data["capture"]["raw"]=={"$bytes":request.capture.raw.hex()}
    again=context.capture_context(envelope,budgets)
    assert all(a is b for a,b in zip(pointers,again[0],strict=True)) and again[1]==values
    assert {p.name:p.read_bytes() for p in (tmp_path/"inputs").iterdir()}==files


@pytest.mark.parametrize("fault",["envelope","base","budget","nodes","base_captures","targets","members",
    "node_id","node_ports","target_operation","target_params","target_node","member_raw","member_target",
    "declaration_value","declaration_evidence","budget_amount","base_raw"])
def test_opaque_current_context_refuses_without_any_caller_hook(tmp_path,fault):
    envelope,budgets,_prepared,_files=original(tmp_path/"inputs")
    calls=[]
    class Opaque(str):
        def __eq__(self,other):calls.append("equality");raise AssertionError
        def __hash__(self):calls.append("hash");raise AssertionError
        def __deepcopy__(self,memo):calls.append("deepcopy");raise AssertionError
    class Foreign:
        def __getattribute__(self,name):calls.append("property");raise AssertionError
    class ForeignTuple(tuple):
        def __iter__(self):calls.append("iteration");raise AssertionError
    node=envelope.base.nodes[0];target=envelope.targets[0];member=envelope.captures[0]
    if fault=="envelope":envelope=Foreign()
    elif fault=="base":object.__setattr__(envelope,"base",Foreign())
    elif fault=="budget":budgets=Foreign()
    elif fault=="nodes":object.__setattr__(envelope.base,"nodes",ForeignTuple(envelope.base.nodes))
    elif fault=="base_captures":object.__setattr__(envelope.base,"captures",ForeignTuple(envelope.base.captures))
    elif fault=="targets":object.__setattr__(envelope,"targets",ForeignTuple(envelope.targets))
    elif fault=="members":object.__setattr__(envelope,"captures",ForeignTuple(envelope.captures))
    elif fault=="node_id":object.__setattr__(node,"id",Opaque(node.id))
    elif fault=="node_ports":object.__setattr__(node,"ports",ForeignTuple(node.ports))
    elif fault=="target_operation":object.__setattr__(target,"operation",Opaque(target.operation))
    elif fault=="target_params":object.__setattr__(target,"params",Foreign())
    elif fault=="target_node":object.__setattr__(target,"node",Foreign())
    elif fault=="member_raw":object.__setattr__(member,"raw",Foreign())
    elif fault=="member_target":object.__setattr__(member,"target",Foreign())
    elif fault=="declaration_value":object.__setattr__(envelope.declaration,"value",Opaque(envelope.context))
    elif fault=="declaration_evidence":object.__setattr__(envelope.declaration,"evidence",ForeignTuple(envelope.declaration.evidence))
    elif fault=="budget_amount":object.__setattr__(budgets,"nesting_depth",Opaque("64"))
    else:object.__setattr__(envelope.base,"raw",Foreign())
    with pytest.raises(ValueError):context.capture_context(envelope,budgets)
    assert calls==[]


@pytest.mark.parametrize("fault",["raw_string","raw_bytes","metadata","context"])
def test_request_snapshot_rejects_malformed_graphs_before_snapshot_hooks(tmp_path,fault):
    _envelope,_budgets,prepared,_files=original(tmp_path/"inputs")
    output=prepared.source.executed[0]
    request=receipts.CaptureRequest(capture=output.receipt.capture,context=output.receipt.context)
    calls=[]
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
        def __deepcopy__(self,memo):calls.append("deepcopy");raise AssertionError
    if fault=="raw_string":object.__setattr__(request.capture,"raw",request.capture.raw.hex())
    elif fault=="raw_bytes":object.__setattr__(request.capture,"raw",request.capture.raw+b"changed\n")
    elif fault=="metadata":object.__setattr__(request.capture,"metadata",Foreign())
    else:object.__setattr__(request,"context",Foreign())
    with pytest.raises(ValueError):context.request_values((request,))
    assert calls==[]


@pytest.mark.parametrize("field",["context","target_operation","target_owner","target_params",
    "member_path","envelope_raw","base_raw","budget_amount"])
def test_plain_current_changes_are_detectable_without_mutating_prior_snapshot(tmp_path,field):
    envelope,budgets,_prepared,_files=original(tmp_path/"inputs")
    pointers,before=context.capture_context(envelope,budgets)
    if field=="context":object.__setattr__(envelope,"context","changed")
    elif field=="target_operation":object.__setattr__(envelope.targets[0],"operation","iosxe.changed")
    elif field=="target_owner":object.__setattr__(envelope.targets[0],"owner","changed/owner")
    elif field=="target_params":object.__setattr__(envelope.targets[0],"params",b"{}")
    elif field=="member_path":object.__setattr__(envelope.captures[0],"path","changed.txt")
    elif field=="envelope_raw":object.__setattr__(envelope,"raw",envelope.raw+b" ")
    elif field=="base_raw":object.__setattr__(envelope.base,"raw",envelope.base.raw+b" ")
    else:object.__setattr__(budgets,"nesting_depth",budgets.nesting_depth+1)
    _current,after=context.capture_context(envelope,budgets)
    assert after!=before and pointers[0] is envelope
    immutable(before)


@pytest.mark.parametrize("field",["envelope","base","budgets"])
def test_equal_content_clones_change_pointer_data_but_grant_no_origin(tmp_path,field):
    envelope,budgets,_prepared,_files=original(tmp_path/"inputs")
    pointers,values=context.capture_context(envelope,budgets)
    if field=="envelope":envelope=replace(envelope)
    elif field=="base":object.__setattr__(envelope,"base",replace(envelope.base))
    else:budgets=replace(budgets)
    current,actual=context.capture_context(envelope,budgets)
    assert actual==values and any(a is not b for a,b in zip(pointers,current,strict=True))
