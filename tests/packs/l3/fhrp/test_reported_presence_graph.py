"""Strict row graphs reject opaque hooks; comparison bytes establish no Source authority."""
import json
from dataclasses import asdict, replace

import pytest
from test_gateway_source import LIMITS, folder
from test_version_inputs import fixture as version_fixture

from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import TimeInterval
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp import version_inputs as inputs
from atlas_brain.runner.p4_fhrp_policy import prepare_fhrp_source


def original(root,missing=None):
    files=folder(root,missing)
    prepared=prepare_fhrp_source(root,LIMITS)
    indexed={(target.context,target.node.key):target for target in prepared.domains}
    return prepared.source.rows,indexed,graph.retain_targets(indexed),files


@pytest.mark.parametrize("missing",[None,"hsrp","hsrp-cold","both"])
def test_genuine_plain_originals_detach_exact_metadata_and_preserve_unknown_facts(tmp_path,missing):
    rows,indexed,held,files=original(tmp_path/"inputs",missing)
    states=tuple(row.value for row in rows)
    encoded=graph.source_rows_bytes(rows,indexed,held)
    expected=json.dumps(tuple(asdict(row) for row in rows),sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
    assert encoded==expected and len(json.loads(encoded))==len(rows)==6
    assert tuple(row.value for row in rows)==states
    assert all(row.value is value for row,value in zip(rows,states,strict=True))
    assert any(type(value) is k.Unknown for value in states)
    assert {p.name:p.read_bytes() for p in (tmp_path/"inputs").iterdir()}==files
    saved=encoded
    object.__setattr__(rows[0],"interface","mutated")
    assert encoded==saved and type(encoded) is bytes
    with pytest.raises(ValueError):graph.source_rows_bytes(rows,indexed,held)


@pytest.mark.parametrize("fault",["interface","group","subject","target","node","node_id","target_context","groups","ports",
    "value","value_type","raw","basis","evidence","ref","capture","digest","role","span","locator","registry","registry_digest",
    "reason","need_operation","need_params","candidates","declaration_value","declaration_evidence"])
def test_opaque_final_row_graph_refuses_before_any_hook_comparison_or_serialization(tmp_path,monkeypatch,fault):
    rows,indexed,held,_files=original(tmp_path/"inputs")
    calls=[]
    class Opaque(str):
        def __deepcopy__(self,memo):calls.append("deepcopy");raise AssertionError("opaque deepcopy")
        def __eq__(self,other):calls.append("eq");raise AssertionError("opaque equality")
        __hash__=str.__hash__
    class OpaqueTuple(tuple):
        def __iter__(self):calls.append("iter");raise AssertionError("opaque iteration")
        def __deepcopy__(self,memo):calls.append("deepcopy");raise AssertionError("opaque deepcopy")
    class Foreign:
        def __getattribute__(self,name):calls.append("property");raise AssertionError("foreign property")
    known=next(row for row in reversed(rows) if type(row.value) is k.Known)
    unknown=next(row for row in reversed(rows) if type(row.value) is k.Unknown)
    row=rows[-1]
    if fault in ("interface","group","subject"):object.__setattr__(row,fault,Opaque({"interface":row.interface,"group":row.group,"subject":row.subject}[fault]))
    elif fault=="target":object.__setattr__(row,"target",Foreign())
    elif fault=="node":object.__setattr__(row.target,"node",Foreign())
    elif fault=="node_id":object.__setattr__(row.target.node,"id",Opaque(row.target.node.id))
    elif fault=="target_context":object.__setattr__(row.target,"context",Opaque(row.target.context))
    elif fault=="groups":object.__setattr__(row.target,"groups",OpaqueTuple(row.target.groups))
    elif fault=="ports":object.__setattr__(row.target.node,"ports",OpaqueTuple(row.target.node.ports))
    elif fault=="value_type":object.__setattr__(known,"value",Foreign())
    elif fault in ("value","raw","basis"):object.__setattr__(known.value,fault,Opaque(str(getattr(known.value,fault))))
    elif fault=="evidence":object.__setattr__(known.value,"evidence",OpaqueTuple(known.value.evidence))
    elif fault=="ref":object.__setattr__(known.value,"evidence",(Foreign(),))
    elif fault in ("capture","digest","role","span","locator"):
        ref=next(ref for ref in known.value.evidence if type(ref) is k.EvidenceRef)
        if fault=="locator":object.__setattr__(ref,"locator",Foreign())
        elif fault=="span":object.__setattr__(ref.locator,"start",Foreign())
        else:object.__setattr__(ref,{"capture":"capture","digest":"excerpt_sha256","role":"role"}[fault],Opaque(str({"capture":ref.capture,"digest":ref.excerpt_sha256,"role":ref.role}[fault])))
    elif fault in ("registry","registry_digest"):
        ref=next(ref for ref in known.value.evidence if type(ref) is k.RegistryRef)
        object.__setattr__(ref,"table" if fault=="registry" else "table_digest",Opaque(ref.table if fault=="registry" else ref.table_digest))
    elif fault=="reason":object.__setattr__(unknown.value,"reason",Opaque(str(unknown.value.reason)))
    elif fault=="need_operation":object.__setattr__(unknown.value.next_evidence[0],"operation",Opaque(unknown.value.next_evidence[0].operation))
    elif fault=="need_params":object.__setattr__(unknown.value.next_evidence[0],"params",OpaqueTuple(unknown.value.next_evidence[0].params))
    elif fault=="candidates":object.__setattr__(unknown.value,"candidates",(Opaque("candidate"),))
    elif fault=="declaration_value":object.__setattr__(row.target.node.declaration,"value",Opaque(row.target.node.id))
    else:object.__setattr__(row.target.node.declaration,"evidence",OpaqueTuple(row.target.node.declaration.evidence))
    def forbidden(*args,**kwargs):calls.append("projection");raise AssertionError("projection before whole graph validation")
    monkeypatch.setattr(graph,"_target_data",forbidden);monkeypatch.setattr(graph,"_bytes",forbidden)
    monkeypatch.setattr(state,"subject",forbidden)
    with pytest.raises(ValueError):graph.source_rows_bytes(rows,indexed,held)
    assert calls==[]


@pytest.mark.parametrize("fault",["target_copy","node_copy","declaration_copy","index_copy","indexed_target_copy","groups","context"])
def test_equal_content_foreign_or_coherently_changed_target_bindings_refuse_before_projection(tmp_path,monkeypatch,fault):
    rows,indexed,held,_files=original(tmp_path/"inputs")
    row=rows[0];target=row.target;key=(target.context,target.node.key)
    if fault=="target_copy":object.__setattr__(row,"target",replace(target))
    elif fault=="node_copy":object.__setattr__(target,"node",replace(target.node))
    elif fault=="declaration_copy":object.__setattr__(target.node,"declaration",replace(target.node.declaration))
    elif fault=="index_copy":indexed=dict(indexed)
    elif fault=="indexed_target_copy":indexed[key]=replace(target)
    elif fault=="groups":object.__setattr__(target,"groups",target.groups+(("Vl999","1"),))
    else:
        object.__setattr__(target,"context","foreign")
        indexed[("foreign",key[1])]=indexed.pop(key)
    calls=[]
    def forbidden(*args,**kwargs):calls.append(True);raise AssertionError("projection before binding validation")
    if fault!="groups":monkeypatch.setattr(graph,"_target_data",forbidden)
    with pytest.raises(ValueError):graph.source_rows_bytes(rows,indexed,held)
    assert calls==[]


@pytest.mark.parametrize("fault",["rows_list","rows_tuple","row_type","index_type","key_type","held_type","entries_list","duplicate_entry","wrong_subject","wrong_group","missing_row","duplicate_row","extra_row"])
def test_closed_container_and_subject_binding_controls(tmp_path,fault):
    rows,indexed,held,_files=original(tmp_path/"inputs")
    if fault=="missing_row":rows=rows[:-1]
    elif fault=="duplicate_row":rows=(*rows[:-1],rows[0])
    elif fault=="extra_row":rows=(*rows,replace(rows[0]))
    elif fault=="rows_tuple":
        class Tuple(tuple):
            def __iter__(self):raise AssertionError("foreign row iterator")
        rows=Tuple(rows)
    elif fault=="rows_list":rows=list(rows)
    elif fault=="row_type":rows=(object(),*rows[1:])
    elif fault=="index_type":
        class Mapping(dict):
            def items(self):raise AssertionError("foreign mapping hook")
        indexed=Mapping(indexed)
    elif fault=="key_type":indexed[("foreign",1)]=next(iter(indexed.values()))
    elif fault=="held_type":held=object()
    elif fault=="entries_list":object.__setattr__(held,"entries",list(held.entries))
    elif fault=="duplicate_entry":object.__setattr__(held,"entries",held.entries+(held.entries[-1],))
    elif fault=="wrong_subject":object.__setattr__(rows[-1],"subject",k.EntityKey("fhrp_local:foreign"))
    else:object.__setattr__(rows[-1],"group","4095")
    with pytest.raises(ValueError):graph.source_rows_bytes(rows,indexed,held)


def test_equal_row_copy_is_only_comparison_data_and_never_changes_original_state_identity(tmp_path):
    rows,indexed,held,_files=original(tmp_path/"inputs")
    copied=tuple(replace(row) for row in rows)
    assert copied[0] is not rows[0] and copied[0].target is rows[0].target
    assert graph.source_rows_bytes(copied,indexed,held)==graph.source_rows_bytes(rows,indexed,held)
    assert all(a.value is b.value for a,b in zip(copied,rows,strict=True))


def test_retention_refuses_foreign_mapping_before_iterating_it(tmp_path):
    _rows,indexed,_held,_files=original(tmp_path/"inputs")
    class Mapping(dict):
        def items(self):raise AssertionError("foreign mapping hook")
    with pytest.raises(ValueError):graph.retain_targets(Mapping(indexed))


@pytest.mark.parametrize("mode",["true","false","raises"])
@pytest.mark.parametrize("site",["state","known_evidence","unknown_evidence","known_locator","unknown_locator",
    "target_evidence","target_locator","request_evidence","request_locator"])
def test_public_graph_boundaries_refuse_hostile_metaclasses_before_any_callback(monkeypatch,mode,site):
    target,request=version_fixture()
    ref=k.EvidenceRef(capture=k.CaptureId("cap:metaclass"),locator=k.ByteSpan(start=0,end=1),
        role=k.EvidenceRole.WITNESS,excerpt_sha256="a"*64)
    known=k.Known(value="active",raw="Active",basis=k.Basis.OBSERVED,evidence=(ref,))
    unknown=k.Unknown(reason=k.UnknownReason.PARSE_PARTIAL,detail="fixture",evidence=(ref,),candidates=(),next_evidence=())
    calls=[]
    class Alias(type):
        def __eq__(cls,other):
            calls.append("metaclass")
            if mode=="raises":raise AssertionError("metaclass equality callback")
            return mode=="true"
        def __hash__(cls):
            calls.append("metaclass_hash")
            raise AssertionError("metaclass hash callback")
    class Foreign(metaclass=Alias):
        @property
        def __class__(self):
            calls.append("class_property")
            return k.Known
        def __getattr__(self,name):
            calls.append("attribute")
            raise AssertionError("foreign graph attribute")
    foreign=Foreign()
    if site=="state":value=foreign
    elif site.startswith(("known_", "unknown_")):
        value=known if site.startswith("known_") else unknown
        if site.endswith("evidence"):object.__setattr__(value,"evidence",(foreign,))
        else:object.__setattr__(ref,"locator",foreign)
    elif site.startswith("target_"):
        if site.endswith("evidence"):object.__setattr__(target.node.declaration,"evidence",(foreign,))
        else:
            object.__setattr__(ref,"locator",foreign)
            object.__setattr__(target.node.declaration,"evidence",(ref,))
    else:
        metadata=request.capture.metadata
        assert metadata is not None
        if site.endswith("evidence"):object.__setattr__(metadata,"integrity_evidence",(foreign,))
        else:
            object.__setattr__(ref,"locator",foreign)
            object.__setattr__(metadata,"integrity_evidence",(ref,))
    def forbidden(*args,**kwargs):calls.append("snapshot");raise AssertionError("snapshot before graph refusal")
    monkeypatch.setattr(inputs,"asdict",forbidden);monkeypatch.setattr(inputs.custody,"asdict",forbidden)
    with pytest.raises(ValueError):
        if site.startswith("target_"):inputs.retain_version_inputs((target,),())
        elif site.startswith("request_"):inputs.validate_fhrp_request_graph(request)
        else:inputs.validate_version_state_graph(value)
    assert calls==[]


def test_public_request_graph_refuses_foreign_time_before_its_class_property(monkeypatch):
    _target,request=version_fixture()
    metadata=request.capture.metadata
    assert metadata is not None
    calls=[]
    class ForeignTime:
        @property
        def __class__(self):
            calls.append("class_property")
            return TimeInterval
        def __getattr__(self,name):
            calls.append("attribute")
            raise AssertionError("foreign time attribute")
    object.__setattr__(metadata,"collected_utc",ForeignTime())
    def forbidden(*args,**kwargs):calls.append("snapshot");raise AssertionError("snapshot before time refusal")
    monkeypatch.setattr(inputs,"asdict",forbidden);monkeypatch.setattr(inputs.custody,"asdict",forbidden)
    with pytest.raises(ValueError):inputs.validate_fhrp_request_graph(request)
    assert calls==[]


@pytest.mark.parametrize("timed",[False,True])
def test_exact_admitted_time_and_reference_classes_keep_public_graph_and_retention_paths(timed):
    target,request=version_fixture(timed=timed)
    assert inputs.validate_fhrp_request_graph(request) is None
    retained=inputs.retain_version_inputs((target,),(request,))
    assert inputs.validate_version_inputs(retained) is None


@pytest.mark.parametrize("mode",["true","false","raises"])
def test_late_foreign_state_cannot_mutate_an_earlier_value_or_reach_source_projection(tmp_path,monkeypatch,mode):
    rows,indexed,held,_files=original(tmp_path/"inputs")
    victim=k.Known(value=True,raw=None,basis=k.Basis.DERIVED,
        evidence=(k.FactRef(fact=state.REPORTED_STATE,subject=rows[0].subject),))
    calls=[]
    class Alias(type):
        def __eq__(cls,other):
            calls.append("metaclass")
            object.__setattr__(victim,"value",False)
            if mode=="raises":raise AssertionError("late equality callback")
            return mode=="true"
        def __hash__(cls):
            calls.append("metaclass_hash")
            raise AssertionError("metaclass hash callback")
    class Foreign(metaclass=Alias):
        @property
        def __class__(self):
            calls.append("class_property")
            return k.Known
        def __getattr__(self,name):calls.append("attribute");raise AssertionError("foreign state attribute")
    object.__setattr__(rows[-1],"value",Foreign())
    def forbidden(*args,**kwargs):calls.append("projection");raise AssertionError("projection before whole graph refusal")
    monkeypatch.setattr(graph,"_target_data",forbidden);monkeypatch.setattr(graph,"_bytes",forbidden)
    monkeypatch.setattr(state,"subject",forbidden)
    with pytest.raises(ValueError):graph.source_rows_bytes(rows,indexed,held)
    assert calls==[] and victim.value is True
