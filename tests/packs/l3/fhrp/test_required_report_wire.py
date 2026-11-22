"""Literal four-file formatting oracle and exact input/output budgets; no predicate qualification."""
from copy import deepcopy
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.packs.l3.fhrp import required_report_wire as wire


def fixture():
    inputs=(b"{}",b"{}",b"\x00\xff",b"policy",b"baseline")
    header={"schema":"unit-required-wire/1","semantic_group":"declared_synthetic","context":"round",
        "declared_policy":{"raw":sha256(b"policy").hexdigest()},
        "external_baseline":{"raw":sha256(b"baseline").hexdigest()},
        "denominator":{"requested_requirements":1,"expected_participant_occurrences":2}}
    captures=({"id":"capture","raw":sha256(b"\x00\xff").hexdigest(),"operation":"synthetic.fixture"},)
    record={"id":"registry-fixture","table":"declared_fixture","row_id":"gateway0","pointer":"/0",
        "raw":sha256(b"baseline").hexdigest(),"encoding":"hex"}
    registry=((record,b'{"id":"gateway0"}'),)
    local={("node:b","l3.fhrp.reported_group_present"):{"fact":"l3.fhrp.reported_group_present","subject":"node:b",
        "value":{"state":"unknown","reason":"not_collected","next_evidence":[{"node":"node:b","resolves":[],"reruns":["fixture"]}]}},
        ("node:a","l3.fhrp.reported_group_present"):{"fact":"l3.fhrp.reported_group_present","subject":"node:a",
        "value":{"state":"known","basis":"derived","value":True,"raw":None}}}
    requirements={("requirement:1","l3.fhrp.required_report_missing"):{"fact":"l3.fhrp.required_report_missing",
        "subject":"requirement:1","value":{"state":"known","basis":"derived","value":False,"raw":None},
        "premises":[{"name":"baseline","registry":["registry-fixture"]}],
        "operands":[{"fact":"l3.fhrp.reported_group_present","subject":"node:a"}]}}
    return header,inputs,captures,registry,local,requirements


def literal_files():
    raws=[{"sha256":sha256(raw).hexdigest(),"bytes":length,"encoding":"hex","data":data}
        for raw,length,data in ((b"{}",2,"7b7d"),(b"\x00\xff",2,"00ff"),(b"policy",6,"706f6c696379"),
            (b"baseline",8,"626173656c696e65"))]
    result={"schema":"unit-required-wire/1","semantic_group":"declared_synthetic","context":"round",
        "declared_policy":{"raw":sha256(b"policy").hexdigest()},"external_baseline":{"raw":sha256(b"baseline").hexdigest()},
        "denominator":{"requested_requirements":1,"expected_participant_occurrences":2},
        "raws":sorted(raws,key=lambda row:row["sha256"]),
        "captures":[{"id":"capture","raw":sha256(b"\x00\xff").hexdigest(),"operation":"synthetic.fixture"}],
        "registry_records":[{"id":"registry-fixture","table":"declared_fixture","row_id":"gateway0","pointer":"/0",
            "raw":sha256(b"baseline").hexdigest(),"encoding":"hex","canonical":"7b226964223a226761746577617930227d"}]}
    positive={"fact":"l3.fhrp.reported_group_present","subject":"node:a",
        "value":{"state":"known","basis":"derived","value":True,"raw":None}}
    unknown={"fact":"l3.fhrp.reported_group_present","subject":"node:b",
        "value":{"state":"unknown","reason":"not_collected","next_evidence":[{"node":"node:b","resolves":[],"reruns":["fixture"]}]}}
    requirement={"fact":"l3.fhrp.required_report_missing","subject":"requirement:1",
        "value":{"state":"known","basis":"derived","value":False,"raw":None},
        "premises":[{"name":"baseline","registry":["registry-fixture"]}],
        "operands":[{"fact":"l3.fhrp.reported_group_present","subject":"node:a"}]}
    files={"result.json":canonical(result),"facts/fhrp_local.jsonl":canonical(positive)+b"\n"+canonical(unknown)+b"\n",
        "facts/fhrp_requirement.jsonl":canonical(requirement)+b"\n"}
    files["MANIFEST.sha256"]=manifest(files)
    return {name:files[name] for name in sorted(files)}


def limits_for(inputs,files):
    return (sum(map(len,inputs))+sum(map(len,files.values())),
        max(*map(len,inputs),*map(len,files.values())),len(inputs)+len(files))


def test_literal_complete_bytes_order_hex_external_inputs_manifest_and_repeated_calls():
    header,inputs,captures,registry,local,requirements=fixture()
    before=deepcopy((header,captures,registry,local,requirements))
    expected=literal_files()
    limits=limits_for(inputs,expected)
    actual=wire.render(header,inputs,limits,captures,registry,local,requirements)
    assert actual==expected and set(actual)==set(wire.NAMES)
    assert wire.render(header,inputs,limits,captures,registry,local,requirements)==expected
    assert (header,captures,registry,local,requirements)==before
    assert wire.render(header,tuple(reversed(inputs)),limits,captures,registry,
        dict(reversed(list(local.items()))),requirements)==expected


@pytest.mark.parametrize("boundary",["bundle","artifact","count"])
def test_each_exact_budget_accepts_and_one_byte_or_one_artifact_less_refuses(boundary):
    header,inputs,captures,registry,local,requirements=fixture()
    expected=literal_files()
    limits=limits_for(inputs,expected)
    assert wire.render(header,inputs,limits,captures,registry,local,requirements)==expected
    changed=list(limits)
    changed[{"bundle":0,"artifact":1,"count":2}[boundary]]-=1
    with pytest.raises(BudgetExceeded):
        wire.render(header,inputs,tuple(changed),captures,registry,local,requirements)


def test_duplicate_raw_blobs_still_count_every_original_input_byte_and_artifact():
    header,inputs,captures,registry,local,requirements=fixture()
    expected=literal_files()
    deduplicated=tuple(dict.fromkeys(inputs))
    limits=limits_for(deduplicated,expected)
    assert wire.render(header,deduplicated,limits,captures,registry,local,requirements)==expected
    with pytest.raises(BudgetExceeded):
        wire.render(header,inputs,limits,captures,registry,local,requirements)


@pytest.mark.parametrize("name",["raws","captures","registry_records"])
def test_header_cannot_override_owned_output_tables(name):
    header,inputs,captures,registry,local,requirements=fixture()
    header[name]=[]
    with pytest.raises(ValueError):wire.render(header,inputs,(100000,100000,100),captures,registry,local,requirements)


@pytest.mark.parametrize("location",["header","record","raw","fragment"])
def test_nonprimitive_or_subclass_payloads_refuse_without_callbacks(location):
    header,inputs,captures,registry,local,requirements=fixture()
    calls=[]
    class Foreign(str):
        def __str__(self):calls.append("str");raise AssertionError
        def __hash__(self):calls.append("hash");raise AssertionError
        def __eq__(self,_other):calls.append("equality");raise AssertionError
    class ForeignBytes(bytes):
        def hex(self,*_args,**_kwargs):calls.append("hex");raise AssertionError
    if location=="header":header["context"]=Foreign("round")
    elif location=="record":local[next(iter(local))]["subject"]=Foreign("node")
    elif location=="raw":inputs=(*inputs,ForeignBytes(b"raw"))
    else:registry=((registry[0][0],ForeignBytes(registry[0][1])),)
    with pytest.raises((ValueError,TypeError)):
        wire.render(header,inputs,(100000,100000,100),captures,registry,local,requirements)
    assert calls==[]


@pytest.mark.parametrize("location",["header_reserved","header_nested","capture_record","registry_record","local_record","requirement_record","row_key"])
def test_exact_key_closure_precedes_membership_encoding_hashing_and_nested_lookup(location):
    header,inputs,captures,registry,local,requirements=fixture()
    calls=[]
    class Key(str):
        armed=False
        def __hash__(self):
            if self.armed:calls.append("hash");raise AssertionError
            return str.__hash__(self)
        def __eq__(self,_other):calls.append("equality");raise AssertionError
        def encode(self,*_args,**_kwargs):calls.append("encode");raise AssertionError
    key=Key("raws" if location=="header_reserved" else "key")
    if location=="header_reserved":header={key:1}
    elif location=="header_nested":header["nested"]={key:1}
    elif location=="capture_record":captures=({key:1},)
    elif location=="registry_record":registry=(({key:1},b"{}"),)
    elif location=="local_record":local={("subject","fact"):{key:1}}
    elif location=="requirement_record":requirements={("subject","fact"):{key:1}}
    else:local={(key,"fact"):{"subject":"literal"}}
    key.armed=True
    with pytest.raises((ValueError,TypeError)):
        wire.render(header,inputs,(100000,100000,100),captures,registry,local,requirements)
    assert calls==[]


@pytest.mark.parametrize("location",["header","captures","capture_record","registry","registry_entry","registry_record",
    "local","requirements","row_key","nested_dict","nested_list","nested_tuple"])
def test_exact_container_gates_precede_every_actual_iteration_values_and_unpack(location):
    header,inputs,captures,registry,local,requirements=fixture()
    calls=[]
    class Dictionary(dict):
        def __iter__(self):calls.append("iteration");raise AssertionError
        def __contains__(self,_key):calls.append("contains");raise AssertionError
        def values(self):calls.append("values");raise AssertionError
        def items(self):calls.append("items");raise AssertionError
        def __getitem__(self,_key):calls.append("getitem");raise AssertionError
    class Tuple(tuple):
        def __iter__(self):calls.append("iteration");raise AssertionError
        def __len__(self):calls.append("length");raise AssertionError
        def __getitem__(self,_key):calls.append("getitem");raise AssertionError
    class List(list):
        def __iter__(self):calls.append("iteration");raise AssertionError
    if location=="header":header=Dictionary(header)
    elif location=="captures":captures=Tuple(captures)
    elif location=="capture_record":captures=(Dictionary(captures[0]),)
    elif location=="registry":registry=Tuple(registry)
    elif location=="registry_entry":registry=(Tuple(registry[0]),)
    elif location=="registry_record":registry=((Dictionary(registry[0][0]),registry[0][1]),)
    elif location=="local":local=Dictionary(local)
    elif location=="requirements":requirements=Dictionary(requirements)
    elif location=="row_key":local={Tuple(("subject","fact")):{"subject":"literal"}}
    elif location=="nested_dict":header["nested"]=Dictionary({"closed":True})
    elif location=="nested_list":header["nested"]=List([True])
    else:header["nested"]=Tuple((True,))
    with pytest.raises((ValueError,TypeError)):
        wire.render(header,inputs,(100000,100000,100),captures,registry,local,requirements)
    assert calls==[]


@pytest.mark.parametrize("number,accepted",[(9007199254740991,True),(-9007199254740991,True),
    (9007199254740992,False),(-9007199254740992,False),(1.5,False)])
def test_primitive_closure_preserves_existing_integer_bounds_and_float_refusal(number,accepted):
    header,inputs,captures,registry,local,requirements=fixture()
    header["number"]=number
    if accepted:
        files=wire.render(header,inputs,(100000,100000,100),captures,registry,local,requirements)
        assert canonical({"number":number})[1:-1] in files["result.json"]
    else:
        with pytest.raises((ValueError,TypeError)):
            wire.render(header,inputs,(100000,100000,100),captures,registry,local,requirements)


def _forbid_wire_encoding(monkeypatch):
    from atlas_brain.contract import bundle
    from atlas_brain.contract import canonical as encoding
    def forbidden(*_args,**_kwargs):pytest.fail("serialization preceded bounded preflight")
    monkeypatch.setattr(wire,"result_bundle",forbidden)
    monkeypatch.setattr(wire,"canonical",forbidden,raising=False)
    monkeypatch.setattr(bundle,"canonical",forbidden)
    monkeypatch.setattr(encoding,"canonical",forbidden)


@pytest.mark.parametrize("location",["header","capture","registry","local","requirement"])
def test_oversized_dto_refuses_before_actual_canonical_or_renderer_dispatch(monkeypatch,location):
    header,inputs,captures,registry,local,requirements=fixture()
    selected={"header":header,"capture":captures[0],"registry":registry[0][0],
        "local":next(iter(local.values())),"requirement":next(iter(requirements.values()))}[location]
    selected["oversized"]="x"*10000
    _forbid_wire_encoding(monkeypatch)
    with pytest.raises(BudgetExceeded):wire.render(header,inputs,(5000,5000,100),captures,registry,local,requirements)


@pytest.mark.parametrize("shape",["cycle","depth","repeated"])
def test_recursive_dto_work_stops_at_depth_or_remaining_bytes(monkeypatch,shape):
    header,inputs,captures,registry,local,requirements=fixture()
    nested=[]
    if shape=="cycle":nested.append(nested)
    else:
        for _ in range(70 if shape=="depth" else 20):
            nested=[nested] if shape=="depth" else (nested,nested)
    header["nested"]=nested
    _forbid_wire_encoding(monkeypatch)
    with pytest.raises(BudgetExceeded):wire.render(header,inputs,(10000,10000,100),captures,registry,local,requirements)


def test_input_count_precedes_payload_walk_and_row_keys_are_bound_before_sort(monkeypatch):
    header,inputs,captures,registry,local,requirements=fixture()
    _forbid_wire_encoding(monkeypatch)
    with pytest.raises(BudgetExceeded):
        wire.render(header,(object(),)*10,(10000,10000,4),captures,registry,local,requirements)
    with pytest.raises(BudgetExceeded):
        wire.render(header,(b"x"*2000,object()),(10000,1000,6),captures,registry,local,requirements)
    local={("x"*10000,"l3.fhrp.reported_group_present"):next(iter(local.values()))}
    with pytest.raises(ValueError,match="^required_report_wire$"):
        wire.render(header,inputs,(10000,10000,100),captures,registry,local,requirements)


def test_exact_escape_unicode_sizes_preserve_frozen_canonical_bytes_and_boundaries():
    header,inputs,captures,registry,local,requirements=fixture()
    vector=['"\\\b\f\n\r\t\x00\x1f\x7f',"é€😀",{"\ue000":"b","\U00010000":"a"}]
    literal=(b'["\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f\x7f",'
        b'"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80",{"\xf0\x90\x80\x80":"a","\xee\x80\x80":"b"}]')
    assert canonical(vector)==literal
    header["vector"]=vector
    expected=literal_files()
    expected["result.json"]=expected["result.json"][:-1]+b',"vector":'+literal+b"}"
    expected["MANIFEST.sha256"]=manifest({name:raw for name,raw in expected.items() if name!="MANIFEST.sha256"})
    limits=limits_for(inputs,expected)
    assert wire.render(header,inputs,limits,captures,registry,local,requirements)==expected
    for boundary in (0,1):
        reduced=list(limits)
        reduced[boundary]-=1
        with pytest.raises(BudgetExceeded):
            wire.render(header,inputs,tuple(reduced),captures,registry,local,requirements)


@pytest.mark.parametrize("codepoint",[0xD800,0xDFFF],ids=["high","low"])
def test_surrogates_refuse_before_any_canonical_encoding(monkeypatch,codepoint):
    header,inputs,captures,registry,local,requirements=fixture()
    header["scalar"]=chr(codepoint)
    _forbid_wire_encoding(monkeypatch)
    with pytest.raises(ValueError,match="^non_unicode_scalar$"):
        wire.render(header,inputs,(10000,10000,100),captures,registry,local,requirements)
