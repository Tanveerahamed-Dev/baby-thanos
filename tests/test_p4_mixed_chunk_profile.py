"""Closed capture-profile controls; no genuine-demo completion or native timing claim."""
import json
import sys
import time
from hashlib import sha256

import pytest

from tools import p4_mixed_control as mixed

ORDER=("normal","none","cold_vrrp","only_vrrp","empty","partial","no_all_capture","no_all_target","zero_vrrp")
FILES=("MANIFEST.sha256","facts/etherchannel_group.jsonl","facts/fhrp_local.jsonl","facts/stp_port_vlan.jsonl","result.json")
V1,V2="root9-v1","root9-three-case-v2"


def records(context):
    return [{"schema":"atlas-brain.p4-root-mixed-api-chunk/2","execution_profile":V2,
        "context":dict(context),"batch":batch,"chunk":chunk,"seed":("1","83")[batch],"api_runs":3,
        "case_order":list(ORDER[chunk*3:chunk*3+3]),"api_process_denied":4,"additional_denials":0}
        for batch in (0,1) for chunk in (0,1,2)]


def payload(profile):
    native=("Linux","ubuntu-latest") if sys.platform=="linux" else ("Windows","windows-latest")
    context={"reviewed_head":"a"*40,"run_id":"123","run_attempt":"1","platform":sys.platform,"runner_os":native[0],"matrix_os":native[1]}
    return {"context":context,"case_order":list(ORDER),"measured_cases":9,"api_runs":18,
        "api_processes":6 if profile==V2 else 2,"cli_runs":18,"hash_seeds":["1","83"],
        "worker_counts":[1,4],"creation_orders":["sorted","reversed"],
        "api_batches":records(context) if profile==V2 else [{},{}],
        "cases":{case:{"batches":[{},{}]} for case in ORDER}}


def paths(profile):
    labels=("api0","api1") if profile==V1 else tuple(f"api{b}-{c}" for b in (0,1) for c in (0,1,2))
    result={f"{label}.{side}.txt" for label in labels for side in ("stdout","stderr")}
    for case in ORDER:
        inputs=["discovery.txt","p2.json","p4.json"]
        inputs+=[] if case=="none" else ["vrrp.txt"] if case=="only_vrrp" else [
            name for name in ("all.txt","brief.txt","channel.txt","tree.txt","vrrp.txt")
            if not (name=="all.txt" and case in ("no_all_capture","no_all_target"))
            and not (name=="vrrp.txt" and case in ("cold_vrrp","zero_vrrp"))]
        result.update(f"{case}/oracle/{name}" for name in FILES)
        for batch in (0,1):
            result.update(f"{case}/inputs{batch}/{name}" for name in inputs)
            result.update(f"{case}/{kind}{batch}/{name}" for kind in ("api","cli") for name in FILES)
            result.update(f"{case}/cli{batch}.{side}.txt" for side in ("stdout","stderr"))
    assert len(result)==(383 if profile==V1 else 391)
    return result


def owner(tmp_path,profile):
    return mixed.MixedCapture(tmp_path/"retained",deadline=time.monotonic()+30,profile=profile)


def populate(value,profile):
    names=paths(profile)
    for name in names:
        path=value.root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(b"fixture")
    return names


def test_real_finalization_retains_exact_v1_bytes_and_closed_v2_population(tmp_path,capfd):
    saved=[]
    for index,profile in enumerate((None,V1,V2)):
        folder=tmp_path/str(index)
        value=mixed.MixedCapture(folder,deadline=time.monotonic()+30,**({} if profile is None else {"profile":profile}))
        selected=V1 if profile is None else profile
        names=populate(value,selected)
        value.finalize(payload(selected))
        raw=(folder/"DIGESTS.json").read_bytes()
        receipt=json.loads(raw)
        assert capfd.readouterr().out.encode()==b"P4_ROOT_MIXED_RECEIPT "+raw
        assert set(receipt["inventory"])==names and set(paths(selected))==mixed.final_paths(selected)
        assert receipt["inventory"]=={name:{"bytes":7,"sha256":sha256(b"fixture").hexdigest()} for name in names}
        assert len([p for p in folder.rglob("*") if p.is_file()])==receipt["retained_files"]==(384 if selected==V1 else 392)
        assert receipt["schema"]=="atlas-brain.p4-root-mixed-hosted-receipt/"+("1" if selected==V1 else "2")
        assert value.retention_ready and value.profile==selected
        assert receipt.get("execution_profile")== (V2 if selected==V2 else None)
        assert len(receipt)==(19 if selected==V1 else 20)
        expected={**payload(selected),"schema":receipt["schema"],"qualification":"synthetic_root_mixed_observations_only",
            "scope":"observations_only","source_required":"original_pinned_evidence_folders","inventory":receipt["inventory"],
            "inventory_excludes":["DIGESTS.json"],"retained_files":384 if selected==V1 else 392,
            "witness_scope":"runner_witness_only_parent_counts_forwarded_not_cryptographic_process_origin"}
        if selected==V2:expected["execution_profile"]=V2
        assert raw==(json.dumps(expected,sort_keys=True,ensure_ascii=False,separators=(",",":"),allow_nan=False)+"\n").encode()
        saved.append(raw)
    assert saved[0]==saved[1] and mixed.final_paths()==paths(V1)


@pytest.mark.parametrize("profile",["unknown",pytest.param(None,id="none"),pytest.param(True,id="bool"),
    pytest.param(3,id="int"),pytest.param(3.0,id="float"),pytest.param([],id="list")])
def test_profile_selection_is_closed_before_root_writes(tmp_path,profile):
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_profile$"):
        owner(tmp_path,profile)
    assert not (tmp_path/"retained").exists()


@pytest.mark.parametrize("flag",["--api-batch","--api-chunk"])
def test_both_child_roles_cannot_construct_a_parent(tmp_path,monkeypatch,flag):
    monkeypatch.setattr(sys,"argv",["demo",flag,"0"])
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_parent_role$"):
        owner(tmp_path,V2)
    assert not (tmp_path/"retained").exists()


@pytest.mark.parametrize("changed",[V1,"unknown",pytest.param(True,id="bool")])
def test_observed_profile_drift_is_readonly_and_absorbing(tmp_path,changed):
    value=owner(tmp_path,V2)
    with pytest.raises(AttributeError):
        value.profile=V1
    value._profile=changed
    assert not value.retention_ready and value._unknown
    value._profile=V2
    assert not value.retention_ready
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_parent_or_unknown$"):
        value.finalize(payload(V2))
    assert not (value.root/"DIGESTS.json").exists()


@pytest.mark.parametrize("label",["api0-0","api0-1","api0-2","api1-0","api1-1","api1-2"])
def test_each_closed_chunk_capture_keeps_shared_deadline_and_channel_fences(tmp_path,monkeypatch,label):
    monkeypatch.chdir(tmp_path);monkeypatch.setattr(mixed,"REPO",tmp_path)
    value=owner(tmp_path,V2)
    module=mixed.linux if sys.platform=="linux" else mixed.windows
    calls=[]
    def captured(command,**kwargs):
        calls.append(command)
        assert kwargs["deadline"]==value.deadline and kwargs["timeout"]==90
        assert not any(key.casefold() in mixed.CHANNELS for key in kwargs["env"])
        kwargs["stdout_path"].write_bytes(b"out");kwargs["stderr_path"].write_bytes(b"")
        return module.Result(0,b"out",b"",True)
    monkeypatch.setattr(module,"run_linux" if sys.platform=="linux" else "run_windows",captured)
    result=value.run_saved([sys.executable,"-c","pass"],{"GITHUB_OUTPUT":"unowned"},value.root,label)
    assert result.stdout==b"out" and value.retention_ready and len(calls)==1


@pytest.mark.parametrize("profile,label",[(V1,"api0-0"),(V2,"api0"),(V2,"api0-3"),(V2,"api2-0"),(V2,"api0-0-extra")])
def test_foreign_version_or_nonexact_labels_never_spawn(tmp_path,monkeypatch,profile,label):
    monkeypatch.chdir(tmp_path);monkeypatch.setattr(mixed,"REPO",tmp_path)
    value=owner(tmp_path,profile)
    def forbidden(*args,**kwargs):raise AssertionError("invalid label must not launch")
    module=mixed.linux if sys.platform=="linux" else mixed.windows
    monkeypatch.setattr(module,"run_linux" if sys.platform=="linux" else "run_windows",forbidden)
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_capture_path$"):
        value.run_saved([sys.executable,"-c","pass"],{},value.root,label)
    assert value._captures==[] and list(value.root.iterdir())==[]


@pytest.mark.parametrize("fault",["missing","extra","duplicate","reorder","schema","profile","seed","chunk","batch",
    "bool","float","count","denials","additional","case","case_order","context","legacy","legacy_count","run_float","batch_bool","extra_field"])
def test_chunk_cover_is_exact_typed_context_bound_and_never_payload_selected(tmp_path,monkeypatch,capfd,fault):
    value=owner(tmp_path,V2);data=payload(V2);chunks=data["api_batches"];first=chunks[0]
    if fault=="missing":chunks.pop()
    elif fault=="extra":chunks.append(dict(first))
    elif fault=="duplicate":chunks[1]=dict(first)
    elif fault=="reorder":chunks.reverse()
    elif fault=="schema":first["schema"]="atlas-brain.p4-root-mixed-api-batch/1"
    elif fault=="profile":first["execution_profile"]=V1
    elif fault=="seed":first["seed"]="83"
    elif fault=="chunk":first["chunk"]=1
    elif fault=="batch":first["batch"]=1
    elif fault=="bool":first["chunk"]=False
    elif fault=="float":first["chunk"]=0.0
    elif fault=="count":first["api_runs"]=2
    elif fault=="denials":first["api_process_denied"]=3
    elif fault=="additional":first["additional_denials"]=False
    elif fault=="case":first["case_order"][-1]="zero_vrrp"
    elif fault=="case_order":first["case_order"].reverse()
    elif fault=="context":first["context"]["run_id"]="999"
    elif fault=="legacy":data["api_batches"]=[{},{}]*3
    elif fault=="legacy_count":data["api_processes"]=2
    elif fault=="run_float":first["api_runs"]=3.0
    elif fault=="batch_bool":first["batch"]=False
    else:first["unexpected"]="extra"
    opened=[]
    def forbidden(*args,**kwargs):opened.append(args);raise AssertionError("bad metadata must not read files")
    monkeypatch.setattr(mixed.Path,"open",forbidden)
    with pytest.raises(mixed.CaptureError):value.finalize(data)
    assert opened==[] and capfd.readouterr().out=="" and list(value.root.iterdir())==[]


@pytest.mark.parametrize("fault",["v2_fields","v2_count","v2_records"])
def test_legacy_never_adopts_new_version_from_payload(tmp_path,capfd,fault):
    value=owner(tmp_path,V1);data=payload(V1)
    if fault=="v2_fields":data["execution_profile"]=V2
    elif fault=="v2_count":data["api_processes"]=6
    else:data["api_batches"]=[records(data["context"])[0],{}]
    with pytest.raises(mixed.CaptureError):value.finalize(data)
    assert capfd.readouterr().out=="" and not (value.root/"DIGESTS.json").exists()


@pytest.mark.parametrize("fault",["missing","extra","v1_name"])
def test_actual_v2_inventory_rejects_missing_extra_or_cross_version_paths(tmp_path,capfd,fault):
    value=owner(tmp_path,V2);populate(value,V2)
    if fault=="missing":(value.root/"api0-1.stderr.txt").unlink()
    else:(value.root/("api0.stdout.txt" if fault=="v1_name" else "unexpected")).write_bytes(b"preserved")
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_final_population$"):
        value.finalize(payload(V2))
    assert capfd.readouterr().out=="" and not (value.root/"DIGESTS.json").exists()


def test_chunk_constructor_has_fixed_partition_and_rejects_boolean_indices():
    expected=records(payload(V2)["context"])
    assert mixed.API_CHUNK_PREFIX==b"P4_ROOT_MIXED_API_CHUNK "
    actual=[mixed.chunk_receipt(payload(V2)["context"],b,c) for b in (0,1) for c in (0,1,2)]
    assert actual==expected and [name for row in actual[:3] for name in row["case_order"]]==list(ORDER)
    for batch,chunk in ((True,0),(0,True),(0,3),(2,0)):
        with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_chunk$"):
            mixed.chunk_receipt({},batch,chunk)

def test_profile_change_after_owned_child_completion_stays_unknown(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);monkeypatch.setattr(mixed,"REPO",tmp_path)
    value=owner(tmp_path,V2)
    module=mixed.linux if sys.platform=="linux" else mixed.windows
    def captured(*args,**kwargs):
        kwargs["stdout_path"].write_bytes(b"out");kwargs["stderr_path"].write_bytes(b"")
        value._profile=V1
        return module.Result(0,b"out",b"",True)
    monkeypatch.setattr(module,"run_linux" if sys.platform=="linux" else "run_windows",captured)
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_root_or_role_changed$"):
        value.run_saved([sys.executable,"-c","pass"],{},value.root,"api0-0")
    value._profile=V2
    assert not value.retention_ready and value._captures[-1][1]=="unknown"


def test_received_factory_order_cannot_redefine_the_closed_chunk_cover(tmp_path,monkeypatch,capfd):
    value=owner(tmp_path,V2);data=payload(V2)
    monkeypatch.setattr(mixed.factory,"CASES",tuple(reversed(ORDER)))
    data["case_order"]=list(mixed.factory.CASES)
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_final_chunks$"):
        value.finalize(data)
    assert capfd.readouterr().out=="" and not (value.root/"DIGESTS.json").exists()
