"""Controlled v2 coverage; only the dedicated native workflow can qualify complete execution."""
import io
import json
import os
import sys
from types import SimpleNamespace

import pytest
from test_p4_root_mixed_demo import CURRENT, controlled as controlled, diagnostics_default_off as diagnostics_default_off, encoded

from tools import p4_mixed_control as control
from tools import p4_root_mixed_demo as demo
from atlas_brain.runner import p4_root_mixed_report

V2="root9-three-case-v2"
ORDER=("normal","none","cold_vrrp","only_vrrp","empty","partial","no_all_capture","no_all_target","zero_vrrp")


@pytest.fixture
def chunks(controlled,monkeypatch):
    state=controlled
    state.fail_at=None;state.api_cases=[];state.chunk_cases=[];state.input_checks=[]
    monkeypatch.setattr(demo.sys,"argv",["demo","--profile",V2])
    module=control.linux if sys.platform=="linux" else control.windows
    attribute="run_linux" if sys.platform=="linux" else "run_windows"
    previous=getattr(module,attribute)
    report=p4_root_mixed_report.analyse_root_mixed_folder
    def observed(root,budgets):
        state.api_cases.append(root.parent.name)
        return report(root,budgets)
    monkeypatch.setattr(p4_root_mixed_report,"analyse_root_mixed_folder",observed)
    unchanged=demo.unchanged
    def checked(originals,owner):
        state.input_checks.append((len(state.calls),tuple(originals),owner.deadline))
        return unchanged(originals,owner)
    monkeypatch.setattr(demo,"unchanged",checked)
    def saved(command,**kwargs):
        if "--api-chunk" not in command:return previous(command,**kwargs)
        batch=int(command[command.index("--api-batch")+1]);chunk=int(command[command.index("--api-chunk")+1])
        if state.fault in ("exit","timeout","stderr","opaque","unknown"):return previous(command,**kwargs)
        assert kwargs["timeout"]==90 and kwargs["deadline"]==state.owners[0].deadline and kwargs["cwd"]==control.REPO
        assert not any(key.casefold() in control.CHANNELS for key in kwargs["env"])
        state.calls.append(("chunk",batch,chunk,kwargs["env"]["PYTHONHASHSEED"]))
        if state.fail_at==batch*3+chunk:
            kwargs["stdout_path"].write_bytes(b"partial");kwargs["stderr_path"].write_bytes(b"owned-error")
            return module.Result(7,b"partial",b"owned-error",True)
        state.events.clear();buffer=io.BytesIO();start=len(state.api_cases)
        with monkeypatch.context() as patch:
            patch.setenv("PYTHONHASHSEED",kwargs["env"]["PYTHONHASHSEED"])
            patch.setattr(demo.sys,"argv",["demo",*command[4:]])
            patch.setattr(demo.sys,"stdout",SimpleNamespace(buffer=buffer))
            demo.main()
        state.chunk_cases.append((batch,chunk,state.api_cases[start:]))
        raw=buffer.getvalue()
        assert raw.startswith(b"P4_ROOT_MIXED_API_CHUNK ")
        record=json.loads(raw.removeprefix(control.API_CHUNK_PREFIX))
        if state.fault.startswith("chunk_"):
            kind=state.fault.removeprefix("chunk_")
            if kind=="context":record["context"]["run_id"]="999"
            elif kind=="seed":record["seed"]="83"
            elif kind=="batch":record["batch"]=1
            elif kind=="index":record["chunk"]=1
            elif kind=="type":record["chunk"]=False
            elif kind=="float":record["api_runs"]=3.0
            elif kind=="count":record["api_runs"]=2
            elif kind=="case":record["case_order"].pop()
            elif kind=="order":record["case_order"].reverse()
            elif kind=="schema":record["schema"]="atlas-brain.p4-root-mixed-api-batch/1"
            elif kind=="extra":record["extra"]="not-authority"
            elif kind=="graft":record=control.chunk_receipt(CURRENT,1,2)
            elif kind=="omitted":(state.root/ORDER[chunk*3+2]/f"api{batch}"/"result.json").unlink()
            raw=control.API_CHUNK_PREFIX+encoded(record)+b"\n"
            if kind=="prefix":raw=raw.replace(control.API_CHUNK_PREFIX,b"P4_ROOT_MIXED_API_BATCH ")
            elif kind=="missing":raw=b""
        kwargs["stdout_path"].write_bytes(raw);kwargs["stderr_path"].write_bytes(b"")
        return module.Result(0,raw,b"",True)
    monkeypatch.setattr(module,attribute,saved)
    return state


def test_complete_controlled_v2_has_fixed_cover_24_calls_392_files_and_52_stages(chunks,monkeypatch,capfd):
    monkeypatch.setenv("P4_ROOT_MIXED_DIAGNOSTICS","1")
    clock=SimpleNamespace(monotonic=lambda:100.0)
    monkeypatch.setattr(demo,"time",clock);monkeypatch.setattr(control,"time",clock)
    current=demo.context
    def delayed():clock.monotonic=lambda:150.0;return current()
    monkeypatch.setattr(demo,"context",delayed)
    demo.main()
    assert chunks.owners[0].deadline==520.0
    emitted=capfd.readouterr();value=json.loads((chunks.root/"DIGESTS.json").read_bytes())
    expected=[]
    for batch,seed in enumerate(("1","83")):
        expected.extend(("chunk",batch,chunk,seed) for chunk in (0,1,2))
        expected.extend((case,batch,seed,1 if batch==0 else 4) for case in ORDER)
    assert chunks.calls==expected and chunks.checks==[0,24]
    assert chunks.api_cases==list(ORDER)*2
    assert chunks.chunk_cases==[(b,c,list(ORDER[c*3:c*3+3])) for b in (0,1) for c in (0,1,2)]
    assert [row[0] for row in chunks.input_checks]==list(range(1,25))
    assert all(row[1]==ORDER and row[2]==chunks.owners[0].deadline for row in chunks.input_checks)
    assert value["schema"]=="atlas-brain.p4-root-mixed-hosted-receipt/2" and value["execution_profile"]==V2
    assert value["context"]==CURRENT and value["case_order"]==list(ORDER)
    assert (value["hash_seeds"],value["worker_counts"],value["creation_orders"])==(["1","83"],[1,4],["sorted","reversed"])
    assert (value["api_runs"],value["api_processes"],value["cli_runs"],value["measured_cases"])==(18,6,18,9)
    expected_chunks=[{"schema":"atlas-brain.p4-root-mixed-api-chunk/2","execution_profile":V2,
        "context":CURRENT,"batch":b,"chunk":c,"seed":("1","83")[b],"api_runs":3,
        "case_order":list(ORDER[c*3:c*3+3]),"api_process_denied":4,"additional_denials":0}
        for b in (0,1) for c in (0,1,2)]
    assert value["api_batches"]==expected_chunks
    files={p.relative_to(chunks.root).as_posix():p.read_bytes() for p in chunks.root.rglob("*") if p.is_file()}
    assert len(files)==value["retained_files"]==392 and len(value["inventory"])==391
    assert value["inventory"]=={name:{"bytes":len(raw),"sha256":demo.sha256(raw).hexdigest()} for name,raw in files.items() if name!="DIGESTS.json"}
    assert all(len(value["cases"][case]["batches"])==2 and all(row["api_files"]==row["cli_files"]==value["cases"][case]["oracle_files"] for row in value["cases"][case]["batches"]) for case in ORDER)
    stages=[json.loads(line.removeprefix("P4_ROOT_MIXED_STAGE ")) for line in emitted.err.splitlines()]
    order=[("context",0)]
    for batch in (0,1):
        order.extend(("api",batch*3+chunk) for chunk in (0,1,2));order.extend(("cli",batch*9+i) for i in range(9))
    order.append(("context",1))
    assert [(row["stage"],row["ordinal"]) for row in stages]==[(name+"_"+edge,n) for name,n in order for edge in ("before","after")]
    assert len(stages)==52 and all(set(row)=={"stage","ordinal","elapsed_ms"} and type(row["elapsed_ms"]) is int and 0<=row["elapsed_ms"]<420000 for row in stages)
    assert [row["elapsed_ms"] for row in stages]==sorted(row["elapsed_ms"] for row in stages)
    assert emitted.out.encode()==b"P4_ROOT_MIXED_RECEIPT "+files["DIGESTS.json"]
    assert chunks.output.read_bytes()==b"retention_ready=false\nretention_ready=true\n"


@pytest.mark.parametrize("kind",["context","seed","batch","index","type","float","count","case","order","schema","extra","graft","omitted","prefix","missing"])
def test_invalid_chunk_frame_or_missing_case_never_publishes(chunks,capfd,kind):
    chunks.fault="chunk_"+kind
    with pytest.raises(ValueError):demo.main()
    assert not (chunks.root/"DIGESTS.json").exists() and chunks.output.read_bytes()==b"retention_ready=false\n"
    assert capfd.readouterr().out==""


@pytest.mark.parametrize("slot",range(6))
def test_failure_at_each_chunk_has_no_after_no_later_reads_and_no_publication(chunks,monkeypatch,capfd,slot):
    chunks.fail_at=slot;monkeypatch.setenv("P4_ROOT_MIXED_DIAGNOSTICS","1")
    with pytest.raises(control.CaptureError):demo.main()
    emitted=capfd.readouterr()
    rows=[json.loads(line.removeprefix("P4_ROOT_MIXED_STAGE ")) for line in emitted.err.splitlines()]
    assert rows[-1]["stage"]=="api_before" and rows[-1]["ordinal"]==slot
    assert len(chunks.calls)==slot+1+9*(slot//3)
    assert [row[0] for row in chunks.input_checks]==list(range(1,len(chunks.calls)))
    assert chunks.checks==[0] and not (chunks.root/"DIGESTS.json").exists()
    assert chunks.output.read_bytes()==b"retention_ready=false\n" and emitted.out=="" and "owned-error" not in emitted.err


@pytest.mark.parametrize("fault",["exit","timeout","stderr","deadline","opaque","unknown"])
def test_failed_owned_v2_helper_cannot_read_inputs_or_finalize(chunks,monkeypatch,capfd,fault):
    chunks.fault=fault;monkeypatch.setenv("P4_ROOT_MIXED_DIAGNOSTICS","1")
    reads=[]
    def forbidden(*args,**kwargs):reads.append(args);raise AssertionError("failed helper must not read")
    monkeypatch.setattr(demo,"snapshot",forbidden);monkeypatch.setattr(demo.MixedCapture,"finalize",forbidden)
    with pytest.raises(TypeError if fault=="opaque" else control.CaptureError):demo.main()
    emitted=capfd.readouterr()
    assert reads==[] and chunks.input_checks==[] and chunks.checks==[0]
    assert emitted.err.splitlines()[-1].startswith("P4_ROOT_MIXED_STAGE ") and emitted.out==""
    assert chunks.output.read_bytes()==b"retention_ready=false\n" and not (chunks.root/"DIGESTS.json").exists()


@pytest.mark.parametrize("arguments",[
    ["--profile"],["--profile","root9-v1"],["--profile","unknown"],
    ["--profile",V2,"--api-batch","0"],["--api-chunk","0"],
    ["--api-batch","0","--api-chunk","0"],["--profile",V2,"--api-chunk","0"],
    ["--profile",V2,"--api-batch","00","--api-chunk","0"],
    ["--profile",V2,"--api-batch","0","--api-chunk","00"],
    ["--profile",V2,"--api-batch","False","--api-chunk","0"],
    ["--profile",V2,"--api-batch","0","--api-chunk","3"],
    ["--profile",V2,"--api-batch","0","--api-chunk","0","extra"],
    ["--profile",V2,"--api-batch","0","--api-chunk","True"],
    ["--profile",V2,"--api-chunk","0","--api-batch","0"],
    ["--profile",V2,"--api-batch","0","--api-chunk","-1"],
    ["--profile",V2,"--api-batch","2","--api-chunk","0"],["--profile",V2,"--profile",V2]])
def test_only_closed_trusted_argv_can_choose_v2(controlled,monkeypatch,arguments):
    monkeypatch.setattr(demo.sys,"argv",["demo",*arguments])
    with pytest.raises(ValueError,match="^p4_root_mixed_demo_arguments$"):demo.main()
    assert controlled.calls==[] and not controlled.root.exists() and controlled.output.read_bytes()==b""


def test_profile_environment_cannot_select_v2_without_trusted_argv(controlled,monkeypatch):
    monkeypatch.setenv("P4_ROOT_MIXED_PROFILE",V2)
    demo.main()
    value=json.loads((controlled.root/"DIGESTS.json").read_bytes())
    assert len(controlled.calls)==20 and value["retained_files"]==384 and value["api_processes"]==2
    assert value["schema"]=="atlas-brain.p4-root-mixed-hosted-receipt/1" and "execution_profile" not in value


@pytest.mark.parametrize("flag",["--api-batch","--api-chunk"])
def test_actual_child_role_suppresses_inherited_parent_diagnostics(tmp_path,flag):
    module=control.linux if sys.platform=="linux" else control.windows
    run=module.run_linux if sys.platform=="linux" else module.run_windows
    code="import os,sys\nfrom tools import p4_root_mixed_demo as d\nos.environ['P4_ROOT_MIXED_DIAGNOSTICS']='1'\nsys.argv=['demo',sys.argv[1],'0']\nd.diagnostic('bad',object(),object(),d.CHUNK_PROFILE)\n"
    env={k:v for k,v in os.environ.items() if k.casefold() not in control.CHANNELS}
    value=run([sys.executable,"-B","-c",code,flag],env=env,cwd=control.REPO,stdout_path=tmp_path/"stdout",stderr_path=tmp_path/"stderr",deadline=demo.time.monotonic()+30,timeout=20)
    assert value.returncode==0 and value.quiescent is True and value.stdout==value.stderr==b""


@pytest.mark.parametrize("mode",["arguments","canary"])
def test_actual_protected_v2_entry_renders_only_fixed_refusal(tmp_path,mode):
    module=control.linux if sys.platform=="linux" else control.windows
    run=module.run_linux if sys.platform=="linux" else module.run_windows
    env={k:v for k,v in os.environ.items() if k.casefold() not in control.CHANNELS}
    env.update(GITHUB_ACTIONS="true",P4_ROOT_MIXED_REVIEWED_SHA=CURRENT["reviewed_head"],RUNNER_OS=CURRENT["runner_os"],
        P4_ROOT_MIXED_MATRIX_OS=CURRENT["matrix_os"],GITHUB_RUN_ID="123",GITHUB_RUN_ATTEMPT="1")
    command=[sys.executable,"-B","-m","tools.p4_root_mixed_demo","--profile",V2,"--api-chunk","00"]
    if mode=="canary":
        code="import os,runpy,sys\nclass Env(dict):\n def get(self,key,default=None):\n  if key=='GITHUB_ACTIONS':raise OSError('V2_ENTRY_CANARY')\n  return super().get(key,default)\nos.environ=Env(os.environ)\nsys.argv=['demo','--profile','root9-three-case-v2']\nrunpy.run_module('tools.p4_root_mixed_demo',run_name='__main__')\n"
        command=[sys.executable,"-B","-c",code]
    existed=demo.ROOT.exists()
    value=run(command,env=env,cwd=control.REPO,stdout_path=tmp_path/"stdout",stderr_path=tmp_path/"stderr",deadline=demo.time.monotonic()+30,timeout=20)
    assert value.returncode==1 and value.quiescent is True and value.stdout==b"" and value.stderr==b"P4_ROOT_MIXED_REFUSED\n"
    assert b"CANARY" not in value.stderr and demo.ROOT.exists()==existed


def test_workflow_uses_the_explicit_closed_v2_profile():
    text=(control.REPO/".github/workflows/p4-root-mixed.yml").read_text(encoding="utf-8")
    assert "run: uv run --no-sync python -B -m tools.p4_root_mixed_demo --profile root9-three-case-v2\n" in text


@pytest.mark.parametrize("fault",["installed","probe","extra_egress"])
def test_each_v2_api_chunk_keeps_tripwire_install_probe_and_no_extra_egress(chunks,capfd,fault):
    chunks.fault=fault
    with pytest.raises(ValueError):demo.main()
    assert len(chunks.calls)==1 and chunks.checks==[0]
    assert chunks.output.read_bytes()==b"retention_ready=false\n" and not (chunks.root/"DIGESTS.json").exists()
    assert capfd.readouterr().out==""


@pytest.mark.parametrize("fault",["input","oracle","receipt","late_head","inventory"])
def test_v2_input_or_oracle_or_witness_or_final_context_drift_never_publishes(chunks,capfd,fault):
    chunks.fault=fault
    with pytest.raises((ValueError,control.CaptureError)):demo.main()
    assert chunks.output.read_bytes()==b"retention_ready=false\n" and not (chunks.root/"DIGESTS.json").exists()
    assert capfd.readouterr().out==""


def test_workflow_requires_success_and_explicit_true_and_preserves_native_budget_pins():
    text=(control.REPO/".github/workflows/p4-root-mixed.yml").read_text(encoding="utf-8")
    assert "id: demo\n" in text and "continue-on-error" not in text
    assert "P4_ROOT_MIXED_DIAGNOSTICS: '1'" in text
    assert all("P4_ROOT_MIXED_DIAGNOSTICS" not in path.read_text(encoding="utf-8") for path in (control.REPO/".github/workflows").glob("*.yml") if path.name!="p4-root-mixed.yml")
    assert "if: \u0024{{ always() && steps.demo.outcome == 'success' && steps.demo.outputs.retention_ready == 'true' }}" in text
    assert "os: [ubuntu-latest, windows-latest]" in text and "timeout-minutes: 10" in text and "fail-fast: false" in text
    assert "permissions:\n  contents: read\n" in text and "path: .ci-evidence/p4-root-mixed" in text
    for pin in ("checkout@11d5960a326750d5838078e36cf38b85af677262","setup-uv@1c37ad07a6a961277cf70c0d37d6f313000f5884","upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"):assert pin in text
    for token in ("github.event.pull_request.head.sha || github.sha","github.run_id","github.run_attempt","include-hidden-files: true","if-no-files-found: error","uv sync --locked","uv run --no-sync python -B -m tools.p4_root_mixed_demo"):assert token in text


