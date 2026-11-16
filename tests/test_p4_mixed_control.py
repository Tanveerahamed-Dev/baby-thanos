"""Parent capture custody/state regressions; helper completion is not complete-demo qualification."""
import json
import os
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import p4_linux_process_api as linux_api
from tools import p4_mixed_control as mixed

NATIVE = sys.platform in ("linux", "win32")


def session(tmp_path):
    return mixed.MixedCapture(tmp_path/"retained", deadline=time.monotonic()+30)


def command(code):
    return [sys.executable, "-c", code]


def native_module():
    return mixed.linux if sys.platform == "linux" else mixed.windows


def snapshot():
    if sys.platform == "linux":
        return linux_api.get_subreaper(), signal.getsignal(signal.SIGCHLD), os.getsid(0), os.getpgrp()
    return None


@pytest.mark.parametrize("mode", ["ok", "cli", "exit", "stderr", "orphan"])
def test_real_native_capture_owns_pairs_and_never_forwards_child_stderr(tmp_path, capfd, mode):
    if not NATIVE:
        value=session(tmp_path)
        with pytest.raises(mixed.CaptureError, match="^p4_mixed_capture_platform$"):
            value.run_saved(command("pass"), {}, value.root, "api0")
        return
    before=snapshot()
    value=session(tmp_path)
    folder,label=value.root,"api0"
    if mode=="cli":
        folder=value.root/"normal";folder.mkdir();label="cli0"
    attack="::error::fixture-must-stay-in-owned-file"
    code="import os;os.write(1,b'out')"
    if mode=="stderr":code+=";os.write(2,"+repr(attack.encode())+")"
    if mode=="exit":code+=";raise SystemExit(7)"
    if mode=="orphan":
        writer="import os,sys,time\nwith open(sys.argv[1],'xb') as marker: marker.write(b'ready')\nwhile True: os.write(1,b'x');time.sleep(.01)\n"
        code=("import subprocess,sys,time\nfrom pathlib import Path\np=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
              "end=time.monotonic()+3\nwhile not Path(sys.argv[2]).exists() and time.monotonic()<end: time.sleep(.005)\nassert Path(sys.argv[2]).exists()\n")
        args=command(code)+[writer,str(tmp_path/"ready")]
    else:args=command(code)
    if mode in ("ok","cli"):
        result=value.run_saved(args,dict(os.environ),folder,label)
        assert type(result) is native_module().Result and result.stdout==b"out" and result.stderr==b""
    else:
        with pytest.raises(mixed.CaptureError) as error:
            value.run_saved(args,dict(os.environ),value.root,"api0")
        assert error.value.quiescent is True
        assert error.value.reason==("native_refusal" if mode=="orphan" else "child_result")
        if mode=="orphan":assert type(error.value.__cause__) is native_module().ProcessError and error.value.__cause__.cleanup==()
    assert value.retention_ready and len(value._captures)==1 and value._captures[0][1]=="quiet"
    assert {path.name for path in folder.iterdir()}=={label+".stdout.txt",label+".stderr.txt"}
    emitted=capfd.readouterr()
    assert emitted.out=="" and attack not in emitted.out+emitted.err and snapshot()==before
    assert emitted.err==('P4_LINUX_FAILURE {"kind":"LinuxError","reason":"descendants"}\n' if sys.platform=="linux" and mode=="orphan" else "")
    if mode=="stderr":assert (value.root/"api0.stderr.txt").read_bytes()==attack.encode()


@pytest.mark.parametrize("plant", ["opaque", "memory", "interrupt", "exit", "bad_type", "bad_code", "bad_bytes", "false_result", "false_error", "dirty_error", "clock", "post_drift"])
def test_unknown_is_absorbing_even_after_real_helper_completed(tmp_path, monkeypatch, plant):
    if not NATIVE:return
    before=snapshot()
    value=session(tmp_path)
    module=native_module()
    attribute="run_linux" if sys.platform=="linux" else "run_windows"
    real=getattr(module,attribute)
    calls=[]
    opaque={"opaque":TypeError("opaque"),"memory":MemoryError("allocation"),"interrupt":KeyboardInterrupt(),"exit":SystemExit("not-forwarded")}
    def changed(*args,**kwargs):
        assert value._active and not value.retention_ready and value._captures[-1][1]=="pending"
        calls.append(kwargs)
        result=real(*args,**kwargs)
        if plant in opaque:raise opaque[plant]
        if plant=="clock":
            def broken():raise TypeError("opaque clock failure")
            monkeypatch.setattr(mixed,"time",SimpleNamespace(monotonic=broken))
            return result
        if plant=="post_drift":
            value.root.rename(tmp_path/"preserved")
            value.root.mkdir()
            return result
        if plant=="bad_type":return SimpleNamespace(returncode=0,stdout=b"out",stderr=b"",quiescent=True)
        if plant=="false_error":raise module.ProcessError("fixture",False)
        if plant=="dirty_error":raise module.ProcessError("fixture",True,("unacknowledged",))
        return module.Result(False if plant=="bad_code" else 0,"text" if plant=="bad_bytes" else result.stdout,result.stderr,plant!="false_result")
    monkeypatch.setattr(module,attribute,changed)
    kind=type(opaque[plant]) if plant in opaque else TypeError if plant=="clock" else mixed.CaptureError
    with pytest.raises(kind):
        value.run_saved(command("print('out',end='')"),dict(os.environ),value.root,"api0")
    assert len(calls)==1 and not value.retention_ready and value._captures[-1][1]=="unknown"
    def forbidden(path):
        raise AssertionError("unknown capture must not be read")
    monkeypatch.setattr(Path,"read_bytes",forbidden)
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_parent_or_unknown$"):
        value.run_saved(command("pass"),dict(os.environ),value.root,"api1")
    assert len(calls)==1 and not value.retention_ready and snapshot()==before


def test_parent_owned_environment_removes_all_file_command_channels(tmp_path, monkeypatch):
    if not NATIVE:return
    value=session(tmp_path)
    module=native_module()
    attribute="run_linux" if sys.platform=="linux" else "run_windows"
    real=getattr(module,attribute)
    env={**os.environ,"GITHUB_OUTPUT":"fixture","gItHuB_eNv":"fixture","GITHUB_PATH":"fixture","GITHUB_STATE":"fixture","GITHUB_STEP_SUMMARY":"fixture","P4_ORDINARY":"retained"}
    captured=[]
    def observed(*args,**kwargs):
        captured.append(kwargs)
        assert not any(key.casefold() in mixed.CHANNELS for key in kwargs["env"])
        assert kwargs["env"]["P4_ORDINARY"]=="retained" and kwargs["deadline"]==value.deadline and kwargs["timeout"]==90
        return real(*args,**kwargs)
    monkeypatch.setattr(module,attribute,observed)
    result=value.run_saved(command("import json,os;assert os.environ['P4_ORDINARY']=='retained';print(json.dumps(sorted(k for k in os.environ if k.lower().startswith('github_'))))"),env,value.root,"api0")
    assert not any(name.casefold() in mixed.CHANNELS for name in json.loads(result.stdout))
    assert len(captured)==1 and env["GITHUB_OUTPUT"]=="fixture" and value.retention_ready


@pytest.mark.parametrize("fault", ["batch", "pid", "drift", "existing", "command", "env", "folder", "label", "deadline", "cwd"])
def test_prelaunch_guards_never_spawn_or_claim_prior_root_ownership(tmp_path, monkeypatch, fault):
    if fault=="batch":
        monkeypatch.setattr(sys,"argv",["demo","--api-batch","0"])
        with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_parent_role$"):session(tmp_path)
        assert not (tmp_path/"retained").exists()
        return
    value=session(tmp_path)
    module=native_module() if NATIVE else mixed.linux
    attribute="run_linux" if sys.platform=="linux" else "run_windows"
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append(args)
        raise AssertionError("prelaunch refusal cannot spawn")
    monkeypatch.setattr(module,attribute,forbidden)
    args,env,folder,label=command("pass"),dict(os.environ),value.root,"api0"
    if fault=="pid":monkeypatch.setattr(mixed.os,"getpid",lambda:value._pid+1)
    elif fault=="drift":
        value.root.rename(tmp_path/"preserved")
        value.root.mkdir()
    elif fault=="existing":(value.root/"api0.stdout.txt").write_bytes(b"prior")
    elif fault=="command":args=["not-python"]
    elif fault=="env":env["BAD"]="bad\0value"
    elif fault=="folder":folder=tmp_path
    elif fault=="label":label="../escape"
    elif fault=="deadline":monkeypatch.setattr(mixed,"time",SimpleNamespace(monotonic=lambda:value.deadline-1))
    elif fault=="cwd":monkeypatch.chdir(tmp_path)
    with pytest.raises((mixed.CaptureError,ValueError)):
        value.run_saved(args,env,folder,label)
    assert calls==[]
    if fault in ("pid","drift"):assert not value.retention_ready
    if fault=="existing":assert (value.root/"api0.stdout.txt").read_bytes()==b"prior"


def test_replayed_root_and_read_only_deadline_cannot_be_blessed(tmp_path):
    value=session(tmp_path)
    (value.root/"prior").write_bytes(b"preserved")
    with pytest.raises(FileExistsError):session(tmp_path)
    assert (value.root/"prior").read_bytes()==b"preserved"
    with pytest.raises(AttributeError):value.deadline=time.monotonic()+420
    with pytest.raises(AttributeError):value.retention_ready=True
    assert value.retention_ready  # Stable current-run root is not a completed demo.


def test_known_api_batch_and_forked_session_role_are_refused_before_new_calls(tmp_path,monkeypatch):
    value=session(tmp_path)
    monkeypatch.setattr(sys,"argv",["demo","--api-batch","0"])
    assert not value.retention_ready
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_parent_or_unknown$"):
        value.run_saved(command("pass"),dict(os.environ),value.root,"api0")


def test_fd_capture_witness_sees_real_os_stderr_forwarding_counterfactual(tmp_path, monkeypatch, capfd):
    if not NATIVE:return
    value=session(tmp_path)
    module=native_module()
    attribute="run_linux" if sys.platform=="linux" else "run_windows"
    real=getattr(module,attribute)
    attack=b"FD_CAPTURE_COUNTERFACTUAL"
    def forwarded(*args,**kwargs):
        result=real(*args,**kwargs)
        os.write(2,result.stderr)
        return result
    monkeypatch.setattr(module,attribute,forwarded)
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_child_result$"):
        value.run_saved(command("import os;os.write(2,"+repr(attack)+")"),dict(os.environ),value.root,"api0")
    emitted=capfd.readouterr()
    assert emitted.out=="" and emitted.err==attack.decode() and value.retention_ready


@pytest.mark.parametrize("drift", ["root", "batch", "pid"])
def test_real_quiet_native_error_cannot_bless_changed_ownership_even_after_restoration(tmp_path, monkeypatch, drift):
    if not NATIVE:return
    value=session(tmp_path)
    module=native_module()
    attribute="run_linux" if sys.platform=="linux" else "run_windows"
    real=getattr(module,attribute)
    errors=[]
    preserved=tmp_path/"preserved"
    writer="import os,sys,time\nwith open(sys.argv[1],'xb') as marker: marker.write(b'ready')\nwhile True: os.write(1,b'x');time.sleep(.01)\n"
    code=("import subprocess,sys,time\nfrom pathlib import Path\np=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
          "end=time.monotonic()+3\nwhile not Path(sys.argv[2]).exists() and time.monotonic()<end: time.sleep(.005)\nassert Path(sys.argv[2]).exists()\n")
    with monkeypatch.context() as changed:
        def observed(*args,**kwargs):
            try:
                return real(*args,**kwargs)
            except module.ProcessError as error:
                assert type(error) is module.ProcessError and error.quiescent is True and error.cleanup==()
                errors.append(error)
                if drift=="root":
                    value.root.rename(preserved)
                    value.root.mkdir()
                elif drift=="batch":changed.setattr(sys,"argv",["demo","--api-batch","0"])
                else:changed.setattr(mixed.os,"getpid",lambda:value._pid+1)
                raise
        changed.setattr(module,attribute,observed)
        try:
            with pytest.raises(mixed.CaptureError) as refused:
                value.run_saved(command(code)+[writer,str(tmp_path/"ready")],dict(os.environ),value.root,"api0")
        finally:
            if drift=="root" and preserved.exists():
                value.root.rmdir()
                preserved.rename(value.root)
    assert len(errors)==1 and refused.value.__cause__ is errors[0] and refused.value.quiescent is False
    assert value._owned() and not value.retention_ready and value._captures[-1][1]=="unknown"
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append(args)
        raise AssertionError("restoring ownership cannot clear Unknown")
    monkeypatch.setattr(module,attribute,forbidden)
    with pytest.raises(mixed.CaptureError,match="^p4_mixed_capture_parent_or_unknown$"):
        value.run_saved(command("pass"),dict(os.environ),value.root,"api1")
    assert calls==[] and not value.retention_ready
