"""Parent-only Root9 capture ownership/retention state; never demo completion or upload authentication.

The reviewed orchestrator, trusted fresh artifact tree and no external writers are premises.
API-batch processes may not start nested full controllers. Raw child stderr stays in owned files.
"""
import json
import math
import os
import re
import stat
import sys
import tempfile
import time
from hashlib import sha256
from pathlib import Path

from tools import p4_linux_process as linux
from tools import p4_process_state as metadata
from tools import p4_root_mixed_cases as factory
from tools import p4_windows_job as windows

REPO = Path(__file__).resolve().parents[1]
CASE_ORDER = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all_capture", "no_all_target", "zero_vrrp")
CASES = frozenset(CASE_ORDER)
LEGACY_PROFILE, CHUNK_PROFILE = "root9-v1", "root9-three-case-v2"
API_CHUNK_PREFIX = b"P4_ROOT_MIXED_API_CHUNK "
CHANNELS = frozenset(("github_output", "github_env", "github_path", "github_state", "github_step_summary"))

CONTEXT_SCHEMA = "atlas-brain.p4-git-context/1"
GIT_RELAY = r"""
import json,os,subprocess,sys
expected,repo=sys.argv[1:]
prefix=["git","--no-pager","--no-optional-locks","--no-replace-objects","--no-lazy-fetch","-c","core.fsmonitor=false","-c","core.attributesFile="+os.devnull,"-c","credential.helper=","-c","protocol.allow=never"]
try:
    head=subprocess.run(prefix+["rev-parse","--verify","HEAD"],cwd=repo,capture_output=True,check=False,timeout=10)
    if head.returncode: raise ValueError("head")
    actual=head.stdout.decode("ascii").strip()
    if len(actual)!=40 or any(c not in "0123456789abcdef" for c in actual): raise ValueError("head")
    diff=subprocess.run(prefix+["diff","--no-ext-diff","--no-textconv","--quiet","HEAD","--"],cwd=repo,capture_output=True,check=False,timeout=10)
    if diff.returncode not in (0,1): raise ValueError("diff")
    sys.stdout.buffer.write((json.dumps({"schema":"atlas-brain.p4-git-context/1","observed_head":actual,"tracked_clean":diff.returncode==0},sort_keys=True,separators=(",",":"))+"\n").encode("ascii"))
    raise SystemExit(0 if actual==expected and diff.returncode==0 else 1)
except (OSError,ValueError,subprocess.SubprocessError):
    sys.stderr.write("P4_CONTEXT_REFUSED\n")
    raise SystemExit(2)
"""
FINAL_NAMES = ("MANIFEST.sha256", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl", "facts/stp_port_vlan.jsonl", "result.json")
FINAL_FILE_LIMIT, FINAL_TREE_LIMIT, FINAL_FRAME_LIMIT = 4*1024*1024, 16*1024*1024, 4*1024*1024
PAYLOAD_FIELDS = {"context", "case_order", "measured_cases", "api_runs", "api_processes", "cli_runs", "hash_seeds", "worker_counts", "creation_orders", "api_batches", "cases"}


def plain_json(value):
    if type(value) is dict:
        return all(type(key) is str and plain_json(item) for key,item in value.items())
    if type(value) is list:
        return all(plain_json(item) for item in value)
    return value is None or type(value) in (str,bool,int) or type(value) is float and math.isfinite(value)


def api_labels(profile):
    if type(profile) is not str or profile not in (LEGACY_PROFILE, CHUNK_PROFILE):
        raise CaptureError("profile",True)
    return ("api0","api1") if profile==LEGACY_PROFILE else tuple(f"api{batch}-{chunk}" for batch in (0,1) for chunk in (0,1,2))


def chunk_receipt(context, batch, chunk):
    if type(batch) is not int or batch not in (0,1) or type(chunk) is not int or chunk not in (0,1,2):
        raise CaptureError("chunk",True)
    return {"schema":"atlas-brain.p4-root-mixed-api-chunk/2","execution_profile":CHUNK_PROFILE,
        "context":context,"batch":batch,"chunk":chunk,"seed":("1","83")[batch],"api_runs":3,
        "case_order":list(CASE_ORDER[chunk*3:chunk*3+3]),"api_process_denied":4,"additional_denials":0}


def final_paths(profile=LEGACY_PROFILE):
    paths = {f"{label}.{stream}.txt" for label in api_labels(profile) for stream in ("stdout","stderr")}
    for case in factory.CASES:
        paths.update(f"{case}/oracle/{name}" for name in FINAL_NAMES)
        for batch in (0,1):
            paths.update(f"{case}/inputs{batch}/{name}" for name in factory.members(case))
            paths.update(f"{case}/{kind}{batch}/{name}" for kind in ("api","cli") for name in FINAL_NAMES)
            paths.update(f"{case}/cli{batch}.{stream}.txt" for stream in ("stdout","stderr"))
    if len(paths)!=(383 if profile==LEGACY_PROFILE else 391) or set(factory.CASES)!=CASES or (profile==CHUNK_PROFILE and factory.CASES!=CASE_ORDER):
        raise CaptureError("final_profile",True)
    return paths

class CaptureError(metadata.ProcessError):
    def __init__(self, reason, quiescent, cleanup=()):
        RuntimeError.__init__(self, "p4_mixed_capture_" + reason)
        self.reason, self.quiescent, self.cleanup = reason, quiescent, cleanup


class MixedCapture:
    def __init__(self, root, *, deadline, profile=LEGACY_PROFILE):
        if any(flag in sys.argv[1:] for flag in ("--api-batch","--api-chunk")):
            raise CaptureError("parent_role", False)
        api_labels(profile)
        now = time.monotonic()
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or not now < deadline <= now + 420:
            raise CaptureError("deadline", True)
        self._pid, self._deadline = os.getpid(), deadline
        root = Path(root)
        root.mkdir(parents=True, exist_ok=False)
        self.root = root.resolve(strict=True)
        info = self.root.lstat()
        self._profile = profile
        self._identity = info.st_dev, info.st_ino, profile
        self._unknown, self._active, self._captures = False, False, []

    @property
    def profile(self):
        return self._profile

    @property
    def deadline(self):
        return self._deadline

    def _parent(self):
        return os.getpid() == self._pid and not any(flag in sys.argv[1:] for flag in ("--api-batch","--api-chunk"))

    def _owned(self):
        try:
            info = self.root.lstat()
        except OSError:
            return False
        return stat.S_ISDIR(info.st_mode) and type(self._profile) is str and (info.st_dev, info.st_ino, self._profile) == self._identity

    @property
    def retention_ready(self):
        if not self._parent() or self._unknown or self._active:
            return False
        if not self._owned():
            self._unknown = True
            return False
        return all(state == "quiet" for pair, state in self._captures)

    def run_saved(self, command, env, folder, label):
        if not self._parent() or self._active or self._unknown:
            raise CaptureError("parent_or_unknown", False)
        if not self.retention_ready:
            raise CaptureError("root_ownership", False)
        if sys.platform not in ("linux", "win32"):
            raise CaptureError("platform", True)
        if type(command) not in (list, tuple) or not command or any(type(part) is not str or not part or "\0" in part for part in command) or Path(command[0]).resolve() != Path(sys.executable).resolve():
            raise CaptureError("command", True)
        if type(env) is not dict or any(type(key) is not str or not key or "=" in key or "\0" in key or type(value) is not str or "\0" in value for key, value in env.items()):
            raise CaptureError("environment", True)
        if Path.cwd().resolve() != REPO.resolve():
            raise CaptureError("repository_cwd", True)
        folder = Path(folder).resolve(strict=True)
        relative = folder.relative_to(self.root).parts
        if type(label) is not str or not ((label in api_labels(self.profile) and not relative) or (label in ("cli0", "cli1") and len(relative) == 1 and relative[0] in CASES)):
            raise CaptureError("capture_path", True)
        pair = folder / (label + ".stdout.txt"), folder / (label + ".stderr.txt")
        if any(path.exists() or path.is_symlink() for path in pair) or any(old == pair for old, state in self._captures):
            raise CaptureError("capture_exists", True)
        module = linux if sys.platform == "linux" else windows
        if self.deadline - time.monotonic() <= (11 if sys.platform == "linux" else 5):
            raise CaptureError("deadline", True)
        verified, known_completion, self._active = False, False, True
        try:
            self._captures.append((pair, "pending"))
            child_env = {key: value for key, value in env.items() if key.casefold() not in CHANNELS}
            try:
                run = module.run_linux if sys.platform == "linux" else module.run_windows
                value = run(command, env=child_env, cwd=REPO, stdout_path=pair[0], stderr_path=pair[1], deadline=self.deadline, timeout=90)
            except metadata.ProcessError as error:
                native_error = type(error) is module.ProcessError
                verified = native_error and error.quiescent is True and error.cleanup == ()
                if verified and (not self._parent() or not self._owned()):
                    verified = False
                known_completion = verified
                raise CaptureError("native_refusal", verified, error.cleanup if native_error else ()) from error
            if type(value) is not module.Result or type(value.returncode) is not int or type(value.stdout) is not bytes or type(value.stderr) is not bytes or value.quiescent is not True:
                raise CaptureError("unverified_result", False)
            verified = True
            if not self._parent() or not self._owned():
                raise CaptureError("root_or_role_changed", False)
            if time.monotonic() >= self.deadline:
                known_completion = True
                raise CaptureError("deadline", True)
            if value.returncode != 0 or value.stderr:
                known_completion = True
                raise CaptureError("child_result", True)
            known_completion = True
            return value
        finally:
            verified &= known_completion
            self._active = False
            self._unknown |= not verified
            if self._captures and self._captures[-1][0] == pair:
                self._captures[-1] = pair, "quiet" if verified else "unknown"

    def check_context(self, expected_head):
        """Observe actual local checkout state; trusted Git/config/attributes, not native egress or origin attestation."""
        if not self._parent() or self._unknown or self._active or not self.retention_ready:
            raise CaptureError("parent_or_unknown", False)
        if type(expected_head) is not str or re.fullmatch("[0-9a-f]{40}", expected_head) is None:
            raise CaptureError("reviewed_head", True)
        if sys.platform not in ("linux", "win32") or Path.cwd().resolve() != REPO.resolve():
            raise CaptureError("repository_cwd", True)
        if self.deadline-time.monotonic() <= (11 if sys.platform=="linux" else 5):
            raise CaptureError("deadline", True)
        temp=Path(os.environ.get("RUNNER_TEMP",""))
        if not temp.is_absolute() or not temp.is_dir():
            raise CaptureError("runner_temp", True)
        temp=temp.resolve(strict=True)
        if temp.is_relative_to(self.root):
            raise CaptureError("runner_temp",True)
        verified,known_completion,self._active=False,False,True
        scratch,pair,identity=None,None,None
        def owned():
            if scratch is None or not self._parent() or not self._owned():
                return False
            try:info=scratch.lstat()
            except OSError:return False
            return stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==identity and scratch.parent.resolve()==temp and not scratch.resolve().is_relative_to(self.root)
        try:
            scratch=Path(tempfile.mkdtemp(prefix="p4-root-mixed-context-",dir=temp))
            info=scratch.lstat()
            identity=info.st_dev,info.st_ino
            pair=scratch/"stdout.bin",scratch/"stderr.bin"
            self._captures.append((pair,"pending"))
            if not owned():
                raise CaptureError("context_ownership",False)
            module=linux if sys.platform=="linux" else windows
            env={key:value for key,value in os.environ.items() if not key.casefold().startswith("git_") and key.casefold() not in CHANNELS}
            env.update(GIT_CONFIG_GLOBAL=os.devnull,GIT_CONFIG_SYSTEM=os.devnull,GIT_TERMINAL_PROMPT="0")
            try:
                run=module.run_linux if sys.platform=="linux" else module.run_windows
                value=run([sys.executable,"-I","-S","-c",GIT_RELAY,expected_head,str(REPO)],env=env,cwd=REPO,
                    stdout_path=pair[0],stderr_path=pair[1],deadline=self.deadline,timeout=90)
            except metadata.ProcessError as error:
                native_error=type(error) is module.ProcessError
                verified=native_error and error.quiescent is True and error.cleanup==() and owned()
                known_completion=verified
                raise CaptureError("context_native_refusal",verified,error.cleanup if native_error else ()) from error
            if type(value) is not module.Result or type(value.returncode) is not int or type(value.stdout) is not bytes or type(value.stderr) is not bytes or value.quiescent is not True:
                raise CaptureError("context_unverified",False)
            verified=True
            if not owned():
                raise CaptureError("context_ownership",False)
            if value.returncode or value.stderr:
                known_completion=True
                raise CaptureError("context_refused",True)
            record={"schema":CONTEXT_SCHEMA,"observed_head":expected_head,"tracked_clean":True}
            frame=(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
            if value.stdout!=frame:
                raise CaptureError("context_frame",False)
            if {path.name for path in scratch.iterdir()}!={"stdout.bin","stderr.bin"} or any(not stat.S_ISREG(path.lstat().st_mode) for path in pair):
                raise CaptureError("context_population",False)
            if time.monotonic()>=self.deadline:
                known_completion=True
                raise CaptureError("deadline",True)
            for path in pair:path.unlink()
            scratch.rmdir()
            if not self._parent() or not self._owned():
                raise CaptureError("context_ownership",False)
            if time.monotonic()>=self.deadline:
                known_completion=True
                raise CaptureError("deadline",True)
            known_completion=True
            return record
        finally:
            verified &= known_completion
            self._active=False
            self._unknown |= not verified
            if pair is not None and self._captures and self._captures[-1][0]==pair:
                self._captures[-1]=pair,"quiet" if verified else "unknown"

    def finalize(self, payload):
        """Emit an inventory-complete synthetic candidate, not semantic/origin/health or demo acceptance.

        Profile-local bounds are 4 MiB/file, 16 MiB/tree and 4 MiB/frame; these are not input Budgets.
        Deadlines are checked after regular-file I/O, not an OS-level interruptible-I/O guarantee.
        """
        if not self.retention_ready:
            raise CaptureError("parent_or_unknown",False)
        chunked=self.profile==CHUNK_PROFILE
        self._active=True
        created,closed,complete,identity,known_failure=False,False,False,None,False
        try:
            if type(payload) is not dict or not plain_json(payload) or set(payload)!=PAYLOAD_FIELDS:
                raise CaptureError("final_payload",True)
            data=payload
            if any(type(data[key]) is not int or data[key]!=count for key,count in (("measured_cases",9),("api_runs",18),("api_processes",6 if chunked else 2),("cli_runs",18))):
                raise CaptureError("final_counts",True)
            if data["case_order"]!=list(factory.CASES) or data["hash_seeds"]!=["1","83"] or any(type(value) is not int for value in data["worker_counts"]) or data["worker_counts"]!=[1,4] or data["creation_orders"]!=["sorted","reversed"] or type(data["cases"]) is not dict or set(data["cases"])!=CASES or type(data["api_batches"]) is not list or len(data["api_batches"])!=(6 if chunked else 2):
                raise CaptureError("final_profile",True)
            context=data["context"]
            native={"linux":("Linux","ubuntu-latest"),"win32":("Windows","windows-latest")}
            if type(context) is not dict or set(context)!={"reviewed_head","run_id","run_attempt","platform","runner_os","matrix_os"} or any(type(value) is not str for value in context.values()):
                raise CaptureError("final_context",True)
            if re.fullmatch("[0-9a-f]{40}",context["reviewed_head"]) is None or any(re.fullmatch("[1-9][0-9]*",context[key]) is None for key in ("run_id","run_attempt")) or sys.platform not in native or (context["platform"],context["runner_os"],context["matrix_os"])!=(sys.platform,*native[sys.platform]):
                raise CaptureError("final_context",True)
            if chunked:
                expected=[chunk_receipt(context,batch,chunk) for batch in (0,1) for chunk in (0,1,2)]
                def encode(value):return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)
                if factory.CASES!=CASE_ORDER or encode(data["api_batches"])!=encode(expected):
                    raise CaptureError("final_chunks",True)
            elif any(type(item) is dict and ("execution_profile" in item or "chunk" in item or item.get("schema")=="atlas-brain.p4-root-mixed-api-chunk/2") for item in data["api_batches"]):
                raise CaptureError("final_chunks",True)
            target=self.root/"DIGESTS.json"
            if target.exists() or target.is_symlink():
                raise CaptureError("receipt_exists",True)
            paths=final_paths(self.profile)
            def check():
                if self._unknown or not self._parent() or not self._owned():
                    self._unknown=True
                    raise CaptureError("final_ownership",False)
                if time.monotonic()>=self.deadline:
                    raise CaptureError("deadline",True)
            def inventory(expected):
                directories={parent.as_posix() for name in expected for parent in Path(name).parents if parent.as_posix()!="."}
                actual=set()
                for path in self.root.rglob("*"):
                    check()
                    name=path.relative_to(self.root).as_posix()
                    info=path.lstat()
                    if stat.S_ISDIR(info.st_mode):
                        if name not in directories:raise CaptureError("final_population",True)
                    elif stat.S_ISREG(info.st_mode) and name in expected:actual.add(name)
                    else:raise CaptureError("final_population",True)
                    if len(actual)>len(expected):raise CaptureError("final_population",True)
                if actual!=expected:raise CaptureError("final_population",True)
                result,total={},0
                for name in sorted(expected):
                    check()
                    size,digest=0,sha256()
                    with (self.root/name).open("rb") as stream:
                        while True:
                            check()
                            block=stream.read(min(65536,FINAL_FILE_LIMIT-size+1,FINAL_TREE_LIMIT-total+1))
                            size+=len(block);total+=len(block)
                            if size>FINAL_FILE_LIMIT or total>FINAL_TREE_LIMIT:raise CaptureError("final_budget",True)
                            if not block:break
                            digest.update(block)
                    result[name]={"bytes":size,"sha256":digest.hexdigest()}
                return result
            before=inventory(paths)
            receipt={**data,"schema":"atlas-brain.p4-root-mixed-hosted-receipt/2" if chunked else "atlas-brain.p4-root-mixed-hosted-receipt/1","qualification":"synthetic_root_mixed_observations_only",
                "scope":"observations_only","source_required":"original_pinned_evidence_folders","inventory":before,
                "inventory_excludes":["DIGESTS.json"],"retained_files":392 if chunked else 384,
                "witness_scope":"runner_witness_only_parent_counts_forwarded_not_cryptographic_process_origin"}
            if chunked:receipt["execution_profile"]=CHUNK_PROFILE
            raw=json.dumps(receipt,sort_keys=True,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode("utf-8")+b"\n"
            frame=b"P4_ROOT_MIXED_RECEIPT "+raw
            if len(raw)>FINAL_FRAME_LIMIT or len(frame)>FINAL_FRAME_LIMIT:raise CaptureError("final_frame_budget",True)
            check()
            stream=target.open("xb")
            created=True
            try:
                info=os.fstat(stream.fileno());identity=info.st_dev,info.st_ino
                try:
                    if stream.write(raw)!=len(raw):raise CaptureError("receipt_short_write",True)
                    stream.flush()
                except OSError as error:
                    raise CaptureError("receipt_io",True) from error
            finally:
                try:
                    stream.close()
                    closed=True
                finally:
                    if not closed:self._unknown=True
            after=inventory(paths|{"DIGESTS.json"})
            if {name:value for name,value in after.items() if name!="DIGESTS.json"}!=before:
                raise CaptureError("final_readback",True)
            with target.open("rb") as saved:
                if saved.read(FINAL_FRAME_LIMIT+1)!=raw:raise CaptureError("final_readback",True)
            check()
            try:
                if sys.stdout.buffer.write(frame)!=len(frame):raise CaptureError("final_stdout_short_write",True)
                sys.stdout.buffer.flush()
            except OSError as error:
                raise CaptureError("stdout_io",True) from error
            check()  # A late/partial stdout write cannot be retracted; it is not completion authority.
            complete=True
        except CaptureError as error:
            known_failure=type(error) is CaptureError and error.quiescent is True and error.reason in {
                "final_payload","final_counts","final_profile","final_context","final_chunks","receipt_exists","final_population","final_budget",
                "final_readback","final_frame_budget","receipt_short_write","receipt_io","final_stdout_short_write","stdout_io","deadline"}
            raise
        finally:
            if not complete and not known_failure:self._unknown=True
            self._active=False
            rollback_finished=False
            try:
                if created and not complete:
                    if not closed or identity is None:self._unknown=True
                    if self.retention_ready:
                        current=target.lstat()
                        if stat.S_ISREG(current.st_mode) and (current.st_dev,current.st_ino)==identity:
                            target.unlink()
                        else:self._unknown=True
                rollback_finished=True
            finally:
                if not rollback_finished:self._unknown=True
