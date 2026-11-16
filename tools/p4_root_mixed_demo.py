"""Hosted original-fixture API/CLI comparison; runner counts are not cryptographic process-origin or network qualification."""
import json
import os
import stat
import sys
import time
from hashlib import sha256
from pathlib import Path

from tools.p4_mixed_control import MixedCapture

ROOT = Path(".ci-evidence/p4-root-mixed")
CASES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all_capture", "no_all_target", "zero_vrrp")
NAMES = ("MANIFEST.sha256", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl", "facts/stp_port_vlan.jsonl", "result.json")
SEEDS, WORKERS = ("1", "83"), (1, 4)


def need(condition, code):
    if not condition:
        raise ValueError("p4_root_mixed_demo_" + code)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def snapshot(root, owner):
    need(owner.retention_ready, "unknown")
    files,total={},0
    for path in root.rglob("*"):
        need(owner.retention_ready, "unknown")
        need(time.monotonic()<owner.deadline, "deadline")
        kind=path.lstat().st_mode
        if stat.S_ISDIR(kind):continue
        need(stat.S_ISREG(kind), "snapshot_population")
        with path.open("rb") as stream:
            raw=stream.read(min(4*1024*1024+1,16*1024*1024-total+1))
        total+=len(raw)
        need(len(raw)<=4*1024*1024 and total<=16*1024*1024, "snapshot_budget")
        files[path.relative_to(root).as_posix()]=raw
        need(owner.retention_ready and time.monotonic()<owner.deadline, "deadline")
    need(owner.retention_ready and time.monotonic()<owner.deadline, "deadline")
    return files


def signatures(files):
    return {name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()} for name, raw in sorted(files.items())}


def context():
    """Validate inherited hosted labels only; actual Git observation belongs to the owning parent."""
    need(os.environ.get("GITHUB_ACTIONS") == "true", "hosted_only")
    head = os.environ.get("P4_ROOT_MIXED_REVIEWED_SHA", "")
    need(len(head) == 40 and all(char in "0123456789abcdef" for char in head), "reviewed_head")
    native = {"linux": ("Linux", "ubuntu-latest"), "win32": ("Windows", "windows-latest")}
    need(sys.platform in native and native[sys.platform] == (os.environ.get("RUNNER_OS"), os.environ.get("P4_ROOT_MIXED_MATRIX_OS")), "platform")
    ids = [os.environ.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    need(all(value and value[0] in "123456789" and all(char in "0123456789" for char in value) for value in ids), "run_context")
    return {"reviewed_head": head, "run_id": ids[0], "run_attempt": ids[1], "platform": sys.platform, "runner_os": native[sys.platform][0], "matrix_os": native[sys.platform][1]}


def write_files(root, files, reverse=False):
    root.mkdir(parents=True, exist_ok=False)
    for name in sorted(files, reverse=reverse):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(files[name])


def batch_receipt(current, batch):
    return {"schema": "atlas-brain.p4-root-mixed-api-batch/1", "context": current, "batch": batch, "seed": SEEDS[batch], "api_runs": 9, "case_order": list(CASES), "api_process_denied": 4, "additional_denials": 0}


def api_batch(current, batch):
    need(os.environ.get("PYTHONHASHSEED") == SEEDS[batch], "hash_seed")
    from atlas_brain.runner import tripwire
    need(tripwire.install() and tripwire.probe() == 4, "tripwire")
    events = tripwire.violations()
    need(len(events) == 4, "tripwire")
    from atlas_brain.evidence.admission import Budgets
    from atlas_brain.runner.p4_root_mixed_report import analyse_root_mixed_folder
    for case in CASES:
        files = analyse_root_mixed_folder(ROOT / case / f"inputs{batch}", Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128))
        need(set(files) == set(NAMES) and all(type(raw) is bytes for raw in files.values()), "api_reports")
        write_files(ROOT / case / f"api{batch}", files)
    need(tripwire.violations() == events, "extra_egress")
    need(context() == current, "context_changed")
    sys.stdout.buffer.write(b"P4_ROOT_MIXED_API_BATCH " + encoded(batch_receipt(current, batch)) + b"\n")


def cli_receipt(raw, files):
    expected = {"schema": "atlas-brain.p4-root-mixed-cli-witness/1", "format": "p4-root-mixed-observations", "report_schema": "atlas-brain.p4-root-mixed-observations/1", "manifest_sha256": sha256(files["MANIFEST.sha256"]).hexdigest(),
        "execution": {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4}, "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
            "steps": [{"denied": 4, "id": f"witness/{index:02d}"} for index in range(8)]}, "scope": "runner_witness_only"}
    frame = b"P4_ROOT_MIXED_CLI_RECEIPT " + encoded(expected) + b"\nrunner: ok egress_denied=40\n"
    need(raw in (frame, frame.replace(b"\n", b"\r\n")), "cli_receipt")
    return expected


def unchanged(originals, owner):
    need(all(snapshot(ROOT / case / f"inputs{batch}", owner) == raw for case, raw in originals.items() for batch in (0, 1)), "input_changed")


class _RetentionOutput:
    """Fixed parent-only runner output; trusted path configuration, not origin authentication."""
    def __init__(self, owner):
        need(type(owner) is MixedCapture and owner.retention_ready and not owner._captures and not any(owner.root.iterdir()), "output_owner")
        self.owner,self._pid=owner,os.getpid()
        self.path=Path(os.environ.get("GITHUB_OUTPUT",""))
        need(self.path.is_absolute(), "output_path")
        info=self.path.lstat()
        need(stat.S_ISREG(info.st_mode) and not self.path.resolve(strict=True).is_relative_to(owner.root), "output_path")
        self.identity=info.st_dev,info.st_ino
        self._append(b"retention_ready=false\n")

    def _check(self):
        need(os.getpid()==self._pid and self.owner.retention_ready, "output_owner")
        need(time.monotonic()<self.owner.deadline, "deadline")
        info=self.path.lstat()
        need(stat.S_ISREG(info.st_mode) and (info.st_dev,info.st_ino)==self.identity and not self.path.resolve(strict=True).is_relative_to(self.owner.root), "output_identity")

    def _append(self, raw):
        self._check()
        flags=os.O_WRONLY|os.O_APPEND
        for name in ("O_BINARY","O_NONBLOCK","O_CLOEXEC","O_NOFOLLOW"):flags|=getattr(os,name,0)
        fd=os.open(self.path,flags)
        try:
            info=os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and (info.st_dev,info.st_ino)==self.identity and not os.get_inheritable(fd), "output_identity")
            stream=os.fdopen(fd,"ab",closefd=False)
            try:
                need(stream.write(raw)==len(raw), "output_short_write")
                stream.flush()
            finally:
                stream.close()
        finally:
            os.close(fd)
        self._check()

    def publish(self):
        self._append(b"retention_ready=true\n")


def main():
    deadline = time.monotonic() + 420
    current = context()
    arguments = sys.argv[1:]
    if arguments:
        need(len(arguments) == 2 and arguments[0] == "--api-batch" and arguments[1] in ("0", "1"), "arguments")
        api_batch(current, int(arguments[1]))
        return
    owner=MixedCapture(ROOT,deadline=deadline)
    output=_RetentionOutput(owner)
    owner.check_context(current["reviewed_head"])
    from atlas_brain.model.pack_registration import compile_packs
    from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS
    from tools.p4_root_mixed_cases import CASES as factory_cases
    from tools.p4_root_mixed_cases import members
    from tools.p4_root_mixed_evidence import evidence_tables
    from tools.p4_root_mixed_expected import expected_bundle
    need(factory_cases == CASES and len(CASES) == len(set(CASES)) == 9, "cases")
    compiled = compile_packs(DECLARATIONS)
    need(sum(len(pack.facts) for pack in DECLARATIONS) == 9 and len(compiled.operations) == 5 and compiled.registration_sha256 == sha256(compiled.registration_bytes).hexdigest(), "registration")
    originals, expected, cases = {}, {}, {}
    for case in CASES:
        raw = members(case)
        originals[case], expected[case] = raw, expected_bundle(case, raw, compiled.registration_sha256)
        need(set(expected[case]) == set(NAMES), "oracle_reports")
        write_files(ROOT / case / "oracle", expected[case])
        for batch in (0, 1):
            write_files(ROOT / case / f"inputs{batch}", raw, reverse=bool(batch))
        cells = [json.loads(line) for name in NAMES if name.startswith("facts/") for line in expected[case][name].splitlines()]
        cases[case] = {"input_files": signatures(raw), "oracle_files": signatures(expected[case]), "anchor_sha256": sha256(encoded(evidence_tables(case, raw, compiled.registration_sha256)["anchors"])).hexdigest(),
            "cells": len(cells), "known": sum(row["value"]["state"] == "known" for row in cells), "unknown": sum(row["value"]["state"] == "unknown" for row in cells), "denominator": json.loads(expected[case]["result.json"])["denominator"], "batches": []}
    batches = []
    for batch, (seed, workers) in enumerate(zip(SEEDS, WORKERS, strict=True)):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"}
        result = owner.run_saved([sys.executable, "-B", "-m", "tools.p4_root_mixed_demo", "--api-batch", str(batch)], env, ROOT, f"api{batch}")
        unchanged(originals, owner)
        receipt = batch_receipt(current, batch)
        need(result.stdout == b"P4_ROOT_MIXED_API_BATCH " + encoded(receipt) + b"\n", "api_receipt")
        batches.append(receipt)
        for case in CASES:
            folder = ROOT / case
            result = owner.run_saved([sys.executable, "-B", "-m", "atlas_brain.runner", "--format", "p4-root-mixed-observations", "--evidence", str(folder / f"inputs{batch}"), "--out", str(folder / f"cli{batch}"), "--workers", str(workers)], env, folder, f"cli{batch}")
            unchanged(originals, owner)
            api, cli = snapshot(folder / f"api{batch}", owner), snapshot(folder / f"cli{batch}", owner)
            need(api == cli == expected[case], "oracle_" + case + "_b" + str(batch))
            witness = cli_receipt(result.stdout, cli)
            cases[case]["batches"].append({"batch": batch, "seed": seed, "workers": workers, "creation_order": "reversed" if batch else "sorted", "api_files": signatures(api), "cli_files": signatures(cli), "cli_witness": witness})
    need(context() == current, "context_changed")
    owner.check_context(current["reviewed_head"])
    payload={"context":current,"case_order":list(CASES),"measured_cases":9,"api_runs":18,"api_processes":2,"cli_runs":18,
        "hash_seeds":list(SEEDS),"worker_counts":list(WORKERS),"creation_orders":["sorted","reversed"],"api_batches":batches,"cases":cases}
    owner.finalize(payload)
    output.publish()

if __name__ == "__main__":
    try:
        main()
    finally:
        if sys.exception() is not None:
            try:
                os.write(2,b"P4_ROOT_MIXED_REFUSED\n")
            finally:
                os._exit(1)
