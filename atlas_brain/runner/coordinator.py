"""Coordinator and worker roles: explicit-spawn scheduler that writes the result bytes."""
import json
import re
import stat
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical

from . import tripwire
from .evidence import analyse_input, require_evidence
from .p2 import analyse_group
from .records import RunnerRefused, capture_facts, missing_interfaces

SCHEMA = "atlas-brain.runner-manifest/1"
STEPS = tuple(f"witness/{index:02d}" for index in range(8))
STEP_PATTERN = r"witness/[0-9][0-9]"


def run_worker(steps: tuple[str, ...]) -> None:
    """Worker role: run the assigned witness steps, one receipt line each on stdout."""
    if not steps or any(re.fullmatch(STEP_PATTERN, step, re.ASCII) is None for step in steps):
        raise RunnerRefused("invalid_steps")
    for step in steps:
        denied = tripwire.probe()
        if denied != tripwire.WITNESS_ATTEMPTS:
            raise RunnerRefused("egress_witness_failed")
        print(json.dumps({"denied": denied, "step": step}, sort_keys=True))


def run(*, evidence: Path, out: Path, workers: int, parent_denied: int) -> int:
    """Coordinator role: run the plan, collect workers, write SUMMARY.txt and MANIFEST.json."""
    if workers < 1:
        raise RunnerRefused("invalid_workers")
    require_evidence(evidence)
    try:
        source, destination = Path.resolve(evidence), Path.resolve(out)
    except OSError as error:
        raise RunnerRefused("evidence_output_unreadable") from error
    if Path.is_relative_to(source, destination) or Path.is_relative_to(destination, source):
        raise RunnerRefused("evidence_output_overlap")
    for name in ("SUMMARY.txt", "MANIFEST.json"):
        try:
            info = Path.lstat(out / name)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RunnerRefused("output_unwritable") from error
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
            raise RunnerRefused("output_unsafe_member")
    admitted = analyse_input(evidence)
    p3_group = admitted.p3
    captures, group = admitted.captures, admitted.group
    files = len(captures) + (2 if p3_group is not None else int(group is not None))
    entries = [{"capture": str(capture.id), "sha256": capture.bytes_sha256} for capture in captures]
    digest_input: object = sorted(entries, key=lambda entry: entry["capture"])
    if p3_group is not None:
        digest_input = {"captures": digest_input, "registry_sha256": sha256(p3_group.raw).hexdigest(),
                        "base_registry_sha256": sha256(p3_group.base.raw).hexdigest()}
    elif group is not None:
        digest_input = {"captures": digest_input, "registry_sha256": sha256(group.raw).hexdigest()}
    evidence_digest = sha256(canonical(digest_input)).hexdigest()
    facts: dict[str, object] = {}
    fact_lines: list[str] = []
    p2: dict[str, object] | None = None
    p3: dict[str, object] | None = None
    if p3_group is not None:
        from .p3 import analyse_group as analyse_p3_group
        try:
            p3, lines = analyse_p3_group(p3_group)
        except RunnerRefused:
            raise
        except ValueError as error:
            code = str(error)
            if re.fullmatch(r"[a-z][a-z0-9_]*", code, re.ASCII) is None:
                code = "analysis_failed"
            raise RunnerRefused("p3_" + code) from error
        fact_lines.extend(lines)
    elif group is None:
        for capture in sorted(captures, key=lambda capture: capture.id):
            projected, lines = capture_facts(capture)
            facts[str(capture.id)] = projected
            fact_lines.extend(lines)
    else:
        try:
            p2, lines = analyse_group(group)
        except RunnerRefused:
            raise
        except ValueError as error:
            code = str(error)
            if re.fullmatch(r"[a-z][a-z0-9_]*", code, re.ASCII) is None:
                code = "analysis_failed"
            raise RunnerRefused("p2_" + code) from error
        fact_lines.extend(lines)
    interface_present = any(capture.operation in (
        "iosxe.show_interfaces", "iosxe.show_ip_interface_brief") for capture in captures)
    legacy_interface_missing = p3_group is None and not interface_present
    schema = ("atlas-brain.runner-manifest/3" if p3_group is not None else
              SCHEMA if group is None else "atlas-brain.runner-manifest/2")
    missing, missing_text = missing_interfaces()
    coordinator_denied = tripwire.probe()
    if coordinator_denied != tripwire.WITNESS_ATTEMPTS:
        raise RunnerRefused("egress_witness_failed")
    results = _spawn_workers(workers)
    worker_denied = sum(denied for _, denied in results)
    total = parent_denied + coordinator_denied + worker_denied
    summary = "\n".join((
        "BABY THANOS RUNNER - P3 CONDITIONAL MTU / OSPF CANDIDATE" if p3_group is not None else
        "BABY THANOS RUNNER - P2 DECLARED SYNTHETIC TWO ENDS" if group is not None else
        "BABY THANOS RUNNER - P1 INTERFACE ANSWER" if interface_present else "BABY THANOS RUNNER - P0 SYSTEM FACTS",
        f"schema: {schema}",
        f"evidence: files={files} digest={evidence_digest}",
        f"steps: {len(results)}",
        f"witness: {tripwire.WITNESS_ATTEMPTS} denied egress attempts per step",
        f"egress denied: {total} (parent={parent_denied} coordinator={coordinator_denied} workers={worker_denied})",
        "determinism: sorted keys, no run timestamps, no host-root paths, no worker-count fields",
        "execution status: OK",
        *(("l1.interface: " + missing_text,) if legacy_interface_missing else ()),
        "",
        "FACTS",
        *fact_lines,
    )) + "\n"
    record = {
        "schema": schema,
        "evidence": {"digest": evidence_digest, "files": files},
        "plan": {"steps": len(results), "witness_attempts": tripwire.WITNESS_ATTEMPTS},
        "egress": {"parent_denied": parent_denied, "coordinator_denied": coordinator_denied,
                   "worker_denied": worker_denied, "denied": total},
        "steps": [{"denied": denied, "id": step} for step, denied in results],
        "facts": facts,
    }
    if legacy_interface_missing:
        record["interface_coverage"] = missing
    if p2 is not None and group is not None:
        record["p2"] = p2
        record["evidence"] = {"digest": evidence_digest, "files": files,
                              "captures": len(captures), "registry_sha256": sha256(group.raw).hexdigest()}
    if p3 is not None and p3_group is not None:
        record["p3"] = p3
        record["evidence"] = {"digest": evidence_digest, "files": files, "captures": len(captures),
                              "registry_sha256": sha256(p3_group.raw).hexdigest(),
                              "base_registry_sha256": sha256(p3_group.base.raw).hexdigest()}
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "SUMMARY.txt").write_text(summary, encoding="utf-8", newline="\n")
        (out / "MANIFEST.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    except OSError as error:
        raise RunnerRefused("output_unwritable") from error
    return total


def _spawn_workers(workers: int) -> tuple[tuple[str, int], ...]:
    batches: list[list[str]] = [[] for _ in range(workers)]
    for index, step in enumerate(STEPS):
        batches[index % workers].append(step)
    results: list[tuple[str, int]] = []
    for batch in batches:
        if not batch:
            continue
        command = [sys.executable, "-m", "atlas_brain.runner", "--role", "worker", "--steps", ",".join(batch)]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        rows = [json.loads(line) for line in completed.stdout.splitlines() if line]
        if completed.returncode != 0 or len(rows) != len(batch):
            raise RunnerRefused("worker_protocol_failed")
        for row in rows:
            if not isinstance(row, dict):
                raise RunnerRefused("worker_protocol_failed")
            record = cast(dict[str, object], row)
            if set(record) != {"denied", "step"}:
                raise RunnerRefused("worker_protocol_failed")
            step, denied = record["step"], record["denied"]
            if not (isinstance(step, str) and isinstance(denied, int)
                    and step in batch and denied == tripwire.WITNESS_ATTEMPTS):
                raise RunnerRefused("worker_protocol_failed")
            results.append((step, denied))
    if sorted(step for step, _ in results) != sorted(STEPS):
        raise RunnerRefused("worker_protocol_failed")
    return tuple(sorted(results))


P4_NAMES = ("MANIFEST.sha256", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl",
            "facts/stp_port_vlan.jsonl", "result.json")


type OwnedPath = tuple[Path, int, int]


def _owned_p4(item: OwnedPath, *, directory: bool) -> bool:
    path, device, inode = item
    try:
        info = Path.lstat(path)
    except OSError:
        return False
    return ((info.st_dev, info.st_ino) == (device, inode)
            and (stat.S_ISDIR(info.st_mode) and not path.is_junction() if directory
                 else stat.S_ISREG(info.st_mode) and info.st_nlink == 1))


def _rollback_p4(files: list[OwnedPath], directories: list[OwnedPath]) -> None:
    for item in reversed(files):
        try:
            if _owned_p4(item, directory=False):
                item[0].unlink()
        except OSError:
            pass
    for item in reversed(directories):
        try:
            if _owned_p4(item, directory=True):
                item[0].rmdir()
        except OSError:
            pass


def _publish_p4(out: Path, stage: Path, files: dict[str, bytes]) -> None:
    created_files: list[OwnedPath] = []
    created_directories: list[OwnedPath] = []
    try:
        for directory in (stage, stage / "facts"):
            directory.mkdir()
            info = Path.lstat(directory)
            created_directories.append((directory, info.st_dev, info.st_ino))
        for name, raw in sorted(files.items()):
            path = stage / name
            with path.open("xb") as stream:
                info = Path.lstat(path)
                created_files.append((path, info.st_dev, info.st_ino))
                if stream.write(raw) != len(raw):
                    raise RunnerRefused("output_verification_failed")
        if (not all(_owned_p4(item, directory=True) for item in created_directories)
                or not all(_owned_p4(item, directory=False) for item in created_files)
                or {path.name for path in stage.iterdir()} != {"facts", "result.json", "MANIFEST.sha256"}
                or {path.name for path in (stage / "facts").iterdir()} != {"etherchannel_group.jsonl", "fhrp_local.jsonl", "stp_port_vlan.jsonl"}
                or any((stage / name).read_bytes() != raw for name, raw in files.items())):
            raise RunnerRefused("output_verification_failed")
        try:
            Path.lstat(out)
        except FileNotFoundError:
            pass
        else:
            raise RunnerRefused("output_exists")
        stage.rename(out)
    except (OSError, RunnerRefused) as error:
        _rollback_p4(created_files, created_directories)
        if isinstance(error, RunnerRefused):
            raise
        raise RunnerRefused("output_unwritable") from error


def run_p4(*, evidence: Path, out: Path, workers: int, parent_denied: int) -> int:
    """Publish P4 observations on stable trees; rename visibility does not promise fsync or hostile-race safety."""
    from atlas_brain.contract.manifest import manifest
    from atlas_brain.evidence.admission import Budgets

    from .p4 import SCHEMA as P4_SCHEMA
    from .p4 import analyse_folder

    if type(workers) is not int or workers < 1:
        raise RunnerRefused("invalid_workers")
    if type(parent_denied) is not int or parent_denied not in (0, tripwire.WITNESS_ATTEMPTS):
        raise RunnerRefused("invalid_parent_witness")
    require_evidence(evidence)
    try:
        source, destination = Path.resolve(evidence), Path.resolve(out)
        stage = out.with_name("." + out.name + ".p4-stage")
    except (OSError, ValueError) as error:
        raise RunnerRefused("evidence_output_unreadable") from error
    if Path.is_relative_to(source, destination) or Path.is_relative_to(destination, source):
        raise RunnerRefused("evidence_output_overlap")
    try:
        parent = Path.lstat(out.parent)
        if not stat.S_ISDIR(parent.st_mode) or out.parent.is_symlink() or out.parent.is_junction():
            raise RunnerRefused("output_parent_invalid")
        for path, code in ((out, "output_exists"), (stage, "output_staging_exists")):
            try:
                Path.lstat(path)
            except FileNotFoundError:
                continue
            raise RunnerRefused(code)
    except OSError as error:
        raise RunnerRefused("output_unwritable") from error
    try:
        files = dict(analyse_folder(evidence, Budgets(
            bundle_bytes=16 * 1024 * 1024, artifact_bytes=4 * 1024 * 1024, artifacts=128)))
    except RunnerRefused:
        raise
    except OSError as error:
        raise RunnerRefused("evidence_unreadable") from error
    except ValueError as error:
        code = str(error)
        if re.fullmatch(r"[a-z][a-z0-9_]*", code, re.ASCII) is None:
            code = "analysis_failed"
        raise RunnerRefused("p4_" + code) from error
    if set(files) != set(P4_NAMES) or any(type(raw) is not bytes for raw in files.values()):
        raise RunnerRefused("p4_output_invalid")
    if files["MANIFEST.sha256"] != manifest({name: raw for name, raw in files.items() if name != "MANIFEST.sha256"}):
        raise RunnerRefused("p4_output_invalid")
    try:
        payload = json.loads(files["result.json"])
    except ValueError as error:
        raise RunnerRefused("p4_output_invalid") from error
    if not isinstance(payload, dict):
        raise RunnerRefused("p4_output_invalid")
    record = cast(dict[str, object], payload)
    if (record.get("schema") != P4_SCHEMA or record.get("scope") != "observations_only"
            or record.get("checks") != "not_implemented" or "execution" in record):
        raise RunnerRefused("p4_output_invalid")
    coordinator_denied = tripwire.probe()
    if type(coordinator_denied) is not int or coordinator_denied != tripwire.WITNESS_ATTEMPTS:
        raise RunnerRefused("egress_witness_failed")
    try:
        results = _spawn_workers(workers)
    except RunnerRefused:
        raise
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise RunnerRefused("worker_protocol_failed") from error
    worker_denied = sum(denied for _, denied in results)
    total = parent_denied + coordinator_denied + worker_denied
    record["execution"] = {
        "schema": "atlas-brain.runner-witness/1",
        "plan": {"steps": len(results), "witness_attempts": tripwire.WITNESS_ATTEMPTS},
        "egress": {"parent_denied": parent_denied, "coordinator_denied": coordinator_denied,
                   "worker_denied": worker_denied, "denied": total},
        "steps": [{"denied": denied, "id": step} for step, denied in results],
    }
    files["result.json"] = canonical(record)
    files["MANIFEST.sha256"] = manifest({name: raw for name, raw in files.items() if name != "MANIFEST.sha256"})
    _publish_p4(out, stage, files)
    return total
