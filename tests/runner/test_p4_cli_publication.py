import json
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_p2_runner import snapshot as tree_snapshot
from test_p4_observations import FACTS, snapshot, unpack
from test_p4_proof_index import estate
from test_runner import evidence_folder, read_outputs, run_cli

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from atlas_brain.runner import cli, coordinator, p4

RECEIPTS = tuple((f"witness/{i:02d}", 4) for i in range(8))


def stage(out):
    return out.with_name("." + out.name + ".p4-stage")


def prepared(tmp_path, monkeypatch):
    evidence, out = tmp_path / "evidence", tmp_path / "out"
    evidence.mkdir()
    estate(evidence)
    monkeypatch.setattr(coordinator.tripwire, "probe", lambda: 4)
    monkeypatch.setattr(coordinator, "_spawn_workers", lambda workers: RECEIPTS)
    return evidence, out


def test_real_cli_witness_worker_seed_and_directory_invariance(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    estate(evidence, guard=b"disabled", protocol=b"-")
    before, outputs = snapshot(evidence), []
    for role, workers, seed, total in (("parent", "1", "1", 40), ("parent", "4", "83", 40), ("coordinator", "2", "1", 36)):
        monkeypatch.setenv("PYTHONHASHSEED", seed)
        out = tmp_path / (role + workers)
        args = ("--format", "p4-observations", "--evidence", str(evidence), "--out", str(out), "--workers", workers)
        result = run_cli(*(args + (("--role", role) if role != "parent" else ())))
        assert result.returncode == 0, result.stderr
        files = tree_snapshot(out)
        head, rows = unpack(files)
        execution = head["execution"]
        assert execution["schema"] == "atlas-brain.runner-witness/1" and set(execution) == {"schema", "plan", "egress", "steps"}
        assert execution["plan"] == {"steps": 8, "witness_attempts": 4}
        assert execution["steps"] == [{"id": step, "denied": denied} for step, denied in RECEIPTS]
        assert execution["egress"] == {"parent_denied": total - 36, "coordinator_denied": 4, "worker_denied": 32, "denied": total}
        pure = p4.analyse_folder(evidence, p4.Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128))
        pure_head = json.loads(pure["result.json"])
        assert {k: v for k, v in head.items() if k != "execution"} == pure_head
        assert all(files[name] == pure[name] for name in FACTS) and snapshot(evidence) == before and not stage(out).exists()
        assert next(r for r in rows if r["fact"] == p4.stp.ROOT_GUARD and r["vlan"] == 1)["value"] is False
        assert next(r for r in rows if r["fact"] == p4.ec.REPORTED_PROTOCOL and r["group"] == "2")["value"] == "none_reported"
        assert b"worker" not in canonical({k: v for k, v in head.items() if k != "execution"})
        if role == "parent":
            outputs.append(files)
    assert outputs[0] == outputs[1]


def test_default_and_explicit_legacy_bytes_and_parent_argv_remain_unchanged(tmp_path, monkeypatch):
    evidence = evidence_folder(tmp_path)
    first, second = tmp_path / "one", tmp_path / "two"
    assert run_cli("--evidence", str(evidence), "--out", str(first)).returncode == 0
    assert run_cli("--format", "legacy", "--evidence", str(evidence), "--out", str(second)).returncode == 0
    assert read_outputs(first) == read_outputs(second)
    commands = []
    monkeypatch.setattr(cli.tripwire, "probe", lambda: 4)
    monkeypatch.setattr(cli.subprocess, "run", lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=0))
    assert cli._run(["--evidence", str(evidence), "--out", str(tmp_path / "unused")]) == 0
    assert commands == [[cli.sys.executable, "-m", "atlas_brain.runner", "--role", "coordinator", "--evidence", str(evidence),
                         "--out", str(tmp_path / "unused"), "--workers", "4", "--parent-denied", "4"]]


@pytest.mark.parametrize("arguments", [("--format", "other"), ("--role", "worker", "--steps", "witness/00", "--format", "p4-observations")])
def test_invalid_formats_refuse_without_publishing(tmp_path, arguments):
    out = tmp_path / "out"
    result = run_cli(*arguments, "--evidence", str(tmp_path), "--out", str(out))
    assert result.returncode == 2 and result.stderr == "runner refused: invalid_format\n"
    assert not out.exists() and not stage(out).exists()


@pytest.mark.parametrize("fault", ["analysis", "probe", "worker", "worker_os", "profile", "manifest", "workers_bool", "parent_bool", "parent_count"])
def test_all_analysis_profile_and_witnesses_close_before_any_stage(tmp_path, monkeypatch, fault):
    real_spawn = coordinator._spawn_workers
    evidence, out = prepared(tmp_path, monkeypatch)
    original, events = p4.analyse_folder, []
    def analyse(*args):
        assert not out.exists() and not stage(out).exists() and events == []
        if fault == "analysis":
            raise coordinator.RunnerRefused("p4_projection_scope")
        files = original(*args)
        if fault in ("profile", "manifest"):
            head = json.loads(files["result.json"])
            head["scope"] = "healthy" if fault == "profile" else head["scope"]
            files["result.json"] = canonical(head)
            if fault == "profile":
                files["MANIFEST.sha256"] = manifest({n: b for n, b in files.items() if n != "MANIFEST.sha256"})
            else:
                files["MANIFEST.sha256"] = b"wrong"
        events.append("analysis")
        return files
    monkeypatch.setattr(p4, "analyse_folder", analyse)
    def probe():
        assert not out.exists() and not stage(out).exists() and events == ["analysis"]
        events.append("probe")
        return 0 if fault == "probe" else 4
    def workers(count):
        assert not out.exists() and not stage(out).exists() and events == ["analysis", "probe"]
        events.append("workers")
        if fault in ("worker", "worker_os"):
            def child(*args, **kwargs):
                if fault == "worker_os":
                    raise OSError("worker spawn failed")
                return SimpleNamespace(returncode=0, stdout="invalid json")
            monkeypatch.setattr(coordinator.subprocess, "run", child)
            return real_spawn(count)
        return RECEIPTS
    monkeypatch.setattr(coordinator.tripwire, "probe", probe)
    monkeypatch.setattr(coordinator, "_spawn_workers", workers)
    with pytest.raises(coordinator.RunnerRefused, match="^(p4_projection_scope|egress_witness_failed|worker_protocol_failed|p4_output_invalid|invalid_workers|invalid_parent_witness)$"):
        coordinator.run_p4(evidence=evidence, out=out, workers=True if fault == "workers_bool" else 2, parent_denied=False if fault == "parent_bool" else 99 if fault == "parent_count" else 4)
    assert not out.exists() and not stage(out).exists()


@pytest.mark.parametrize("which", ["out", "stage"])
@pytest.mark.parametrize("kind", ["file", "empty", "directory", "symlink", "broken", "hardlink"] + (["junction"] if os.name == "nt" else []))
def test_preexisting_output_or_stage_is_refused_and_never_changed(tmp_path, monkeypatch, which, kind):
    evidence, out = prepared(tmp_path, monkeypatch)
    path = out if which == "out" else stage(out)
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "marker"
    marker.write_bytes(b"preserve")
    if kind == "file":
        path.write_bytes(b"preserve")
    elif kind in ("empty", "directory"):
        path.mkdir()
        if kind == "directory":
            (path / "marker").write_bytes(b"preserve")
    elif kind == "hardlink":
        os.link(marker, path)
    elif kind == "junction" and os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(target)], check=True, capture_output=True)
    else:
        path.symlink_to(tmp_path / "missing" if kind == "broken" else target, target_is_directory=True)
    identity = path.lstat()[:3]
    monkeypatch.setattr(p4, "analyse_folder", lambda *args: pytest.fail("analysis before output safety"))
    with pytest.raises(coordinator.RunnerRefused, match="^" + ("output_exists" if which == "out" else "output_staging_exists") + "$"):
        coordinator.run_p4(evidence=evidence, out=out, workers=1, parent_denied=4)
    preserved = path / "marker" if kind == "directory" else path if kind in ("file", "hardlink") else marker
    assert marker.read_bytes() == preserved.read_bytes() == b"preserve" and path.lstat()[:3] == identity
    if kind == "empty":
        assert not list(path.iterdir())


@pytest.mark.parametrize("overlap", ["same", "inside", "ancestor", "parent_link", "nameless"])
def test_overlapping_and_linked_output_paths_refuse_before_analysis(tmp_path, monkeypatch, overlap):
    evidence, normal = prepared(tmp_path, monkeypatch)
    out = Path(".") if overlap == "nameless" else evidence if overlap == "same" else evidence / "out" if overlap == "inside" else tmp_path if overlap == "ancestor" else normal
    if overlap == "parent_link":
        linked = tmp_path / "link"
        linked.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
        (tmp_path / "elsewhere").mkdir()
        out = linked / "out"
    monkeypatch.setattr(p4, "analyse_folder", lambda *args: pytest.fail("unsafe path analysed"))
    with pytest.raises(coordinator.RunnerRefused, match="^" + ("output_parent_invalid" if overlap == "parent_link" else "evidence_output_unreadable" if overlap == "nameless" else "evidence_output_overlap") + "$"):
        coordinator.run_p4(evidence=evidence, out=out, workers=1, parent_denied=4)


@pytest.mark.parametrize("fault", ["open", "partial_write", "short_write", "readback", "read_error", "rename", "cleanup", "unknown", "replacement", "inventory", "directory"])
def test_publication_failure_never_exposes_final_and_cleanup_is_ownership_bounded(tmp_path, monkeypatch, fault):
    evidence, out = prepared(tmp_path, monkeypatch)
    staging = stage(out)
    real_open, real_read, real_rename, real_unlink, real_iter = Path.open, Path.read_bytes, Path.rename, Path.unlink, Path.iterdir
    first, second = staging / "MANIFEST.sha256", staging / "facts/etherchannel_group.jsonl"
    replaced = []
    @contextmanager
    def opened(path, *args, **kwargs):
        if path == second and args == ("xb",):
            if fault in ("unknown", "inventory"):
                (staging / "unknown").write_bytes(b"preserve")
            if fault == "replacement":
                real_rename(first, staging / "displaced")
                first.write_bytes(b"foreign")
            if fault == "directory":
                real_rename(staging / "facts", tmp_path / "displaced-facts")
                (staging / "facts").mkdir()
                (staging / "facts/foreign").write_bytes(b"preserve")
                replaced.append(True)
            if fault in ("open", "unknown", "cleanup", "replacement"):
                raise OSError("injected open failure")
        with real_open(path, *args, **kwargs) as stream:
            def write(raw):
                if path == second and fault == "partial_write":
                    stream.write(raw[:1])
                    raise OSError("injected partial write")
                return stream.write(raw[:-1] if path == second and fault == "short_write" else raw)
            yield SimpleNamespace(write=write) if args == ("xb",) else stream
    def accessed(path, listing=False):
        assert not (replaced and path.is_relative_to(staging)), "verification visited replaced output tree"
        if not listing and path == first and fault == "read_error":
            raise OSError("injected verification read")
        return real_iter(path) if listing else b"changed" if path == first and fault == "readback" else real_read(path)
    def blocked(method, code, target):
        def apply(path, *args, **kwargs):
            if path == target and fault == code:
                raise OSError("injected " + code + " failure")
            return method(path, *args, **kwargs)
        return apply
    monkeypatch.setattr(Path, "iterdir", lambda path: accessed(path, True))
    monkeypatch.setattr(Path, "open", opened)
    monkeypatch.setattr(Path, "read_bytes", accessed)
    monkeypatch.setattr(Path, "rename", blocked(real_rename, "rename", staging))
    monkeypatch.setattr(Path, "unlink", blocked(real_unlink, "cleanup", first))
    with pytest.raises(coordinator.RunnerRefused, match="^" + ("output_verification_failed" if fault in ("short_write", "readback", "inventory", "directory") else "output_unwritable") + "$") as refusal:
        coordinator.run_p4(evidence=evidence, out=out, workers=2, parent_denied=4)
    assert not out.exists()
    if fault in ("cleanup", "unknown", "replacement", "inventory", "directory"):
        assert staging.is_dir()
        if fault in ("unknown", "inventory"):
            assert real_read(staging / "unknown") == b"preserve"
        elif fault == "replacement":
            assert real_read(first) == b"foreign"
        elif fault == "directory":
            assert real_read(staging / "facts/foreign") == b"preserve" and (tmp_path / "displaced-facts").is_dir()
        else:
            assert real_read(first) and str(refusal.value.__cause__) == "injected open failure"
    else:
        assert not staging.exists()
