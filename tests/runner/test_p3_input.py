"""P3 whole-folder custody, public CLI/API and generated negative regressions."""
import json
import os
import subprocess
import sys
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p3_records import SCHEMA
from atlas_brain.runner import coordinator, evidence, run
from atlas_brain.runner.p3_manifest import validate
from atlas_brain.runner.records import RunnerRefused
from tools.p3_cases import members as case_members


def members():
    discovery, mtu = b"Device ID: sw-b\n", b"GigabitEthernet1 is up, line protocol is up\n  MTU is 9000 bytes\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": ["GigabitEthernet1"]} for node in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    def point(node, number):
        return {"node": node, "port": "GigabitEthernet1", "process": number,
                "router_id": "192.0.2." + str(number), "address": "198.51.100." + str(number), "vrf": "default"}
    side = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic", "base_sha256": sha256(base).hexdigest(),
        "adjacencies": [{"id": "link", "domain": "lab", "area": 0, "left": point("a", 1), "right": point("b", 7)}],
        "samples": [{"id": "first", "time": None, "captures": [{"path": "mtu.txt", "node": "a",
            "operation": "iosxe.show_ip_interface", "sha256": sha256(mtu).hexdigest()}]}]})
    return {"p2.json": base, "p3.json": side, "discovery.txt": discovery, "mtu.txt": mtu}


def folder(tmp_path, files):
    root = tmp_path / "input"
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return root


def test_whole_folder_is_read_once_and_both_registries_all_captures_are_retained(tmp_path, monkeypatch):
    files = members()
    root = folder(tmp_path, files)
    original, calls = evidence.folder_members, []
    def tracked(path, limits):
        calls.append(path)
        return original(path, limits)
    monkeypatch.setattr(evidence, "folder_members", tracked)
    result = evidence.analyse_input(root)
    assert calls == [root] and result.group is None and result.p3 is not None
    assert result.p3.raw == files["p3.json"] and result.p3.base.raw == files["p2.json"]
    expected = result.p3.base.captures + result.p3.samples[0].captures
    assert set(result.captures) == set(expected) and len(result.captures) == 2
    assert {capture.raw for capture in result.captures} == {files["discovery.txt"], files["mtu.txt"]}
    assert all((root / name).read_bytes() == raw for name, raw in files.items())
    with pytest.raises(RunnerRefused, match="^evidence_group_context_required$"):
        evidence.analyse_evidence(root)


@pytest.mark.parametrize("limits", [
    Budgets(bundle_bytes=100000, artifact_bytes=10000, artifacts=3),
    Budgets(bundle_bytes=100000, artifact_bytes=8, artifacts=10),
    Budgets(bundle_bytes=8, artifact_bytes=10000, artifacts=10),
])
def test_p3_never_reaches_semantic_admission_before_whole_folder_budgets(tmp_path, monkeypatch, limits):
    root = folder(tmp_path, members())
    monkeypatch.setattr(evidence, "admit_p3", lambda *args: pytest.fail("admitted before budgets"))
    with pytest.raises(RunnerRefused, match="^evidence_budget_exceeded$"):
        evidence.analyse_input(root, budgets=limits)


@pytest.mark.parametrize("fault", ["missing_base", "base_hash", "capture_hash", "schema", "extra"])
def test_invalid_sidecar_never_falls_back_to_p2_or_raw_capture_route(tmp_path, monkeypatch, fault):
    files = members()
    if fault == "missing_base":
        files.pop("p2.json")
    elif fault == "base_hash":
        files["p2.json"] += b"\n"
    elif fault == "capture_hash":
        files["mtu.txt"] += b"changed\n"
    elif fault == "schema":
        files["p3.json"] = files["p3.json"].replace(SCHEMA.encode(), b"atlas-brain.synthetic-p3/9")
    else:
        files["extra.txt"] = b"unlisted"
    root = folder(tmp_path, files)
    monkeypatch.setattr(evidence, "admit_members", lambda *args: pytest.fail("P3 fell back to P2"))
    with pytest.raises(RunnerRefused):
        evidence.analyse_input(root)
    assert all((root / name).read_bytes() == raw for name, raw in files.items())


def test_invalid_p3_refuses_before_workers_or_output_changes(tmp_path, monkeypatch):
    files = members()
    files["mtu.txt"] += b"changed\n"
    root = folder(tmp_path, files)
    out = tmp_path / "output"
    out.mkdir()
    previous = {name: b"previous " + name.encode() for name in ("MANIFEST.json", "SUMMARY.txt")}
    for name, raw in previous.items():
        (out / name).write_bytes(raw)
    monkeypatch.setattr(coordinator.tripwire, "probe", lambda: pytest.fail("witness ran before admission"))
    with pytest.raises(RunnerRefused, match="^evidence_p3_capture_hash$"):
        coordinator.run(evidence=root, out=out, workers=1, parent_denied=0)
    assert {name: (out / name).read_bytes() for name in previous} == previous


NAMES = ("MANIFEST.json", "SUMMARY.txt")


def write(root, files):
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)


def snapshot(root):
    return {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}


def cli(evidence, out, workers=4, seed=1):
    before = snapshot(evidence)
    result = subprocess.run([sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
        "--out", str(out), "--workers", str(workers)], capture_output=True, text=True, check=False,
        timeout=120, env={**os.environ, "PYTHONHASHSEED": str(seed)})
    assert snapshot(evidence) == before
    return result


def test_public_p3_bytes_are_deterministic_api_matches_and_both_registries_are_counted(tmp_path, monkeypatch):
    files, evidence = case_members(canonical), tmp_path / "inputs"
    write(evidence, files)
    outputs = []
    for index, (workers, seed) in enumerate(((1, 1), (4, 97), (4, 11))):
        out = tmp_path / ("out" + str(index))
        result = cli(evidence, out, workers, seed)
        assert result.returncode == 0, result.stderr
        outputs.append(snapshot(out))
    assert outputs[0] == outputs[1] == outputs[2] and set(outputs[0]) == set(NAMES)
    record = json.loads(outputs[0]["MANIFEST.json"])
    assert record["schema"] == "atlas-brain.runner-manifest/3" and record["facts"] == {}
    assert "p2" not in record and "interface_coverage" not in record
    validate(record["p3"], record["evidence"])
    assert record["evidence"]["files"] == len(files) == 24 and record["evidence"]["captures"] == 22
    assert record["egress"] == {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40}
    assert len(record["steps"]) == 8 and record["plan"] == {"steps": 8, "witness_attempts": 4}
    finding, = record["p3"]["findings"]
    assert finding["state"] == "problem" and finding["interpretation"] == "conditional_mtu_ospf_candidate"
    assert b"P3 CONDITIONAL" in outputs[0]["SUMMARY.txt"] and b"unique cause is not proven" in outputs[0]["SUMMARY.txt"]
    original = subprocess.run
    def bounded(*args, **kwargs):
        kwargs.setdefault("timeout", 120)
        return original(*args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", bounded)
        api = run(evidence, tmp_path / "api")
    assert (api.evidence_files, api.evidence_digest, api.steps, api.egress_denied) == (
        len(files), record["evidence"]["digest"], 8, 40)
    assert snapshot(tmp_path / "api") == outputs[0] and snapshot(evidence) == files


@pytest.mark.parametrize("case,state,reason,hop", [
    ("single_sample", "unknown", "single_sample", "sampled_persistence"),
    ("untimed_conflict", "unknown", "conflicting_evidence", "sampled_persistence"),
    ("missing_mtu", "unknown", "not_collected", "ip_mtu"),
    ("mtu_ignore", "not_applicable", "feature_not_enabled", "receiving_control"),
])
def test_cli_demo_negatives_keep_the_unknown_or_countercondition_hop(tmp_path, case, state, reason, hop):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    write(evidence, case_members(canonical, case))
    result = cli(evidence, out)
    assert result.returncode == 0, result.stderr
    record = json.loads((out / "MANIFEST.json").read_bytes())
    validate(record["p3"], record["evidence"])
    finding, = record["p3"]["findings"]
    assert (finding["state"], finding["reason"], finding["hops"][-1]["id"]) == (state, reason, hop)
    assert state != "unknown" or finding["next_evidence"]
    assert (hop + "=").encode() in (out / "SUMMARY.txt").read_bytes()


def test_api_rejects_mislabeled_or_unbound_p3_manifest(tmp_path, monkeypatch):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    write(evidence, case_members(canonical))
    result = cli(evidence, out)
    assert result.returncode == 0, result.stderr
    original = json.loads((out / "MANIFEST.json").read_bytes())
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""))
    for plant in ("schema", "missing", "scope", "digest", "facts", "legacy_coverage"):
        record = json.loads(canonical(original))
        if plant == "schema":
            record["schema"] = "atlas-brain.runner-manifest/4"
        elif plant == "missing":
            record.pop("p3")
        elif plant == "scope":
            record["p3"]["scope"] = "qualified_estate"
        elif plant == "digest":
            record["evidence"]["base_registry_sha256"] = "0" * 64
        elif plant == "facts":
            record["facts"]["unbound"] = {}
        else:
            record["interface_coverage"] = {}
        (out / "MANIFEST.json").write_bytes(canonical(record))
        with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
            run(evidence, out)
