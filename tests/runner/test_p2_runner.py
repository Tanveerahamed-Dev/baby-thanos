"""Real CLI P2 regressions over generated declared-synthetic bytes."""
import json
import os
import subprocess
import sys
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import SCHEMA
from atlas_brain.runner import RunnerRefused, run

PORT = "Gi1/0/1"
CDP, TRUNK = "iosxe.show_cdp_neighbors_detail", "iosxe.show_interfaces_trunk"
NATIVE, ALLOWED = "l2.vlan_trunk.native_mismatch", "l2.vlan_trunk.allowed_asymmetry"


def members(*, missing_b=False, asymmetric=False, discovery_only=False):
    files, references = {}, []
    for node, peer, native, allowed in (("sw-a", "sw-b", "10", "10,20"), ("sw-b", "sw-a", "20", "10")):
        if missing_b and node == "sw-b":
            continue
        remote = "Gi1/0/9" if asymmetric and node == "sw-b" else PORT
        outputs = [(CDP, "Device ID: " + peer + "\nPlatform: synthetic-switch, Capabilities: Switch\n"
                    + "Interface: " + PORT + ", Port ID (outgoing port): " + remote + "\n")]
        if not discovery_only:
            outputs.append((TRUNK, "Port Mode Encapsulation Status Native vlan\n" + PORT
                            + " on 802.1q trunking " + native + "\nPort Vlans allowed on trunk\n"
                            + PORT + " " + allowed + "\n"))
        for operation, text in outputs:
            path = node + "." + operation + ".txt"
            files[path] = text.encode()
            references.append({"path": path, "node": node, "operation": operation,
                               "sha256": sha256(files[path]).hexdigest()})
    declaration = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                   "nodes": [{"id": node, "discovery_id": node, "ports": [PORT]} for node in ("sw-a", "sw-b")],
                   "captures": references}
    return {**files, "p2.json": canonical(declaration)}


def write_members(root, files):
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def cli(evidence, out, workers=4, seed=1):
    before = snapshot(evidence)
    completed = subprocess.run([sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
                                "--out", str(out), "--workers", str(workers)],
                               capture_output=True, text=True, check=False, timeout=60,
                               env={**os.environ, "PYTHONHASHSEED": str(seed)})
    assert snapshot(evidence) == before
    return completed


def leaves(records):
    return [leaf for item in records for leaf in
            ([item] if item["kind"] == "capture" else
             leaves(item["state"]["evidence"]) if item["kind"] == "fact" else [])]


def assert_proofs(payload, files):
    declaration = json.loads(files["p2.json"])
    captures = {capture["id"]: capture for capture in payload["captures"]}
    for finding in payload["findings"]:
        refs = leaves(finding["evidence"])
        assert {ref["source"] for ref in refs} == {"node:demo:sw-a", "node:demo:sw-b"}
        observed = set()
        for ref in refs:
            capture = captures[ref["capture"]]
            node = capture["source"].removeprefix("node:demo:")
            path = next(row["path"] for row in declaration["captures"]
                        if row["node"] == node and row["operation"] == capture["operation"])
            raw = files[path]
            assert ref["source"] == capture["source"] and 0 <= ref["start"] < ref["end"] <= len(raw)
            assert sha256(raw[ref["start"]:ref["end"]]).hexdigest() == ref["sha256"]
            assert ref["capture_sha256"] == capture["sha256"] == sha256(raw).hexdigest()
            assert ref["read_scope"] == "unknown" and ref["role"] == "subject"
            observed.add((node, capture["operation"]))
        assert observed == {(node, operation) for node in ("sw-a", "sw-b") for operation in (CDP, TRUNK)}


def test_cli_demo_worker_hash_seed_determinism_proofs_and_python_api(tmp_path, monkeypatch):
    files = members()
    evidence = tmp_path / "evidence"
    write_members(evidence, files)
    outputs = []
    for index, (workers, seed) in enumerate(((1, 1), (4, 97), (4, 11))):
        out = tmp_path / ("out" + str(index))
        completed = cli(evidence, out, workers, seed)
        assert completed.returncode == 0, completed.stderr
        outputs.append(snapshot(out))
    assert outputs[0] == outputs[1] == outputs[2]
    record = json.loads(outputs[0]["MANIFEST.json"])
    assert record["schema"] == "atlas-brain.runner-manifest/2" and record["facts"] == {}
    assert record["interface_coverage"]["state"] == "unknown"
    assert record["interface_coverage"]["reason"] == "not_collected"
    payload = record["p2"]
    assert payload["schema"] == "atlas-brain.p2-demo/1" and payload["variant_support"] == "allowlisted"
    assert payload["group"]["semantic_group"] == "declared_synthetic"
    registry = sha256(files["p2.json"]).hexdigest()
    entries = sorted(({"capture": c["id"], "sha256": c["sha256"]} for c in payload["captures"]),
                     key=lambda row: row["capture"])
    digest = sha256(canonical({"captures": entries, "registry_sha256": registry})).hexdigest()
    assert record["evidence"] == {"files": 5, "captures": 4, "registry_sha256": registry, "digest": digest}
    assert payload["registry_sha256"] == registry
    assert record["egress"] == {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40}
    assert record["plan"] == {"steps": 8, "witness_attempts": 4}
    assert len(record["steps"]) == 8 and all(step["denied"] == 4 for step in record["steps"])
    assert payload["denominator"] == {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    assert payload["coverage"]["state"] == "unknown" and payload["coverage"]["reason"] == "denominator_open"
    assert {point["node"]: point["facts"]["l2.vlan_trunk.native"]["value"]
            for point in payload["endpoints"]} == {"sw-a": 10, "sw-b": 20}
    findings = {finding["check"]: finding for finding in payload["findings"]}
    assert len(payload["findings"]) == 2 and set(findings) == {NATIVE, ALLOWED}
    for finding in findings.values():
        assert finding["state"] == "problem" and finding["reason"] is None and finding["next_evidence"]
        assert {finding["left"]["node"], finding["right"]["node"]} == {"sw-a", "sw-b"}
    allowed = findings[ALLOWED]
    assert (allowed["left_only"], allowed["right_only"]) == (
        ("20", "none") if allowed["left"]["node"] == "sw-a" else ("none", "20"))
    assert_proofs(payload, files)
    for capture in payload["captures"]:
        assert capture["integrity"] == capture["parse"] == "complete"
        assert capture["read_scope"] == capture["view"] == "unknown"
        assert capture["collected_utc"]["state"] == "unknown"
        assert capture["collected_utc"]["reason"] == "as_of_missing"
    summary = outputs[0]["SUMMARY.txt"].decode()
    assert NATIVE in summary and ALLOWED in summary and "sw-a/" + PORT + "=10" in summary
    assert "sw-b/" + PORT + "=20" in summary and '"kind": "capture"' in summary
    original = subprocess.run
    def bounded(*args, **kwargs):
        kwargs.setdefault("timeout", 60)
        return original(*args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", bounded)
        api = run(evidence, tmp_path / "api", workers=4)
    assert (api.evidence_files, api.evidence_digest, api.steps, api.egress_denied) == (5, digest, 8, 40)
    assert snapshot(tmp_path / "api") == outputs[0] and snapshot(evidence) == files
    malformed = tmp_path / "malformed-api"
    malformed.mkdir()
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""))
        for fault in ("missing_p2", "legacy_with_p2", "future_schema", "wrong_p2_version",
                      "non_mapping_p2", "wrong_findings", "wrong_endpoints", "wrong_denominator",
                      "extra_top", "boolean_count"):
            damaged = json.loads(outputs[0]["MANIFEST.json"])
            if fault == "missing_p2":
                damaged.pop("p2")
            elif fault == "legacy_with_p2":
                damaged["schema"] = "atlas-brain.runner-manifest/1"
            elif fault == "future_schema":
                damaged["schema"] = "atlas-brain.runner-manifest/3"
            elif fault == "wrong_p2_version":
                damaged["p2"]["schema"] = "atlas-brain.p2-demo/2"
            elif fault == "non_mapping_p2":
                damaged["p2"] = []
            elif fault in ("wrong_findings", "wrong_endpoints"):
                damaged["p2"][fault.removeprefix("wrong_")] = {}
            elif fault == "wrong_denominator":
                damaged["p2"]["denominator"] = []
            elif fault == "extra_top":
                damaged["unexpected"] = True
            else:
                damaged["evidence"]["files"] = True
            (malformed / "MANIFEST.json").write_bytes(canonical(damaged))
            with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
                run(evidence, malformed)


def test_cli_missing_peer_retains_both_declared_endpoints_and_four_unknown_checks(tmp_path):
    files, evidence, out = members(missing_b=True), tmp_path / "input", tmp_path / "out"
    write_members(evidence, files)
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    payload = json.loads((out / "MANIFEST.json").read_bytes())["p2"]
    assert payload["denominator"] == {"declared_endpoints": 2, "reciprocal_pairs": 0, "unresolved_endpoints": 2}
    assert len(payload["endpoints"]) == 2 and len(payload["findings"]) == 4
    assert all(row["state"] == "unknown" and row["right"] is None and row["next_evidence"]
               for row in payload["findings"])
    missing = next(point for point in payload["endpoints"] if point["node"] == "sw-b")
    assert all(fact["state"] == "unknown" for fact in missing["facts"].values())


@pytest.mark.parametrize("plant,code", [("asymmetric", "p2_asymmetric_discovery_claim"),
                                       ("hash", "synthetic_capture_hash")])
def test_cli_refusal_preserves_previous_outputs(tmp_path, plant, code):
    files, evidence, out = members(asymmetric=plant == "asymmetric"), tmp_path / "input", tmp_path / "out"
    if plant == "hash":
        declaration = json.loads(files["p2.json"])
        declaration["captures"][0]["sha256"] = "0" * 64
        files["p2.json"] = canonical(declaration)
    write_members(evidence, files)
    out.mkdir()
    for name in ("MANIFEST.json", "SUMMARY.txt"):
        (out / name).write_bytes(b"previous " + name.encode())
    before = snapshot(out)
    completed = cli(evidence, out)
    assert completed.returncode == 2 and code in completed.stderr
    assert snapshot(out) == before


def test_cli_discovery_only_dispatch_retains_missing_trunk_and_interface_unknowns(tmp_path):
    files, evidence, out = members(discovery_only=True), tmp_path / "input", tmp_path / "out"
    write_members(evidence, files)
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    record = json.loads((out / "MANIFEST.json").read_bytes())
    assert record["facts"] == {} and record["interface_coverage"]["reason"] == "not_collected"
    assert all(row["state"] == "unknown" for row in record["p2"]["findings"])
    assert all(point["facts"]["l2.vlan_trunk.native"]["state"] == "unknown"
               for point in record["p2"]["endpoints"])
