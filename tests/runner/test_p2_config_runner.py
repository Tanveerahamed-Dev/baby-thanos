"""Public configured-intent CLI/API regressions use only generated schema-2 bytes."""
import json
import os
import subprocess
import sys
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import CONFIG_SCHEMA
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as trunk
from atlas_brain.packs.l2.vlan_trunk import config_build, config_check
from atlas_brain.runner import RunnerRefused, p2_config, run
from tools.p2_demo import members as show_members

P, CDP = "Gi1/0/1", "iosxe.show_cdp_neighbors_detail"
OBSERVED = {"l2.vlan_trunk.native_mismatch", "l2.vlan_trunk.allowed_asymmetry"}
LEGACY = {"MANIFEST.json": "97c5477d566a1de37c5b74c377dc92ef9d969e963d782391bd108922557a447a",
          "SUMMARY.txt": "7b0b53d2d8a23201d4a68f9a49c70c3a696d70b3f44da3adb246452dc5a6b671"}


def members(*, missing_config=False, asymmetric=False, unsupported=False):
    files, references = {}, []
    for node, peer in (("sw-a", "sw-b"), ("sw-b", "sw-a")):
        remote = "Gi1/0/9" if asymmetric and node == "sw-b" else P
        config = ("interface " + P + "\n switchport mode trunk\n switchport trunk native vlan 10\n"
                  + " switchport trunk allowed vlan 10,20\n!\nend\n") if node == "sw-a" else (
                      "template BASE\n switchport mode trunk\n switchport trunk native vlan 20\n!\n"
                      + "template EDGE\n source template BASE\n switchport trunk allowed vlan 10\n!\n"
                      + "interface " + P + "\n source template EDGE\n!\nend\n")
        if unsupported and node == "sw-a":
            config = config.replace("allowed vlan 10,20", "allowed vlan add 10,20")
        outputs = ((CDP, "Device ID: " + peer + "\nPlatform: synthetic-switch, Capabilities: Switch\n"
                    + "Interface: " + P + ", Port ID (outgoing port): " + remote + "\n"),
                   (config_build.OP, config))
        for operation, text in outputs:
            if missing_config and node == "sw-b" and operation == config_build.OP:
                continue
            path = node + "." + operation + ".txt"
            files[path] = text.encode()
            references.append({"path": path, "node": node, "operation": operation,
                               "sha256": sha256(files[path]).hexdigest()})
    manifest = {"schema": CONFIG_SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": node, "ports": [P]} for node in ("sw-a", "sw-b")],
                "captures": references}
    return {**files, "p2.json": canonical(manifest)}


def write_members(root, files):
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def cli(evidence, out, workers=4, seed=1):
    before = snapshot(evidence)
    result = subprocess.run([sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
                             "--out", str(out), "--workers", str(workers)], capture_output=True, text=True,
                            check=False, timeout=60, env={**os.environ, "PYTHONHASHSEED": str(seed)})
    assert snapshot(evidence) == before
    return result


def references(records):
    for record in records:
        yield record
        if record["kind"] == "fact":
            yield from references(record["state"]["evidence"])


def verify(record, files):
    assert record["schema"] == "atlas-brain.runner-manifest/2" and record["facts"] == {}
    assert record["interface_coverage"]["reason"] == "not_collected"
    payload = record["p2"]
    assert payload["schema"] == "atlas-brain.p2-demo/2" and payload["variant_support"] == "allowlisted"
    denominator = {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    assert payload["denominator"] == payload["configuration"]["denominator"] == denominator
    layer = payload["configuration"]
    assert set(layer) == {"basis", "interpretation", "comparison", "coverage", "denominator"}
    assert (layer["basis"], layer["interpretation"], layer["comparison"]) == (
        "configured", "supplied_statements_only", "configuration_only_no_cross_basis_inference")
    assert layer["coverage"]["reason"] == payload["coverage"]["reason"] == "denominator_open"
    facts = discovery.FACTS + trunk.FACTS + config_build.FACTS + link.FACTS
    catalogue = build_catalogue(entity_kinds=link.KINDS, facts=facts, relations=link.RELATIONS, steps=p2_config.STEPS)
    assert payload["catalogue_digest"] == catalogue_digest(catalogue)
    assert len(facts) == len(p2_config.PROJECT.reads) == 9 and len(p2_config.STEPS) == 7
    assert len(payload["endpoints"]) == 2 and {point["node"] for point in payload["endpoints"]} == {"sw-a", "sw-b"}
    for point in payload["endpoints"]:
        assert tuple(point["facts"]) == p2_config.FACT_IDS
        native, allowed = ((10, "10,20") if point["node"] == "sw-a" else (20, "10"))
        for identifier, value in ((config_build.MODE, "trunk"), (config_build.NATIVE, native),
                                  (config_build.ALLOWED, allowed)):
            fact = point["facts"][str(identifier)]
            assert (fact["state"], fact["basis"], fact["value"], fact["raw"]) == (
                "known", "configured", value, str(value))
        assert all(point["facts"]["l2.vlan_trunk." + field]["reason"] == "not_collected"
                   for field in ("native", "allowed"))
    declaration, registry = json.loads(files["p2.json"]), sha256(files["p2.json"]).hexdigest()
    assert payload["registry_sha256"] == registry
    registry_rows = {("synthetic_p2.groups", "demo", "/group"): "demo"}
    registry_rows.update({("synthetic_p2.nodes", row["id"], "/nodes/" + str(index)): row
                          for index, row in enumerate(declaration["nodes"])})
    raw = {("node:demo:" + row["node"], row["operation"]): files[row["path"]] for row in declaration["captures"]}
    captures = {capture["id"]: capture for capture in payload["captures"]}
    assert len(captures) == len(payload["captures"]) == 4
    for capture in captures.values():
        assert capture["sha256"] == sha256(raw[capture["source"], capture["operation"]]).hexdigest()
        assert capture["integrity"] == capture["parse"] == "complete"
        assert capture["read_scope"] == capture["view"] == "unknown"
        assert capture["collected_utc"]["reason"] == "as_of_missing"
    entries = sorted(({"capture": c["id"], "sha256": c["sha256"]} for c in captures.values()), key=lambda c: c["capture"])
    digest = sha256(canonical({"captures": entries, "registry_sha256": registry})).hexdigest()
    assert record["evidence"] == {"files": 5, "captures": 4, "registry_sha256": registry, "digest": digest}
    assert record["egress"] == {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40}
    assert record["plan"] == {"steps": 8, "witness_attempts": 4}
    assert [step["id"] for step in record["steps"]] == [f"witness/{i:02d}" for i in range(8)]
    assert all(step["denied"] == 4 for step in record["steps"])
    findings = {finding["check"]: finding for finding in payload["findings"]}
    assert len(payload["findings"]) == 4 and set(findings) == OBSERVED | set(config_check.CHECKS)
    for name, finding in findings.items():
        assert finding["next_evidence"] and {finding["left"]["node"], finding["right"]["node"]} == {"sw-a", "sw-b"}
        if name in OBSERVED:
            assert (finding["state"], finding["reason"]) == ("unknown", "not_collected")
            continue
        assert (finding["state"], finding["reason"]) == ("problem", None)
        seen, excerpts, nodes = set(), {"sw-a": set(), "sw-b": set()}, set()
        for ref in references(finding["evidence"]):
            if ref["kind"] == "registry":
                key = (ref["table"], ref["row_id"], ref["citation"])
                assert ref["table_digest"] == registry and key in registry_rows and ref["value"] == registry_rows[key]
                nodes.add((ref["table"], ref["row_id"]))
            elif ref["kind"] == "capture":
                capture = captures[ref["capture"]]
                body = raw[capture["source"], capture["operation"]]
                assert ref["source"] == capture["source"] and ref["operation"] == capture["operation"]
                assert ref["role"] == "subject" and ref["read_scope"] == ref["view"] == "unknown"
                assert ref["locator"] == "bytes" and 0 <= ref["start"] < ref["end"] <= len(body)
                part = body[ref["start"]:ref["end"]]
                assert sha256(part).hexdigest() == ref["sha256"] and ref["capture_sha256"] == capture["sha256"]
                seen.add((ref["source"], ref["operation"]))
                excerpts[ref["source"].removeprefix("node:demo:")].add(part)
        assert seen == set(raw) and nodes == {("synthetic_p2.groups", "demo"),
            ("synthetic_p2.nodes", "sw-a"), ("synthetic_p2.nodes", "sw-b")}
        assert {b"interface Gi1/0/1", b"trunk", b"10", b"10,20"} <= excerpts["sw-a"]
        assert {b"template BASE", b"template EDGE", b"interface Gi1/0/1", b"BASE", b"EDGE",
                b"trunk", b"20", b"10"} <= excerpts["sw-b"]
    return digest


def test_public_configured_cli_determinism_api_parity_and_decoder_refusals(tmp_path, monkeypatch):
    evidence, files = tmp_path / "inputs", members()
    write_members(evidence, files)
    outputs = []
    for index, (workers, seed) in enumerate(((1, 1), (4, 97), (4, 11))):
        out = tmp_path / ("out" + str(index))
        result = cli(evidence, out, workers, seed)
        assert result.returncode == 0, result.stderr
        outputs.append(snapshot(out))
    assert outputs[0] == outputs[1] == outputs[2]
    digest = verify(json.loads(outputs[0]["MANIFEST.json"]), files)
    original = subprocess.run
    def bounded(*args, **kwargs):
        kwargs.setdefault("timeout", 60)
        return original(*args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", bounded)
        api = run(evidence, tmp_path / "api")
    assert (api.evidence_files, api.evidence_digest, api.steps, api.egress_denied) == (5, digest, 8, 40)
    assert snapshot(tmp_path / "api") == outputs[0] and snapshot(evidence) == files
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    with monkeypatch.context() as patch:
        patch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""))
        for fault in ("missing", "nonmapping", "basis", "interpretation", "comparison", "denominator", "coverage", "inner3", "demo1", "extra_configuration"):
            record = json.loads(outputs[0]["MANIFEST.json"])
            payload = record["p2"]
            if fault == "missing":
                payload.pop("configuration")
            elif fault == "nonmapping":
                payload["configuration"] = []
            elif fault == "extra_configuration":
                payload["configuration"]["winner"] = "observed"
            elif fault in ("inner3", "demo1"):
                payload["schema"] = "atlas-brain.p2-demo/" + ("3" if fault == "inner3" else "1")
            else:
                payload["configuration"][fault] = [] if fault in ("denominator", "coverage") else "unverified"
            (malformed / "MANIFEST.json").write_bytes(canonical(record))
            with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
                run(evidence, malformed)


def test_missing_configuration_and_unsupported_statements_never_fall_back(tmp_path):
    for label, kwargs, reason in (("missing", {"missing_config": True}, "not_collected"),
                                 ("unsupported", {"unsupported": True}, "parse_unsupported_variant")):
        evidence, out = tmp_path / label, tmp_path / (label + "-out")
        write_members(evidence, members(**kwargs))
        result = cli(evidence, out)
        assert result.returncode == 0, result.stderr
        payload = json.loads((out / "MANIFEST.json").read_bytes())["p2"]
        assert payload["denominator"] == payload["configuration"]["denominator"] == {
            "declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
        configured = [row for row in payload["findings"] if row["check"] in config_check.CHECKS]
        assert len(payload["endpoints"]) == 2 and len(configured) == 2
        assert all(row["state"] == "unknown" and row["reason"] == reason for row in configured)
        node = "sw-b" if label == "missing" else "sw-a"
        point = next(point for point in payload["endpoints"] if point["node"] == node)
        assert all(point["facts"][str(fact)]["reason"] == reason for fact in config_build.IDS)


@pytest.mark.parametrize("fault,code", [("asymmetric", "asymmetric_discovery_claim"), ("hash", "synthetic_capture_hash")])
def test_configured_cli_refusals_preserve_previous_outputs(tmp_path, fault, code):
    files, evidence, out = members(asymmetric=fault == "asymmetric"), tmp_path / "inputs", tmp_path / "out"
    if fault == "hash":
        declaration = json.loads(files["p2.json"])
        declaration["captures"][0]["sha256"] = "0" * 64
        files["p2.json"] = canonical(declaration)
    write_members(evidence, files)
    out.mkdir()
    for name in LEGACY:
        (out / name).write_bytes(b"previous " + name.encode())
    before = snapshot(out)
    result = cli(evidence, out)
    assert result.returncode == 2 and code in result.stderr
    assert snapshot(out) == before


def test_legacy_show_only_p2_cli_keeps_accepted_output_hashes(tmp_path):
    evidence, out = tmp_path / "inputs", tmp_path / "out"
    write_members(evidence, show_members(canonical))
    result = cli(evidence, out)
    assert result.returncode == 0, result.stderr
    assert {name: sha256((out / name).read_bytes()).hexdigest() for name in LEGACY} == LEGACY
