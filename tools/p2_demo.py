"""Hosted-only generated P2 CLI demonstration; never imports private or captured data."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

PORT = "Gi1/0/1"
CDP, TRUNK = "iosxe.show_cdp_neighbors_detail", "iosxe.show_interfaces_trunk"
NATIVE, ALLOWED = "l2.vlan_trunk.native_mismatch", "l2.vlan_trunk.allowed_asymmetry"
NAMES = ("MANIFEST.json", "SUMMARY.txt")


def need(condition, code):
    if not condition:
        raise ValueError("p2_demo_" + code)


def members(canonical):
    files, references = {}, []
    for node, peer, native, allowed in (("sw-a", "sw-b", "10", "10,20"), ("sw-b", "sw-a", "20", "10")):
        outputs = ((CDP, "Device ID: " + peer + "\nPlatform: synthetic-switch, Capabilities: Switch\n"
                    + "Interface: " + PORT + ", Port ID (outgoing port): " + PORT + "\n"),
                   (TRUNK, "Port Mode Encapsulation Status Native vlan\n" + PORT
                    + " on 802.1q trunking " + native + "\nPort Vlans allowed on trunk\n"
                    + PORT + " " + allowed + "\n"))
        for operation, text in outputs:
            path = node + "." + operation + ".txt"
            files[path] = text.encode("ascii")
            references.append({"path": path, "node": node, "operation": operation,
                               "sha256": sha256(files[path]).hexdigest()})
    declaration = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic",
                   "group": "demo", "nodes": [{"id": node, "discovery_id": node, "ports": [PORT]}
                                             for node in ("sw-a", "sw-b")], "captures": references}
    return {**files, "p2.json": canonical(declaration)}


def snapshot(root):
    return {path.name: path.read_bytes() for path in root.iterdir()}


def leaves(records):
    result = []
    for item in records:
        need(item["kind"] in ("capture", "fact", "registry"), "proof_kind")
        if item["kind"] == "capture":
            result.append(item)
        elif item["kind"] == "fact":
            result.extend(leaves(item["state"]["evidence"]))
    return result


def validate(record, files, canonical):
    need(record["schema"] == "atlas-brain.runner-manifest/2" and record["facts"] == {}, "runner_schema")
    need(record["interface_coverage"]["state"] == "unknown"
         and record["interface_coverage"]["reason"] == "not_collected", "interface_honesty")
    payload = record["p2"]
    need(payload["schema"] == "atlas-brain.p2-demo/1" and payload["variant_support"] == "allowlisted", "p2_schema")
    need(payload["group"]["semantic_group"] == "declared_synthetic", "declared_scope")
    need(len(payload["nodes"]) == 2 and {node["id"] for node in payload["nodes"]} == {"sw-a", "sw-b"}, "nodes")
    need(len(payload["endpoints"]) == 2 and {(point["node"], point["port"]) for point in payload["endpoints"]}
         == {("sw-a", PORT), ("sw-b", PORT)}, "endpoint_population")
    need(payload["denominator"] == {"declared_endpoints": 2, "reciprocal_pairs": 1,
                                    "unresolved_endpoints": 0}, "denominator")
    need(payload["coverage"]["state"] == "unknown"
         and payload["coverage"]["reason"] == "denominator_open", "coverage_honesty")
    need({point["node"]: point["facts"]["l2.vlan_trunk.native"]["value"]
          for point in payload["endpoints"]} == {"sw-a": 10, "sw-b": 20}, "native_values")
    registry = sha256(files["p2.json"]).hexdigest()
    need(payload["registry_sha256"] == registry, "registry_digest")
    declaration = json.loads(files["p2.json"])
    raw_by_scope = {("node:demo:" + row["node"], row["operation"]): files[row["path"]]
                    for row in declaration["captures"]}
    captures = {capture["id"]: capture for capture in payload["captures"]}
    need(len(captures) == len(payload["captures"]) == 4, "capture_count")
    need({(c["source"], c["operation"]) for c in captures.values()} == set(raw_by_scope), "capture_identity")
    for capture in captures.values():
        raw = raw_by_scope[capture["source"], capture["operation"]]
        need(capture["sha256"] == sha256(raw).hexdigest(), "capture_hash")
        need(capture["integrity"] == capture["parse"] == "complete", "capture_quality")
        need(capture["read_scope"] == capture["view"] == "unknown", "capture_scope")
        need(capture["collected_utc"]["state"] == "unknown"
             and capture["collected_utc"]["reason"] == "as_of_missing", "capture_time")
    entries = sorted(({"capture": c["id"], "sha256": c["sha256"]} for c in captures.values()),
                     key=lambda entry: entry["capture"])
    digest = sha256(canonical({"captures": entries, "registry_sha256": registry})).hexdigest()
    need(record["evidence"] == {"files": 5, "captures": 4, "registry_sha256": registry,
                                "digest": digest}, "input_digest")
    need(record["egress"] == {"parent_denied": 4, "coordinator_denied": 4,
                              "worker_denied": 32, "denied": 40}, "egress")
    need(record["plan"] == {"steps": 8, "witness_attempts": 4}
         and len(record["steps"]) == 8 and all(step["denied"] == 4 for step in record["steps"]), "receipts")
    need([step["id"] for step in record["steps"]] == [f"witness/{index:02d}" for index in range(8)], "step_ids")
    findings = {finding["check"]: finding for finding in payload["findings"]}
    need(len(payload["findings"]) == 2 and set(findings) == {NATIVE, ALLOWED}, "check_set")
    for finding in findings.values():
        need(finding["state"] == "problem" and finding["reason"] is None
             and finding["next_evidence"], "owner_verdict")
        need({finding["left"]["node"], finding["right"]["node"]} == {"sw-a", "sw-b"}
             and finding["left"]["port"] == finding["right"]["port"] == PORT, "both_endpoints")
        refs, observed = leaves(finding["evidence"]), set()
        for ref in refs:
            capture = captures[ref["capture"]]
            raw = raw_by_scope[capture["source"], capture["operation"]]
            need(ref["source"] == capture["source"] and ref["role"] == "subject", "proof_source")
            need(0 <= ref["start"] < ref["end"] <= len(raw), "proof_bounds")
            need(ref["sha256"] == sha256(raw[ref["start"]:ref["end"]]).hexdigest()
                 and ref["capture_sha256"] == capture["sha256"], "proof_hash")
            need(ref["read_scope"] == "unknown", "proof_scope")
            observed.add((capture["source"], capture["operation"]))
        need(observed == set(raw_by_scope), "both_end_proofs")
    allowed = findings[ALLOWED]
    expected = ("20", "none") if allowed["left"]["node"] == "sw-a" else ("none", "20")
    need((allowed["left_only"], allowed["right_only"]) == expected, "allowed_difference")
    return payload


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("p2_demo_hosted_only")
    from atlas_brain.contract.canonical import canonical

    root = Path(".ci-evidence/p0-demo/p2")
    root.mkdir(parents=True, exist_ok=False)
    evidence = root / "inputs"
    evidence.mkdir()
    files = members(canonical)
    for name, raw in sorted(files.items()):
        (evidence / name).write_bytes(raw)
    outputs = []
    for index, (workers, seed) in enumerate(((1, 1), (4, 97), (4, 11))):
        out = root / ("out" + str(index))
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "atlas_brain.runner", "--evidence", str(evidence),
             "--out", str(out), "--workers", str(workers)], capture_output=True, check=False, timeout=60,
            env={**os.environ, "PYTHONHASHSEED": str(seed)})
        (root / ("run" + str(index) + ".stdout.txt")).write_bytes(completed.stdout)
        (root / ("run" + str(index) + ".stderr.txt")).write_bytes(completed.stderr)
        need(snapshot(evidence) == files, "input_changed")
        need(completed.returncode == 0 and b"egress_denied=40" in completed.stdout, "cli_failed")
        outputs.append({name: (out / name).read_bytes() for name in NAMES})
    need(outputs[0] == outputs[1] == outputs[2], "determinism")
    payload = validate(json.loads(outputs[0]["MANIFEST.json"]), files, canonical)
    digests = {name: sha256(raw).hexdigest() for name, raw in sorted(outputs[0].items())}
    receipt = {"schema": "atlas-brain.p2-hosted-receipt/1", "semantic_group": "declared_synthetic",
               "admitted_nodes": len(payload["nodes"]), "reciprocal_pairs": 1, "checks": 2,
               "egress_denied": 40, "runs": 3}
    need(receipt["admitted_nodes"] == 2, "node_count")
    (root / "DIGESTS.json").write_bytes(canonical({"digests": digests, "receipt": receipt}) + b"\n")
    print(outputs[0]["SUMMARY.txt"].decode("ascii"), end="")
    print("P2_DIGESTS " + canonical(digests).decode("ascii"))
    print("P2_RECEIPT " + canonical(receipt).decode("ascii"))


if __name__ == "__main__":
    main()
