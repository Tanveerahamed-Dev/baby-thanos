"""Hosted generated configured-intent demo; no operational fallback or live-device claim."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

P = "Gi1/0/1"
SCHEMA = "atlas-brain.synthetic-p2/2"
CDP, CONFIG = "iosxe.show_cdp_neighbors_detail", "iosxe.show_running_config"
OBSERVED = ("l2.vlan_trunk.native_mismatch", "l2.vlan_trunk.allowed_asymmetry")
CONFIGURED = ("l2.vlan_trunk.configured_native_mismatch", "l2.vlan_trunk.configured_allowed_asymmetry")
FACTS = tuple(sorted(("l1.link.peer", "l2.discovery.bridge_capable", "l2.discovery.device_id",
                     "l2.discovery.remote_port", "l2.vlan_trunk.allowed", "l2.vlan_trunk.native",
                     "l2.vlan_trunk.configured_mode", "l2.vlan_trunk.configured_native",
                     "l2.vlan_trunk.configured_allowed")))
STEPS = {"l2.discovery/parse", "l2.vlan_trunk/parse", "l2.vlan_trunk/parse_config", "l1.link/pair",
         "l2.vlan_trunk/check", "l2.vlan_trunk/check_config", "l2.vlan_trunk/project_config"}
NAMES = ("MANIFEST.json", "SUMMARY.txt")
LEGACY = {"MANIFEST.json": "97c5477d566a1de37c5b74c377dc92ef9d969e963d782391bd108922557a447a",
          "SUMMARY.txt": "7b0b53d2d8a23201d4a68f9a49c70c3a696d70b3f44da3adb246452dc5a6b671"}


def need(condition, code):
    if not condition:
        raise ValueError("p2_config_demo_" + code)


def members(canonical):
    files, references = {}, []
    for node, peer in (("sw-a", "sw-b"), ("sw-b", "sw-a")):
        raw_config = ("interface " + P + "\n switchport mode trunk\n switchport trunk native vlan 10\n"
                      + " switchport trunk allowed vlan 10,20\n!\nend\n") if node == "sw-a" else (
                          "template BASE\n switchport mode trunk\n switchport trunk native vlan 20\n!\n"
                          + "template EDGE\n source template BASE\n switchport trunk allowed vlan 10\n!\n"
                          + "interface " + P + "\n source template EDGE\n!\nend\n")
        outputs = ((CDP, "Device ID: " + peer + "\nPlatform: synthetic-switch, Capabilities: Switch\n"
                    + "Interface: " + P + ", Port ID (outgoing port): " + P + "\n"), (CONFIG, raw_config))
        for operation, text in outputs:
            path = node + "." + operation + ".txt"
            files[path] = text.encode("ascii")
            references.append({"path": path, "node": node, "operation": operation,
                               "sha256": sha256(files[path]).hexdigest()})
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": node, "ports": [P]} for node in ("sw-a", "sw-b")],
                "captures": references}
    return {**files, "p2.json": canonical(manifest)}


def snapshot(root):
    return {path.name: path.read_bytes() for path in root.iterdir()}


def references(records):
    for record in records:
        need(record["kind"] in ("capture", "fact", "registry"), "reference_kind")
        yield record
        if record["kind"] == "fact":
            yield from references(record["state"]["evidence"])


def validate(record, files, canonical, catalogue):
    need(record["schema"] == "atlas-brain.runner-manifest/2" and record["facts"] == {}, "outer_schema")
    need(record["interface_coverage"]["state"] == "unknown"
         and record["interface_coverage"]["reason"] == "not_collected", "interface_scope")
    payload = record["p2"]
    need(payload["schema"] == "atlas-brain.p2-demo/2" and payload["variant_support"] == "allowlisted", "inner_schema")
    need(payload["catalogue_digest"] == catalogue, "catalogue_digest")
    need(payload["group"]["id"] == "demo" and payload["group"]["semantic_group"] == "declared_synthetic", "group")
    need(len(payload["nodes"]) == 2 and {(node["id"], node["key"], node["discovery_id"], tuple(node["ports"]))
         for node in payload["nodes"]} == {(node, "node:demo:" + node, node, (P,))
         for node in ("sw-a", "sw-b")}, "nodes")
    denominator = {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    need(payload["denominator"] == denominator, "observed_denominator")
    layer = payload["configuration"]
    need(layer["basis"] == "configured" and layer["interpretation"] == "supplied_statements_only"
         and layer["comparison"] == "configuration_only_no_cross_basis_inference", "configuration_basis")
    need(layer["denominator"] == denominator, "configured_denominator")
    for coverage in (payload["coverage"], layer["coverage"]):
        need(coverage["state"] == "unknown" and coverage["reason"] == "denominator_open", "coverage")
    points = {point["node"]: point for point in payload["endpoints"]}
    need(len(payload["endpoints"]) == len(points) == 2 and set(points) == {"sw-a", "sw-b"}, "endpoints")
    for node, point in points.items():
        subject = "interface:" + sha256(canonical(("node:demo:" + node, P))).hexdigest()
        need(point["port"] == P and point["subject"] == subject and tuple(point["facts"]) == FACTS, "fact_matrix")
        values = {"configured_mode": ("trunk", "trunk"),
                  "configured_native": (10, "10") if node == "sw-a" else (20, "20"),
                  "configured_allowed": ("10,20", "10,20") if node == "sw-a" else ("10", "10")}
        for name, (value, raw) in values.items():
            fact = point["facts"]["l2.vlan_trunk." + name]
            need(fact["state"] == "known" and fact["basis"] == "configured"
                 and fact["value"] == value and fact["raw"] == raw, "configured_value")
        for name in ("native", "allowed"):
            fact = point["facts"]["l2.vlan_trunk." + name]
            need(fact["state"] == "unknown" and fact["reason"] == "not_collected", "no_observed_fallback")
    declaration = json.loads(files["p2.json"])
    registry = sha256(files["p2.json"]).hexdigest()
    need(payload["registry_sha256"] == registry, "registry_digest")
    rows = {("node:demo:" + row["node"], row["operation"]): row for row in declaration["captures"]}
    captures = {capture["id"]: capture for capture in payload["captures"]}
    need(len(captures) == len(payload["captures"]) == 4, "capture_count")
    need({(capture["source"], capture["operation"]) for capture in captures.values()} == set(rows), "capture_scope")
    raw_by_id = {}
    for identity, capture in captures.items():
        row = rows[capture["source"], capture["operation"]]
        raw = files[row["path"]]
        digest = sha256(raw).hexdigest()
        expected = "cap:" + sha256(canonical((SCHEMA, "demo", registry, row["path"],
                                              row["node"], row["operation"], digest))).hexdigest()
        need(identity == expected and capture["sha256"] == row["sha256"] == digest, "capture_identity")
        need(capture["integrity"] == capture["parse"] == "complete", "capture_quality")
        need(capture["read_scope"] == capture["view"] == "unknown", "capture_uncertainty")
        need(capture["collected_utc"]["state"] == "unknown"
             and capture["collected_utc"]["reason"] == "as_of_missing", "capture_time")
        raw_by_id[identity] = raw
    entries = sorted(({"capture": c["id"], "sha256": c["sha256"]} for c in captures.values()),
                     key=lambda entry: entry["capture"])
    digest = sha256(canonical({"captures": entries, "registry_sha256": registry})).hexdigest()
    need(record["evidence"] == {"files": 5, "captures": 4, "registry_sha256": registry,
                                "digest": digest}, "evidence_digest")
    need(record["egress"] == {"parent_denied": 4, "coordinator_denied": 4,
                              "worker_denied": 32, "denied": 40}, "egress")
    need(record["plan"] == {"steps": 8, "witness_attempts": 4}
         and len(record["steps"]) == 8 and all(step["denied"] == 4 for step in record["steps"]), "witness_counts")
    need([step["id"] for step in record["steps"]] == [f"witness/{i:02d}" for i in range(8)], "witness_ids")
    findings = {finding["check"]: finding for finding in payload["findings"]}
    need(len(payload["findings"]) == 4 and set(findings) == set(OBSERVED + CONFIGURED), "finding_matrix")
    registry_rows = {("synthetic_p2.groups", "demo", "/group"): "demo"}
    registry_rows.update({("synthetic_p2.nodes", row["id"], "/nodes/" + str(index)): row
                          for index, row in enumerate(declaration["nodes"])})
    for identifier, finding in findings.items():
        need(finding["next_evidence"] and {finding["left"]["node"], finding["right"]["node"]}
             == {"sw-a", "sw-b"}, "finding_endpoints")
        need(all(point["port"] == P and point["subject"] == points[point["node"]]["subject"]
                 for point in (finding["left"], finding["right"])), "finding_subjects")
        if identifier in OBSERVED:
            need(finding["state"] == "unknown" and finding["reason"] == "not_collected", "observed_unknown")
            continue
        need(finding["state"] == "problem" and finding["reason"] is None, "configured_problem")
        seen, excerpts, registries = set(), {"sw-a": set(), "sw-b": set()}, set()
        for ref in references(finding["evidence"]):
            if ref["kind"] == "registry":
                key = (ref["table"], ref["row_id"], ref["citation"])
                need(ref["table_digest"] == registry and key in registry_rows
                     and ref["value"] == registry_rows[key], "registry_proof")
                registries.add(key)
            elif ref["kind"] == "capture":
                capture, raw = captures[ref["capture"]], raw_by_id[ref["capture"]]
                need(ref["source"] == capture["source"] and ref["operation"] == capture["operation"]
                     and ref["role"] == "subject" and ref["locator"] == "bytes", "field_source")
                need(0 <= ref["start"] < ref["end"] <= len(raw), "field_bounds")
                excerpt = raw[ref["start"]:ref["end"]]
                need(ref["sha256"] == sha256(excerpt).hexdigest()
                     and ref["capture_sha256"] == capture["sha256"], "field_hash")
                need(ref["read_scope"] == ref["view"] == "unknown", "field_uncertainty")
                seen.add((ref["source"], ref["operation"]))
                excerpts[ref["source"].removeprefix("node:demo:")].add(excerpt)
        need(seen == set(rows) and registries == set(registry_rows), "complete_both_end_proofs")
        need({b"interface Gi1/0/1", b"trunk", b"10", b"10,20"} <= excerpts["sw-a"], "direct_lineage")
        need({b"template BASE", b"template EDGE", b"interface Gi1/0/1", b"BASE", b"EDGE",
              b"trunk", b"20", b"10"} <= excerpts["sw-b"], "inherited_lineage")
    allowed = findings[CONFIGURED[1]]
    expected = ("20", "none") if allowed["left"]["node"] == "sw-a" else ("none", "20")
    need((allowed["left_only"], allowed["right_only"]) == expected, "directional_difference")
    return payload


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("p2_config_demo_hosted_only")
    from atlas_brain.contract.canonical import canonical
    from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
    from atlas_brain.packs.l1.link import build as link
    from atlas_brain.packs.l2.discovery import build as discovery
    from atlas_brain.packs.l2.vlan_trunk import build as trunk
    from atlas_brain.packs.l2.vlan_trunk import config_build
    from atlas_brain.runner import p2_config

    legacy = Path(".ci-evidence/p0-demo/p2/out0")
    need({name: sha256((legacy / name).read_bytes()).hexdigest() for name in NAMES} == LEGACY,
         "legacy_show_digest_changed")
    facts = discovery.FACTS + trunk.FACTS + config_build.FACTS + link.FACTS
    need(tuple(sorted(str(fact.id) for fact in facts)) == FACTS
         and tuple(str(fact) for fact in p2_config.PROJECT.reads) == FACTS, "catalogue_facts")
    need(p2_config.PROJECT in p2_config.STEPS and p2_config.PROJECT.produces == ()
         and p2_config.PROJECT.scope == "estate", "project_step")
    need(len(p2_config.STEPS) == 7 and {str(step.id) for step in p2_config.STEPS} == STEPS, "catalogue_steps")
    catalogue = catalogue_digest(build_catalogue(entity_kinds=link.KINDS, facts=facts,
        relations=link.RELATIONS, steps=p2_config.STEPS))
    root = Path(".ci-evidence/p0-demo/p2-config")
    root.mkdir(parents=True, exist_ok=False)
    evidence = root / "inputs"
    evidence.mkdir()
    files = members(canonical)
    for name, raw in sorted(files.items()):
        (evidence / name).write_bytes(raw)
    outputs = []
    for index, (workers, seed) in enumerate(((1, 1), (4, 97), (4, 11))):
        out = root / ("out" + str(index))
        try:
            completed = subprocess.run(
                [sys.executable, "-B", "-m", "atlas_brain.runner", "--evidence", str(evidence),
                 "--out", str(out), "--workers", str(workers)], capture_output=True, check=False, timeout=60,
                env={**os.environ, "PYTHONHASHSEED": str(seed)})
        except subprocess.TimeoutExpired as error:
            (root / ("run" + str(index) + ".stdout.txt")).write_bytes(error.stdout or b"")
            (root / ("run" + str(index) + ".stderr.txt")).write_bytes(error.stderr or b"")
            raise
        (root / ("run" + str(index) + ".stdout.txt")).write_bytes(completed.stdout)
        (root / ("run" + str(index) + ".stderr.txt")).write_bytes(completed.stderr)
        need(snapshot(evidence) == files, "input_changed")
        need(completed.returncode == 0 and b"egress_denied=40" in completed.stdout, "cli_failed")
        outputs.append({name: (out / name).read_bytes() for name in NAMES})
    need(outputs[0] == outputs[1] == outputs[2], "determinism")
    payload = validate(json.loads(outputs[0]["MANIFEST.json"]), files, canonical, catalogue)
    digests = {name: sha256(raw).hexdigest() for name, raw in sorted(outputs[0].items())}
    receipt = {"schema": "atlas-brain.p2-config-hosted-receipt/1", "semantic_group": "declared_synthetic",
               "basis": "configured", "admitted_nodes": len(payload["nodes"]), "reciprocal_pairs": 1,
               "configured_checks": 2, "observed_unknown": 2, "runs": 3, "egress_denied": 40,
               "catalogue_facts": 9, "catalogue_steps": 7}
    (root / "DIGESTS.json").write_bytes(canonical({"digests": digests, "receipt": receipt, "preserved_show_digests": LEGACY}) + b"\n")
    print(outputs[0]["SUMMARY.txt"].decode("ascii"), end="")
    print("P2_CONFIG_DIGESTS " + canonical(digests).decode("ascii"))
    print("P2_CONFIG_RECEIPT " + canonical(receipt).decode("ascii"))


if __name__ == "__main__":
    main()
