"""Hosted-only generated guard reports; declared comparison, never live/default qualification."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

ROOT = Path(".ci-evidence/p0-demo/p4-guards")
SEEDS = ("1", "83")
PORT = "GigabitEthernet1/0/1"
OP = "iosxe.show_spanning_tree_interface_detail"
POLICY, FACTS, CHECKS = "declared_guard_policy.json", "facts/stp_port_vlan.jsonl", "checks/l2.stp.jsonl"
NAMES = {"result.json", FACTS, CHECKS, POLICY, "MANIFEST.sha256"}
EXPECTED = {"mismatch": ("problem", None, "reported_root_guard"),
    "omitted_guard": ("unknown", "field_not_printed", "reported_root_guard"),
    "equal_untimed": ("unknown", "as_of_missing", "reported_root_guard"),
    "role_excludes": ("not_applicable", "role_excludes", "reported_role")}


def need(condition, code):
    if not condition:
        raise ValueError("p4_guard_demo_" + code)


def members(canonical, case):
    need(case in EXPECTED, "case")
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic",
        "group": "guard_demo", "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [PORT]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    files = {"p2.json": base, "discovery.txt": discovery}
    for target, word, role in (("left", "disabled" if case == "equal_untimed" else "enabled",
                               "root" if case == "role_excludes" else "designated"),
                              ("right", None if case == "omitted_guard" else "disabled", "designated")):
        files[target + ".txt"] = (f"Port 1 ({PORT}) of VLAN0001 is {role} forwarding\n"
            + ("" if word is None else f"   Root guard is {word} on the port\n")).encode("ascii")
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "guard_demo",
        "base_sha256": sha256(base).hexdigest(), "targets": [{"id": name, "node": node, "operation": OP,
            "params": {"port": PORT, "vlans": [1]}} for name, node in (("left", "a"), ("right", "b"))],
        "captures": [{"target": name, "path": name + ".txt", "sha256": sha256(files[name + ".txt"]).hexdigest()}
                     for name in ("left", "right")]}
    return {**files, "p4.json": canonical(side)}


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def guard():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("p4_guard_demo_hosted_only")
    reviewed = os.environ.get("P4_REVIEWED_SHA", "")
    need(len(reviewed) == 40 and all(char in "0123456789abcdef" for char in reviewed), "reviewed_head")
    actual = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    need(actual == reviewed, "checkout_head")
    return reviewed


def run_saved(command, env, root, batch):
    try:
        result = subprocess.run(command, env=env, capture_output=True, check=False, timeout=60)
    except subprocess.TimeoutExpired as error:
        (root / f"batch{batch}.stdout.txt").write_bytes(error.stdout or b"")
        (root / f"batch{batch}.stderr.txt").write_bytes(error.stderr or b"")
        print(f"P4_GUARD_TIMEOUT batch={batch}: " + (error.stderr or b"").decode("utf-8", "replace"), file=sys.stderr)
        raise
    (root / f"batch{batch}.stdout.txt").write_bytes(result.stdout)
    (root / f"batch{batch}.stderr.txt").write_bytes(result.stderr)
    if result.returncode:
        print(result.stderr.decode("utf-8", "replace"), file=sys.stderr)
    need(result.returncode == 0, "child_failed")
    return result


def run_batch(batch, reviewed):
    need(batch in (0, 1) and os.environ.get("PYTHONHASHSEED") == SEEDS[batch], "hash_seed")
    from atlas_brain.runner import tripwire
    need(tripwire.install() and tripwire.probe() == 4, "tripwire")
    events = tripwire.violations()
    need(len(events) == 4, "tripwire")
    from atlas_brain.contract.canonical import canonical
    from atlas_brain.evidence.admission import Budgets
    from atlas_brain.runner.p4_guard_policy import policy, report_guard_comparisons
    policies = (policy.GuardPolicy(id="same_guard", domain="demo", expectation="same_reported_root_guard",
        participants=tuple(policy.GuardParticipant(target_id=name, vlan=1, declared_mode="pvst",
            position="designated_downstream") for name in ("left", "right"))),)
    for case in EXPECTED:
        out = ROOT / case / f"out{batch}"
        reports = report_guard_comparisons(ROOT / case / "inputs", Budgets(1000000, 1000000, 1000), policies)
        out.mkdir()
        for name, content in sorted(reports.items()):
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    extra = len(tripwire.violations()) - len(events)
    need(tripwire.violations() == events and extra == 0, "extra_egress")
    receipt = {"schema": "atlas-brain.p4-guard-api-batch/1", "reviewed_head": reviewed, "batch": batch,
        "seed": SEEDS[batch], "api_runs": len(EXPECTED), "api_process_denied": len(events), "additional_denials": extra}
    print("P4_GUARD_BATCH " + canonical(receipt).decode("ascii"))


def validate(reports, inputs, case, canonical):
    need(set(reports) == NAMES and reports["MANIFEST.sha256"] == b"".join(
        f"{sha256(reports[name]).hexdigest()}  {name}\n".encode("ascii") for name in sorted(NAMES - {"MANIFEST.sha256"})), "manifest")
    head, policy = json.loads(reports["result.json"]), json.loads(reports[POLICY])
    facts = [json.loads(line) for line in reports[FACTS].splitlines()]
    checks = [json.loads(line) for line in reports[CHECKS].splitlines()]
    need(reports["result.json"] == canonical(head) and reports[POLICY] == canonical(policy), "canonical")
    need(all(reports[name] == b"".join(canonical(row) + b"\n" for row in rows)
             for name, rows in ((FACTS, facts), (CHECKS, checks))), "canonical")
    need(head["schema"] == "atlas-brain.p4-guard-report/1" and head["semantic_group"] == "declared_synthetic"
         and head["scope"] == "conditional_reported_guard_comparisons" and head["fact_scope"] == "stp_operands_only"
         and head["source_required"] == "original_pinned_evidence_folder", "scope")
    need(head["coverage"]["state"] == "unknown" and head["coverage"]["reason"] == "denominator_open"
         and head["denominator"] == {"declared_policies": 1, "declared_participant_occurrences": 2}, "coverage")
    base, side = json.loads(inputs["p2.json"]), json.loads(inputs["p4.json"])
    base_hash, side_hash = sha256(inputs["p2.json"]).hexdigest(), sha256(inputs["p4.json"]).hexdigest()
    need(head["registry_sha256"] == side_hash and head["base_registry_sha256"] == base_hash, "input_registry")
    need(head["policy_registry"] == {"path": POLICY, "sha256": sha256(reports[POLICY]).hexdigest(), "basis": "declared"}
         and policy["registration_sha256"] == head["registration_sha256"] and policy["registry_sha256"] == side_hash
         and policy["base_registry_sha256"] == base_hash and policy["context"] == side["context"], "policy_registry")
    declared, = policy["policies"]
    need(declared["id"] == "same_guard" and declared["domain"] == "demo"
         and declared["expectation"] == "same_reported_root_guard", "policy_intent")
    points = {}
    for target in side["targets"]:
        node = "node:" + base["group"] + ":" + target["node"]
        subject = "stp_port_vlan:" + sha256(canonical(("atlas-brain.stp-port-vlan/1", side["context"], node, PORT, 1))).hexdigest()
        points[target["id"]] = (node, subject)
    pair = tuple(points[name][1] for name in ("left", "right"))
    need(len(facts) == 4 and {(row["subject"], row["fact"]) for row in facts}
         == {(subject, "l2.stp." + fact) for subject in pair for fact in ("root_guard", "reported_role")}, "facts")
    need(len(checks) == 1, "checks")
    finding = checks[0]
    actual = finding["state"], finding["reason"], finding["hops"][-1]["id"]
    need(actual == EXPECTED[case] and finding["conditional"] is True and finding["check"] == "l2.stp.reported_root_guard_mismatch"
         and (finding["left"], finding["right"]) == pair and finding["policy_id"] == "same_guard", "outcome")
    need(all(point["declared_mode"] == "pvst" and point["position"] == "designated_downstream"
         and point["subject"] == points[point["target_id"]][1] for point in declared["participants"]), "declared_assumptions")
    captures = {capture["id"]: capture for capture in head["captures"]}
    expected = {}
    for member in side["captures"]:
        raw = inputs[member["path"]]
        need(member["sha256"] == sha256(raw).hexdigest(), "source_hash")
        identifier = "cap:" + sha256(canonical((side["schema"], side_hash, base_hash, side["context"],
            member["target"], member["path"], member["sha256"], head["registration_sha256"]))).hexdigest()
        expected[identifier] = member
    need(set(captures) == set(expected) and len(captures) == len(head["captures"]) == 2, "captures")
    table = {(row["subject"], row["fact"]): row for row in facts}
    seen = set()
    def walk(value):
        if isinstance(value, dict):
            kind = value.get("kind")
            if kind == "fact":
                need(value["subject"] in pair and value["fact"] in ("l2.stp.root_guard", "l2.stp.reported_role")
                     and value["value"] == table[value["subject"], value["fact"]], "fact_scope")
            elif kind == "registry":
                raw = reports[POLICY] if value["table"] == "declared_stp_guard_policies" else inputs[
                    "p2.json" if value["table"].startswith("synthetic_p2.") else "p4.json"]
                selected = json.loads(raw)
                for token in value["citation"].removeprefix("/").split("/"):
                    selected = selected[int(token)] if isinstance(selected, list) else selected[token]
                need(value["table_digest"] == sha256(raw).hexdigest() and value["value"] == selected, "registry")
            elif kind == "capture":
                need(value["capture"] in expected, "capture")
                member, capture = expected[value["capture"]], captures[value["capture"]]
                raw = inputs[member["path"]]
                need(value["source"] == capture["source"] == points[member["target"]][0]
                     and value["path"] == capture["path"] == member["path"] and value["operation"] == capture["operation"] == OP
                     and value["capture_sha256"] == capture["sha256"] == member["sha256"], "capture_scope")
                excerpt = raw
                if value["locator"] == "bytes":
                    need(type(value["start"]) is int and type(value["end"]) is int
                         and 0 <= value["start"] < value["end"] <= len(raw), "span")
                    excerpt = raw[value["start"]:value["end"]]
                else:
                    need(value["locator"] == "whole_capture", "locator")
                need(value["sha256"] == sha256(excerpt).hexdigest(), "proof_hash")
                seen.add(member["target"])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk([head, facts, checks])
    need(seen == {"left", "right"}, "both_nodes")
    state, reason, hop = EXPECTED[case]
    return {"state": actual[0], "reason": actual[1], "last_hop": actual[2],
        "expected": {"state": state, "reason": reason, "last_hop": hop},
        "source": {name: sha256(raw).hexdigest() for name, raw in sorted(inputs.items())},
        "reports": {name: sha256(raw).hexdigest() for name, raw in sorted(reports.items())},
        "policy_sha256": sha256(reports[POLICY]).hexdigest()}


def main():
    reviewed = guard()
    if sys.argv[1:]:
        need(len(sys.argv) == 3 and sys.argv[1] == "--run" and sys.argv[2] in ("0", "1"), "arguments")
        run_batch(int(sys.argv[2]), reviewed)
        return
    from atlas_brain.contract.canonical import canonical
    ROOT.mkdir(parents=True, exist_ok=False)
    originals = {}
    for case in EXPECTED:
        folder = ROOT / case / "inputs"
        folder.mkdir(parents=True)
        originals[case] = members(canonical, case)
        for name, content in sorted(originals[case].items()):
            (folder / name).write_bytes(content)
    outputs, batches, cases = {}, [], {}
    for batch, seed in enumerate(SEEDS):
        result = run_saved([sys.executable, "-B", "-m", "tools.p4_guard_demo", "--run", str(batch)],
                           {**os.environ, "PYTHONHASHSEED": seed}, ROOT, batch)
        lines = result.stdout.decode("ascii").splitlines()
        need(len(lines) == 1 and lines[0].startswith("P4_GUARD_BATCH "), "batch_receipt")
        receipt = json.loads(lines[0].removeprefix("P4_GUARD_BATCH "))
        need(receipt == {"schema": "atlas-brain.p4-guard-api-batch/1", "reviewed_head": reviewed, "batch": batch,
            "seed": seed, "api_runs": 4, "api_process_denied": 4, "additional_denials": 0}, "batch_receipt")
        batches.append(receipt)
        for case in EXPECTED:
            need(snapshot(ROOT / case / "inputs") == originals[case], "input_changed")
            reports = snapshot(ROOT / case / f"out{batch}")
            cases[case] = validate(reports, originals[case], case, canonical)
            if batch == 0:
                outputs[case] = reports
            else:
                need(reports == outputs[case], "determinism")
    receipt = {"schema": "atlas-brain.p4-guard-hosted-receipt/1", "reviewed_head": reviewed,
        "qualification": "synthetic_regression_only", "scope": "caller_declared_guard_reports",
        "source_required": "original_pinned_evidence_folder", "measured_cases": len(EXPECTED), "api_runs": 8,
        "api_processes": 2, "hash_seeds": list(SEEDS), "api_process_denied": [row["api_process_denied"] for row in batches],
        "additional_denials": [row["additional_denials"] for row in batches], "cases": cases}
    (ROOT / "DIGESTS.json").write_bytes(canonical(receipt) + b"\n")
    print("P4_GUARD_RECEIPT " + canonical(receipt).decode("ascii"))


if __name__ == "__main__":
    main()
