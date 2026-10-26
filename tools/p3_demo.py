"""Hosted-only P3 witness: generated cases, independent byte proofs and bounded claims."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from tools.p3_cases import members

NAMES = ("MANIFEST.json", "SUMMARY.txt")
EXPECTED = {
    "supported": ("problem", None, "candidate"),
    "single_sample": ("unknown", "single_sample", "sampled_persistence"),
    "untimed_conflict": ("unknown", "conflicting_evidence", "sampled_persistence"),
    "missing_mtu": ("unknown", "not_collected", "ip_mtu"),
    "mtu_ignore": ("not_applicable", "feature_not_enabled", "receiving_control"),
}


def need(condition, code):
    if not condition:
        raise ValueError("p3_demo_" + code)


def snapshot(root):
    return {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}


def leaves(records):
    for record in records:
        need(record["kind"] in ("fact", "registry", "capture"), "proof_kind")
        if record["kind"] == "fact":
            yield from leaves(record["state"]["evidence"])
        else:
            yield record


def pointer(value, citation):
    for token in citation.removeprefix("/").split("/"):
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


def validate(record, files, case, canonical):
    from atlas_brain.runner.p3_manifest import validate as validate_shape

    need(record["schema"] == "atlas-brain.runner-manifest/3" and record["facts"] == {}, "schema")
    need("p2" not in record and "interface_coverage" not in record, "scope")
    payload = record["p3"]
    validate_shape(payload, record["evidence"])
    base, side = json.loads(files["p2.json"]), json.loads(files["p3.json"])
    base_digest, side_digest = sha256(files["p2.json"]).hexdigest(), sha256(files["p3.json"]).hexdigest()
    expected = {}
    for row in base["captures"]:
        identity = "cap:" + sha256(canonical((base["schema"], base["group"], base_digest,
                    row["path"], row["node"], row["operation"], row["sha256"]))).hexdigest()
        expected[identity] = (row, None)
    for sample in side["samples"]:
        for row in sample["captures"]:
            identity = "cap:" + sha256(canonical((side["schema"], side_digest, base_digest, sample["id"],
                        row["node"], row["path"], row["operation"], row["sha256"]))).hexdigest()
            expected[identity] = (row, sample["id"])
    captures = {capture["id"]: capture for capture in payload["captures"]}
    need(set(captures) == set(expected) and len(captures) == len(payload["captures"]), "capture_population")
    need(record["evidence"]["files"] == len(files) == len(captures) + 2, "file_population")
    for identifier, capture in captures.items():
        row, sample_id = expected[identifier]
        need(capture["source"] == "node:" + base["group"] + ":" + row["node"]
             and capture["operation"] == row["operation"] and capture["sample"] == sample_id, "capture_identity")
        need(capture["sha256"] == row["sha256"] == sha256(files[row["path"]]).hexdigest(), "capture_hash")
    need(record["egress"] == {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40}, "egress")
    need(record["plan"] == {"steps": 8, "witness_attempts": 4}
         and record["steps"] == [{"denied": 4, "id": f"witness/{index:02d}"} for index in range(8)], "worker_receipts")
    finding, = payload["findings"]
    need((finding["state"], finding["reason"], finding["hops"][-1]["id"]) == EXPECTED[case], "owner_result")
    need(finding["state"] != "unknown" or finding["next_evidence"], "next_evidence")
    seen_sources, seen_samples, counters = set(), set(), set()
    for ref in leaves(finding["evidence"]):
        if ref["kind"] == "registry":
            raw, declaration = (base_digest, base) if ref["table"].startswith("synthetic_p2.") else (side_digest, side)
            need(ref["table_digest"] == raw and ref["value"] == pointer(declaration, ref["citation"]), "registry_proof")
            continue
        need(ref["capture"] in captures, "proof_capture")
        capture, (row, sample_id) = captures[ref["capture"]], expected[ref["capture"]]
        raw = files[row["path"]]
        need(ref["source"] == capture["source"] and ref["operation"] == row["operation"]
             and ref.get("sample") == sample_id and ref["path"] == row["path"], "proof_scope")
        need(ref["capture_sha256"] == sha256(raw).hexdigest(), "whole_hash")
        if ref["locator"] == "bytes":
            need(type(ref["start"]) is int and type(ref["end"]) is int
                 and 0 <= ref["start"] <= ref["end"] <= len(raw), "proof_bounds")
            excerpt = raw[ref["start"]:ref["end"]]
        else:
            need(ref["locator"] == "whole_capture", "locator")
            excerpt = raw
        need(ref["sha256"] == sha256(excerpt).hexdigest(), "proof_hash")
        seen_sources.add(ref["source"])
        if sample_id is not None:
            seen_samples.add(sample_id)
        if ref["role"] == "counter_evidence":
            counters.add(excerpt)
    need(len(seen_sources) == 2 and seen_samples == {sample["id"] for sample in side["samples"]}, "both_ends_rounds")
    need(case != "mtu_ignore" or b"ip ospf mtu-ignore" in counters, "positive_counter_evidence")
    return payload


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("p3_demo_hosted_only")
    from atlas_brain.contract.canonical import canonical

    reviewed = os.environ.get("P3_REVIEWED_SHA", "")
    need(len(reviewed) == 40 and all(char in "0123456789abcdef" for char in reviewed), "reviewed_head")
    checkout = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    need(checkout == reviewed, "checkout_head")
    root = Path(".ci-evidence/p0-demo/p3")
    root.mkdir(parents=True, exist_ok=False)
    receipts, runs = {}, 0
    for case in EXPECTED:
        case_root = root / case
        case_root.mkdir()
        evidence = case_root / "inputs"
        evidence.mkdir()
        files = members(canonical, case)
        for name, raw in sorted(files.items()):
            (evidence / name).write_bytes(raw)
        outputs = []
        settings = ((1, 1), (4, 97), (4, 11)) if case == "supported" else ((4, 97),)
        for index, (workers, seed) in enumerate(settings):
            out = case_root / ("out" + str(index))
            completed = subprocess.run([sys.executable, "-B", "-m", "atlas_brain.runner", "--evidence", str(evidence),
                "--out", str(out), "--workers", str(workers)], capture_output=True, check=False, timeout=120,
                env={**os.environ, "PYTHONHASHSEED": str(seed)})
            (case_root / ("run" + str(index) + ".stdout.txt")).write_bytes(completed.stdout)
            (case_root / ("run" + str(index) + ".stderr.txt")).write_bytes(completed.stderr)
            need(snapshot(evidence) == files, "input_changed")
            need(completed.returncode == 0 and b"egress_denied=40" in completed.stdout, "cli_failed")
            outputs.append({name: (out / name).read_bytes() for name in NAMES})
            runs += 1
        need(all(output == outputs[0] for output in outputs), "determinism")
        payload = validate(json.loads(outputs[0]["MANIFEST.json"]), files, case, canonical)
        receipts[case] = {"manifest": sha256(outputs[0]["MANIFEST.json"]).hexdigest(),
            "summary": sha256(outputs[0]["SUMMARY.txt"]).hexdigest(),
            "result": sha256(canonical(payload)).hexdigest(), "catalogue": payload["catalogue_digest"]}
        print(outputs[0]["SUMMARY.txt"].decode("ascii"), end="")
    receipt = {"schema": "atlas-brain.p3-hosted-receipt/1", "reviewed_head": reviewed,
        "qualification": "synthetic_regression_only", "cases": receipts, "runs": runs,
        "measured_cases": len(EXPECTED), "measured_false_supported": 0, "egress_denied_per_run": 40}
    (root / "DIGESTS.json").write_bytes(canonical(receipt) + b"\n")
    print("P3_RECEIPT " + canonical(receipt).decode("ascii"))


if __name__ == "__main__":
    main()
