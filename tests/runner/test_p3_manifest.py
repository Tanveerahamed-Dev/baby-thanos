"""Pure decoder plants against generated P3 projection, not merely permissive JSON."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.runner import p3, p3_manifest
from atlas_brain.runner.records import RunnerRefused
from tools.p3_cases import members


def record(case="supported", supplied=None):
    payload, _ = p3.analyse_group(admit_members(members(canonical, case) if supplied is None else supplied))
    expected = {"captures": sorted(({"capture": capture["id"], "sha256": capture["sha256"]} for capture in payload["captures"]), key=lambda entry: entry["capture"]),
                "registry_sha256": payload["registry_sha256"], "base_registry_sha256": payload["base_registry_sha256"]}
    metadata = {key: value for key, value in expected.items() if key != "captures"}
    metadata.update(digest=sha256(canonical(expected)).hexdigest(), captures=len(payload["captures"]), files=len(payload["captures"]) + 2)
    return payload, metadata


@pytest.mark.parametrize("case", ["supported", "single_sample", "missing_mtu", "mtu_ignore", "no_rounds", "untimed", "untimed_conflict", "missing_ignore", "full"])
def test_current_projections_and_unknown_denominators_are_accepted(case):
    payload, metadata = record(case)
    p3_manifest.validate(payload, metadata)


@pytest.fixture(scope="module")
def valid():
    return record()


@pytest.mark.parametrize("plant", ["schema", "interpretation", "scope", "timing", "coverage", "denominator",
                                  "population", "sample_fact", "settled_fact", "candidate", "healthy", "float",
                                  "digest", "registry", "files", "duplicate_capture", "extra"])
def test_malformed_manifest_cannot_claim_current_p3_contract(valid, plant):
    payload, metadata = json.loads(canonical(valid))
    if plant in ("schema", "interpretation", "scope", "timing"):
        payload[plant] = "unverified"
    elif plant == "coverage":
        payload["coverage"]["state"] = "known"
    elif plant == "denominator":
        payload["denominator"]["rounds"] = 1
    elif plant == "population":
        payload["samples"][0]["endpoints"].pop()
    elif plant == "sample_fact":
        payload["samples"][0]["endpoints"][0]["facts"].pop("l3.mtu.ip_bytes")
    elif plant == "settled_fact":
        payload["adjacencies"][0]["facts"].pop("l3.ospf.context_match")
    elif plant == "candidate":
        payload["findings"][0]["hops"][-1]["state"]["value"] = False
    elif plant == "healthy":
        payload["findings"][0]["state"] = "ok"
    elif plant == "float":
        payload["samples"][0]["endpoints"][0]["facts"]["l3.mtu.ip_bytes"]["value"] = 1500.5
    elif plant == "digest":
        metadata["digest"] = "0" * 64
    elif plant == "registry":
        metadata["registry_sha256"] = "0" * 64
    elif plant == "files":
        metadata["files"] = True
    elif plant == "duplicate_capture":
        payload["captures"].append(payload["captures"][0])
    else:
        payload["qualified"] = True
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)


@pytest.mark.parametrize("plant", ["candidate_only", "hop_order", "false_premise", "ip_mtu_boolean",
                                  "process_text", "ignore_integer", "clock_basis", "unknown_reason", "extra_state_key"])
def test_valid_looking_shape_laundering_is_rejected(valid, plant):
    payload, metadata = json.loads(canonical(valid))
    finding = payload["findings"][0]
    facts = payload["samples"][0]["endpoints"][0]["facts"]
    if plant == "candidate_only":
        finding["hops"] = finding["hops"][-1:]
    elif plant == "hop_order":
        finding["hops"][0], finding["hops"][1] = finding["hops"][1], finding["hops"][0]
    elif plant == "false_premise":
        finding["hops"][0]["state"]["value"] = False
    elif plant == "ip_mtu_boolean":
        facts["l3.mtu.ip_bytes"]["value"] = True
    elif plant == "process_text":
        facts["l3.ospf.process"]["value"] = "1"
    elif plant == "ignore_integer":
        facts["l3.ospf.mtu_ignore"]["value"] = 0
    elif plant == "clock_basis":
        facts["l3.ospf.collector_clock"]["basis"] = "observed"
    elif plant == "unknown_reason":
        state = facts["l3.mtu.ip_bytes"]
        facts["l3.mtu.ip_bytes"] = {"state": "unknown", "reason": "fiction", "detail": None,
            "candidates": [], "next_evidence": [{"operation": "show ip interface"}], "evidence": state["evidence"]}
    else:
        facts["l3.mtu.ip_bytes"]["reason"] = "not_collected"
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)


def test_two_adjacencies_require_each_declared_endpoint_pair_in_every_round():
    files = members(canonical)
    base, side = json.loads(files["p2.json"]), json.loads(files["p3.json"])
    for node in base["nodes"]:
        node["ports"].append("GigabitEthernet2")
    files["p2.json"] = canonical(base)
    side["base_sha256"] = sha256(files["p2.json"]).hexdigest()
    second = json.loads(canonical(side["adjacencies"][0]))
    second["id"] = "other"
    for name, number in (("left", 1), ("right", 7)):
        second[name]["port"] = "GigabitEthernet2"
        second[name]["address"] = "203.0.113." + str(number)
    side["adjacencies"].append(second)
    files["p3.json"] = canonical(side)
    payload, metadata = record(supplied=files)
    p3_manifest.validate(payload, metadata)
    assert len(payload["samples"][0]["endpoints"]) == 4
    for point in payload["samples"][0]["endpoints"]:
        point["adjacency"] = "link"
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)


def test_not_applicable_reason_namespace_is_closed():
    payload, metadata = record("mtu_ignore")
    finding = payload["findings"][0]
    finding["reason"] = finding["hops"][-1]["state"]["reason"] = "fiction"
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)


@pytest.mark.parametrize("plant", [
    "declaration", "source", "round", "receiver_none", "receiver_other", "base_subject", "adj_subject", "sample_subject",
    "no_adj", "no_nodes", "null_time", "bad_time", "duplicate_capture_ref", "integrity", "read_scope", "view",
    "extra_node", "extra_base", "extra_sample", "extra_point", "extra_adj", "extra_finding", "extra_hop", "extra_capture",
    "extra_registry", "extra_capture_proof", "extra_fact_proof", "extra_need",
])
def test_projected_custody_labels_subjects_and_closed_rows_cannot_be_forged(valid, plant):
    payload, metadata = json.loads(canonical(valid))
    sample, finding = payload["samples"][0], payload["findings"][0]
    capture = next(row for row in payload["captures"] if row["sample"] == sample["id"] and row["source"] == "node:demo:a")
    targets = {"node": payload["nodes"][0], "base": payload["endpoints"][0], "sample": sample,
        "point": sample["endpoints"][0], "adj": payload["adjacencies"][0], "finding": finding, "hop": finding["hops"][0],
        "capture": capture, "registry": sample["declaration"]["evidence"][0], "capture_proof": capture["evidence"][0],
        "fact_proof": finding["hops"][0]["state"]["evidence"][0], "need": finding["next_evidence"][0]}
    if plant.startswith("extra_"):
        targets[plant.removeprefix("extra_")]["qualified"] = True
    elif plant == "declaration":
        sample["declaration"]["evidence"] = [{}]
    elif plant in ("source", "round"):
        capture["source" if plant == "source" else "sample"] = "node:demo:b" if plant == "source" else "second"
    elif plant.startswith("receiver_"):
        finding["receiving_endpoint"] = None if plant == "receiver_none" else payload["endpoints"][0]["subject"]
    elif plant == "sample_subject":
        sample["endpoints"][0]["subject"] = "ospf_sample:" + "0" * 64
    elif plant == "base_subject":
        old, new = payload["endpoints"][0]["subject"], "interface:" + "0" * 64
        payload["endpoints"][0]["subject"] = new
        for round_ in payload["samples"]:
            for point in round_["endpoints"]:
                state = point["facts"]["l3.ospf.interface"]
                if state["value"] == old:
                    state["value"] = new
        if finding["receiving_endpoint"] == old:
            finding["receiving_endpoint"] = new
    elif plant == "adj_subject":
        new = "ospf_adjacency:" + "0" * 64
        payload["adjacencies"][0]["subject"] = finding["subject"] = new
        for round_ in payload["samples"]:
            for point in round_["endpoints"]:
                point["facts"]["l3.ospf.adjacency"]["value"] = new
    elif plant == "no_adj":
        payload["adjacencies"] = payload["findings"] = []
        for round_ in payload["samples"]:
            round_["endpoints"] = []
        payload["denominator"].update(declared_adjacencies=0, expected_endpoint_samples=0)
    elif plant == "no_nodes":
        payload["nodes"] = []
    elif plant in ("null_time", "bad_time"):
        sample["declaration"]["evidence"][0]["value"]["time"] = None if plant == "null_time" else {"unit": "seconds"}
    elif plant == "duplicate_capture_ref":
        refs = sample["declaration"]["evidence"][0]["value"]["captures"]
        refs.append(dict(refs[0]))
    else:
        capture[plant] = capture["evidence"][0][plant] = "fiction"
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)


def test_explicit_fact_types_match_authoritative_owner_specs():
    specs = p3.discovery.FACTS + p3.link.FACTS + p3.l2_mtu.FACTS + p3.l3_mtu.FACTS + p3.s.FACTS + p3.s.SETTLED_FACTS
    primitive = {"boolean": bool, "integer": int, "text": str, "entity_ref": str}
    expected = {str(spec.id): primitive[spec.value_type] for spec in specs}
    assert len(expected) == len(specs) and set(expected) == set(p3.FACT_IDS)
    assert p3_manifest._TYPES == expected
