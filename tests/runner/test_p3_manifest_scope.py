"""Coherent projected rewrites are checked against the bounded declared scope."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA
from atlas_brain.runner import p3, p3_manifest
from atlas_brain.runner.records import RunnerRefused
from tools.p3_cases import members


@pytest.fixture(scope="module")
def valid():
    payload, _ = p3.analyse_group(admit_members(members(canonical)))
    expected = {"captures": sorted(({"capture": row["id"], "sha256": row["sha256"]}
                for row in payload["captures"]), key=lambda row: row["capture"]),
                "registry_sha256": payload["registry_sha256"], "base_registry_sha256": payload["base_registry_sha256"]}
    metadata = {key: value for key, value in expected.items() if key != "captures"}
    metadata.update(digest=sha256(canonical(expected)).hexdigest(), captures=len(payload["captures"]),
                    files=len(payload["captures"]) + 2)
    p3_manifest.validate(payload, metadata)
    return payload, metadata


def resubject(payload, field, value):
    adjacency = payload["adjacencies"][0]
    declaration = json.loads(canonical(adjacency["declaration"]["evidence"][0]["value"]))
    declaration["left"][field] = value
    nodes = {row["id"]: row["key"] for row in payload["nodes"]}

    def scope(point):
        return nodes[point["node"]], point["port"], point["process"], point["router_id"], point["address"], point["vrf"]

    def identity(prefix, context):
        return prefix + sha256(canonical(context)).hexdigest()

    context = (SCHEMA, declaration["id"], declaration["domain"], declaration["area"],
               scope(declaration["left"]), scope(declaration["right"]))
    scopes = {(point["node"], point["port"]): scope(point) for point in (declaration["left"], declaration["right"])}
    subjects = {adjacency["subject"]: identity("ospf_adjacency:", context)}
    for sample in payload["samples"]:
        for point in sample["endpoints"]:
            if point["adjacency"] == adjacency["id"]:
                subjects[point["subject"]] = identity("ospf_sample:", context + (scopes[point["node"], point["port"]], sample["id"]))

    def rewrite(item):
        if isinstance(item, str):
            return subjects.get(item, item)
        if isinstance(item, list):
            return [rewrite(child) for child in item]
        if isinstance(item, dict):
            result = {key: rewrite(child) for key, child in item.items()}
            if (item.get("kind") == "registry" and item.get("table") == "synthetic_p3.adjacencies"
                    and item.get("row_id") == adjacency["id"]):
                result["value"] = json.loads(canonical(declaration))
            return result
        return item

    result = rewrite(payload)
    encoded = canonical(result)
    assert len(subjects) == 1 + 2 * len(payload["samples"])
    assert result["scope"] == payload["scope"] == "declared_synthetic_default_vrf_point_to_point"
    for old, new in subjects.items():
        assert old != new and old.encode() not in encoded and new.encode() in encoded
    return result


@pytest.mark.parametrize("field,value", [("router_id", "192.0.2.9"), ("address", "198.51.100.9")])
def test_canonical_resubjection_is_consistent_without_authentication_claim(valid, field, value):
    payload, metadata = valid
    p3_manifest.validate(resubject(payload, field, value), metadata)


@pytest.mark.parametrize("field,value", [
    ("vrf", "other"), ("router_id", "192.00.2.1"), ("address", "198.051.100.1"),
    ("router_id", "256.0.2.1"), ("address", "198.51.100"), ("router_id", "192.0.2.\uFF11"),
    ("address", "198.51.100.0001"), ("router_id", "192.0.2.+1"),
    ("address", "198..100.1"), ("router_id", "192.0.2.x"), ("router_id", None), ("address", False),
])
def test_coherent_registry_and_all_subject_rewrites_cannot_expand_declared_scope(valid, field, value):
    payload, metadata = valid
    changed = resubject(payload, field, value)
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(changed, metadata)
