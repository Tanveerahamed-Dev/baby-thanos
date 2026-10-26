"""Generated P3 envelopes exercise strict admission without runtime or device claims."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import (
    OPERATIONS,
    SCHEMA,
    adjacency_subject,
    sample_subject,
)
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource


def members(adjacencies=1, rounds=2):
    ports = [f"Gi1/0/{i + 1}" for i in range(max(1, adjacencies))]
    files = {node + ".txt": ("Device ID: sw-" + peer + "\n").encode()
             for node, peer in (("a", "b"), ("b", "a"))}
    base = {"schema": BASE_SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
            "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": ports} for node in ("a", "b")],
            "captures": [{"path": node + ".txt", "node": node, "operation": "iosxe.show_cdp_neighbors_detail",
                          "sha256": sha256(files[node + ".txt"]).hexdigest()} for node in ("a", "b")]}
    files["p2.json"] = canonical(base)
    def point(node, index):
        return {"node": node, "port": ports[index], "process": 1, "router_id": "192.0.2." + ("1" if node == "a" else "2"),
                "address": "198.51.100." + str(index * 2 + (1 if node == "a" else 2)), "vrf": "default"}
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "base_sha256": sha256(files["p2.json"]).hexdigest(),
        "adjacencies": [{"id": f"adj{i}", "domain": "demo", "area": 0,
                        "left": point("a", i), "right": point("b", i)} for i in range(adjacencies)], "samples": []}
    for index in range(rounds):
        sample = {"id": f"s{index}", "time": {"unit": "unix_us", "clock": "collector:test", "earliest": index * 120000000,
                  "latest": index * 120000000, "bound": "collector_recorded"}, "captures": []}
        add_capture(files, sample, "iosxe.show_ip_ospf_neighbor")
        manifest["samples"].append(sample)
    return files, manifest


def add_capture(files, sample, operation):
    path, raw = sample["id"] + "." + operation + ".txt", b"Neighbor ID Pri State Dead Time Address Interface\n"
    files[path] = raw
    sample["captures"].append({"path": path, "node": "a", "operation": operation, "sha256": sha256(raw).hexdigest()})


def admit(files, manifest):
    return admit_members({**files, "p3.json": json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")})


def test_round_metadata_is_exact_and_capture_identity_binds_both_registries():
    files, manifest = members()
    group = admit(files, manifest)
    assert group.base.raw == files["p2.json"] and len(group.adjacencies) == 1 and len(group.samples) == 2
    assert group.samples[0].captures[0].id != group.samples[1].captures[0].id
    for sample in group.samples:
        capture, = sample.captures
        ref = next(row for row in manifest["samples"] if row["id"] == sample.id)["captures"][0]
        expected = sha256(canonical((SCHEMA, sha256(group.raw).hexdigest(), sha256(group.base.raw).hexdigest(),
                                    sample.id, "a", ref["path"], ref["operation"], ref["sha256"]))).hexdigest()
        assert capture.id == "cap:" + expected and capture.collected_utc == sample.time
        assert sample.time.bound is BoundSource.COLLECTOR_RECORDED
        assert capture.scope.node == capture.source == group.base.nodes[0].key
        assert capture.scope.instance == "1" and capture.scope.vrf == "default"
        witness, = capture.integrity_evidence
        assert witness.capture == capture.id and isinstance(witness.locator, k.WholeCapture)
        assert witness.excerpt_sha256 == sha256(capture.raw).hexdigest()
        assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
    manifest["samples"][0]["time"] = None
    assert admit(files, manifest).samples[0].captures[0].collected_utc.reason is k.UnknownReason.AS_OF_MISSING


@pytest.mark.parametrize("adjacencies,rounds", [(1, 0), (16, 16)])
def test_inclusive_population_bounds(adjacencies, rounds):
    group = admit(*members(adjacencies, rounds))
    assert len(group.adjacencies) == adjacencies and len(group.samples) == rounds


@pytest.mark.parametrize("adjacencies,rounds", [(0, 1), (17, 1), (1, 17)])
def test_population_overflow_refuses(adjacencies, rounds):
    with pytest.raises(AdmissionRefused):
        admit(*members(adjacencies, rounds))


@pytest.mark.parametrize("path,value", [
    (("schema",), "other"), (("semantic_group",), "real"), (("base_sha256",), "0" * 64), (("extra",), 1),
    (("adjacencies", 0, "extra"), 1), (("adjacencies", 0, "area"), True), (("adjacencies", 0, "area"), -1),
    (("adjacencies", 0, "area"), 4294967296), (("adjacencies", 0, "left", "process"), True),
    (("adjacencies", 0, "left", "process"), 0), (("adjacencies", 0, "left", "process"), 65536),
    (("adjacencies", 0, "left", "router_id"), "192.0.02.1"), (("adjacencies", 0, "left", "address"), "198.51.100.256"),
    (("adjacencies", 0, "left", "vrf"), "other"), (("adjacencies", 0, "left", "node"), "missing"),
    (("adjacencies", 0, "left", "port"), "Gi1/0/99"), (("adjacencies", 0, "left", "extra"), 1),
    (("samples", 0, "time", "earliest"), True), (("samples", 0, "time", "earliest"), -1),
    (("samples", 0, "time", "latest"), 9007199254740992), (("samples", 0, "time", "latest"), 0.5),
    (("samples", 0, "time", "unit"), "unix_s"), (("samples", 0, "time", "bound"), "unbounded"),
    (("samples", 0, "time", "clock"), "node:a/epoch:1"), (("samples", 0, "time", "clock"), "collector:" + "a" * 65),
    (("samples", 0, "time", "extra"), 1), (("samples", 0, "captures", 0, "sha256"), "0" * 64),
    (("samples", 0, "captures", 0, "operation"), "iosxe.show_version"), (("samples", 0, "captures", 0, "node"), "missing"),
    (("samples", 0, "captures", 0, "path"), "../x"), (("samples", 0, "captures", 0, "path"), "a.txt"),
])
def test_invalid_closed_fields_refuse(path, value):
    files, manifest = members()
    target = manifest
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(AdmissionRefused):
        admit(files, manifest)


@pytest.mark.parametrize("plant", ["sample_id", "adjacency_id", "endpoint", "process", "router_id", "self",
                                   "source_operation", "path", "unlisted", "missing", "reverse_time", "base_schema", "base_operation", "unused_node"])
def test_identity_scope_partition_and_base_refusals(plant):
    files, manifest = members(adjacencies=2)
    first, second = manifest["samples"]
    if plant == "sample_id": second["id"] = first["id"]
    elif plant == "adjacency_id": manifest["adjacencies"][1]["id"] = manifest["adjacencies"][0]["id"]
    elif plant == "endpoint": manifest["adjacencies"][1]["left"]["port"] = "Gi1/0/1"
    elif plant in ("process", "router_id"): manifest["adjacencies"][1]["left"][plant] = 2 if plant == "process" else "192.0.2.9"
    elif plant == "self":
        manifest["adjacencies"] = manifest["adjacencies"][:1]
        manifest["adjacencies"][0]["right"].update(node="a", port="Gi1/0/2", router_id="192.0.2.1")
    elif plant == "source_operation":
        duplicate = dict(first["captures"][0], path="duplicate.txt")
        files[duplicate["path"]] = files[first["captures"][0]["path"]]
        first["captures"].append(duplicate)
    elif plant == "path": second["captures"][0]["path"] = first["captures"][0]["path"]
    elif plant == "unlisted": files["extra.txt"] = b"extra"
    elif plant == "missing": files.pop(first["captures"][0]["path"])
    elif plant == "reverse_time": first["time"]["earliest"] = 1
    else:
        base = json.loads(files["p2.json"])
        if plant == "base_schema": base["schema"] = "atlas-brain.synthetic-p2/2"
        elif plant == "base_operation": base["captures"][0]["operation"] = "iosxe.show_interfaces_trunk"
        else:
            base["nodes"].append({"id": "c", "discovery_id": "sw-c", "ports": ["Gi1/0/1"]})
            first["captures"][0]["node"] = "c"
        files["p2.json"] = canonical(base)
        manifest["base_sha256"] = sha256(files["p2.json"]).hexdigest()
    with pytest.raises(AdmissionRefused):
        admit(files, manifest)


def test_capture_limit_is_global_not_per_round():
    files, manifest = members(rounds=13)
    extra = [op for op in OPERATIONS if op != "iosxe.show_ip_ospf_neighbor"]
    for index, sample in enumerate(manifest["samples"]):
        for operation in (extra if index < 12 else extra[:3]): add_capture(files, sample, operation)
    assert sum(len(s.captures) for s in admit(files, manifest).samples) == 64
    add_capture(files, manifest["samples"][-1], extra[-1])
    with pytest.raises(AdmissionRefused, match="p3_capture_budget"):
        admit(files, manifest)


def test_capture_removal_and_round_reordering_preserve_declared_subjects():
    files, manifest = members()
    before = admit(files, manifest)
    point = before.adjacencies[0].left
    subjects = {s.id: sample_subject(before.adjacencies[0], point, s) for s in before.samples}
    files.pop(manifest["samples"][0]["captures"][0]["path"])
    manifest["samples"][0]["captures"] = []
    manifest["samples"].reverse()
    after = admit(files, manifest)
    assert len(after.samples) == 2 and not after.samples[0].captures
    assert adjacency_subject(before.adjacencies[0]) == adjacency_subject(after.adjacencies[0])
    assert {s.id: sample_subject(after.adjacencies[0], after.adjacencies[0].left, s) for s in after.samples} == subjects
    assert before.samples[1].captures[0].id != after.samples[1].captures[0].id
    assert after.samples[0].declaration.evidence[0].citation == "/samples/1"


def test_integer_and_clock_boundary_values_are_admitted():
    files, manifest = members()
    manifest["adjacencies"][0]["area"] = 4294967295
    for point in (manifest["adjacencies"][0]["left"], manifest["adjacencies"][0]["right"]): point["process"] = 65535
    manifest["samples"][0]["time"].update(earliest=9007199254740991, latest=9007199254740991, clock="collector:" + "a" * 64)
    assert admit(files, manifest).samples[0].time.earliest == 9007199254740991


@pytest.mark.parametrize("raw,expected", [
    (b"", "empty"), (b"% Invalid input\n", "error"), (b"[truncated]\n", "truncated"),
    (b"unmodelled body\n", "complete"), (b"\xff", "p3_invalid_encoding"), (b"\x1b[31m", "p3_invalid_text"),
    (b"show ip ospf neighbor\nshow version\n", "p3_mixed_context"),
    (b"sw-a#show ip ospf neighbor\nbody\nsw-b#\n", "p3_mixed_context"),
    (b"sw-a#show ip ospf neighbor\nbody\nsw-a#\n", "complete"),
])
def test_text_custody_classifies_damage_and_rejects_mixed_command_context(raw, expected):
    files, manifest = members(rounds=1)
    ref = manifest["samples"][0]["captures"][0]
    files[ref["path"]], ref["sha256"] = raw, sha256(raw).hexdigest()
    if expected.startswith("p3_"):
        with pytest.raises(AdmissionRefused, match=expected):
            admit(files, manifest)
    else:
        assert str(admit(files, manifest).samples[0].captures[0].integrity) == expected
