"""Generated P3 pipeline receipt plants; all execution belongs to hosted CI."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA, sample_subject
from atlas_brain.kernel import states as k
from atlas_brain.runner import p3_pipeline as pipeline
from atlas_brain.runner.records import RunnerRefused

P = "GigabitEthernet1"


def bundle(missing=()):
    files, baseline = {}, []
    for node, peer in (("a", "b"), ("b", "a")):
        raw = (f"Device ID: sw-{peer}\nPlatform: synthetic-switch, Capabilities: Switch\n"
               f"Interface: {P}, Port ID (outgoing port): {P}\n").encode()
        path = node + "_cdp.txt"
        files[path] = raw
        baseline.append({"path": path, "node": node, "operation": "iosxe.show_cdp_neighbors_detail",
                         "sha256": sha256(raw).hexdigest()})
    files["p2.json"] = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic",
        "group": "demo", "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in ("a", "b")],
        "captures": baseline})
    def point(node, number):
        return {"node": node, "port": P, "process": number, "router_id": "192.0.2." + str(number),
                "address": "198.51.100." + str(number), "vrf": "default"}
    samples = []
    for round_id, start in (("first", 1000000), ("second", 122000000)):
        captures = []
        for node, number, peer, mtu in (("a", 1, 7, 9000), ("b", 7, 1, 1500)):
            outputs = {
                pipeline.l2_mtu.OP: f"{P} is up, line protocol is up\n  MTU {mtu} bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n",
                pipeline.l3_mtu.OP: f"{P} is up, line protocol is up\n  MTU is {mtu} bytes\n",
                pipeline.neighbor.OP: f"Neighbor ID Pri State Dead Time Address Interface\n192.0.2.{peer} 0 EXSTART/- 00:00:30 198.51.100.{peer} {P}\n",
                pipeline.interface.OP: f"{P} is up, line protocol is up\n  Internet Address 198.51.100.{number}/30, Area 0\n"
                    f"  Process ID {number}, VRF default Router ID 192.0.2.{number}, Network Type POINT_TO_POINT, Cost: 10\n",
                pipeline.ignore.OP: f"interface {P}\n no ip ospf mtu-ignore\nend\n",
            }
            for index, (operation, output) in enumerate(outputs.items()):
                if (round_id, node, operation) in missing:
                    continue
                raw, path = output.encode(), f"{round_id}_{node}_{index}.txt"
                files[path] = raw
                captures.append({"path": path, "node": node, "operation": operation, "sha256": sha256(raw).hexdigest()})
        samples.append({"id": round_id, "time": {"unit": "unix_us", "clock": "collector:fixture", "earliest": start,
            "latest": start + 1, "bound": "collector_recorded"}, "captures": captures})
    files["p3.json"] = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "base_sha256": sha256(files["p2.json"]).hexdigest(), "adjacencies": [{"id": "link", "domain": "lab", "area": 0,
            "left": point("a", 1), "right": point("b", 7)}], "samples": samples})
    return admit_members(files)


def test_every_capture_receipt_and_declared_sample_operand_precedes_successful_chain():
    group = bundle()
    result = pipeline.run(group)
    assert len(result.receipts) == 22 and len({item.capture for item in result.receipts}) == 22
    assert sum(item.sample is None for item in result.receipts) == 2
    expected = {capture.id: (capture.source, sample.id) for sample in group.samples for capture in sample.captures}
    assert all((item.node, item.sample) == expected[item.capture] for item in result.receipts if item.sample is not None)
    for adjacency in group.adjacencies:
        for point in (adjacency.left, adjacency.right):
            for sample in group.samples:
                subject = sample_subject(adjacency, point, sample)
                assert all(k.FactRef(fact=fact, subject=subject) in result.store.values for fact in pipeline.SAMPLE_FACTS)
    finding, = result.findings.rows
    assert finding.state == "problem" and finding.hops[-1].id == "candidate"


def test_missing_capture_is_unknown_operand_not_a_dropped_population():
    group = bundle(missing=(("first", "a", pipeline.l3_mtu.OP),))
    result = pipeline.run(group)
    assert len(result.receipts) == 21 and result.findings.denominator == (
        ("declared_adjacencies", 1), ("rounds", 2), ("expected_endpoint_samples", 4))
    finding, = result.findings.rows
    assert finding.state == "unknown" and finding.hops[-1].id == "ip_mtu"


@pytest.mark.parametrize("plant,code", [("missing", "parse_coverage"), ("duplicate", "parse_coverage"),
                                       ("source", "parse_source"), ("sample", "parse_sample")])
def test_receipt_laundering_is_rejected_before_any_estate_consumer(monkeypatch, plant, code):
    group = bundle()
    original = pipeline.l2_mtu.build_sample
    def changed(group, sample, node, store):
        result = original(group, sample, node, store)
        if plant == "missing":
            return replace(result, parses=())
        if plant == "duplicate":
            return replace(result, parses=result.parses * 2)
        target_sample = next(item for item in group.samples if item.id != sample.id) if plant == "sample" else sample
        target = next(capture for capture in target_sample.captures if capture.operation == pipeline.l2_mtu.OP
                      and (capture.source != node.key if plant == "source" else capture.source == node.key))
        return replace(result, parses=tuple((target.id, parsed) for _, parsed in result.parses))
    monkeypatch.setattr(pipeline.l2_mtu, "build_sample", changed)
    monkeypatch.setattr(pipeline.link, "build_group", lambda *args: pytest.fail("estate consumer ran before barrier"))
    with pytest.raises(RunnerRefused, match="^p3_" + code + "$"):
        pipeline.run(group)


def test_operation_owner_receipts_cannot_be_exchanged(monkeypatch):
    group = bundle()
    for owner, other in ((pipeline.l2_mtu, pipeline.l3_mtu), (pipeline.l3_mtu, pipeline.l2_mtu)):
        original = owner.build_sample
        def changed(group, sample, node, store, original=original, operation=other.OP):
            result = original(group, sample, node, store)
            target = next(capture for capture in sample.captures if capture.source == node.key and capture.operation == operation)
            return replace(result, parses=tuple((target.id, parsed) for _, parsed in result.parses))
        monkeypatch.setattr(owner, "build_sample", changed)
    monkeypatch.setattr(pipeline.link, "build_group", lambda *args: pytest.fail("estate consumer ran before barrier"))
    with pytest.raises(RunnerRefused, match="^p3_parse_owner$"):
        pipeline.run(group)


@pytest.mark.parametrize("plant", ["duplicate", "base_owner", "sample_owner"])
def test_unowned_and_duplicate_captures_refuse_before_producers(monkeypatch, plant):
    group = bundle()
    if plant == "duplicate":
        group = replace(group, base=replace(group.base, captures=group.base.captures * 2))
    elif plant == "base_owner":
        first, *rest = group.base.captures
        group = replace(group, base=replace(group.base, captures=(replace(first, operation=pipeline.l2_mtu.OP), *rest)))
    else:
        sample = group.samples[0]
        first, *rest = sample.captures
        sample = replace(sample, captures=(replace(first, operation="iosxe.unowned"), *rest))
        group = replace(group, samples=(sample,) + group.samples[1:])
    monkeypatch.setattr(pipeline.discovery, "build_node", lambda *args: pytest.fail("producer ran before custody preflight"))
    with pytest.raises(RunnerRefused):
        pipeline.run(group)
