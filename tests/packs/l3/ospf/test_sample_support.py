"""Generated admitted helper cases; no runtime or vendor qualification claims."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.ospf import neighbor
from atlas_brain.packs.l3.ospf import sample_support as helper

P = "GigabitEthernet1"
RAW = b"Neighbor ID Pri State Dead Time Address Interface\n192.0.2.2 0 EXSTART/- 00:00:30 198.51.100.2 GigabitEthernet1\n"


def group(timed=True):
    discovery = b"Device ID: sw-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": name, "discovery_id": "sw-" + name, "ports": [P]} for name in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    def point(name, number):
        return {"node": name, "port": P, "process": number, "router_id": "192.0.2." + str(number),
                "address": "198.51.100." + str(number), "vrf": "default"}
    side = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic", "base_sha256": sha256(base).hexdigest(),
        "adjacencies": [{"id": "link", "domain": "lab", "area": 0, "left": point("a", 1), "right": point("b", 2)}],
        "samples": [{"id": "first", "time": {"unit": "unix_us", "clock": "collector:fixture", "earliest": 1,
            "latest": 2, "bound": "collector_recorded"} if timed else None,
            "captures": [{"path": "neighbor.txt", "node": "a", "operation": neighbor.OP, "sha256": sha256(RAW).hexdigest()}]}]})
    return admit_members({"p2.json": base, "p3.json": side, "discovery.txt": discovery, "neighbor.txt": RAW})


def test_prepare_binds_expected_endpoint_capture_population_and_exact_proof():
    estate = group()
    context = helper.prepare(estate, estate.samples[0], estate.base.nodes[0])
    assert len(context.points) == len(context.documents) == 1
    capture, parsed = context.documents[0]
    row, = parsed.rows
    refs = helper.witnesses(capture, row)
    assert len(refs) == 2 and all(ref.capture == capture.id for ref in refs)
    for ref in refs:
        assert sha256(capture.raw[ref.locator.start:ref.locator.end]).hexdigest() == ref.excerpt_sha256


@pytest.mark.parametrize("plant", ["scope", "time", "registry", "sample", "node", "schema"])
def test_scope_time_registry_and_membership_fail_closed(plant):
    estate = group()
    sample, node = estate.samples[0], estate.base.nodes[0]
    if plant in ("scope", "time"):
        capture, = sample.captures
        metadata = capture.resolved_metadata
        metadata = (replace(metadata, scope=replace(metadata.scope, instance="99")) if plant == "scope"
                    else replace(metadata, collected_utc=replace(sample.time, earliest=0)))
        sample = replace(sample, captures=(replace(capture, metadata=metadata),))
        estate = replace(estate, samples=(sample,))
    elif plant == "registry":
        sample = replace(sample, declaration=replace(sample.declaration, value="wrong"))
        estate = replace(estate, samples=(sample,))
    elif plant == "sample":
        sample = replace(sample, id="outside")
    elif plant == "node":
        node = replace(node, id="outside")
    else:
        estate = replace(estate, base=replace(estate.base, schema="wrong"))
    with pytest.raises(ValueError):
        helper.prepare(estate, sample, node)


def test_null_time_requires_the_exact_unrecorded_capture_witness():
    estate = group(timed=False)
    sample, = estate.samples
    assert helper.prepare(estate, sample, estate.base.nodes[0]).documents
    capture, = sample.captures
    metadata = replace(capture.resolved_metadata, collected_utc=replace(capture.collected_utc, detail="wrong"))
    sample = replace(sample, captures=(replace(capture, metadata=metadata),))
    with pytest.raises(ValueError, match="ospf_sample_time"):
        helper.prepare(replace(estate, samples=(sample,)), sample, estate.base.nodes[0])


@pytest.mark.parametrize("plant", ["bytes", "bounds"])
def test_positive_witness_requires_original_field_bytes_and_bounds(plant):
    estate = group()
    capture, parsed = helper.prepare(estate, estate.samples[0], estate.base.nodes[0]).documents[0]
    row, = parsed.rows
    fields = dict(row.fields)
    field = fields["neighbor_id"]
    fields["neighbor_id"] = replace(field, **({"raw": "192.0.2.9"} if plant == "bytes" else
        {"span": k.ByteSpan(start=0, end=len(capture.raw) + 1)}))
    with pytest.raises(ValueError):
        helper.witnesses(capture, replace(row, fields=tuple(fields.items())))
