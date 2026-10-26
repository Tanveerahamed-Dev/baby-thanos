"""Generated admitted sidecars; no device qualification or imported fixtures."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA, sample_subject
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore
from atlas_brain.packs.l2.mtu import build

P = "GigabitEthernet1"
BODY = (b"GigabitEthernet1 is up, line protocol is up\n"
        b"  MTU 9000 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n")


def files(raw=BODY, timed=True, source="a", operation=build.OP):
    discovery = b"Device ID: sw-b\nInterface: GigabitEthernet1, Port ID (outgoing port): GigabitEthernet1\n"
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
            "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in ("a", "b")],
            "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                          "sha256": sha256(discovery).hexdigest()}]}
    base_raw = canonical(base)
    samples = [{"id": name, "time": {"unit": "unix_us", "clock": "collector:fixture",
                "earliest": start, "latest": start + 1, "bound": "collector_recorded"} if timed else None,
                "captures": [{"path": name + ".txt", "node": source, "operation": operation,
                              "sha256": sha256(raw).hexdigest()}]}
               for name, start in (("first", 1000000), ("second", 122000000))]
    def point(node, number):
        return {"node": node, "port": P, "process": number, "router_id": "192.0.2." + str(number),
                "address": "198.51.100." + str(number), "vrf": "default"}
    sidecar = {"schema": SCHEMA, "semantic_group": "declared_synthetic",
               "base_sha256": sha256(base_raw).hexdigest(),
               "adjacencies": [{"id": "link", "domain": "lab", "area": 0,
                                "left": point("a", 1), "right": point("b", 7)}], "samples": samples}
    return {"p2.json": base_raw, "p3.json": canonical(sidecar), "discovery.txt": discovery,
            "first.txt": raw, "second.txt": raw}


def change_sample(group, sample):
    return replace(group, samples=tuple(sample if item.id == sample.id else item for item in group.samples))


def test_owned_observed_facts_keep_both_rounds_and_exact_registry_byte_proofs():
    group, store = admit_members(files()), FactStore()
    node = group.base.nodes[0]
    outputs = [build.build_sample(group, sample, node, store) for sample in group.samples]
    assert build.STEP.reads == () and build.STEP.produces == (build.MTU,)
    assert build.FACTS[0].subject == "ospf_sample" and build.FACTS[0].step == build.STEP.id
    assert store.owners == {build.MTU: build.STEP.id} and len(store.values) == 2
    assert len({result.rows[0].subject for result in outputs}) == 2
    for sample, result in zip(group.samples, outputs):
        row, = result.rows
        capture, = sample.captures
        assert result.quality == "complete" and result.parses[0][0] == capture.id
        assert row.subject == sample_subject(row.adjacency, row.point, sample)
        assert row.value.value == 9000 and row.value.raw == "9000" and row.value.basis is k.Basis.OBSERVED
        assert store.values[k.FactRef(fact=build.MTU, subject=row.subject)] is row.value
        assert {ref.table for ref in row.value.evidence if isinstance(ref, k.RegistryRef)} == {
            "synthetic_p2.groups", "synthetic_p2.nodes", "synthetic_p3.samples", "synthetic_p3.adjacencies"}
        refs = [ref for ref in row.value.evidence if isinstance(ref, k.EvidenceRef)]
        assert len(refs) == 3
        for ref in refs:
            assert ref.capture == capture.id and isinstance(ref.locator, k.ByteSpan)
            excerpt = capture.raw[ref.locator.start:ref.locator.end]
            assert sha256(excerpt).hexdigest() == ref.excerpt_sha256


def test_removed_capture_and_uncollected_end_preserve_declared_population_and_subject():
    group = admit_members(files())
    sample = group.samples[0]
    original = build.build_sample(group, sample, group.base.nodes[0], FactStore()).rows[0]
    removed = replace(sample, captures=())
    changed = change_sample(group, removed)
    row, = build.build_sample(changed, removed, group.base.nodes[0], FactStore()).rows
    assert row.subject == original.subject and row.value.reason is k.UnknownReason.NOT_COLLECTED
    other, = build.build_sample(group, sample, group.base.nodes[1], FactStore()).rows
    assert other.value.reason is k.UnknownReason.NOT_COLLECTED
    need, = row.value.next_evidence
    assert need.node == row.point.node.key and need.operation == build.OP and need.resolves == (build.MTU,)


@pytest.mark.parametrize("raw,reason", [
    (BODY.splitlines(keepends=True)[0], k.UnknownReason.FIELD_NOT_PRINTED),
    (BODY.replace(b"9000", b"0"), k.UnknownReason.PARSE_PARTIAL),
    (BODY + b"unmodeled\n", k.UnknownReason.PARSE_PARTIAL),
    (b"", k.UnknownReason.EMPTY_UNREGISTERED),
    (b"% Invalid input\n", k.UnknownReason.CAPTURE_ERROR),
    (BODY + b"--More--\n", k.UnknownReason.CAPTURE_TRUNCATED),
])
def test_no_default_and_exact_parser_integrity_reasons(raw, reason):
    group, store = admit_members(files(raw)), FactStore()
    result = build.build_sample(group, group.samples[0], group.base.nodes[0], store)
    assert result.rows[0].value.reason is reason and result.quality == "partial" and len(store.values) == 1


def test_forged_duplicate_captures_conflict_without_vote_or_second_write():
    group = admit_members(files())
    sample = replace(group.samples[0], captures=group.samples[0].captures * 2)
    store = FactStore()
    result = build.build_sample(change_sample(group, sample), sample, group.base.nodes[0], store)
    assert result.rows[0].value.reason is k.UnknownReason.CONFLICTING_EVIDENCE
    assert len(result.parses) == 2 and len(store.values) == 1


def test_undeclared_port_refuses_before_registering_owner():
    group = admit_members(files(BODY + b"GigabitEthernet99 is malformed\n"))
    store = FactStore()
    with pytest.raises(ValueError, match="undeclared_local_port"):
        build.build_sample(group, group.samples[0], group.base.nodes[0], store)
    assert not store.owners and not store.values


@pytest.mark.parametrize("plant", ["scope", "process", "time", "null_time", "sample", "node", "base_schema"])
def test_membership_scope_and_time_bindings_refuse_before_write(plant):
    group, store = admit_members(files()), FactStore()
    sample, node = group.samples[0], group.base.nodes[0]
    if plant in ("scope", "process", "time"):
        capture, = sample.captures
        metadata = capture.resolved_metadata
        if plant == "time":
            metadata = replace(metadata, collected_utc=group.samples[1].time)
        else:
            scope = replace(metadata.scope, **({"vrf": "other"} if plant == "scope" else {"instance": "2"}))
            metadata = replace(metadata, scope=scope)
        sample = replace(sample, captures=(replace(capture, metadata=metadata),))
        group = change_sample(group, sample)
    elif plant == "null_time":
        sample = replace(sample, time=None)
        group = change_sample(group, sample)
    elif plant == "sample":
        sample = replace(sample, id="outside")
    elif plant == "node":
        node = replace(node, id="outside")
    else:
        group = replace(group, base=replace(group.base, schema="atlas-brain.synthetic-p2/2"))
    with pytest.raises(ValueError):
        build.build_sample(group, sample, node, store)
    assert not store.owners and not store.values


def test_null_sample_time_is_unknown_time_not_an_invented_clock():
    group = admit_members(files(timed=False))
    result = build.build_sample(group, group.samples[0], group.base.nodes[0], FactStore())
    assert result.rows[0].value.value == 9000
    capture, = group.samples[0].captures
    assert capture.collected_utc.reason is k.UnknownReason.AS_OF_MISSING


@pytest.mark.parametrize("plant", ["population", "raw", "span"])
def test_forged_parser_receipt_refuses_before_any_store_mutation(monkeypatch, plant):
    group, store = admit_members(files()), FactStore()
    original = build.parser.parse_capture
    def forged(capture, ports):
        result = original(capture, ports)
        row, = result.rows
        if plant == "population":
            return replace(result, rows=())
        fields = dict(row.fields)
        token = fields[build.parser.FIELD]
        fields[build.parser.FIELD] = replace(token, **(
            {"raw": "8000", "value": "8000"} if plant == "raw" else
            {"span": k.ByteSpan(start=0, end=len(capture.raw) + 1)}))
        return replace(result, rows=(replace(row, fields=tuple(fields.items())),))
    monkeypatch.setattr(build.parser, "parse_capture", forged)
    with pytest.raises(ValueError):
        build.build_sample(group, group.samples[0], group.base.nodes[0], store)
    assert not store.owners and not store.values


def test_sidecar_schema_is_admitted_before_builder_use():
    supplied = files()
    supplied["p3.json"] = supplied["p3.json"].replace(SCHEMA.encode(), b"atlas-brain.synthetic-p3/9")
    with pytest.raises(AdmissionRefused, match="p3_schema"):
        admit_members(supplied)


def test_other_declared_capture_source_never_supplies_this_node_mtu():
    group = admit_members(files(source="b"))
    row, = build.build_sample(group, group.samples[0], group.base.nodes[0], FactStore()).rows
    assert row.value.reason is k.UnknownReason.NOT_COLLECTED
    other, = build.build_sample(group, group.samples[0], group.base.nodes[1], FactStore()).rows
    assert other.value.value == 9000


def test_ip_mtu_capture_cannot_substitute_for_interface_mtu():
    raw = b"GigabitEthernet1 is up, line protocol is up\n  MTU is 1500 bytes\n"
    group = admit_members(files(raw, operation="iosxe.show_ip_interface"))
    row, = build.build_sample(group, group.samples[0], group.base.nodes[0], FactStore()).rows
    assert row.value.reason is k.UnknownReason.NOT_COLLECTED
