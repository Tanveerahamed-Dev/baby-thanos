"""P3 leaf proofs bind admitted registry, capture bytes and collector metadata."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.runner import p2_evidence
from atlas_brain.runner.p3_refs import RefResolver
from atlas_brain.runner.records import RunnerRefused


def bundle(timed=True):
    raw = b"Neighbor ID Pri State Dead Time Address Interface\n"
    files = {"a.txt": b"Device ID: sw-b\n", "b.txt": b"Device ID: sw-a\n", "sample.txt": raw}
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "sw-" + n, "ports": ["Gi1/0/1"]} for n in ("a", "b")],
        "captures": [{"path": n + ".txt", "node": n, "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(files[n + ".txt"]).hexdigest()} for n in ("a", "b")]}
    files["p2.json"] = canonical(base)
    def point(n, index):
        return {"node": n, "port": "Gi1/0/1", "process": 1, "router_id": f"192.0.2.{index}",
                "address": f"198.51.100.{index}", "vrf": "default"}
    time = {"unit": "unix_us", "clock": "collector:test", "earliest": 0, "latest": 1, "bound": "collector_recorded"}
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "base_sha256": sha256(files["p2.json"]).hexdigest(),
        "adjacencies": [{"id": "ab", "domain": "demo", "area": 0, "left": point("a", 1), "right": point("b", 2)}],
        "samples": [{"id": "first", "time": time if timed else None,
                     "captures": [{"path": "sample.txt", "node": "a", "operation": "iosxe.show_ip_ospf_neighbor",
                                   "sha256": sha256(raw).hexdigest()}]}]}
    return admit_members({**files, "p3.json": canonical(manifest)})


def reader():
    step = StepSpec(id=StepId("l3.ospf/proof"), pack=k.PackId("l3.ospf"), kind="check", scope="estate",
                    reads=(), produces=(), evaluator="l3.ospf.proof")
    return bind_reader(FactStore(), step=step)


def field(group):
    capture, = group.samples[0].captures
    return k.EvidenceRef(capture=capture.id, locator=k.ByteSpan(start=0, end=8),
                         role=k.EvidenceRole.SUBJECT, excerpt_sha256=sha256(capture.raw[:8]).hexdigest())


def with_capture(group, capture):
    return replace(group, samples=(replace(group.samples[0], captures=(capture,)),))


def test_capture_and_registry_proofs_retain_exact_time_bytes_role_and_original_pointer():
    group = bundle()
    resolver = RefResolver(group, reader())
    proof = replace(field(group), role=k.EvidenceRole.COUNTER_EVIDENCE)
    projected = resolver.resolve(proof)
    assert projected["role"] == "counter_evidence" and projected["sample"] == "first"
    assert projected["source"] == group.adjacencies[0].left.node.key and projected["path"] == "sample.txt"
    assert projected["collected_utc"] == json.loads(group.raw)["samples"][0]["time"]
    assert projected["sha256"] == sha256(b"Neighbor").hexdigest()
    for item in (group.adjacencies[0], group.samples[0]):
        ref, = item.declaration.evidence
        result = resolver.resolve(ref)
        assert result["kind"] == "registry" and result["table_digest"] == sha256(group.raw).hexdigest()
        assert result["value"]["id"] == item.id and "capture" not in result


@pytest.mark.parametrize("plant", ["time", "scope", "instance", "source", "operation", "rendered", "raw", "identity"])
def test_capture_metadata_and_identity_cannot_be_rebound(plant):
    group = bundle()
    capture, = group.samples[0].captures
    meta, proof = capture.metadata, field(group)
    if plant == "time": capture = replace(capture, metadata=replace(meta, collected_utc=replace(group.samples[0].time, earliest=2, latest=3)))
    elif plant in ("scope", "instance"):
        scope = replace(meta.scope, **({"vrf": "other"} if plant == "scope" else {"instance": "2"}))
        capture = replace(capture, metadata=replace(meta, scope=scope))
    elif plant == "source":
        source = group.adjacencies[0].right.node.key
        capture = replace(capture, source=source, metadata=replace(meta, scope=replace(meta.scope, node=source)))
    elif plant == "operation": capture = replace(capture, operation="iosxe.show_ip_interface")
    elif plant == "rendered": capture = replace(capture, rendered="show version")
    elif plant == "raw":
        raw = capture.raw + b"extra\n"
        witness = replace(meta.integrity_evidence[0], excerpt_sha256=sha256(raw).hexdigest())
        capture = replace(capture, raw=raw, metadata=replace(meta, integrity_evidence=(witness,)))
    else:
        witness = replace(meta.integrity_evidence[0], capture=k.CaptureId("cap:changed"))
        capture = replace(capture, id=k.CaptureId("cap:changed"), metadata=replace(meta, integrity_evidence=(witness,)))
        proof = replace(proof, capture=capture.id)
    with pytest.raises(RunnerRefused):
        RefResolver(with_capture(group, capture), reader()).resolve(proof)


def test_null_time_requires_original_missing_time_witness():
    group = bundle(timed=False)
    assert RefResolver(group, reader()).resolve(field(group))["collected_utc"] is None
    capture, = group.samples[0].captures
    missing = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail=None, evidence=(), candidates=(), next_evidence=())
    changed = replace(capture, metadata=replace(capture.metadata, collected_utc=missing))
    with pytest.raises(RunnerRefused, match="capture_metadata"):
        RefResolver(with_capture(group, changed), reader()).resolve(field(group))


@pytest.mark.parametrize("plant", ["schema", "base_pin", "adjacency", "sample_time", "duplicate"])
def test_registry_objects_and_base_pin_cannot_be_rebound(plant):
    group = bundle()
    if plant == "schema": group = replace(group, raw=group.raw.replace(SCHEMA.encode(), b"atlas-brain.synthetic-p3/2"))
    elif plant == "base_pin": group = replace(group, base=replace(group.base, raw=group.base.raw + b" "))
    elif plant == "adjacency": group = replace(group, adjacencies=(replace(group.adjacencies[0], area=1),))
    elif plant == "sample_time": group = replace(group, samples=(replace(group.samples[0], time=None),))
    else: group = replace(group, samples=group.samples * 2)
    with pytest.raises(RunnerRefused):
        RefResolver(group, reader())


@pytest.mark.parametrize("change", [{"citation": "/samples/01"}, {"row_id": "other"},
                                    {"table_digest": "0" * 64}, {"table": "synthetic_p3.other"}])
def test_registry_reference_must_match_exact_source_row(change):
    group = bundle()
    with pytest.raises(RunnerRefused):
        RefResolver(group, reader()).resolve(replace(group.samples[0].declaration.evidence[0], **change))


@pytest.mark.parametrize("change", [{"excerpt_sha256": "0" * 64}, {"capture": "cap:missing"},
    {"locator": k.ByteSpan(start=0, end=1000)}, {"locator": k.FieldPointer(pointer="/samples/0")}])
def test_capture_span_hash_and_locator_refuse(change):
    group = bundle()
    with pytest.raises(RunnerRefused):
        RefResolver(group, reader()).resolve(replace(field(group), **change))


def test_baseline_proofs_delegate_without_projection_changes():
    group, handle = bundle(), reader()
    capture = group.base.captures[0]
    refs = group.base.declaration.evidence + (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(),
        role=k.EvidenceRole.SUBJECT, excerpt_sha256=capture.bytes_sha256),)
    resolver = RefResolver(group, handle)
    for ref in refs:
        assert resolver.resolve(ref) == p2_evidence.resolve_evidence(group.base, handle, (ref,))[0]


def test_needs_keep_collector_constraints_and_cannot_expand_operation_or_node_scope():
    group = bundle()
    need = k.EvidenceNeed(node=group.adjacencies[0].left.node.key, operation="show ip ospf neighbor", params=(),
        resolves=("l3.ospf.state",), reruns=("l3.ospf/settle",), after_s=120, unprintable=("collector_time_required",))
    projected = RefResolver(group, reader()).need(need)
    assert projected["operation"] == "iosxe.show_ip_ospf_neighbor" and projected["after_s"] == 120
    assert projected["unprintable"] == ["collector_time_required"] and projected["params"] == []
    for change in ({"node": "node:other:a"}, {"operation": "show version"}, {"params": (("port", "Gi1/0/1"),)}):
        with pytest.raises(RunnerRefused):
            RefResolver(group, reader()).need(replace(need, **change))
