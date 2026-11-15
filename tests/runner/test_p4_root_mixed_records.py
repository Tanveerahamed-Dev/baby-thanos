"""Trusted record/byte-budget oracles only; these helpers confer no source or admission authority."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.bundle import result_bundle
from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.evidence.capture import (
    Capture,
    CaptureMetadata,
    Channel,
    ErrorKind,
    Scope,
)
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.runner import p4_root_mixed_records as records

RAW = b"synthetic\r\n"
REGISTRY = canonical({"context": "ctx", "nodes": [{"id": "a", "ports": ["Gi1/0/1"]}]})
INPUTS = (REGISTRY, REGISTRY, RAW, bytes(bytearray(RAW)))
LIMITS = (100000, 100000, 100, 64, 40, 100, 100000)


def capture(identity="cap:shared", node="node:demo:a", raw=RAW):
    return Capture(id=identity, source=node, operation="iosxe.show_standby_brief", rendered="show standby brief",
        codec="utf-8", raw=raw, integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
        read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


def witness(identity="cap:shared", locator=None, role=k.EvidenceRole.SUBJECT):
    return k.EvidenceRef(capture=identity, locator=k.WholeCapture() if locator is None else locator,
        role=role, excerpt_sha256=sha256(RAW).hexdigest())


def unknown():
    need = k.EvidenceNeed(node="node:demo:a", operation="iosxe.show_standby_all",
        params=(("group", "9"), ("interface", "Vl20")), resolves=("l3.fhrp.reported_protocol_version",),
        reruns=("l3.fhrp/check_version",), after_s=0, unprintable=("collection_clock",))
    return k.Unknown(reason=k.UnknownReason.AS_OF_MISSING, detail="no_collector_time", evidence=(witness(),),
        candidates=("node:demo:a", "node:demo:b"), next_evidence=(need,))


def wire(value):
    return json.loads(canonical(value))


def bundle(limits=LIMITS, empty=False):
    header = {"schema": records.SCHEMA, "raws": [], "captures": [], "registry_records": []}
    budget = records.RecordBudget(INPUTS, limits, header)
    blobs = records.raw_blobs(INPUTS)
    for digest, raw in sorted(blobs.items()):
        records.append_record(header["raws"], {"sha256": digest, "bytes": len(raw), "encoding": "hex"}, budget, ("data", raw))
    for layer, cap in (("p2", capture()), ("p4", capture(node="node:demo:b"))):
        records.append_record(header["captures"], records.capture_record(cap, layer, sha256(cap.raw).hexdigest()), budget)
    ref = k.RegistryRef(table="synthetic_p2.nodes", row_id="a", table_digest=sha256(REGISTRY).hexdigest(), citation="/nodes/0")
    ids = {}
    first = records.registry_record_id(ref, REGISTRY, canonical(json.loads(REGISTRY)["nodes"][0]), blobs, ids, header["registry_records"], budget)
    assert records.registry_record_id(replace(ref), REGISTRY, canonical(json.loads(REGISTRY)["nodes"][0]), blobs, ids, header["registry_records"], budget) == first
    facts = {kind: {} for kind in records.KINDS}
    for index, (kind, value, expected) in enumerate(zip(records.KINDS, (0, False, "aBcD.EF01.2345"), (int, bool, str), strict=True)):
        if not empty:
            row = {"fact": f"demo.fact_{index}", "subject": "subject:a", "value": records.state_record(
                k.Known(value=value, raw=str(value), basis=k.Basis.OBSERVED, evidence=(witness(),)), expected)}
            budget.add(f"facts/{kind}.jsonl", len(canonical(row)) + 1)
            facts[kind]["subject:a", row["fact"]] = row
    files = result_bundle(header, facts=facts, checks={})
    records.verify_bundle(files, budget)
    return files, budget


def test_complete_bundle_losslessly_deduplicates_raws_keeps_layer_ids_and_canonical_registry_records():
    files, budget = bundle()
    assert set(files) == set(records.NAMES) and len(files) == 5
    assert budget.input_bytes == sum(map(len, INPUTS)) and budget.sizes == {name: len(raw) for name, raw in files.items()}
    header = json.loads(files["result.json"])
    blobs = {row["sha256"]: bytes.fromhex(row["data"]) for row in header["raws"]}
    assert blobs == {sha256(raw).hexdigest(): raw for raw in INPUTS} and len(blobs) == 2
    assert all(row["bytes"] == len(blobs[row["sha256"]]) and row["encoding"] == "hex" for row in header["raws"])
    assert [(row["layer"], row["id"], row["node"]) for row in header["captures"]] == [
        ("p2", "cap:shared", "node:demo:a"), ("p4", "cap:shared", "node:demo:b")]
    assert len(header["registry_records"]) == 1
    row = header["registry_records"][0]
    assert row == {"id": "registry-0", "table": "synthetic_p2.nodes", "row_id": "a", "pointer": "/nodes/0",
        "table_sha256": sha256(REGISTRY).hexdigest(), "raw": sha256(REGISTRY).hexdigest(),
        "encoding": "hex", "canonical": canonical(json.loads(REGISTRY)["nodes"][0]).hex()}
    decoded = bytes.fromhex(row["canonical"])
    assert decoded == canonical(json.loads(blobs[row["raw"]])["nodes"][0])
    values = [json.loads(files[f"facts/{kind}.jsonl"])["value"]["value"] for kind in records.KINDS]
    assert values == [0, False, "aBcD.EF01.2345"] and [type(value) for value in values] == [int, bool, str]
    expected = b"".join(f"{sha256(files[name]).hexdigest()}  {name}\n".encode() for name in sorted(files) if name != "MANIFEST.sha256")
    assert files["MANIFEST.sha256"] == expected and bundle()[0] == files


@pytest.mark.parametrize("empty", [False, True])
def test_all_five_files_and_empty_jsonl_exact_bytes_drive_manifest_and_budget_math(empty):
    files, budget = bundle(empty=empty)
    if empty:
        assert all(files[f"facts/{kind}.jsonl"] == b"" and budget.sizes[f"facts/{kind}.jsonl"] == 0 for kind in records.KINDS)
    assert len(files["MANIFEST.sha256"]) == sum(67 + len(name) for name in records.NAMES if name != "MANIFEST.sha256")
    assert sum(budget.sizes.values()) == sum(map(len, files.values()))


@pytest.mark.parametrize("field", ["count", "artifact", "total"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_exact_original_inputs_plus_five_outputs_and_one_deficits_are_enforced(field, delta):
    files, _ = bundle()
    limits = list(LIMITS)
    limits[2] = len(INPUTS) + 5
    limits[1] = max(map(len, (*INPUTS, *files.values())))
    limits[0] = sum(map(len, INPUTS)) + sum(map(len, files.values()))
    limits[{"total": 0, "artifact": 1, "count": 2}[field]] += delta
    if delta < 0:
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
            bundle(tuple(limits))
        assert caught.value.member == "p4_root_mixed_observations_outputs"
    else:
        assert bundle(tuple(limits))[0] == files


@pytest.mark.parametrize("length", range(7))
@pytest.mark.parametrize("row", [{}, {"quoted": '"\\\u03b1'}])
def test_append_exact_hex_non_utf8_unicode_keys_object_framing_and_table_commas(length, row):
    header = {"table": []}
    budget = records.RecordBudget((), LIMITS, header)
    raw = b"\x00\xff\x80\r\n\\"[:length]
    for key in ("data", '"\\\u03b1'):
        value = dict(row)
        records.append_record(header["table"], value, budget, (key, raw))
        assert bytes.fromhex(value[key]) == raw
        assert len(value[key]) == 2 * len(raw)
        assert budget.sizes["result.json"] == len(canonical(header))


@pytest.mark.parametrize("field", ["artifact", "total"])
def test_predicted_large_hex_payload_is_refused_before_encoding_or_table_mutation(field):
    calls = []

    class HexBytes(bytes):
        def hex(self):
            calls.append(self)
            raise AssertionError("hex encoding reached")
    raw = HexBytes(b"x" * (4 * 1024 * 1024 + 1))
    header = {"table": []}
    expected = len(canonical({"table": [{"data": ""}]})) + 2 * len(raw)
    manifest = sum(67 + len(name) for name in records.NAMES if name != "MANIFEST.sha256")
    limits = [len(raw) + expected + manifest, expected, 6, *LIMITS[3:]]
    ample = records.RecordBudget((raw,), (limits[0] * 2, limits[1] * 2, *limits[2:]), header)
    with pytest.raises(AssertionError, match="^hex encoding reached$"):
        records.append_record(header["table"], {}, ample, ("data", raw))
    assert calls == [raw] and header == {"table": []}
    calls.clear()
    limits[1 if field == "artifact" else 0] -= 1
    budget = records.RecordBudget((raw,), tuple(limits), header)
    before = dict(budget.sizes)
    with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
        records.append_record(header["table"], {}, budget, ("data", raw))
    assert caught.value.member == "p4_root_mixed_observations_outputs" and calls == [] and header == {"table": []}
    assert budget.sizes == before


@pytest.mark.parametrize("expected", [bool, int, str])
def test_unknown_reason_candidates_and_every_need_field_are_preserved_without_coercion(expected):
    value = unknown()
    projected = wire(records.state_record(value, expected))
    assert projected == {"state": "unknown", "reason": "as_of_missing", "detail": "no_collector_time",
        "candidates": ["node:demo:a", "node:demo:b"], "next_evidence": [{"node": "node:demo:a",
            "operation": "iosxe.show_standby_all", "params": [["group", "9"], ["interface", "Vl20"]],
            "resolves": ["l3.fhrp.reported_protocol_version"], "reruns": ["l3.fhrp/check_version"],
            "after_s": 0, "unprintable": ["collection_clock"]}]}
    assert records.state_record(value, expected) == records.unknown_record(value)


@pytest.mark.parametrize("value,expected", [(False, int), (0, bool), (True, str), ("0", int)])
def test_known_scalar_types_do_not_coerce_bool_integer_or_text(value, expected):
    state = k.Known(value=value, raw=str(value), basis=k.Basis.OBSERVED, evidence=(witness(),))
    with pytest.raises(ValueError, match="^p4_root_mixed_report_value$"):
        records.state_record(state, expected)


@pytest.mark.parametrize("point,expected", [(k.ByteSpan(start=0, end=3), {"kind": "bytes", "start": 0, "end": 3}),
    (k.WholeCapture(), {"kind": "whole_capture"}), (k.FieldPointer(pointer="/data/0"), {"kind": "field", "pointer": "/data/0"}),
    (k.XmlPath(path="/data/item"), {"kind": "xml", "path": "/data/item"})])
def test_evidence_locators_layer_role_and_exact_reference_identity_are_serialized(point, expected):
    ref = witness(locator=point, role=k.EvidenceRole.COUNTER_EVIDENCE)
    assert records.evidence_record(ref, "p2") == {"type": "capture", "layer": "p2", "capture": ref.capture,
        "role": "counter_evidence", "locator": expected, "excerpt_sha256": ref.excerpt_sha256}
    assert records.evidence_record(k.FactRef(fact="l2.stp.root_guard", subject="subject:a"), "p4") == {
        "type": "fact", "fact": "l2.stp.root_guard", "subject": "subject:a"}
    registry = k.RegistryRef(table="synthetic_p2.nodes", row_id="a", table_digest=sha256(REGISTRY).hexdigest(), citation="/nodes/0")
    assert records.evidence_record(registry, "p2") == {"type": "registry", "table": registry.table,
        "row_id": "a", "table_sha256": registry.table_digest, "pointer": "/nodes/0"}


@pytest.mark.parametrize("known_time", [False, True])
def test_full_recorded_capture_metadata_and_legacy_bridge_preserve_scope_time_error_and_evidence(known_time):
    cap = capture()
    scope = Scope(node=cap.source, vrf="blue", context="ctx", vdc="v1", tenant="t", afi="ipv4", instance="i", plane="admin")
    time = TimeInterval(earliest=0, latest=1, clock="collector:synthetic", bound=BoundSource.COLLECTOR_RECORDED) if known_time else unknown()
    metadata = CaptureMetadata(channel=Channel.CLI, scope=scope, collected_utc=time, error=ErrorKind.UNAUTHORIZED,
        integrity_evidence=(witness(),), read_scope_evidence=(witness(role=k.EvidenceRole.WITNESS),), envelope=None)
    cap = replace(cap, metadata=metadata, integrity=k.IntegrityState.ERROR, read_scope=k.ReadScope.LIMITED, view=k.ViewConsistency.CACHED)
    row = records.capture_record(cap, "p4", sha256(RAW).hexdigest())
    assert {name: row[name] for name in ("layer", "id", "raw", "node", "operation", "rendered", "codec")} == {
        "layer": "p4", "id": cap.id, "raw": sha256(RAW).hexdigest(), "node": cap.source, "operation": cap.operation, "rendered": cap.rendered, "codec": "utf-8"}
    assert row["metadata_recorded"] is True and row["integrity"] == "error" and row["read_scope"] == "limited" and row["view"] == "cached"
    assert row["metadata"]["scope"] == {"node": cap.source, "vrf": "blue", "context": "ctx", "vdc": "v1", "tenant": "t", "afi": "ipv4", "instance": "i", "plane": "admin"}
    assert row["metadata"]["channel"] == "cli" and row["metadata"]["error"] == "unauthorized" and row["metadata"]["envelope"] is None
    assert row["metadata"]["integrity_evidence"] == [records.evidence_record(witness(), "p4")]
    assert row["metadata"]["read_scope_evidence"] == [records.evidence_record(witness(role=k.EvidenceRole.WITNESS), "p4")]
    assert row["metadata"]["collected_utc"] == ({"earliest": 0, "latest": 1, "clock": "collector:synthetic", "bound": "collector_recorded"} if known_time else {
        **records.unknown_record(time), "evidence": [records.evidence_record(ref, "p4") for ref in time.evidence]})
    legacy = records.capture_record(capture(), "p2", sha256(RAW).hexdigest())
    assert legacy["metadata_recorded"] is False and legacy["metadata"]["collected_utc"]["reason"] == "as_of_missing"


@pytest.mark.parametrize("plant", ["missing", "extra", "type", "size"])
def test_bundle_verification_requires_exact_names_byte_types_and_independently_counted_sizes(plant):
    files, budget = bundle()
    if plant == "missing":
        files.pop("result.json")
    elif plant == "extra":
        files["unexpected"] = b""
    elif plant == "type":
        files["result.json"] = bytearray(files["result.json"])
    else:
        files["result.json"] += b"x"
    with pytest.raises(ValueError, match="^p4_root_mixed_report_bundle$"):
        records.verify_bundle(files, budget)


def test_raw_payload_dedup_requires_actual_byte_equality_even_when_digest_labels_collide(monkeypatch):
    values = (RAW, bytes(bytearray(RAW)))
    assert records.raw_blobs(values) == {sha256(RAW).hexdigest(): RAW}
    class Digest:
        def hexdigest(self):
            return "0" * 64
    monkeypatch.setattr(records, "sha256", lambda raw: Digest())
    assert records.raw_blobs(values) == {"0" * 64: RAW}
    with pytest.raises(ValueError, match="^p4_root_mixed_report_raw_collision$"):
        records.raw_blobs((*values, RAW + b"x"))


@pytest.mark.parametrize("plant", ["digest", "raw", "canonical"])
def test_registry_ledger_rejects_wrong_registry_bytes_and_conflicting_canonical_value(plant):
    header = {"records": []}
    budget = records.RecordBudget(INPUTS, LIMITS, header)
    blobs, identifiers = records.raw_blobs(INPUTS), {}
    ref = k.RegistryRef(table="synthetic_p2.nodes", row_id="a", table_digest=sha256(REGISTRY).hexdigest(), citation="/nodes/0")
    value = canonical(json.loads(REGISTRY)["nodes"][0])
    assert records.registry_record_id(ref, REGISTRY, value, blobs, identifiers, header["records"], budget) == "registry-0"
    context = replace(ref, table="synthetic_p4.context", row_id="ctx", citation="/context")
    assert records.registry_record_id(context, REGISTRY, canonical("ctx"), blobs, identifiers, header["records"], budget) == "registry-1"
    bad_ref, raw, current = replace(ref, table_digest="0" * 64) if plant == "digest" else ref, REGISTRY, value
    raw = raw + b" " if plant == "raw" else raw
    current = canonical({"id": "neighbor"}) if plant == "canonical" else current
    with pytest.raises(ValueError, match="^p4_root_mixed_report_registry$"):
        records.registry_record_id(bad_ref, raw, current, blobs, identifiers, header["records"], budget)


def test_legacy_capture_metadata_is_resolved_once_per_record(monkeypatch):
    cap, seen = capture(), []
    original = Capture.resolved_metadata.fget
    def resolving(self):
        seen.append(self)
        return original(self)
    monkeypatch.setattr(Capture, "resolved_metadata", property(resolving))
    assert records.capture_record(cap, "p2", sha256(RAW).hexdigest())["id"] == cap.id
    assert seen == [cap]
