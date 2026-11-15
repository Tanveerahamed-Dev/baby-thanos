"""Trusted Root9 hex wire formatting only; no admission, Reader, origin, coverage or health authority."""
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import TimeInterval

SCHEMA = "atlas-brain.p4-root-mixed-observations/1"
KINDS = ("stp_port_vlan", "etherchannel_group", "fhrp_local")
NAMES = ("result.json", *(f"facts/{kind}.jsonl" for kind in KINDS), "MANIFEST.sha256")
type ScalarState = k.Known[bool] | k.Known[int] | k.Known[str] | k.Unknown


def _need(condition: bool, code: str) -> None:
    k.require(condition, "p4_root_mixed_report_" + code)


class RecordBudget:
    def __init__(self, inputs: tuple[bytes, ...], limits: tuple[int, ...], header: dict[str, object]) -> None:
        self.limits, self.input_bytes = limits, sum(map(len, inputs))
        self.sizes = {name: 0 for name in NAMES}
        if len(inputs) + len(NAMES) > limits[2] or any(len(raw) > limits[1] for raw in inputs):
            raise BudgetExceeded("p4_root_mixed_observations_outputs")
        self.add("MANIFEST.sha256", sum(67 + len(name) for name in NAMES if name != "MANIFEST.sha256"))
        self.add("result.json", len(canonical(header)))

    def add(self, name: str, count: int) -> None:
        size = self.sizes[name] + count
        if size > self.limits[1] or self.input_bytes + sum(self.sizes.values()) + count > self.limits[0]:
            raise BudgetExceeded("p4_root_mixed_observations_outputs")
        self.sizes[name] = size


def append_record(table: list[dict[str, object]], row: dict[str, object], budget: RecordBudget,
    payload: tuple[str, bytes] | None = None,
) -> None:
    size = len(canonical(row))
    if payload is not None:
        name, raw = payload
        _need(name not in row, "value")
        size += len(canonical(name)) + 3 + 2 * len(raw) + int(bool(row))
    budget.add("result.json", size + int(bool(table)))
    if payload is not None:
        row[payload[0]] = payload[1].hex()
    table.append(row)


def evidence_record(ref: k.Evidence, layer: str) -> dict[str, object]:
    if isinstance(ref, k.RegistryRef):
        return {"type": "registry", "table": ref.table, "row_id": ref.row_id,
            "table_sha256": ref.table_digest, "pointer": ref.citation}
    if isinstance(ref, k.FactRef):
        return {"type": "fact", "fact": ref.fact, "subject": ref.subject}
    point = ref.locator
    locator: dict[str, object]
    if isinstance(point, k.ByteSpan):
        locator = {"kind": "bytes", "start": point.start, "end": point.end}
    elif isinstance(point, k.WholeCapture):
        locator = {"kind": "whole_capture"}
    elif isinstance(point, k.FieldPointer):
        locator = {"kind": "field", "pointer": point.pointer}
    else:
        locator = {"kind": "xml", "path": point.path}
    return {"type": "capture", "layer": layer, "capture": ref.capture, "role": str(ref.role),
        "locator": locator, "excerpt_sha256": ref.excerpt_sha256}


def unknown_record(value: k.Unknown) -> dict[str, object]:
    return {"state": "unknown", "reason": str(value.reason), "detail": value.detail,
        "candidates": value.candidates, "next_evidence": [
            {"node": need.node, "operation": need.operation, "params": need.params,
                "resolves": need.resolves, "reruns": need.reruns, "after_s": need.after_s,
                "unprintable": need.unprintable} for need in value.next_evidence]}


def capture_record(capture: Capture, layer: str, digest: str) -> dict[str, object]:
    metadata = capture.resolved_metadata
    scope, collected = metadata.scope, metadata.collected_utc
    time = ({"earliest": collected.earliest, "latest": collected.latest, "clock": collected.clock,
        "bound": str(collected.bound)} if isinstance(collected, TimeInterval) else
        {**unknown_record(collected), "evidence": [evidence_record(ref, layer) for ref in collected.evidence]})
    return {"layer": layer, "id": capture.id, "raw": digest, "node": capture.source,
        "operation": capture.operation, "rendered": capture.rendered, "codec": capture.codec,
        "integrity": str(capture.integrity), "read_scope": str(capture.read_scope), "view": str(capture.view),
        "metadata_recorded": capture.metadata is not None, "metadata": {"channel": str(metadata.channel),
            "scope": {"node": scope.node, "vrf": scope.vrf, "context": scope.context, "vdc": scope.vdc,
                "tenant": scope.tenant, "afi": scope.afi, "instance": scope.instance, "plane": scope.plane},
            "collected_utc": time, "error": None if metadata.error is None else str(metadata.error),
            "integrity_evidence": [evidence_record(ref, layer) for ref in metadata.integrity_evidence],
            "read_scope_evidence": [evidence_record(ref, layer) for ref in metadata.read_scope_evidence], "envelope": None}}


def state_record(value: ScalarState, expected: type[bool | int | str]) -> dict[str, object]:
    if isinstance(value, k.Known):
        _need(type(value.value) is expected, "value")
        return {"state": "known", "basis": str(value.basis), "value": value.value, "raw": value.raw}
    return unknown_record(value)


def raw_blobs(inputs: tuple[bytes, ...]) -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    for raw in inputs:
        digest = sha256(raw).hexdigest()
        _need(digest not in blobs or blobs[digest] == raw, "raw_collision")
        blobs[digest] = raw
    return blobs


def registry_record_id(ref: k.RegistryRef, raw: bytes, value: bytes, blobs: dict[str, bytes],
    identifiers: dict[k.RegistryRef, tuple[str, bytes]], table: list[dict[str, object]], budget: RecordBudget,
) -> str:
    _need(ref.table_digest in blobs and blobs[ref.table_digest] == raw, "registry")
    if ref not in identifiers:
        identifier = "registry-" + str(len(identifiers))
        identifiers[ref] = identifier, value
        append_record(table, {"id": identifier, "table": ref.table, "row_id": ref.row_id,
            "table_sha256": ref.table_digest, "pointer": ref.citation, "raw": ref.table_digest,
            "encoding": "hex"}, budget, ("canonical", value))
    _need(identifiers[ref][1] == value, "registry")
    return identifiers[ref][0]


def verify_bundle(files: dict[str, bytes], budget: RecordBudget) -> None:
    _need(set(files) == set(NAMES) and all(type(raw) is bytes and len(raw) == budget.sizes[name]
        for name, raw in files.items()), "bundle")
