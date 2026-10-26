"""Bounded P3 registry and capture custody, independent of parser truth."""
import re
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import member_names, record, strict_json
from atlas_brain.evidence.capture import (
    Capture,
    CaptureMetadata,
    Channel,
    Scope,
    unrecorded_time,
)
from atlas_brain.evidence.p3_records import (
    OPERATIONS,
    SCHEMA,
    Endpoint,
    P3Group,
    Sample,
    registry_ref,
)
from atlas_brain.evidence.p3_text import integrity
from atlas_brain.evidence.synthetic import OPERATIONS as BASE_OPERATIONS
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.model.store import FactReader
from atlas_brain.runner import p2_evidence
from atlas_brain.runner.records import RunnerRefused

DISCOVERY = ("iosxe.show_cdp_neighbors_detail", "iosxe.show_lldp_neighbors_detail")
COMMANDS = {op: BASE_OPERATIONS[op] for op in DISCOVERY} | OPERATIONS


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p3_evidence_" + code)


def _point(point: Endpoint) -> dict[str, object]:
    return {"node": point.node.id, "port": point.port, "process": point.process,
            "router_id": point.router_id, "address": point.address, "vrf": point.vrf}


def _time(sample: Sample) -> dict[str, object] | None:
    value = sample.time
    if value is None:
        return None
    _need(type(value) is TimeInterval and value.bound is BoundSource.COLLECTOR_RECORDED, "time")
    _need(re.fullmatch(r"collector:[A-Za-z0-9_.:/-]{1,64}", value.clock, re.ASCII) is not None, "clock")
    _need(type(value.earliest) is int and type(value.latest) is int
          and 0 <= value.earliest <= value.latest <= 9007199254740991, "time")
    return {"unit": "unix_us", "clock": value.clock, "earliest": value.earliest,
            "latest": value.latest, "bound": str(value.bound)}


class RefResolver:
    """Validate registry-object agreement once; hash raw captures only when cited."""

    def __init__(self, group: P3Group, reader: FactReader) -> None:
        self.group, self.reader = group, reader
        self.registry: dict[k.RegistryRef, object] = {}
        self.captures: dict[str, tuple[Sample, Capture, dict[str, object]]] = {}
        self.points: dict[str, Endpoint] = {}
        self.base_ids = {str(c.id) for c in group.base.captures}
        try:
            self._registry()
        except RunnerRefused:
            raise
        except (ValueError, TypeError, UnicodeError, KeyError, AttributeError) as error:
            raise RunnerRefused("p3_evidence_registry") from error

    def _registry(self) -> None:
        group = self.group
        raw = record(strict_json(group.raw), ("schema", "semantic_group", "base_sha256", "adjacencies", "samples"))
        digest, base_digest = sha256(group.raw).hexdigest(), sha256(group.base.raw).hexdigest()
        _need(raw["schema"] == SCHEMA and raw["semantic_group"] == "declared_synthetic"
              and raw["base_sha256"] == base_digest and group.base.schema == BASE_SCHEMA, "registry_group")
        base = record(strict_json(group.base.raw), ("schema", "semantic_group", "group", "nodes", "captures"))
        _need(base["schema"] == BASE_SCHEMA and type(base["captures"]) is list, "base")
        _need(len(self.base_ids) == len(group.base.captures)
              and all(c.operation in DISCOVERY for c in group.base.captures), "base")
        base_ref = k.RegistryRef(table="synthetic_p2.groups", row_id=group.base.id,
                                 table_digest=base_digest, citation="/group")
        p2_evidence.resolve_evidence(group.base, self.reader, (base_ref,))
        paths = ["p2.json", "p3.json"]
        for value in cast(list[object], base["captures"]):
            row = record(value, ("path", "node", "operation", "sha256"))
            _need(type(row["path"]) is str and row["operation"] in DISCOVERY, "base")
            paths.append(cast(str, row["path"]))
        for table, objects in (("adjacencies", group.adjacencies), ("samples", group.samples)):
            rows = raw[table]
            _need(type(rows) is list, "registry_rows")
            by_id = {item.id: item for item in objects}
            _need(len(by_id) == len(objects) == len(cast(list[object], rows)), "registry_rows")
            seen: set[str] = set()
            for index, value in enumerate(cast(list[object], rows)):
                fields = ("id", "domain", "area", "left", "right") if table == "adjacencies" else ("id", "time", "captures")
                row = record(value, fields)
                identifier = row["id"]
                _need(type(identifier) is str and identifier in by_id and identifier not in seen, "registry_row")
                item = by_id[cast(str, identifier)]
                ref = registry_ref(group.raw, table, item.id, index)
                expected = k.Known(value=item.id, basis=k.Basis.DECLARED, evidence=(ref,), raw=item.id)
                _need(item.declaration == expected, "declaration")
                self.registry[ref] = row
                seen.add(item.id)
        for adjacency in group.adjacencies:
            row = self.registry[cast(k.RegistryRef, adjacency.declaration.evidence[0])]
            expected_row = {"id": adjacency.id, "domain": adjacency.domain, "area": adjacency.area,
                            "left": _point(adjacency.left), "right": _point(adjacency.right)}
            _need(canonical(row) == canonical(expected_row), "adjacency")
            for point in (adjacency.left, adjacency.right):
                _need(point.node in group.base.nodes and point.port in point.node.ports, "endpoint")
                other = self.points.get(str(point.node.key))
                _need(other is None or (other.process, other.router_id, other.vrf)
                      == (point.process, point.router_id, point.vrf), "node_scope")
                self.points[str(point.node.key)] = point
        for sample in group.samples:
            row = cast(dict[str, object], self.registry[cast(k.RegistryRef, sample.declaration.evidence[0])])
            _need(canonical(row["time"]) == canonical(_time(sample)) and type(row["captures"]) is list, "sample")
            captures = {str(c.id): c for c in sample.captures}
            _need(len(captures) == len(sample.captures) == len(cast(list[object], row["captures"])), "sample")
            for value in cast(list[object], row["captures"]):
                capture_row = record(value, ("path", "node", "operation", "sha256"))
                _need(all(type(v) is str for v in capture_row.values()), "capture_registry")
                node, path, operation, expected_hash = (capture_row[name] for name in ("node", "path", "operation", "sha256"))
                identity = "cap:" + sha256(canonical((SCHEMA, digest, base_digest, sample.id,
                                                      node, path, operation, expected_hash))).hexdigest()
                _need(identity in captures and identity not in self.captures and identity not in self.base_ids, "capture_registry")
                capture = captures[identity]
                _need(operation in OPERATIONS and any(p.node.id == node for p in self.points.values()), "capture_registry")
                self.captures[identity] = (sample, capture, capture_row)
                paths.append(cast(str, path))
        member_names(paths)

    def resolve(self, ref: k.EvidenceRef | k.RegistryRef) -> dict[str, object]:
        try:
            if isinstance(ref, k.RegistryRef):
                if ref.table in ("synthetic_p2.groups", "synthetic_p2.nodes"):
                    return p2_evidence.resolve_evidence(self.group.base, self.reader, (ref,))[0]
                _need(ref in self.registry, "registry_reference")
                return {"kind": "registry", "table": ref.table, "row_id": ref.row_id,
                        "table_digest": ref.table_digest, "citation": ref.citation, "value": self.registry[ref]}
            _need(type(ref) is k.EvidenceRef, "reference")
            if str(ref.capture) in self.base_ids:
                return p2_evidence.resolve_evidence(self.group.base, self.reader, (ref,))[0]
            return self._capture(ref)
        except RunnerRefused:
            raise
        except (ValueError, TypeError, UnicodeError, KeyError, AttributeError) as error:
            raise RunnerRefused("p3_evidence_reference") from error

    def _capture(self, ref: k.EvidenceRef) -> dict[str, object]:
        _need(str(ref.capture) in self.captures, "missing_capture")
        sample, capture, row = self.captures[str(ref.capture)]
        point = next((p for p in self.points.values() if p.node.id == row["node"]), None)
        _need(point is not None, "capture_source")
        if point is None:
            raise RunnerRefused("p3_evidence_capture_source")
        operation = cast(str, row["operation"])
        _need(capture.source == point.node.key and capture.operation == operation
              and capture.rendered == OPERATIONS[operation] and capture.codec == "utf-8", "capture_source")
        _need(capture.bytes_sha256 == row["sha256"] and capture.integrity is integrity(capture.raw, operation)
              and capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN, "capture_hash")
        witness = k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(),
                                 role=k.EvidenceRole.SUBJECT, excerpt_sha256=capture.bytes_sha256)
        expected = CaptureMetadata(channel=Channel.CLI,
            scope=Scope(node=point.node.key, vrf="default", context=None, vdc=None, tenant=None,
                        afi=None, instance=str(point.process), plane="exec"),
            collected_utc=sample.time if sample.time is not None else unrecorded_time(witness),
            error=None, integrity_evidence=(witness,), read_scope_evidence=(), envelope=None)
        _need(capture.metadata == expected, "capture_metadata")
        result: dict[str, object] = {"kind": "capture", "capture": str(capture.id), "sample": sample.id,
            "source": str(capture.source), "path": row["path"], "operation": operation,
            "rendered": OPERATIONS[operation], "role": str(ref.role), "sha256": ref.excerpt_sha256,
            "capture_sha256": capture.bytes_sha256, "integrity": str(capture.integrity),
            "read_scope": str(capture.read_scope), "view": str(capture.view), "collected_utc": _time(sample)}
        if type(ref.locator) is k.ByteSpan:
            _need(ref.locator.end <= capture.byte_len, "capture_bounds")
            excerpt = capture.raw[ref.locator.start:ref.locator.end]
            result.update(locator="bytes", start=ref.locator.start, end=ref.locator.end)
        elif type(ref.locator) is k.WholeCapture:
            excerpt = capture.raw
            result["locator"] = "whole_capture"
        else:
            raise RunnerRefused("p3_evidence_capture_locator")
        _need(sha256(excerpt).hexdigest() == ref.excerpt_sha256, "capture_hash")
        return result

    def need(self, need: k.EvidenceNeed) -> dict[str, object]:
        operation = next((op for op, command in COMMANDS.items() if need.operation in (op, command)), None)
        _need(operation is not None and need.params == (), "need_operation")
        if operation is None:
            raise RunnerRefused("p3_evidence_need_operation")
        nodes = {node.key for node in self.group.base.nodes} if operation in DISCOVERY else set(self.points)
        _need(need.node in nodes, "need_node")
        return {"node": str(need.node), "operation": operation, "rendered": COMMANDS[operation], "params": [],
                "resolves": list(need.resolves), "reruns": list(need.reruns),
                "after_s": need.after_s, "unprintable": list(need.unprintable)}
