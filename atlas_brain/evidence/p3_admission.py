"""Strict P3 sidecar admission after caller-owned whole-folder safety budgets."""
import re
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import (
    AdmissionRefused,
    member_names,
    record,
    strict_json,
    string,
)
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
    Adjacency,
    Endpoint,
    P3Group,
    Sample,
    registry_ref,
)
from atlas_brain.evidence.p3_text import integrity
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import admit_members as admit_base
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval

_SAFE = r"[a-z][a-z0-9_-]{0,31}"
_DISCOVERY = ("iosxe.show_cdp_neighbors_detail", "iosxe.show_lldp_neighbors_detail")


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionRefused("p3_" + code)


def _rows(value: object, maximum: int, minimum: int = 0) -> list[object]:
    _need(type(value) is list, "rows")
    rows = cast(list[object], value)
    _need(minimum <= len(rows) <= maximum, "rows")
    return rows


def _integer(value: object, minimum: int, maximum: int) -> int:
    _need(type(value) is int, "integer")
    number = cast(int, value)
    _need(minimum <= number <= maximum, "integer")
    return number


def _safe(value: str) -> str:
    _need(re.fullmatch(_SAFE, value, re.ASCII) is not None, "identifier")
    return value


def _ipv4(value: str) -> str:
    parts = value.split(".")
    _need(len(parts) == 4 and all(
        1 <= len(part) <= 3 and part.isascii() and part.isdigit()
        and int(part) <= 255 and str(int(part)) == part for part in parts), "ipv4")
    return value


def _time(value: object) -> TimeInterval | None:
    if value is None:
        return None
    row = record(value, ("unit", "clock", "earliest", "latest", "bound"))
    _need(row["unit"] == "unix_us" and row["bound"] == "collector_recorded", "time_unit")
    clock = string(row, "clock")
    _need(re.fullmatch(r"collector:[A-Za-z0-9_.:/-]{1,64}", clock, re.ASCII) is not None, "clock")
    earliest, latest = (_integer(row[name], 0, 9007199254740991) for name in ("earliest", "latest"))
    _need(earliest <= latest, "time_order")
    return TimeInterval(earliest=earliest, latest=latest, clock=clock, bound=BoundSource.COLLECTOR_RECORDED)


def admit_members(members: dict[str, bytes]) -> P3Group:
    """Never expose a subset: names, identities and exact partition must all pass."""
    member_names(list(members))
    _need("p2.json" in members and "p3.json" in members, "missing_manifest")
    raw, base_raw = members["p3.json"], members["p2.json"]
    manifest = record(strict_json(raw), ("schema", "semantic_group", "base_sha256", "adjacencies", "samples"))
    _need(manifest["schema"] == SCHEMA and manifest["semantic_group"] == "declared_synthetic", "schema")
    base_digest, digest = sha256(base_raw).hexdigest(), sha256(raw).hexdigest()
    _need(string(manifest, "base_sha256") == base_digest, "base_hash")
    base_manifest = record(strict_json(base_raw), ("schema", "semantic_group", "group", "nodes", "captures"))
    _need(base_manifest["schema"] == BASE_SCHEMA, "base_schema")
    base_paths: set[str] = {"p2.json"}
    for value in _rows(base_manifest["captures"], 64, 1):
        row = record(value, ("path", "node", "operation", "sha256"))
        path = string(row, "path")
        _need(string(row, "operation") in _DISCOVERY, "base_operation")
        _need(path not in base_paths and path != "p3.json" and path in members, "base_member")
        base_paths.add(path)
    base = admit_base({path: members[path] for path in base_paths})
    nodes = {node.id: node for node in base.nodes}
    scopes: dict[str, tuple[int, str, str]] = {}
    used_endpoints: set[tuple[str, str]] = set()

    def declared(table: str, identifier: str, index: int) -> k.Known[str]:
        return k.Known(value=identifier, basis=k.Basis.DECLARED, raw=identifier,
                       evidence=(registry_ref(raw, table, identifier, index),))

    def point(value: object) -> Endpoint:
        row = record(value, ("node", "port", "process", "router_id", "address", "vrf"))
        node, port = string(row, "node"), string(row, "port")
        _need(node in nodes and port in nodes[node].ports, "endpoint")
        _need((node, port) not in used_endpoints, "duplicate_endpoint")
        process = _integer(row["process"], 1, 65535)
        router_id, address = _ipv4(string(row, "router_id")), _ipv4(string(row, "address"))
        vrf = string(row, "vrf")
        _need(vrf == "default", "vrf")
        scope = (process, router_id, vrf)
        _need(node not in scopes or scopes[node] == scope, "node_scope")
        scopes[node] = scope
        used_endpoints.add((node, port))
        return Endpoint(node=nodes[node], port=port, process=process, router_id=router_id, address=address, vrf=vrf)

    adjacencies: list[Adjacency] = []
    identifiers: set[str] = set()
    for index, value in enumerate(_rows(manifest["adjacencies"], 16, 1)):
        row = record(value, ("id", "domain", "area", "left", "right"))
        identifier, domain = _safe(string(row, "id")), _safe(string(row, "domain"))
        _need(identifier not in identifiers, "duplicate_adjacency")
        left, right = point(row["left"]), point(row["right"])
        _need(left.node.key != right.node.key, "self_adjacency")
        adjacencies.append(Adjacency(id=identifier, domain=domain,
            area=_integer(row["area"], 0, 4294967295), left=left, right=right,
            declaration=declared("adjacencies", identifier, index)))
        identifiers.add(identifier)

    samples: list[Sample] = []
    sample_ids: set[str] = set()
    paths: set[str] = set()
    for index, value in enumerate(_rows(manifest["samples"], 16)):
        row = record(value, ("id", "time", "captures"))
        identifier, collected = _safe(string(row, "id")), _time(row["time"])
        _need(identifier not in sample_ids, "duplicate_sample")
        references: set[tuple[str, str]] = set()
        captures: list[Capture] = []
        for item in _rows(row["captures"], 64):
            ref = record(item, ("path", "node", "operation", "sha256"))
            path, node, operation, expected = (string(ref, name) for name in ("path", "node", "operation", "sha256"))
            member_names([path])
            _need(node in scopes and operation in OPERATIONS, "capture_reference")
            _need(path not in base_paths | paths | {"p3.json"} and path in members, "capture_member")
            _need((node, operation) not in references, "duplicate_capture")
            content = members[path]
            _need(expected == sha256(content).hexdigest(), "capture_hash")
            state = integrity(content, operation)
            identity = sha256(canonical((SCHEMA, digest, base_digest, identifier, node, path, operation, expected))).hexdigest()
            capture_id = k.CaptureId("cap:" + identity)
            witness = k.EvidenceRef(capture=capture_id, locator=k.WholeCapture(),
                                     role=k.EvidenceRole.SUBJECT, excerpt_sha256=expected)
            metadata = CaptureMetadata(channel=Channel.CLI,
                scope=Scope(node=nodes[node].key, vrf="default", context=None, vdc=None, tenant=None,
                            afi=None, instance=str(scopes[node][0]), plane="exec"),
                collected_utc=collected if collected is not None else unrecorded_time(witness),
                error=None, integrity_evidence=(witness,), read_scope_evidence=(), envelope=None)
            captures.append(Capture(id=capture_id, source=nodes[node].key, operation=operation,
                rendered=OPERATIONS[operation], codec="utf-8", raw=content, integrity=state,
                lines=text_lines(content, "utf-8"), read_scope=k.ReadScope.UNKNOWN,
                view=k.ViewConsistency.UNKNOWN, metadata=metadata))
            paths.add(path)
            references.add((node, operation))
            _need(len(paths) <= 64, "capture_budget")
        samples.append(Sample(id=identifier, time=collected, captures=tuple(sorted(captures, key=lambda c: c.id)),
                              declaration=declared("samples", identifier, index)))
        sample_ids.add(identifier)
    _need(set(members) == base_paths | paths | {"p3.json"}, "unlisted_member")
    return P3Group(base=base, raw=raw, adjacencies=tuple(sorted(adjacencies, key=lambda a: a.id)),
                   samples=tuple(sorted(samples, key=lambda s: s.id)))
