"""Checked P2 lineage. Groups must come from synthetic.admit_members."""
import re
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import record, strict_json
from atlas_brain.evidence.capture import Capture, Channel
from atlas_brain.evidence.synthetic import OPERATIONS, SCHEMA, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, StoredState
from atlas_brain.runner.records import RunnerRefused


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p2_evidence_" + code)


def _operation(value: str | None) -> str:
    for operation, rendered in OPERATIONS.items():
        if value in (operation, rendered):
            return operation
    raise RunnerRefused("p2_evidence_operation")


def _manifest(group: SyntheticGroup) -> dict[str, object]:
    try:
        manifest = record(strict_json(group.raw), ("schema", "semantic_group", "group", "nodes", "captures"))
    except ValueError as error:
        raise RunnerRefused("p2_evidence_registry_json") from error
    _need(manifest["schema"] == SCHEMA and manifest["semantic_group"] == "declared_synthetic"
          and manifest["group"] == group.id, "registry_group")
    return manifest


def _capture(group: SyntheticGroup, ref: k.EvidenceRef) -> dict[str, object]:
    identities = tuple(capture.id for capture in group.captures)
    _need(len(identities) == len(set(identities)), "duplicate_capture")
    matches = tuple(capture for capture in group.captures if capture.id == ref.capture)
    _need(len(matches) == 1, "missing_capture")
    capture: Capture = matches[0]
    nodes = tuple(node for node in group.nodes if node.key == capture.source)
    _need(len(nodes) == 1 and capture.channel is Channel.CLI, "capture_source")
    operation = _operation(capture.operation)
    _need(capture.rendered == OPERATIONS[operation], "operation")
    rows = _manifest(group)["captures"]
    _need(type(rows) is list, "capture_registry")
    paths: list[str] = []
    for value in cast(list[object], rows):
        try:
            row = record(value, ("path", "node", "operation", "sha256"))
        except ValueError as error:
            raise RunnerRefused("p2_evidence_capture_registry") from error
        _need(all(type(value) is str for value in row.values()), "capture_registry")
        identity = sha256(canonical((SCHEMA, group.id, sha256(group.raw).hexdigest(), row["path"],
                                    row["node"], row["operation"], row["sha256"]))).hexdigest()
        if (row["node"] == nodes[0].id and row["operation"] == operation
                and row["sha256"] == capture.bytes_sha256 and capture.id == "cap:" + identity):
            paths.append(cast(str, row["path"]))
    _need(len(paths) == 1, "capture_registry")
    result: dict[str, object] = {
        "kind": "capture", "capture": str(capture.id), "source": str(capture.source), "path": paths[0],
        "operation": operation, "rendered": OPERATIONS[operation], "role": str(ref.role),
        "sha256": ref.excerpt_sha256, "capture_sha256": capture.bytes_sha256,
        "integrity": str(capture.integrity), "read_scope": str(capture.read_scope), "view": str(capture.view),
    }
    if isinstance(ref.locator, k.ByteSpan):
        _need(ref.locator.end <= capture.byte_len, "capture_bounds")
        excerpt = capture.raw[ref.locator.start:ref.locator.end]
        result.update(locator="bytes", start=ref.locator.start, end=ref.locator.end)
    elif isinstance(ref.locator, k.WholeCapture):
        excerpt = capture.raw
        result["locator"] = "whole_capture"
    else:
        raise RunnerRefused("p2_evidence_capture_locator")
    _need(sha256(excerpt).hexdigest() == ref.excerpt_sha256, "capture_hash")
    return result


def _registry(group: SyntheticGroup, ref: k.RegistryRef) -> dict[str, object]:
    _need(ref.table_digest == sha256(group.raw).hexdigest(), "registry_hash")
    manifest = _manifest(group)
    _need(type(manifest["nodes"]) is list, "registry_nodes")
    rows = cast(list[object], manifest["nodes"])
    admitted = {node.id: node for node in group.nodes}
    _need(len(admitted) == len(group.nodes) == len(rows), "registry_nodes")
    selected: object = None
    seen: set[str] = set()
    for index, value in enumerate(rows):
        try:
            row = record(value, ("id", "discovery_id", "ports"))
        except ValueError as error:
            raise RunnerRefused("p2_evidence_registry_nodes") from error
        _need(type(row["id"]) is str and type(row["discovery_id"]) is str
              and type(row["ports"]) is list, "registry_nodes")
        identifier = cast(str, row["id"])
        ports = cast(list[object], row["ports"])
        _need(all(type(port) is str for port in ports), "registry_nodes")
        names = cast(list[str], ports)
        _need(identifier in admitted and identifier not in seen, "registry_nodes")
        node = admitted[identifier]
        _need(node.group == group.id and node.discovery_id == row["discovery_id"]
              and len(names) == len(set(names)) and tuple(sorted(names)) == node.ports, "registry_nodes")
        seen.add(identifier)
        if ref.citation == f"/nodes/{index}" and ref.row_id == identifier:
            selected = row
    if ref.table == "synthetic_p2.groups":
        _need(ref.row_id == group.id and ref.citation == "/group", "registry_row")
        selected = group.id
    else:
        _need(ref.table == "synthetic_p2.nodes" and re.fullmatch(r"/nodes/(0|[1-9][0-9]*)",
              ref.citation, re.ASCII) is not None and selected is not None, "registry_row")
    return {"kind": "registry", "table": ref.table, "row_id": ref.row_id,
            "table_digest": ref.table_digest, "citation": ref.citation, "value": selected}


def _value(value: object, depth: int = 0) -> object:
    _need(depth <= 32, "value_depth")
    if type(value) is tuple:
        return [_value(item, depth + 1) for item in cast(tuple[object, ...], value)]
    _need(type(value) in (str, int, bool), "value")
    try:
        canonical(value)
    except (TypeError, ValueError, UnicodeError) as error:
        raise RunnerRefused("p2_evidence_value") from error
    return value


def _next(group: SyntheticGroup, need: k.EvidenceNeed) -> dict[str, object]:
    _need(need.node in tuple(node.key for node in group.nodes), "need_node")
    _need(need.params == (), "need_params")
    operation = _operation(need.operation)
    return {"node": str(need.node), "operation": operation, "rendered": OPERATIONS[operation],
            "params": [], "resolves": list(need.resolves), "reruns": list(need.reruns),
            "after_s": need.after_s, "unprintable": list(need.unprintable)}


def _project(group: SyntheticGroup, reader: FactReader, state: StoredState,
             chain: tuple[k.FactRef, ...]) -> dict[str, object]:
    _need(type(state) in (k.Known, k.Unknown), "state")
    result: dict[str, object] = {"evidence": _resolve(group, reader, state.evidence, chain)}
    if isinstance(state, k.Known):
        result.update(state="known", basis=str(state.basis), value=_value(state.value), raw=state.raw)
    elif isinstance(state, k.Unknown):
        result.update(state="unknown", reason=str(state.reason), detail=state.detail,
                      candidates=list(state.candidates), next_evidence=[_next(group, need) for need in state.next_evidence])
    return result


def _resolve(group: SyntheticGroup, reader: FactReader, evidence: tuple[k.Evidence, ...],
             chain: tuple[k.FactRef, ...]) -> list[dict[str, object]]:
    _need(len(chain) <= 32, "fact_depth")
    records: dict[bytes, dict[str, object]] = {}
    subjects = {endpoint(node, port) for node in group.nodes for port in node.ports}
    for ref in evidence:
        if isinstance(ref, k.EvidenceRef):
            projected = _capture(group, ref)
        elif isinstance(ref, k.RegistryRef):
            projected = _registry(group, ref)
        elif isinstance(ref, k.FactRef):
            _need(ref.subject in subjects, "fact_subject")
            _need(ref not in chain, "fact_cycle")
            try:
                state = reader.read(fact=ref.fact, subject=ref.subject)
            except ValueError as error:
                raise RunnerRefused("p2_evidence_fact_unreadable") from error
            projected = {"kind": "fact", "fact": str(ref.fact), "subject": str(ref.subject),
                         "state": _project(group, reader, state, chain + (ref,))}
        else:
            raise RunnerRefused("p2_evidence_reference")
        records[canonical(projected)] = projected
    return [records[key] for key in sorted(records)]


def resolve_evidence(group: SyntheticGroup, reader: FactReader,
                     evidence: tuple[k.Evidence, ...]) -> list[dict[str, object]]:
    """Validate and retain every reference edge; return stable unique records."""
    return _resolve(group, reader, evidence, ())


def project_fact(group: SyntheticGroup, reader: FactReader, state: StoredState) -> dict[str, object]:
    """Project a P2 state without reading a store map or deriving a new fact."""
    return _project(group, reader, state, ())


def project_needs(group: SyntheticGroup, needs: tuple[k.EvidenceNeed, ...]) -> list[dict[str, object]]:
    return [_next(group, need) for need in needs]
