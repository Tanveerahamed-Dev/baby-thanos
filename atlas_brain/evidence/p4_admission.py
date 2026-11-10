"""Admit declared P4 targets and raw members before any pack-specific interpretation."""
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import (
    AdmissionRefused,
    BudgetExceeded,
    Budgets,
    folder_members,
    member_names,
    record,
    strict_json,
    string,
)
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.evidence.synthetic import admit_members as admit_base
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration, compile_packs
from atlas_brain.model.specs import StepId

SCHEMA = "atlas-brain.synthetic-p4/1"
MAX_TARGETS = 128
MAX_CAPTURES = 128
_RESERVED = ("p2.json", "p3.json", "p4.json", "manifest.json")
_DISCOVERY = ("iosxe.show_cdp_neighbors_detail", "iosxe.show_lldp_neighbors_detail")


@dataclass(frozen=True, slots=True, kw_only=True)
class Target:
    id: str
    node: Node
    operation: str
    owner: StepId
    params: bytes
    declaration: k.Known[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class CaptureMember:
    id: k.CaptureId
    target: Target
    path: str
    raw: bytes
    sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Envelope:
    raw: bytes
    base: SyntheticGroup
    context: str
    declaration: k.Known[str]
    registration_sha256: str
    targets: tuple[Target, ...]
    captures: tuple[CaptureMember, ...]


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionRefused("p4_" + code)


def _rows(value: object, minimum: int, maximum: int, code: str) -> list[object]:
    _need(type(value) is list, code)
    rows = cast(list[object], value)
    _need(minimum <= len(rows) <= maximum, code)
    return rows


def _identifier(value: str) -> str:
    _need(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value, re.ASCII) is not None, "identifier")
    return value


def _params(value: object) -> bytes:
    _need(type(value) is dict, "params")
    params = cast(dict[str, object], value)
    _need(len(params) <= 32, "params")
    try:
        return canonical(params)
    except (TypeError, ValueError, RecursionError) as error:
        raise AdmissionRefused("p4_params") from error


def _claim(path: str, digest: str, members: dict[str, bytes], claimed: set[str]) -> None:
    _need(path in members, "missing_member")
    _need(path.casefold() not in _RESERVED, "reserved_member")
    member_names([path])
    try:
        path.encode("utf-8")
    except UnicodeError as error:
        raise AdmissionRefused("p4_member_encoding") from error
    _need(path not in claimed, "duplicate_member")
    _need(sha256(members[path]).hexdigest() == digest, "capture_hash")
    claimed.add(path)


def admit_folder(root: Path, budgets: Budgets, *, declarations: tuple[PackDeclaration, ...]) -> Envelope:
    """Pin both registries and partition every member before admitting the discovery subset."""
    members = folder_members(root, budgets)
    if sum(len(raw) for raw in members.values()) > budgets.bundle_bytes:
        raise BudgetExceeded("bundle")
    _need("p2.json" in members and "p4.json" in members, "missing_manifest")
    raw, base_raw = members["p4.json"], members["p2.json"]
    base_digest, registry_digest = sha256(base_raw).hexdigest(), sha256(raw).hexdigest()
    manifest = record(strict_json(raw, budgets.nesting_depth, budgets.numeric_digits, "p4.json"),
                      ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    _need(manifest["schema"] == SCHEMA and manifest["semantic_group"] == "declared_synthetic", "schema")
    _need(string(manifest, "base_sha256") == base_digest, "base_hash")
    context = _identifier(string(manifest, "context"))
    registry = record(strict_json(base_raw, budgets.nesting_depth, budgets.numeric_digits, "p2.json"),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
    _need(registry["schema"] == BASE_SCHEMA and registry["semantic_group"] == "declared_synthetic", "base_schema")
    node_ids: set[str] = set()
    for value in _rows(registry["nodes"], 1, 32, "base_nodes"):
        node_id = _identifier(string(record(value, ("id", "discovery_id", "ports")), "id"))
        _need(node_id not in node_ids, "base_duplicate")
        node_ids.add(node_id)
    claimed: set[str] = set()
    discovery: set[tuple[str, str]] = set()
    for value in _rows(registry["captures"], 1, 64, "base_captures"):
        row = record(value, ("path", "node", "operation", "sha256"))
        node_id, operation = string(row, "node"), string(row, "operation")
        _need(node_id in node_ids, "base_node")
        _need(operation in _DISCOVERY, "base_operation")
        _need((node_id, operation) not in discovery, "base_duplicate")
        _claim(string(row, "path"), string(row, "sha256"), members, claimed)
        discovery.add((node_id, operation))
    base_members = {"p2.json": base_raw} | {path: members[path] for path in claimed}

    compiled = compile_packs(declarations)
    owners = {binding.operation: binding.step for binding in compiled.operations}
    target_rows: dict[str, tuple[str, str, bytes, int]] = {}
    definitions: set[tuple[str, str, bytes]] = set()
    for index, value in enumerate(_rows(manifest["targets"], 1, MAX_TARGETS, "targets")):
        row = record(value, ("id", "node", "operation", "params"))
        identifier = _identifier(string(row, "id"))
        node_id, operation = string(row, "node"), string(row, "operation")
        _need(identifier not in target_rows, "duplicate_target")
        _need(node_id in node_ids, "target_node")
        _need(operation in owners, "target_operation")
        definition = (node_id, operation, _params(row["params"]))
        _need(definition not in definitions, "duplicate_target_definition")
        definitions.add(definition)
        target_rows[identifier] = (*definition, index)

    capture_rows: dict[str, tuple[str, str, k.CaptureId]] = {}
    for value in _rows(manifest["captures"], 0, MAX_CAPTURES, "captures"):
        row = record(value, ("target", "path", "sha256"))
        target_id, path, digest = string(row, "target"), string(row, "path"), string(row, "sha256")
        _need(target_id in target_rows, "capture_target")
        _claim(path, digest, members, claimed)
        identity = canonical((SCHEMA, registry_digest, base_digest, context, target_id, path,
                              digest, compiled.registration_sha256))
        capture_rows[path] = (target_id, digest, k.CaptureId("cap:" + sha256(identity).hexdigest()))
    _need(len({capture_id for _, _, capture_id in capture_rows.values()}) == len(capture_rows), "duplicate_capture_id")
    _need(set(members) == claimed | {"p2.json", "p4.json"}, "unlisted_member")

    base = admit_base(base_members)
    nodes = {node.id: node for node in base.nodes}
    targets: dict[str, Target] = {}
    for identifier in sorted(target_rows):
        node_id, operation, params, index = target_rows[identifier]
        ref = k.RegistryRef(table="synthetic_p4.targets", row_id=identifier, table_digest=registry_digest,
                            citation=f"/targets/{index}")
        declaration = k.Known(value=identifier, basis=k.Basis.DECLARED, raw=identifier, evidence=(ref,))
        targets[identifier] = Target(id=identifier, node=nodes[node_id], operation=operation,
                                     owner=owners[operation], params=params, declaration=declaration)
    captures: list[CaptureMember] = []
    for path in sorted(capture_rows):
        target_id, digest, capture_id = capture_rows[path]
        captures.append(CaptureMember(id=capture_id, target=targets[target_id], path=path,
                                      raw=members[path], sha256=digest))
    context_ref = k.RegistryRef(table="synthetic_p4.context", row_id=context, table_digest=registry_digest, citation="/context")
    declared_context = k.Known(value=context, basis=k.Basis.DECLARED, raw=context, evidence=(context_ref,))
    return Envelope(raw=raw, base=base, context=context, declaration=declared_context,
                    registration_sha256=compiled.registration_sha256, targets=tuple(targets.values()), captures=tuple(captures))
