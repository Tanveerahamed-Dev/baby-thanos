"""Declared synthetic grouping; JSON is registry evidence, never a CLI capture."""
import re
from dataclasses import dataclass
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
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k

SCHEMA = "atlas-brain.synthetic-p2/1"
CONFIG_SCHEMA = "atlas-brain.synthetic-p2/2"
CONFIG_OPERATION = "iosxe.show_running_config"
CONFIG_COMMAND = "show running-config"
OPERATIONS = {"iosxe.show_cdp_neighbors_detail": "show cdp neighbors detail",
              "iosxe.show_interfaces_trunk": "show interfaces trunk",
              "iosxe.show_lldp_neighbors_detail": "show lldp neighbors detail"}
_SAFE = r"[a-z][a-z0-9_-]{0,31}"
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]{0,63}"


@dataclass(frozen=True, slots=True, kw_only=True)
class Node:
    group: str
    id: str
    discovery_id: str
    ports: tuple[str, ...]
    declaration: k.Known[str]

    @property
    def key(self) -> k.EntityKey:
        return k.EntityKey("node:" + self.group + ":" + self.id)


@dataclass(frozen=True, slots=True, kw_only=True)
class SyntheticGroup:
    id: str
    nodes: tuple[Node, ...]
    captures: tuple[Capture, ...]
    raw: bytes
    declaration: k.Known[str]
    schema: str = SCHEMA


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionRefused(code)


def _rows(value: object, maximum: int, code: str) -> list[object]:
    _need(isinstance(value, list), code)
    rows = cast(list[object], value)
    _need(0 < len(rows) <= maximum, code)
    return rows


def _matches(pattern: str, value: str) -> bool:
    return re.fullmatch(pattern, value, re.ASCII) is not None


def operation_map(schema: str) -> dict[str, str]:
    _need(schema in (SCHEMA, CONFIG_SCHEMA), "synthetic_schema")
    return OPERATIONS | ({CONFIG_OPERATION: CONFIG_COMMAND} if schema == CONFIG_SCHEMA else {})


def endpoint(node: Node, exact_port: str) -> k.EntityKey:
    """Only a declared exact name can supply a synthetic interface subject."""
    _need(exact_port in node.ports, "synthetic_undeclared_port")
    return k.EntityKey("interface:" + sha256(canonical((node.key, exact_port))).hexdigest())


def _config_integrity(lines: list[str], *, failed: bool, truncated: bool) -> k.IntegrityState:
    """Recognize only the v2 config envelope; the owning parser accounts for its body."""
    if lines and lines[0] == CONFIG_COMMAND:
        lines = lines[1:]
    guards = (r"[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*",
              r"(?:do[ \t]+)?sh(?:ow|o)?[ \t].*", r"banner(?:[ \t]|$).*")
    _need(not any(_matches(pattern, line.strip().casefold()) for line in lines for pattern in guards),
          "synthetic_mixed_context")
    if failed:
        return k.IntegrityState.ERROR
    if truncated:
        return k.IntegrityState.TRUNCATED
    if not lines:
        return k.IntegrityState.EMPTY
    header = (r"Building configuration\.\.\.|Current configuration[ \t]*:[ \t]*[0-9]+ bytes"
              r"|(?:version|hostname|interface|template|default|port-profile|macro)[ \t]+[^\r\n]+|!|end")
    _need(_matches(header, lines[0]), "synthetic_unsupported_capture")
    return k.IntegrityState.COMPLETE


def _integrity(raw: bytes, operation: str) -> k.IntegrityState:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise AdmissionRefused("synthetic_invalid_encoding") from error
    _need("\r" not in text.replace("\r\n", "") and not any(
        ord(c) < 32 and c not in "\t\r\n" or c in "\x7f\u0085\u2028\u2029" for c in text
    ), "synthetic_invalid_text")
    lines = [line.removesuffix("\r") for line in text.split("\n") if line.strip()]
    failed = any(line.lstrip().startswith("%") or "command authorization failed" in line.casefold() for line in lines)
    truncated = any(marker in text.casefold() for marker in ("--more--", "<--- more --->", "--(more)--", "[truncated]", "<output truncated>"))
    prompt = r"[A-Za-z0-9_.:-]+[>#]"
    command = CONFIG_COMMAND if operation == CONFIG_OPERATION else OPERATIONS[operation]
    opening = re.fullmatch("(" + prompt + ") ?" + command, lines[0], re.ASCII) if lines else None
    if opening:
        lines = lines[1:]
    if lines and _matches(prompt, lines[-1]):
        _need(opening is None or lines[-1] == opening[1], "synthetic_mixed_context")
        lines = lines[:-1]
    if operation == CONFIG_OPERATION:
        return _config_integrity(lines, failed=failed, truncated=truncated)
    contexts = (r"[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*", r"(?:end|!|\^c?)",
                r"(?:building configuration|current configuration|banner(?:[ \t]|$)|(?:do[ \t]+)?sh(?:ow|o)?[ \t]).*",
                r"(?:hostname|interface|router|vlan)[ \t].*")
    _need(not any(_matches(pattern, line.strip().casefold()) for line in lines for pattern in contexts),
          "synthetic_mixed_context")
    if failed:
        return k.IntegrityState.ERROR
    if truncated:
        return k.IntegrityState.TRUNCATED
    if not lines:
        return k.IntegrityState.EMPTY
    headers = {
        "iosxe.show_cdp_neighbors_detail": r"Device ID: [A-Za-z0-9][A-Za-z0-9_.:-]{0,127}|-------------------------",
        "iosxe.show_interfaces_trunk": r"Port[ \t]+Mode[ \t]+Encapsulation[ \t]+Status[ \t]+Native vlan[ \t]*",
        "iosxe.show_lldp_neighbors_detail": r"Local Intf: " + _PORT,
    }
    _need(_matches(headers[operation], lines[0]), "synthetic_unsupported_capture")
    return k.IntegrityState.COMPLETE


def admit_members(members: dict[str, bytes]) -> SyntheticGroup:
    """Call only after whole-folder budgets; refuse before exposing any captures."""
    _need("p2.json" in members, "synthetic_missing_manifest")
    member_names(list(members))
    raw = members["p2.json"]
    manifest = record(strict_json(raw), ("schema", "semantic_group", "group", "nodes", "captures"))
    schema = string(manifest, "schema")
    operations = operation_map(schema)
    _need(string(manifest, "semantic_group") == "declared_synthetic", "synthetic_semantic_group")
    group = string(manifest, "group")
    _need(_matches(_SAFE, group), "synthetic_group_id")
    digest = sha256(raw).hexdigest()

    def declaration(table: str, identifier: str, pointer: str) -> k.Known[str]:
        ref = k.RegistryRef(table="synthetic_p2." + table, row_id=identifier,
                            table_digest=digest, citation=pointer)
        return k.Known(value=identifier, basis=k.Basis.DECLARED, evidence=(ref,), raw=identifier)

    nodes: list[Node] = []
    aliases: set[str] = set()
    identifiers: set[str] = set()
    for index, value in enumerate(_rows(manifest["nodes"], 32, "synthetic_nodes")):
        row = record(value, ("id", "discovery_id", "ports"))
        identifier, alias = string(row, "id"), string(row, "discovery_id")
        _need(_matches(_SAFE, identifier), "synthetic_node_id")
        _need(_matches(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", alias), "synthetic_discovery_id")
        _need(identifier not in identifiers and alias not in aliases, "synthetic_duplicate_identity")
        ports: list[str] = []
        for port in _rows(row["ports"], 128, "synthetic_ports"):
            _need(type(port) is str, "synthetic_port")
            exact = cast(str, port)
            _need(_matches(_PORT, exact) and exact not in ports, "synthetic_port")
            ports.append(exact)
        identifiers.add(identifier)
        aliases.add(alias)
        nodes.append(Node(group=group, id=identifier, discovery_id=alias, ports=tuple(sorted(ports)),
                          declaration=declaration("nodes", identifier, f"/nodes/{index}")))
    declared_nodes = {node.id: node for node in nodes}
    captures: list[Capture] = []
    paths: set[str] = set()
    references: set[tuple[str, str]] = set()
    for value in _rows(manifest["captures"], 64, "synthetic_captures"):
        row = record(value, ("path", "node", "operation", "sha256"))
        path, node, operation, expected = (string(row, f) for f in ("path", "node", "operation", "sha256"))
        member_names([path])
        _need(node in identifiers and operation in operations, "synthetic_capture_reference")
        _need(path != "p2.json" and path not in paths and (node, operation) not in references,
              "synthetic_duplicate_reference")
        _need(path in members and _matches(r"[0-9a-f]{64}", expected), "synthetic_capture_hash")
        content = members[path]
        _need(sha256(content).hexdigest() == expected, "synthetic_capture_hash")
        integrity = _integrity(content, operation)
        identity = sha256(canonical((schema, group, digest, path, node, operation, expected))).hexdigest()
        captures.append(Capture(id=k.CaptureId("cap:" + identity), source=declared_nodes[node].key,
                                operation=operation, rendered=operations[operation], codec="utf-8",
                                raw=content, integrity=integrity, lines=text_lines(content, "utf-8"),
                                read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN))
        paths.add(path)
        references.add((node, operation))
    _need(schema == SCHEMA or any(operation == CONFIG_OPERATION for _, operation in references),
          "synthetic_config_required")
    _need(set(members) == paths | {"p2.json"}, "synthetic_unlisted_member")
    return SyntheticGroup(id=group, nodes=tuple(sorted(nodes, key=lambda node: node.id)),
                          captures=tuple(sorted(captures, key=lambda capture: capture.id)), raw=raw,
                          declaration=declaration("groups", group, "/group"), schema=schema)
