"""Generated schema-v2 admission controls; no device/config qualification."""
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.synthetic import (
    CONFIG_COMMAND,
    CONFIG_OPERATION,
    CONFIG_SCHEMA,
    OPERATIONS,
    SCHEMA,
    admit_members,
    endpoint,
    operation_map,
)
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore
from atlas_brain.runner import p2
from atlas_brain.runner.records import RunnerRefused

PORT = "Gi1/0/1"
CONFIG = (b"Building configuration...\n!\ninterface Gi1/0/1\n"
          b" switchport mode trunk\n switchport trunk native vlan 10\n"
          b" switchport trunk allowed vlan 10,20\n!\nend\n")
TRUNK_OP = "iosxe.show_interfaces_trunk"
TRUNK = (b"Port Mode Encapsulation Status Native vlan\nGi1/0/1 on 802.1q trunking 10\n"
         b"Port Vlans allowed on trunk\nGi1/0/1 10,20\n")


def members(raw=CONFIG, schema=CONFIG_SCHEMA, operation=CONFIG_OPERATION):
    manifest = {"schema": schema, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [PORT]}
                          for node in ("a", "b")],
                "captures": [{"path": "capture.txt", "node": "a", "operation": operation,
                              "sha256": sha256(raw).hexdigest()}]}
    return {"p2.json": canonical(manifest), "capture.txt": raw}, manifest


def rewrite(files, manifest):
    return {**files, "p2.json": canonical(manifest)}


def test_config_v2_custody_uses_exact_schema_registry_and_raw_bytes():
    files, manifest = members()
    group = admit_members(files)
    capture, = group.captures
    registry = sha256(files["p2.json"]).hexdigest()
    identity = sha256(canonical((CONFIG_SCHEMA, "demo", registry, "capture.txt",
                                 "a", CONFIG_OPERATION, sha256(CONFIG).hexdigest()))).hexdigest()
    assert operation_map(CONFIG_SCHEMA) == OPERATIONS | {CONFIG_OPERATION: CONFIG_COMMAND}
    assert group.schema == CONFIG_SCHEMA and capture.id == "cap:" + identity
    assert capture.raw == CONFIG and capture.bytes_sha256 == sha256(CONFIG).hexdigest()
    assert capture.source == group.nodes[0].key == "node:demo:a"
    assert capture.operation == CONFIG_OPERATION and capture.rendered == CONFIG_COMMAND
    assert capture.integrity is k.IntegrityState.COMPLETE
    assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
    assert capture.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert len(group.nodes) == 2 and group.nodes[1].ports == (PORT,)
    assert group.declaration.basis is k.Basis.DECLARED
    assert group.declaration.evidence[0].table_digest == registry
    assert group.nodes[0].declaration.evidence[0].citation == "/nodes/0"
    assert manifest["nodes"][0]["id"] == "a"  # Source is an explicit declaration, not a filename.
    with pytest.raises(AttributeError):
        group.schema = SCHEMA


def test_v1_operation_allowlist_and_capture_identity_are_frozen():
    files, _ = members(TRUNK, SCHEMA, TRUNK_OP)
    group = admit_members(files)
    capture, = group.captures
    expected = sha256(canonical((SCHEMA, "demo", sha256(files["p2.json"]).hexdigest(),
                                 "capture.txt", "a", TRUNK_OP, sha256(TRUNK).hexdigest()))).hexdigest()
    assert group.schema == SCHEMA and capture.id == "cap:" + expected
    assert operation_map(SCHEMA) == OPERATIONS and CONFIG_OPERATION not in OPERATIONS
    with pytest.raises(AdmissionRefused, match="synthetic_capture_reference"):
        admit_members(members(schema=SCHEMA)[0])


def test_v2_requires_config_but_missing_other_node_capture_remains_a_declared_subject():
    with pytest.raises(AdmissionRefused, match="synthetic_config_required"):
        admit_members(members(TRUNK, CONFIG_SCHEMA, TRUNK_OP)[0])
    group = admit_members(members()[0])
    assert {capture.source for capture in group.captures} == {group.nodes[0].key}
    assert len({endpoint(node, PORT) for node in group.nodes}) == 2


@pytest.mark.parametrize("raw,expected", [
    (b"", k.IntegrityState.EMPTY),
    (b"% Invalid input detected at '^' marker.\n", k.IntegrityState.ERROR),
    (CONFIG + b"--More--\n", k.IntegrityState.TRUNCATED),
    (CONFIG + b"[truncated]\n", k.IntegrityState.TRUNCATED),
])
def test_failed_empty_and_truncated_config_never_become_complete(raw, expected):
    group = admit_members(members(raw)[0])
    assert group.captures[0].integrity is expected


@pytest.mark.parametrize("raw", [
    b"sw-a#show running-config\n" + CONFIG + b"sw-a#\n",
    b"show running-config\n" + CONFIG,
    CONFIG.replace(b"\n", b"\r\n"),
])
def test_exact_optional_command_envelopes_and_crlf_preserve_original_bytes(raw):
    capture, = admit_members(members(raw)[0]).captures
    assert capture.raw == raw and capture.integrity is k.IntegrityState.COMPLETE


@pytest.mark.parametrize("raw,code", [
    (b"sw-a#show interfaces trunk\n" + CONFIG, "synthetic_mixed_context"),
    (b"sw-a(config)#switchport mode trunk\n" + CONFIG, "synthetic_mixed_context"),
    (CONFIG + b"sw-a#show version\n", "synthetic_mixed_context"),
    (CONFIG + b"banner motd ^C\n", "synthetic_mixed_context"),
    (b"sw-a#show running-config\n" + CONFIG + b"sw-b#\n", "synthetic_mixed_context"),
    (CONFIG + b"\x1b[31m", "synthetic_invalid_text"),
    (CONFIG + b"\xff", "synthetic_invalid_encoding"),
    (b"not an admitted configuration\n", "synthetic_unsupported_capture"),
])
def test_config_context_controls_refuse_before_exposing_a_group(raw, code):
    with pytest.raises(AdmissionRefused, match=code):
        admit_members(members(raw)[0])


@pytest.mark.parametrize("schema", ["atlas-brain.synthetic-p2/3", "", "2"])
def test_unknown_schema_is_not_a_config_capability(schema):
    with pytest.raises(AdmissionRefused, match="synthetic_schema"):
        admit_members(members(schema=schema)[0])


@pytest.mark.parametrize("schema", [SCHEMA, CONFIG_SCHEMA])
def test_existing_show_guards_are_not_relaxed_by_v2(schema):
    files, manifest = members(CONFIG, schema, TRUNK_OP)
    if schema == CONFIG_SCHEMA:
        files["config.txt"] = CONFIG
        manifest["captures"].append({"path": "config.txt", "node": "b", "operation": CONFIG_OPERATION,
                                      "sha256": sha256(CONFIG).hexdigest()})
    with pytest.raises(AdmissionRefused, match="synthetic_mixed_context"):
        admit_members(rewrite(files, manifest))


@pytest.mark.parametrize("plant", ["hash", "unlisted", "unsafe", "duplicate", "unknown_node", "unknown_op"])
def test_v2_preserves_existing_manifest_safety(plant):
    files, manifest = members()
    row = manifest["captures"][0]
    if plant == "hash":
        row["sha256"] = "0" * 64
    elif plant == "unlisted":
        files["extra.txt"] = CONFIG
    elif plant == "unsafe":
        row["path"] = "../capture.txt"
    elif plant == "duplicate":
        manifest["captures"].append(dict(row))
    elif plant == "unknown_node":
        row["node"] = "other"
    else:
        row["operation"] = "iosxe.show_startup_config"
    with pytest.raises(AdmissionRefused):
        admit_members(rewrite(files, manifest))


def test_schema_is_part_of_capture_custody_not_endpoint_identity():
    v1 = admit_members(members(TRUNK, SCHEMA, TRUNK_OP)[0])
    v2 = admit_members(members()[0])
    assert endpoint(v1.nodes[0], PORT) == endpoint(v2.nodes[0], PORT)
    assert v1.captures[0].id != v2.captures[0].id


def test_frozen_show_only_parser_never_silently_skips_a_config_capture():
    group = admit_members(members()[0])
    with pytest.raises(RunnerRefused, match="^p2_unowned_capture$"):
        p2._parse_all(group, FactStore())
