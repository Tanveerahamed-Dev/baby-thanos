"""Synthetic declarations are explicit, bounded registry evidence, never CLI."""
import copy
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.synthetic import SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k


def sample():
    files = {"a.txt": b"Device ID: sw-b\n",
             "b.txt": b"Port Mode Encapsulation Status Native vlan\n"}
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": "b", "discovery_id": "sw-b", "ports": ["Gi1/0/2", "Gi1/0/1"]},
                          {"id": "a", "discovery_id": "sw-a", "ports": ["Gi1/0/1"]}],
                "captures": [{"path": path, "node": node, "operation": operation,
                              "sha256": sha256(files[path]).hexdigest()}
                             for path, node, operation in (
                                 ("a.txt", "a", "iosxe.show_cdp_neighbors_detail"),
                                 ("b.txt", "b", "iosxe.show_interfaces_trunk"))]}
    return manifest, files


def admit(manifest, files):
    return admit_members({**files, "p2.json": json.dumps(manifest).encode()})


def test_declarations_preserve_original_registry_pointers_and_raw_cli():
    manifest, files = sample()
    original = copy.deepcopy((manifest, files))
    result = admit(manifest, files)
    assert (manifest, files) == original
    assert [node.id for node in result.nodes] == ["a", "b"]
    assert result.nodes[1].ports == ("Gi1/0/1", "Gi1/0/2")
    digest = sha256(result.raw).hexdigest()
    for node, pointer in zip(result.nodes, ("/nodes/1", "/nodes/0"), strict=True):
        assert node.declaration.basis is k.Basis.DECLARED
        assert node.declaration.evidence == (k.RegistryRef(
            table="synthetic_p2.nodes", row_id=node.id, table_digest=digest, citation=pointer),)
    assert result.declaration.evidence == (k.RegistryRef(
        table="synthetic_p2.groups", row_id="demo", table_digest=digest, citation="/group"),)
    assert len(result.captures) == 2
    assert {capture.raw for capture in result.captures} == set(files.values())
    assert {capture.source for capture in result.captures} == {"node:demo:a", "node:demo:b"}
    assert all(capture.integrity is k.IntegrityState.COMPLETE for capture in result.captures)
    assert all(capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
               and isinstance(capture.collected_utc, k.Unknown) for capture in result.captures)
    assert result == admit_members(dict(reversed(list({**files, "p2.json": result.raw}.items()))))
    assert endpoint(result.nodes[0], "Gi1/0/1") == "interface:" + sha256(canonical(("node:demo:a", "Gi1/0/1"))).hexdigest()
    with pytest.raises(AdmissionRefused, match="synthetic_undeclared_port"):
        endpoint(result.nodes[0], "GigabitEthernet1/0/1")


@pytest.mark.parametrize("field,value,code", [
    ("schema", "other", "synthetic_schema"),
    ("semantic_group", "inferred", "synthetic_semantic_group"), ("group", "../a", "synthetic_group_id"),
    ("nodes", [], "synthetic_nodes"), ("nodes", [{}] * 33, "synthetic_nodes"),
    ("captures", [], "synthetic_captures"), ("captures", [{}] * 65, "synthetic_captures"),
])
def test_top_level_bounds(field, value, code):
    manifest, files = sample()
    manifest[field] = value
    with pytest.raises(AdmissionRefused, match=code):
        admit(manifest, files)


@pytest.mark.parametrize("kind", ["node", "alias", "port", "source_operation", "path", "unknown_node",
                                  "operation", "missing", "hash", "unlisted", "extra_field", "unsafe_path"])
def test_ambiguous_or_unbound_manifest_is_refused(kind):
    manifest, files = sample()
    nodes, rows = manifest["nodes"], manifest["captures"]
    if kind == "node":
        nodes[1]["id"] = nodes[0]["id"]
    elif kind == "alias":
        nodes[1]["discovery_id"] = nodes[0]["discovery_id"]
    elif kind == "port":
        nodes[0]["ports"].append(nodes[0]["ports"][0])
    elif kind == "source_operation":
        rows[1].update(node=rows[0]["node"], operation=rows[0]["operation"])
    elif kind == "path":
        rows[1]["path"] = rows[0]["path"]
    elif kind == "unknown_node":
        rows[0]["node"] = "missing"
    elif kind == "operation":
        rows[0]["operation"] = "iosxe.show_version"
    elif kind == "missing":
        files.pop("a.txt")
    elif kind == "hash":
        rows[0]["sha256"] = "0" * 64
    elif kind == "unlisted":
        files["extra.txt"] = b"extra"
    elif kind == "extra_field":
        nodes[0]["alias"] = "implicit"
    elif kind == "unsafe_path":
        rows[0]["path"] = "../a.txt"
    with pytest.raises(AdmissionRefused):
        admit(manifest, files)


@pytest.mark.parametrize("raw,state", [(b"", k.IntegrityState.EMPTY),
    (b"% Invalid input\n", k.IntegrityState.ERROR), (b"[truncated]\n", k.IntegrityState.TRUNCATED)])
def test_failed_or_incomplete_bytes_are_never_complete(raw, state):
    manifest, files = sample()
    files["a.txt"] = raw
    manifest["captures"][0]["sha256"] = sha256(raw).hexdigest()
    result = admit(manifest, files)
    assert next(c for c in result.captures if c.source == "node:demo:a").integrity is state


@pytest.mark.parametrize("raw", [b"hostname sw-a\n", b"\xff", b"Device ID: sw-b\x00\n",
    b"% Invalid input\nshow running-config\n", b"Device ID: sw-b\n--More--\n!\n",
    b"sw-a#show version\nDevice ID: sw-b\n", b"sw-a#show cdp neighbors detail\nDevice ID: sw-b\nsw-b#\n"])
def test_invalid_or_mixed_response_refuses(raw):
    manifest, files = sample()
    files["a.txt"] = raw
    manifest["captures"][0]["sha256"] = sha256(raw).hexdigest()
    with pytest.raises(AdmissionRefused):
        admit(manifest, files)


def test_manifest_json_never_becomes_capture_and_duplicate_keys_refuse():
    with pytest.raises(AdmissionRefused, match="synthetic_missing_manifest"):
        admit_members({})
    with pytest.raises(AdmissionRefused):
        admit_members({"p2.json": b'{"schema":"x","schema":"y"}'})
    manifest, files = sample()
    manifest["captures"][0]["path"] = "p2.json"
    with pytest.raises(AdmissionRefused, match="synthetic_duplicate_reference"):
        admit(manifest, files)


@pytest.mark.parametrize("field,value", [("id", "SW-A"), ("discovery_id", ""),
    ("ports", []), ("ports", ["Gi1/0/1"] * 129), ("ports", ["Gi 1/0/1"]), ("ports", [1])])
def test_node_and_port_boundaries(field, value):
    manifest, files = sample()
    manifest["nodes"][0][field] = value
    with pytest.raises(AdmissionRefused):
        admit(manifest, files)


def test_declared_but_uncollected_node_is_retained_for_unknown_peer():
    manifest, files = sample()
    manifest["captures"].pop()
    files.pop("b.txt")
    result = admit(manifest, files)
    assert len(result.nodes) == 2 and len(result.captures) == 1


def test_group_namespaces_and_endpoints_do_not_depend_on_capture_identity():
    manifest, files = sample()
    first = admit(manifest, files)
    manifest["group"] = "other"
    other = admit(manifest, files)
    assert first.nodes[0].key == "node:demo:a" and other.nodes[0].key == "node:other:a"
    assert endpoint(first.nodes[0], "Gi1/0/1") != endpoint(other.nodes[0], "Gi1/0/1")
    manifest["group"] = "demo"
    files["renamed.txt"] = files.pop("a.txt") + b"\n"
    manifest["captures"][0].update(path="renamed.txt", sha256=sha256(files["renamed.txt"]).hexdigest())
    changed = admit(manifest, files)
    assert first.nodes[0].key == changed.nodes[0].key
    assert endpoint(first.nodes[0], "Gi1/0/1") == endpoint(changed.nodes[0], "Gi1/0/1")
    assert {c.id for c in first.captures} != {c.id for c in changed.captures}


def test_lldp_metadata_is_admitted_but_does_not_establish_a_pair():
    manifest, files = sample()
    files["a.txt"] = b"Local Intf: Gi1/0/1\n"
    manifest["captures"][0].update(operation="iosxe.show_lldp_neighbors_detail",
                                  sha256=sha256(files["a.txt"]).hexdigest())
    capture = next(c for c in admit(manifest, files).captures if c.source == "node:demo:a")
    assert capture.rendered == "show lldp neighbors detail"
    assert capture.integrity is k.IntegrityState.COMPLETE
    assert capture.read_scope is k.ReadScope.UNKNOWN
