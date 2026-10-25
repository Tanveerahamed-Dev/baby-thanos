"""A declared group cannot enter the legacy capture-only route without context."""
import json
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.synthetic import SCHEMA
from atlas_brain.runner import evidence
from atlas_brain.runner.records import RunnerRefused


def members():
    raw = {"a.txt": b"Device ID: sw-b\n",
           "b.txt": b"Port Mode Encapsulation Status Native vlan\n"}
    data = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "input",
            "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": ["Gi1/0/1"]}
                      for node in ("a", "b")],
            "captures": [{"path": path, "node": node, "operation": operation,
                          "sha256": sha256(raw[path]).hexdigest()} for path, node, operation in (
                              ("a.txt", "a", "iosxe.show_cdp_neighbors_detail"),
                              ("b.txt", "b", "iosxe.show_interfaces_trunk"))]}
    return {**raw, "p2.json": json.dumps(data).encode()}


def folder(tmp_path, data):
    root = tmp_path / "input"
    root.mkdir()
    for name, raw in data.items():
        (root / name).write_bytes(raw)
    return root


def test_group_intake_reads_folder_once_and_retains_registry_bytes(tmp_path, monkeypatch):
    data = members()
    root = folder(tmp_path, data)
    reads = []
    original = evidence.folder_members
    def tracked(path, budgets):
        reads.append(path)
        return original(path, budgets)
    monkeypatch.setattr(evidence, "folder_members", tracked)
    result = evidence.analyse_input(root)
    assert reads == [root] and result.group is not None
    assert result.captures == result.group.captures and result.group.raw == data["p2.json"]
    assert {capture.source for capture in result.captures} == {"node:input:a", "node:input:b"}
    assert all((root / name).read_bytes() == raw for name, raw in data.items())
    with pytest.raises(RunnerRefused, match="^evidence_group_context_required$"):
        evidence.analyse_evidence(root)


@pytest.mark.parametrize("raw", [
    b'a uptime is 1 day\nSystem image file is "bootflash:packages.conf"\nLast reload reason: PowerOn\n',
    b"Interface IP-Address OK? Method Status Protocol\nGi1/0/1 unassigned YES unset up down\n",
])
def test_raw_p0_p1_identity_and_capture_only_api_remain_unchanged(tmp_path, raw):
    root = folder(tmp_path, {"raw.txt": raw})
    result = evidence.analyse_input(root)
    assert result.group is None and result.captures == evidence.analyse_evidence(root)
    capture, = result.captures
    assert capture.id == "cap:" + sha256(b"raw.txt\0" + raw).hexdigest()
    assert capture.source == "node:file:" + sha256(b"raw.txt").hexdigest()
    assert capture.raw == raw == (root / "raw.txt").read_bytes()


@pytest.mark.parametrize("limits", [
    Budgets(bundle_bytes=100000, artifact_bytes=10000, artifacts=2),
    Budgets(bundle_bytes=100000, artifact_bytes=8, artifacts=10),
    Budgets(bundle_bytes=8, artifact_bytes=10000, artifacts=10),
])
def test_whole_folder_budgets_precede_group_admission(tmp_path, monkeypatch, limits):
    root = folder(tmp_path, members())
    def forbidden(*args):
        raise AssertionError("group_admitted_before_budget_check")
    monkeypatch.setattr(evidence, "admit_members", forbidden)
    with pytest.raises(RunnerRefused, match="^evidence_budget_exceeded$"):
        evidence.analyse_input(root, budgets=limits)


@pytest.mark.parametrize("fault", ["hash", "node", "extra", "path", "schema"])
def test_invalid_group_never_falls_back_to_capture_local_parsing(tmp_path, fault):
    data = members()
    manifest = json.loads(data["p2.json"])
    if fault == "hash":
        manifest["captures"][0]["sha256"] = "0" * 64
    elif fault == "node":
        manifest["captures"][0]["node"] = "unbound"
    elif fault == "extra":
        data["extra.txt"] = b"extra"
    elif fault == "path":
        manifest["captures"][0]["path"] = "../a.txt"
    else:
        manifest["schema"] = "unsupported"
    data["p2.json"] = json.dumps(manifest).encode()
    root = folder(tmp_path, data)
    with pytest.raises(RunnerRefused):
        evidence.analyse_input(root)
    assert all((root / name).read_bytes() == raw for name, raw in data.items())


@pytest.mark.parametrize("raw", [b'{"schema":"x","schema":"y"}', b"\xff", b"[]"])
def test_invalid_registry_is_refused_before_exposing_capture_tuple(tmp_path, raw):
    data = members()
    data["p2.json"] = raw
    root = folder(tmp_path, data)
    with pytest.raises(RunnerRefused):
        evidence.analyse_evidence(root)
