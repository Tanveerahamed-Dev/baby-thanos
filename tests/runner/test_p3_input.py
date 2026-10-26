"""P3 admission retains both registries after whole-folder budgets; activation is separate."""
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p3_records import SCHEMA
from atlas_brain.runner import coordinator, evidence
from atlas_brain.runner.records import RunnerRefused


def members():
    discovery, mtu = b"Device ID: sw-b\n", b"GigabitEthernet1 is up, line protocol is up\n  MTU is 9000 bytes\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": ["GigabitEthernet1"]} for node in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    def point(node, number):
        return {"node": node, "port": "GigabitEthernet1", "process": number,
                "router_id": "192.0.2." + str(number), "address": "198.51.100." + str(number), "vrf": "default"}
    side = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic", "base_sha256": sha256(base).hexdigest(),
        "adjacencies": [{"id": "link", "domain": "lab", "area": 0, "left": point("a", 1), "right": point("b", 7)}],
        "samples": [{"id": "first", "time": None, "captures": [{"path": "mtu.txt", "node": "a",
            "operation": "iosxe.show_ip_interface", "sha256": sha256(mtu).hexdigest()}]}]})
    return {"p2.json": base, "p3.json": side, "discovery.txt": discovery, "mtu.txt": mtu}


def folder(tmp_path, files):
    root = tmp_path / "input"
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return root


def test_whole_folder_is_read_once_and_both_registries_all_captures_are_retained(tmp_path, monkeypatch):
    files = members()
    root = folder(tmp_path, files)
    original, calls = evidence.folder_members, []
    def tracked(path, limits):
        calls.append(path)
        return original(path, limits)
    monkeypatch.setattr(evidence, "folder_members", tracked)
    result = evidence.analyse_input(root)
    assert calls == [root] and result.group is None and result.p3 is not None
    assert result.p3.raw == files["p3.json"] and result.p3.base.raw == files["p2.json"]
    expected = result.p3.base.captures + result.p3.samples[0].captures
    assert set(result.captures) == set(expected) and len(result.captures) == 2
    assert {capture.raw for capture in result.captures} == {files["discovery.txt"], files["mtu.txt"]}
    assert all((root / name).read_bytes() == raw for name, raw in files.items())
    with pytest.raises(RunnerRefused, match="^evidence_group_context_required$"):
        evidence.analyse_evidence(root)


@pytest.mark.parametrize("limits", [
    Budgets(bundle_bytes=100000, artifact_bytes=10000, artifacts=3),
    Budgets(bundle_bytes=100000, artifact_bytes=8, artifacts=10),
    Budgets(bundle_bytes=8, artifact_bytes=10000, artifacts=10),
])
def test_p3_never_reaches_semantic_admission_before_whole_folder_budgets(tmp_path, monkeypatch, limits):
    root = folder(tmp_path, members())
    monkeypatch.setattr(evidence, "admit_p3", lambda *args: pytest.fail("admitted before budgets"))
    with pytest.raises(RunnerRefused, match="^evidence_budget_exceeded$"):
        evidence.analyse_input(root, budgets=limits)


@pytest.mark.parametrize("fault", ["missing_base", "base_hash", "capture_hash", "schema", "extra"])
def test_invalid_sidecar_never_falls_back_to_p2_or_raw_capture_route(tmp_path, monkeypatch, fault):
    files = members()
    if fault == "missing_base":
        files.pop("p2.json")
    elif fault == "base_hash":
        files["p2.json"] += b"\n"
    elif fault == "capture_hash":
        files["mtu.txt"] += b"changed\n"
    elif fault == "schema":
        files["p3.json"] = files["p3.json"].replace(SCHEMA.encode(), b"atlas-brain.synthetic-p3/9")
    else:
        files["extra.txt"] = b"unlisted"
    root = folder(tmp_path, files)
    monkeypatch.setattr(evidence, "admit_members", lambda *args: pytest.fail("P3 fell back to P2"))
    with pytest.raises(RunnerRefused):
        evidence.analyse_input(root)
    assert all((root / name).read_bytes() == raw for name, raw in files.items())


def test_pending_cli_activation_refuses_before_workers_or_output_changes(tmp_path, monkeypatch):
    root = folder(tmp_path, members())
    out = tmp_path / "output"
    out.mkdir()
    previous = {name: b"previous " + name.encode() for name in ("MANIFEST.json", "SUMMARY.txt")}
    for name, raw in previous.items():
        (out / name).write_bytes(raw)
    monkeypatch.setattr(coordinator.tripwire, "probe", lambda: pytest.fail("witness ran before activation guard"))
    with pytest.raises(RunnerRefused, match="^p3_activation_pending$"):
        coordinator.run(evidence=root, out=out, workers=1, parent_denied=0)
    assert {name: (out / name).read_bytes() for name in previous} == previous
