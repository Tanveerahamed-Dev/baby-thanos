"""Actual admitted generated CLI feeds all P2 owners and the pure renderer."""
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import SCHEMA, admit_members
from atlas_brain.kernel import states as k
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as trunk
from atlas_brain.packs.l2.vlan_trunk import check
from atlas_brain.runner import p2
from atlas_brain.runner.records import RunnerRefused

P = "Gi1/0/1"
IDS = ("l1.link.peer", "l2.discovery.bridge_capable", "l2.discovery.device_id",
       "l2.discovery.remote_port", "l2.vlan_trunk.allowed", "l2.vlan_trunk.native")


def members(native=("10", "20"), allowed=("10,30", "10,20"), missing_b=False, remote_b=P, lldp=False):
    files, captures = {}, []
    for index, node in enumerate(("a", "b")):
        if missing_b and node == "b":
            continue
        peer = "b" if node == "a" else "a"
        remote = P if node == "a" else remote_b
        outputs = (("iosxe.show_cdp_neighbors_detail", "-------------------------\nDevice ID: sw-" + peer
                    + "\nPlatform: synthetic-switch, Capabilities: Switch\nInterface: " + P
                    + ", Port ID (outgoing port): " + remote + "\n"),
                   (trunk.OP, "Port Mode Encapsulation Status Native vlan\n" + P
                    + " on 802.1q trunking " + native[index] + "\nPort Vlans allowed on trunk\n"
                    + P + " " + allowed[index] + "\n"))
        if lldp:
            outputs = (("iosxe.show_lldp_neighbors_detail",
                        "Local Intf: " + P + "\nPort id: " + remote + "\nSystem Name: sw-" + peer
                        + "\nEnabled Capabilities: B\n"), outputs[1])
        for operation, text in outputs:
            path = node + "." + operation + ".txt"
            files[path] = text.encode()
            captures.append({"path": path, "node": node, "operation": operation,
                             "sha256": sha256(files[path]).hexdigest()})
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in ("a", "b")],
                "captures": captures}
    return {**files, "p2.json": canonical(manifest)}


def bundle(**kwargs):
    return admit_members(members(**kwargs))


def leaves(records):
    return [leaf for item in records for leaf in
            ([item] if item["kind"] == "capture" else
             leaves(item["state"]["evidence"]) if item["kind"] == "fact" else [])]


@pytest.mark.parametrize("lldp", (False, True))
def test_counterexamples_keep_both_ends_exact_leaf_proofs_and_owner_denominator(lldp):
    group = bundle(lldp=lldp)
    assert {capture.operation for capture in group.captures} == {
        "iosxe.show_lldp_neighbors_detail" if lldp else "iosxe.show_cdp_neighbors_detail", trunk.OP}
    payload, summary = p2.analyse_group(group)
    assert payload["schema"] == "atlas-brain.p2-demo/1"
    assert payload["group"]["semantic_group"] == "declared_synthetic"
    assert payload["variant_support"] == "allowlisted"
    assert payload["registry_sha256"] == sha256(group.raw).hexdigest()
    assert payload["denominator"] == {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    assert payload["coverage"]["state"] == "unknown" and payload["coverage"]["reason"] == "denominator_open"
    assert {(point["node"], point["port"]) for point in payload["endpoints"]} == {("a", P), ("b", P)}
    assert all(tuple(point["facts"]) == IDS for point in payload["endpoints"])
    findings = {row["check"]: row for row in payload["findings"]}
    assert set(findings) == set(check.CHECKS)
    for finding in findings.values():
        assert finding["state"] == "problem" and finding["reason"] is None
        assert {finding["left"]["node"], finding["right"]["node"]} == {"a", "b"}
        refs = leaves(finding["evidence"])
        assert {ref["source"] for ref in refs} == {node.key for node in group.nodes}
        assert all(ref["role"] == "subject" for ref in refs)
        for ref in refs:
            capture = next(capture for capture in group.captures if capture.id == ref["capture"])
            assert sha256(capture.raw[ref["start"]:ref["end"]]).hexdigest() == ref["sha256"]
            assert ref["capture_sha256"] == sha256(capture.raw).hexdigest()
            assert ref["read_scope"] == "unknown"
    allowed = findings[check.ALLOWED_CHECK]
    expected = ("30", "20") if allowed["left"]["node"] == "a" else ("20", "30")
    assert (allowed["left_only"], allowed["right_only"]) == expected
    line = next(line for line in summary if check.NATIVE_CHECK in line)
    assert "a/" + P + "=10" in line and "b/" + P + "=20" in line
    assert "evidence=" in line and '"kind": "capture"' in line


def test_equal_untimed_inputs_and_capture_metadata_remain_unknown():
    payload, _ = p2.analyse_group(bundle(native=("10", "10"), allowed=("10,30", "10,30")))
    assert all(row["state"] == "unknown" and row["reason"] == "as_of_missing" for row in payload["findings"])
    for capture in payload["captures"]:
        assert capture["collected_utc"]["state"] == "unknown"
        assert capture["collected_utc"]["reason"] == "as_of_missing"
        assert capture["read_scope"] == capture["view"] == "unknown"


def test_missing_end_retains_declared_endpoints_and_unknown_denominator():
    payload, _ = p2.analyse_group(bundle(missing_b=True))
    assert payload["denominator"] == {"declared_endpoints": 2, "reciprocal_pairs": 0, "unresolved_endpoints": 2}
    assert len(payload["endpoints"]) == 2 and len(payload["findings"]) == 4
    assert all(row["state"] == "unknown" and row["right"] is None for row in payload["findings"])
    missing = next(point for point in payload["endpoints"] if point["node"] == "b")
    assert all(state["state"] == "unknown" for state in missing["facts"].values())
    assert payload["coverage"]["reason"] == "denominator_open"


def test_asymmetric_discovery_is_fatal():
    with pytest.raises(ValueError, match="asymmetric_discovery_claim"):
        p2.analyse_group(bundle(remote_b="Gi1/0/9"))


def test_capture_and_node_order_do_not_change_payload_or_summary():
    group = bundle()
    first = p2.analyse_group(group)
    reverse = replace(group, captures=tuple(reversed(group.captures)), nodes=tuple(reversed(group.nodes)))
    assert canonical(first) == canonical(p2.analyse_group(reverse))


def test_hash_seeds_do_not_change_payload_or_summary():
    script = ("import sys; from atlas_brain.contract.canonical import canonical; "
              "from atlas_brain.evidence.synthetic import admit_members; "
              "from atlas_brain.runner.p2 import analyse_group; "
              "sys.stdout.buffer.write(canonical(analyse_group(admit_members(" + repr(members()) + "))))")
    outputs = [subprocess.run([sys.executable, "-c", script], capture_output=True, check=True, timeout=60,
                              env={**os.environ, "PYTHONHASHSEED": seed}).stdout for seed in ("1", "97")]
    assert outputs[0] == outputs[1]


def test_all_node_parsers_finish_before_pairing_or_checking(monkeypatch):
    completed, estates = [], []
    original_discovery, original_trunk = discovery.build_node, trunk.build_node
    original_link, original_check = link.build_group, check.build_group
    def disc(group, node, store):
        result = original_discovery(group, node, store)
        completed.append(("discovery", node.id))
        return result
    def trunks(group, node, store):
        result = original_trunk(group, node, store)
        completed.append(("trunk", node.id))
        return result
    def pair(group, store):
        assert set(completed) == {(owner, node) for owner in ("discovery", "trunk") for node in ("a", "b")}
        assert len(completed) == 4 and not estates
        estates.append("pair")
        return original_link(group, store)
    def checks(group, store):
        assert estates == ["pair"]
        estates.append("check")
        return original_check(group, store)
    for module, name, replacement in ((discovery, "build_node", disc), (trunk, "build_node", trunks),
                                       (link, "build_group", pair), (check, "build_group", checks)):
        monkeypatch.setattr(module, name, replacement)
    p2.analyse_group(bundle())
    assert estates == ["pair", "check"]


def test_late_parser_failure_prevents_any_estate_call(monkeypatch):
    original = trunk.build_node
    def late(group, node, store):
        if node.id == "b":
            raise ValueError("late_parser_failure")
        return original(group, node, store)
    def forbidden(*args):
        raise AssertionError("estate_before_full_parse_barrier")
    monkeypatch.setattr(trunk, "build_node", late)
    monkeypatch.setattr(link, "build_group", forbidden)
    monkeypatch.setattr(check, "build_group", forbidden)
    with pytest.raises(ValueError, match="late_parser_failure"):
        p2.analyse_group(bundle())


@pytest.mark.parametrize("plant", ["skip", "duplicate", "foreign"])
def test_parse_results_must_cover_exact_capture_ids_once(monkeypatch, plant):
    original = discovery.build_node
    def planted(group, node, store):
        result = original(group, node, store)
        if node.id == "a":
            parses = (() if plant == "skip" else result.parses * 2 if plant == "duplicate" else
                      ((k.CaptureId("cap:foreign"), result.parses[0][1]),))
            return replace(result, parses=parses)
        return result
    monkeypatch.setattr(discovery, "build_node", planted)
    with pytest.raises(RunnerRefused, match="parse_coverage"):
        p2.analyse_group(bundle())


def test_exact_capture_set_cannot_be_claimed_by_wrong_parser(monkeypatch):
    group = bundle()
    def swap(original, other_operation):
        def planted(group, node, store):
            result = original(group, node, store)
            if node.id == "a":
                other = next(capture.id for capture in group.captures
                             if capture.source == node.key and capture.operation == other_operation)
                return replace(result, parses=((other, result.parses[0][1]),))
            return result
        return planted
    monkeypatch.setattr(discovery, "build_node", swap(discovery.build_node, trunk.OP))
    monkeypatch.setattr(trunk, "build_node", swap(trunk.build_node, "iosxe.show_cdp_neighbors_detail"))
    with pytest.raises(RunnerRefused, match="parse_owner"):
        p2.analyse_group(group)


def test_unowned_operation_and_corrupt_proof_are_refused(monkeypatch):
    group = bundle()
    changed = replace(group.captures[0], operation="iosxe.show_version")
    with pytest.raises(RunnerRefused, match="unowned_capture"):
        p2.analyse_group(replace(group, captures=(changed,) + group.captures[1:]))
    original = trunk._ref
    def corrupt(*args):
        return replace(original(*args), excerpt_sha256="0" * 64)
    monkeypatch.setattr(trunk, "_ref", corrupt)
    with pytest.raises(RunnerRefused, match="capture_hash"):
        p2.analyse_group(group)


def test_projection_copies_owner_verdict_without_comparing_values(monkeypatch):
    original = check.build_group
    def owner(group, store):
        result = original(group, store)
        return replace(result, rows=tuple(replace(row, state="unknown", reason=k.UnknownReason.AS_OF_MISSING)
                                          for row in result.rows))
    monkeypatch.setattr(check, "build_group", owner)
    payload, _ = p2.analyse_group(bundle())
    assert all(row["state"] == "unknown" and row["reason"] == "as_of_missing" for row in payload["findings"])


def test_catalogue_and_projection_reads_include_all_six_facts_and_five_steps():
    payload, _ = p2.analyse_group(bundle())
    assert p2.PROJECT.reads == IDS and p2.PROJECT.produces == () and p2.PROJECT.scope == "estate"
    assert {step.id for step in p2.STEPS} == {"l2.discovery/parse", "l2.vlan_trunk/parse", "l1.link/pair",
                                             "l2.vlan_trunk/check", "l2.vlan_trunk/project"}
    expected = build_catalogue(entity_kinds=link.KINDS, relations=link.RELATIONS,
                               facts=discovery.FACTS + trunk.FACTS + link.FACTS, steps=p2.STEPS)
    assert payload["catalogue_digest"] == catalogue_digest(expected)


def test_same_owner_cross_node_capture_receipts_are_refused(monkeypatch):
    group, original = bundle(), discovery.build_node
    def swapped(group, node, store):
        result = original(group, node, store)
        other = next(capture.id for capture in group.captures
                     if capture.source != node.key and capture.operation == "iosxe.show_cdp_neighbors_detail")
        quality = replace(result.parses[0][1], quality="partial" if node.id == "a" else "complete")
        return replace(result, parses=((other, quality),))
    monkeypatch.setattr(discovery, "build_node", swapped)
    with pytest.raises(RunnerRefused, match="^p2_parse_source$"):
        p2.analyse_group(group)
