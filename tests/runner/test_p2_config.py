"""Real admitted schema-2 owners stay separated through configured-intent projection."""
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import CONFIG_SCHEMA, admit_members
from atlas_brain.kernel import states as k
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as trunk
from atlas_brain.packs.l2.vlan_trunk import check, config_build, config_check
from atlas_brain.runner import p2, p2_config
from atlas_brain.runner.records import RunnerRefused

P = "Gi1/0/1"
CDP = "iosxe.show_cdp_neighbors_detail"


def members(*, observed=("10", "20"), configured=("100", "200"), equal_observed=False,
            equal_configured=False, missing_config=False, missing_peer=False, without_observed=False):
    files, references = {}, []
    for index, node in enumerate(("a", "b")):
        peer = "b" if node == "a" else "a"
        allowed = "10,30" if equal_observed or index == 0 else "10,20"
        intent_allowed = "100,300" if equal_configured or index == 0 else "100,200"
        outputs = [
            (CDP, "Device ID: sw-" + peer + "\nPlatform: synthetic-switch, Capabilities: Switch\n"
             + "Interface: " + P + ", Port ID (outgoing port): " + P + "\n"),
            (trunk.OP, "Port Mode Encapsulation Status Native vlan\n" + P + " on 802.1q trunking "
             + observed[index] + "\nPort Vlans allowed on trunk\n" + P + " " + allowed + "\n"),
            (config_build.OP, "template BASE\n switchport mode trunk\n switchport trunk native vlan "
             + configured[index] + "\n!\ntemplate EDGE\n source template BASE\n switchport trunk allowed vlan "
             + intent_allowed + "\n!\ninterface " + P + "\n source template EDGE\n!\nend\n"),
        ]
        for operation, text in outputs:
            if without_observed and operation == trunk.OP:
                continue
            if node == "b" and (missing_config and operation == config_build.OP or missing_peer and operation == CDP):
                continue
            path = node + "." + operation + ".txt"
            files[path] = text.encode()
            references.append({"path": path, "node": node, "operation": operation,
                               "sha256": sha256(files[path]).hexdigest()})
    manifest = {"schema": CONFIG_SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in ("a", "b")],
                "captures": references}
    return {**files, "p2.json": canonical(manifest)}


def bundle(**kwargs):
    return admit_members(members(**kwargs))


def leaves(records):
    return [leaf for item in records for leaf in
            ([item] if item["kind"] == "capture" else
             leaves(item["state"]["evidence"]) if item["kind"] == "fact" else [])]


@pytest.mark.parametrize("equal_basis", ["neither", "observed", "configured"])
def test_all_owner_builders_keep_inherited_intent_and_operational_counterexamples_separate(equal_basis):
    group = bundle(observed=("10", "10") if equal_basis == "observed" else ("10", "20"),
                   configured=("100", "100") if equal_basis == "configured" else ("100", "200"),
                   equal_observed=equal_basis == "observed", equal_configured=equal_basis == "configured")
    payload, summary = p2_config.analyse_group(group)
    assert payload["schema"] == "atlas-brain.p2-demo/2" and payload["variant_support"] == "allowlisted"
    assert len(payload["endpoints"]) == 2 and len(payload["findings"]) == 4 and len(payload["captures"]) == 6
    assert payload["denominator"] == {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    configuration = payload["configuration"]
    assert configuration["basis"] == "configured" and configuration["interpretation"] == "supplied_statements_only"
    assert configuration["comparison"] == "configuration_only_no_cross_basis_inference"
    assert configuration["denominator"] == payload["denominator"]
    assert configuration["coverage"]["reason"] == payload["coverage"]["reason"] == "denominator_open"
    assert payload["registry_sha256"] == sha256(group.raw).hexdigest()
    captures = {capture.id: capture for capture in group.captures}
    for point in payload["endpoints"]:
        assert len(point["facts"]) == 9 and tuple(point["facts"]) == p2_config.FACT_IDS
        assert point["facts"][str(config_build.MODE)]["value"] == "trunk"
        assert all(point["facts"][str(fact)]["basis"] == "configured" for fact in config_build.IDS)
        assert point["facts"][str(trunk.NATIVE)]["basis"] == "observed"
    for finding in payload["findings"]:
        configured = finding["check"] in config_check.CHECKS
        assert finding["check"] in check.CHECKS + config_check.CHECKS
        equal = equal_basis == ("configured" if configured else "observed")
        assert (finding["state"], finding["reason"]) == (("unknown", "as_of_missing") if equal else ("problem", None))
        refs = leaves(finding["evidence"])
        expected_op = config_build.OP if configured else trunk.OP
        assert {(ref["source"], ref["operation"]) for ref in refs} == {
            (node.key, operation) for node in group.nodes for operation in (CDP, expected_op)}
        excerpts = set()
        for ref in refs:
            capture = captures[ref["capture"]]
            raw = capture.raw[ref["start"]:ref["end"]]
            assert 0 <= ref["start"] < ref["end"] <= len(capture.raw)
            assert ref["source"] == capture.source and ref["capture_sha256"] == capture.bytes_sha256
            assert sha256(raw).hexdigest() == ref["sha256"]
            excerpts.add(raw)
        if configured:
            assert {b"template BASE", b"template EDGE", b"interface Gi1/0/1", b"BASE", b"EDGE"} <= excerpts
    assert any(config_check.NATIVE_CHECK in line and "a/" + P + "=100" in line for line in summary)
    for capture in payload["captures"]:
        assert capture["read_scope"] == capture["view"] == "unknown"
        assert capture["collected_utc"]["reason"] == "as_of_missing"
    assert "configuration_only_no_cross_basis_inference" in summary[1]


@pytest.mark.parametrize("missing", ["config", "peer"])
def test_removing_evidence_cannot_erase_expected_subjects_or_borrow_other_basis(missing):
    payload, _ = p2_config.analyse_group(bundle(missing_config=missing == "config", missing_peer=missing == "peer"))
    assert len(payload["endpoints"]) == 2 and payload["configuration"]["denominator"]["declared_endpoints"] == 2
    configured = [row for row in payload["findings"] if row["check"] in config_check.CHECKS]
    assert configured and all(row["state"] == "unknown" and row["next_evidence"] for row in configured)
    if missing == "peer":
        assert len(payload["findings"]) == 8 and all(row["state"] == "unknown" for row in payload["findings"])
        assert payload["denominator"]["unresolved_endpoints"] == 2
    else:
        missing_point = next(point for point in payload["endpoints"] if point["node"] == "b")
        assert all(missing_point["facts"][str(fact)]["state"] == "unknown" for fact in config_build.IDS)
        assert all(row["state"] == "problem" for row in payload["findings"] if row["check"] in check.CHECKS)


def test_three_node_producers_finish_before_link_or_either_comparison(monkeypatch):
    done, estates = [], []
    for label, module in (("discovery", discovery), ("observed", trunk), ("configured", config_build)):
        original = module.build_node
        def wrapped(group, node, store, original=original, label=label):
            result = original(group, node, store)
            done.append((label, node.id))
            return result
        monkeypatch.setattr(module, "build_node", wrapped)
    expected = {(label, node) for label in ("discovery", "observed", "configured") for node in ("a", "b")}
    for label, module in (("link", link), ("observed", check), ("configured", config_check)):
        original = module.build_group
        def wrapped(group, store, original=original, label=label):
            assert len(done) == 6 and set(done) == expected
            estates.append(label)
            return original(group, store)
        monkeypatch.setattr(module, "build_group", wrapped)
    p2_config.analyse_group(bundle())
    assert estates == ["link", "observed", "configured"]


def test_late_configuration_failure_prevents_every_estate_consumer(monkeypatch):
    original = config_build.build_node
    def failed(group, node, store):
        if node.id == "b":
            raise ValueError("late_config_failure")
        return original(group, node, store)
    def forbidden(*args):
        raise AssertionError("estate_before_all_config")
    monkeypatch.setattr(config_build, "build_node", failed)
    for module in (link, check, config_check):
        monkeypatch.setattr(module, "build_group", forbidden)
    with pytest.raises(ValueError, match="late_config_failure"):
        p2_config.analyse_group(bundle())


@pytest.mark.parametrize("plant", ["skip", "duplicate", "foreign", "cross_node"])
def test_configuration_receipts_bind_every_capture_owner_and_invoking_source(monkeypatch, plant):
    original = config_build.build_node
    def planted(group, node, store):
        result = original(group, node, store)
        if plant == "cross_node":
            other = next(capture.id for capture in group.captures
                         if capture.operation == config_build.OP and capture.source != node.key)
            return replace(result, parses=((other, result.parses[0][1]),))
        if node.id == "a":
            parses = (() if plant == "skip" else result.parses * 2 if plant == "duplicate" else
                      ((k.CaptureId("cap:foreign"), result.parses[0][1]),))
            return replace(result, parses=parses)
        return result
    monkeypatch.setattr(config_build, "build_node", planted)
    reason = "parse_source" if plant == "cross_node" else "parse_coverage"
    with pytest.raises(RunnerRefused, match="^p2_config_" + reason + "$"):
        p2_config.analyse_group(bundle())


def test_permutations_and_catalogue_are_deterministic_without_changing_legacy_projection():
    group = bundle()
    payload, summary = p2_config.analyse_group(group)
    changed = replace(group, nodes=tuple(reversed(group.nodes)), captures=tuple(reversed(group.captures)))
    assert canonical((payload, summary)) == canonical(p2_config.analyse_group(changed))
    expected = build_catalogue(entity_kinds=link.KINDS, relations=link.RELATIONS,
        facts=discovery.FACTS + trunk.FACTS + config_build.FACTS + link.FACTS, steps=p2_config.STEPS)
    assert payload["catalogue_digest"] == catalogue_digest(expected)
    assert len(p2_config.PROJECT.reads) == 9 and len(p2_config.STEPS) == 7 and p2.PROJECT not in p2_config.STEPS
    assert p2.SCHEMA == "atlas-brain.p2-demo/1" and len(p2.FACT_IDS) == 6


def test_hash_seeds_and_version_boundary_do_not_create_an_implicit_config_lane():
    script = ("import sys; from atlas_brain.contract.canonical import canonical; "
              "from atlas_brain.evidence.synthetic import admit_members; "
              "from atlas_brain.runner.p2_config import analyse_group; "
              "sys.stdout.buffer.write(canonical(analyse_group(admit_members(" + repr(members()) + "))))")
    outputs = [subprocess.run([sys.executable, "-c", script], capture_output=True, check=True, timeout=60,
                              env={**os.environ, "PYTHONHASHSEED": seed}).stdout for seed in ("1", "97")]
    assert outputs[0] == outputs[1]
    with pytest.raises(RunnerRefused, match="^p2_config_group_schema$"):
        p2_config.analyse_group(replace(bundle(), schema="atlas-brain.synthetic-p2/1"))


def test_same_node_cross_owner_capture_receipt_swap_is_refused(monkeypatch):
    def swap(original, operation):
        def planted(group, node, store):
            result = original(group, node, store)
            if node.id == "a":
                other = next(c.id for c in group.captures if c.source == node.key and c.operation == operation)
                return replace(result, parses=((other, result.parses[0][1]),))
            return result
        return planted
    monkeypatch.setattr(trunk, "build_node", swap(trunk.build_node, config_build.OP))
    monkeypatch.setattr(config_build, "build_node", swap(config_build.build_node, trunk.OP))
    with pytest.raises(RunnerRefused, match="^p2_config_parse_owner$"):
        p2_config.analyse_group(bundle())


def test_renderer_copies_configured_owner_verdict_without_recomparing_operands(monkeypatch):
    original = config_check.build_group
    def changed(group, store):
        result = original(group, store)
        return replace(result, rows=tuple(replace(row, state="unknown", reason=k.UnknownReason.ANALYSIS_GAP)
                                          for row in result.rows))
    monkeypatch.setattr(config_check, "build_group", changed)
    payload, _ = p2_config.analyse_group(bundle())
    assert all(row["state"] == "unknown" and row["reason"] == "analysis_gap"
               for row in payload["findings"] if row["check"] in config_check.CHECKS)
    assert all(row["state"] == "problem" for row in payload["findings"] if row["check"] in check.CHECKS)


def test_config_only_inputs_never_fill_operational_operands():
    payload, _ = p2_config.analyse_group(bundle(without_observed=True))
    assert all(row["state"] == "unknown" for row in payload["findings"] if row["check"] in check.CHECKS)
    assert all(row["state"] == "problem" for row in payload["findings"] if row["check"] in config_check.CHECKS)
    assert all(point["facts"][str(trunk.NATIVE)]["reason"] == "not_collected" for point in payload["endpoints"])
