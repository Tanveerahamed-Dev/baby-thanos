"""Configured comparisons over actual admission, owner builders and reciprocal peers."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import CONFIG_SCHEMA, SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as observed
from atlas_brain.packs.l2.vlan_trunk import config_build as config
from atlas_brain.packs.l2.vlan_trunk import config_check as check
from atlas_brain.runner.p2_evidence import resolve_evidence

P = "Gi1/0/1"


def bundle(native=("10", "20"), allowed=("10,20", "10"), modes=("trunk", "trunk"),
           missing_config=(), missing_discovery=(), inherited=False, extra=False, observations=False, schema=CONFIG_SCHEMA):
    files, captures = {}, []
    for index, node in enumerate(("a", "b")):
        outputs = []
        peer = "b" if node == "a" else "a"
        if node not in missing_discovery:
            outputs.append(("iosxe.show_cdp_neighbors_detail",
                            "Device ID: sw-" + peer + "\nPlatform: synthetic-switch, Capabilities: Switch\n"
                            + "Interface: " + P + ", Port ID (outgoing port): " + P + "\n"))
        if node not in missing_config and schema == CONFIG_SCHEMA:
            mode = " no switchport\n" if modes[index] == "routed" else " switchport mode " + modes[index] + "\n"
            attrs = mode + (" switchport trunk native vlan " + native[index] + "\n" if native[index] is not None else "")
            attrs += " switchport trunk allowed vlan " + allowed[index] + "\n" if allowed[index] is not None else ""
            text = ("template EDGE\n" + attrs + "!\ninterface " + P + "\n source template EDGE\n!\nend\n"
                    if inherited else "interface " + P + "\n" + attrs + "!\nend\n")
            outputs.append((config.OP, text))
        if observations:
            outputs.append((observed.OP, "Port Mode Encapsulation Status Native vlan\n" + P
                            + " on 802.1q trunking 99\nPort Vlans allowed on trunk\n" + P + " 100\n"))
        for operation, text in outputs:
            path = node + "." + operation + ".txt"
            files[path] = text.encode()
            captures.append({"node": node, "path": path, "operation": operation,
                             "sha256": sha256(files[path]).hexdigest()})
    names = ("a", "b", "c") if extra else ("a", "b")
    manifest = {"schema": schema, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in names],
                "captures": captures}
    return admit_members({**files, "p2.json": canonical(manifest)})


def parse(group, skip_config=()):
    store = FactStore()
    for node in group.nodes:
        discovery.build_node(group, node, store)
        observed.build_node(group, node, store)
        if node.id not in skip_config:
            config.build_node(group, node, store)
    link.build_group(group, store)
    return store


def proof_reader(store):
    ids = tuple(sorted(discovery.IDS + config.IDS + (link.PEER,)))
    step = StepSpec(id=StepId("l2.vlan_trunk/config_proof"), pack=config.PACK, kind="derive",
                    scope="estate", reads=ids, produces=(), evaluator="l2.vlan_trunk.config_proof")
    return bind_reader(store, step=step)


def leaves(records):
    return [leaf for item in records for leaf in
            ([item] if item["kind"] == "capture" else
             leaves(item["state"]["evidence"]) if item["kind"] == "fact" else [])]


def test_inherited_mismatch_uses_both_configured_ends_mode_and_original_proof_chains():
    group = bundle(inherited=True)
    store = parse(group)
    result = check.build_group(group, store)
    assert len(result.rows) == 2 and {row.check for row in result.rows} == set(check.CHECKS)
    assert all(row.state == "problem" and row.reason is None for row in result.rows)
    assert dict(result.denominator) == {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    capture_map = {capture.id: capture for capture in group.captures}
    for row in result.rows:
        assert {(ref.fact, ref.subject) for ref in row.evidence} == {
            (fact, subject) for fact in (link.PEER, config.MODE,
                config.NATIVE if row.check == check.NATIVE_CHECK else config.ALLOWED)
            for subject in (row.left, row.right)}
        records = leaves(resolve_evidence(group, proof_reader(store), row.evidence))
        assert {(ref["source"], ref["operation"]) for ref in records} == {
            (node.key, operation) for node in group.nodes
            for operation in (config.OP, "iosxe.show_cdp_neighbors_detail")}
        for ref in records:
            raw = capture_map[ref["capture"]].raw
            assert sha256(raw[ref["start"]:ref["end"]]).hexdigest() == ref["sha256"]
        definitions = {capture_map[ref["capture"]].raw[ref["start"]:ref["end"]]
                       for ref in records if ref["operation"] == config.OP}
        assert {b"template EDGE", b"interface Gi1/0/1", b"EDGE", b"trunk"} <= definitions
    allowed = next(row for row in result.rows if row.check == check.ALLOWED_CHECK)
    a = endpoint(group.nodes[0], P)
    assert (allowed.left_only, allowed.right_only) == (("20", "none") if allowed.left == a else ("none", "20"))


def test_equal_untimed_config_is_unknown_and_never_healthy():
    group = bundle(native=("10", "10"), allowed=("10,20", "20,10"))
    result = check.build_group(group, parse(group))
    assert all(row.state == "unknown" and row.reason is k.UnknownReason.AS_OF_MISSING for row in result.rows)


@pytest.mark.parametrize("mode", ["access", "routed"])
def test_explicit_nontrunk_mode_cannot_produce_a_configured_mismatch(mode):
    group = bundle(modes=(mode, "trunk"))
    result = check.build_group(group, parse(group))
    assert all(row.state == "unknown" and row.reason is k.UnknownReason.NOT_OBSERVABLE for row in result.rows)


def test_missing_config_retains_both_endpoints_and_the_proven_pair():
    group = bundle(missing_config=("b",))
    result = check.build_group(group, parse(group))
    assert dict(result.denominator) == {"declared_endpoints": 2, "reciprocal_pairs": 1, "unresolved_endpoints": 0}
    assert all(row.state == "unknown" and row.reason is k.UnknownReason.NOT_COLLECTED for row in result.rows)
    assert {need.node for row in result.rows for need in row.next_evidence} == {node.key for node in group.nodes}


def test_missing_peer_and_third_declared_endpoint_never_shrink_the_population():
    group = bundle(missing_discovery=("b",), extra=True)
    result = check.build_group(group, parse(group))
    assert dict(result.denominator) == {"declared_endpoints": 3, "reciprocal_pairs": 0, "unresolved_endpoints": 3}
    assert len(result.rows) == 6 and all(row.state == "unknown" and row.right is None for row in result.rows)
    assert all(any(need.operation == config.OP for need in row.next_evidence) for row in result.rows)


def test_observed_decoys_cannot_replace_or_influence_configured_operands(monkeypatch):
    group = bundle(observations=True)
    store = parse(group)
    original = check.bind_reader
    class OnlyConfigured:
        def read(self, **kwargs):
            assert kwargs["fact"] not in (observed.NATIVE, observed.ALLOWED)
            return delegate.read(**kwargs)
    delegate = original(store, step=check.STEP)
    monkeypatch.setattr(check, "bind_reader", lambda *args, **kwargs: OnlyConfigured())
    monkeypatch.setattr(config, "build_node", lambda *args: pytest.fail("check reparsed config"))
    monkeypatch.setattr(observed, "build_node", lambda *args: pytest.fail("check reparsed operational data"))
    result = check.build_group(group, store)
    assert all(row.state == "problem" for row in result.rows)
    assert set(check.STEP.reads) == {link.PEER, *config.IDS}


def test_all_reads_precede_comparison_and_missing_owner_refuses(monkeypatch):
    group = bundle()
    store = parse(group, skip_config=("b",))
    monkeypatch.setattr(check, "_comparison", lambda *args: pytest.fail("comparison before complete input matrix"))
    with pytest.raises(ValueError, match="missing_fact:"):
        check.build_group(group, store)
    with pytest.raises(ValueError, match="missing_producer:"):
        order_steps((check.STEP, link.STEP, discovery.STEP))


@pytest.mark.parametrize("plant", ["basis", "native_bool", "native_range", "mode", "allowed", "peer"])
def test_invalid_stored_contracts_refuse_instead_of_rederiving_or_normalizing(plant, monkeypatch):
    group = bundle()
    store = parse(group)
    delegate = check.bind_reader(store, step=check.STEP)
    targets = {"basis": config.NATIVE, "native_bool": config.NATIVE, "native_range": config.NATIVE,
               "mode": config.MODE, "allowed": config.ALLOWED, "peer": link.PEER}
    values = {"native_bool": True, "native_range": 4095, "mode": "dynamic",
              "allowed": "20,10", "peer": "interface:foreign"}
    class Planted:
        def read(self, **kwargs):
            state = delegate.read(**kwargs)
            if kwargs["fact"] == targets[plant] and isinstance(state, k.Known):
                return replace(state, basis=k.Basis.OBSERVED) if plant == "basis" else replace(state, value=values[plant])
            return state
    monkeypatch.setattr(check, "bind_reader", lambda *args, **kwargs: Planted())
    with pytest.raises(ValueError, match="invalid_config"):
        check.build_group(group, store)


def test_node_and_capture_permutations_preserve_configured_verdict_order():
    group = bundle(inherited=True, extra=True)
    expected = check.build_group(group, parse(group))
    changed = replace(group, nodes=tuple(reversed(group.nodes)), captures=tuple(reversed(group.captures)))
    assert check.build_group(changed, parse(changed)) == expected


def test_v1_group_cannot_read_configured_facts_even_with_identical_endpoint_keys(monkeypatch):
    configured, legacy = bundle(), bundle(schema=SCHEMA)
    store = parse(configured)
    assert tuple(endpoint(node, P) for node in configured.nodes) == tuple(endpoint(node, P) for node in legacy.nodes)
    monkeypatch.setattr(check, "bind_reader", lambda *args, **kwargs: pytest.fail("read before schema guard"))
    monkeypatch.setattr(check, "_comparison", lambda *args: pytest.fail("comparison before schema guard"))
    with pytest.raises(ValueError, match="^configured_group_schema_required$"):
        check.build_group(legacy, store)
