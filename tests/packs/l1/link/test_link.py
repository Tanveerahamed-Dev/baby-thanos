"""Generated declared-synthetic oracles for the reciprocal stored-fact join."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.synthetic import SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, bind_reader, bind_writer
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery

P, Q, R = "Gi1/0/1", "Gi1/0/2", "Gi1/0/3"


def bundle(claims, ports=None, lldp=()):
    declared = ports or {"a": [P], "b": [Q], "c": [R]}
    by_node = {}
    for node, local, peer, remote, role in claims:
        by_node.setdefault(node, []).append(
            "-------------------------\nDevice ID: " + peer
            + "\nPlatform: synthetic-switch, Capabilities: " + role
            + "\nInterface: " + local + ", Port ID (outgoing port): " + remote + "\n")
    files = {node + ".txt": "".join(records).encode() for node, records in by_node.items()}
    captures = [{"node": node, "path": node + ".txt",
                 "operation": "iosxe.show_cdp_neighbors_detail",
                 "sha256": sha256(files[node + ".txt"]).hexdigest()} for node in by_node]
    for node, local, peer, remote, role in lldp:
        path = node + ".lldp.txt"
        files[path] = ("Local Intf: " + local + "\nPort id: " + remote + "\nSystem Name: " + peer
                       + ("\nEnabled Capabilities: " + role if role is not None else "") + "\n").encode()
        captures.append({"node": node, "path": path, "operation": "iosxe.show_lldp_neighbors_detail",
                         "sha256": sha256(files[path]).hexdigest()})
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": names}
                          for node, names in declared.items()],
                "captures": captures}
    return admit_members({**files, "p2.json": json.dumps(manifest).encode()})


def reciprocal():
    return [("a", P, "sw-b", Q, "Switch"), ("b", Q, "sw-a", P, "Switch")]


def parse(group, skip=()):
    store = FactStore()
    for node in group.nodes:
        if node.id not in skip:
            discovery.build_node(group, node, store)
    return store


def projection(store):
    step = StepSpec(id=StepId("l1.link/project"), pack=link.PACK, kind="derive", scope="estate",
                    reads=(link.PEER,), produces=(), evaluator="l1.link.test")
    return bind_reader(store, step=step)


def test_reciprocal_pair_uses_two_ended_fact_chains_and_is_stored_once():
    group = bundle(reciprocal())
    store = parse(group)
    result = link.build_group(group, store)
    a, b, c = result.rows
    assert a.subject == endpoint(a.node, P) and b.subject == endpoint(b.node, Q)
    assert result.pairs == (tuple(sorted((a.subject, b.subject))),)
    assert a.peer.value == b.subject and b.peer.value == a.subject
    assert c.peer.reason is k.UnknownReason.NOT_COLLECTED
    reader = bind_reader(store, step=link.STEP)
    captures = {capture.id: capture for capture in group.captures}
    for row in (a, b):
        assert row.peer.basis is k.Basis.DERIVED and row.peer.raw is None
        assert projection(store).read(fact=link.PEER, subject=row.subject) is row.peer
        refs = [ref for ref in row.peer.evidence if isinstance(ref, k.FactRef)]
        assert {(ref.fact, ref.subject) for ref in refs} == {
            (fact, subject) for fact in discovery.IDS for subject in (a.subject, b.subject)}
        assert group.declaration.evidence[0] in row.peer.evidence
        assert a.node.declaration.evidence[0] in row.peer.evidence
        assert b.node.declaration.evidence[0] in row.peer.evidence
        cited = set()
        for ref in refs:
            source = reader.read(fact=ref.fact, subject=ref.subject)
            for raw in (e for e in source.evidence if isinstance(e, k.EvidenceRef)):
                excerpt = captures[raw.capture].raw[raw.locator.start:raw.locator.end]
                assert sha256(excerpt).hexdigest() == raw.excerpt_sha256
                cited.add(captures[raw.capture].source)
        assert cited == {a.node.key, b.node.key}
    assert link.FACTS[0].value_type == "entity_ref" and link.FACTS[0].subject == "interface"
    assert [(kind.id, kind.root) for kind in link.KINDS] == [("node", True), ("interface", False)]
    relation, = link.RELATIONS
    assert (relation.source, relation.target, relation.cardinality) == ("interface", "interface", "one_to_one")


def test_parse_all_barrier_and_missing_producer_refuse_before_binding_writer(monkeypatch):
    group = bundle(reciprocal())
    store = parse(group, skip=("c",))
    binds = []
    original = link.bind_writer
    monkeypatch.setattr(link, "bind_writer", lambda *args, **kwargs: binds.append(True) or original(*args, **kwargs))
    with pytest.raises(ValueError, match="missing_fact:"):
        link.build_group(group, store)
    assert not binds
    for row in group.nodes:
        with pytest.raises(ValueError, match="missing_fact:"):
            projection(store).read(fact=link.PEER, subject=endpoint(row, row.ports[0]))
    with pytest.raises(ValueError, match="missing_producer:"):
        order_steps((link.STEP,))
    assert order_steps((link.STEP, discovery.STEP)) == (discovery.STEP, link.STEP)


def test_consumer_reads_the_stored_inputs_and_does_not_reparse_captures(monkeypatch):
    group = bundle(reciprocal())
    expected = link.build_group(group, parse(group))
    store = parse(group)
    monkeypatch.setattr(discovery, "_parse", lambda *a, **kw: pytest.fail("consumer reparsed raw captures"))
    monkeypatch.setattr(discovery, "build_node", lambda *a, **kw: pytest.fail("consumer reran foreign producer"))
    result = link.build_group(group, store)
    assert result == expected
    with pytest.raises(ValueError, match="duplicate_write:"):
        link.build_group(group, store)
    intruder = replace(link.STEP, id=StepId("l1.link/other"))
    with pytest.raises(ValueError, match="duplicate_owner:"):
        bind_writer(store, step=intruder)


def test_missing_reverse_requests_the_explicit_missing_node_and_both_protocols():
    group = bundle(reciprocal()[:1])
    result = link.build_group(group, parse(group))
    a, b, c = result.rows
    assert not result.pairs and a.peer.reason is k.UnknownReason.PEER_NOT_COLLECTED
    assert a.peer.candidates == (b.subject,) and b.peer.reason is k.UnknownReason.NOT_COLLECTED
    assert {need.operation for need in a.peer.next_evidence} == {
        "show cdp neighbors detail", "show lldp neighbors detail"}
    assert all(need.node == b.node.key for need in a.peer.next_evidence)
    assert c.peer.reason is k.UnknownReason.NOT_COLLECTED


@pytest.mark.parametrize("reverse", [("b", Q, "sw-c", P, "Switch"),
    ("b", Q, "unmapped", P, "Switch"), ("b", Q, "sw-a", R, "Switch")])
def test_explicit_asymmetry_is_fatal_before_any_partial_write(reverse, monkeypatch):
    group = bundle([reciprocal()[0], reverse])
    store = parse(group)
    monkeypatch.setattr(link, "bind_writer", lambda *args, **kwargs: pytest.fail("writer bound before validation"))
    with pytest.raises(ValueError, match="^asymmetric_discovery_claim$"):
        link.build_group(group, store)


@pytest.mark.parametrize("peer,remote,reason", [
    ("SW-B", Q, k.UnknownReason.IDENTITY_UNRESOLVED),
    ("sw-b.example", Q, k.UnknownReason.IDENTITY_UNRESOLVED),
    ("sw-b", "GigabitEthernet1/0/2", k.UnknownReason.JOIN_UNPROVEN)])
def test_alias_and_port_matching_are_exact(peer, remote, reason):
    group = bundle([("a", P, peer, remote, "Switch")])
    result = link.build_group(group, parse(group))
    assert not result.pairs and result.rows[0].peer.reason is reason


@pytest.mark.parametrize("role", ["Phone", "Host"])
def test_non_bridge_roles_never_form_a_known_pair(role):
    claims = reciprocal()
    claims[0] = ("a", P, "sw-b", Q, role)
    group = bundle(claims)
    result = link.build_group(group, parse(group))
    assert not result.pairs
    assert all(isinstance(row.peer, k.Unknown) for row in result.rows)


def test_self_loop_and_multiple_incoming_claims_refuse(monkeypatch):
    monkeypatch.setattr(link, "bind_writer", lambda *args, **kwargs: pytest.fail("writer bound before validation"))
    cases = [([("a", P, "sw-a", P, "Switch")], "self_discovery_claim"),
             (reciprocal() + [("c", R, "sw-b", Q, "Switch")], "contradictory_discovery_claims")]
    for claims, reason in cases:
        group = bundle(claims)
        with pytest.raises(ValueError, match="^" + reason + "$"):
            link.build_group(group, parse(group))


def test_node_and_capture_order_cannot_change_the_join():
    group = bundle(reciprocal(), ports={"a": [R, P], "b": [Q], "c": [R]})
    expected = link.build_group(group, parse(group))
    permuted = replace(group, nodes=tuple(reversed(group.nodes)), captures=tuple(reversed(group.captures)))
    assert link.build_group(permuted, parse(permuted)) == expected
    assert len(expected.rows) == 4 and len(expected.pairs) == 1


@pytest.mark.parametrize("role", ["W", None])
def test_ap_and_missing_bridge_capability_through_actual_admission_and_discovery(role):
    group = bundle([reciprocal()[1]], lldp=[("a", P, "sw-b", Q, role)])
    result = link.build_group(group, parse(group))
    assert not result.pairs and all(isinstance(row.peer, k.Unknown) for row in result.rows)
    if role is None:
        assert result.rows[0].peer.reason is k.UnknownReason.PARSE_PARTIAL


def test_multiple_claims_within_a_capture_are_independent_of_record_order():
    claims = reciprocal() + [("a", R, "sw-c", R, "Switch"), ("c", R, "sw-a", R, "Switch")]
    results = []
    for ordered in (claims, list(reversed(claims))):
        group = bundle(ordered, ports={"a": [P, R], "b": [Q], "c": [R]})
        result = link.build_group(group, parse(group))
        results.append((result.pairs, tuple((row.subject, row.peer.value if isinstance(row.peer, k.Known)
                                            else row.peer.reason) for row in result.rows)))
    assert results[0] == results[1] and len(results[0][0]) == 2


@pytest.mark.parametrize("roles,expected", [
    (("Phone", "Switch"), ("a",)),
    (("Switch", "Phone"), ("b",)),
    (("Phone", "Phone"), ("a", "b")),
])
def test_bridge_gaps_request_the_actual_failing_collectors_for_both_rows(roles, expected):
    claims = [(*claim[:4], role) for claim, role in zip(reciprocal(), roles, strict=True)]
    group = bundle(claims, ports={"a": [P], "b": [Q]})
    result = link.build_group(group, parse(group))
    keys = {node.key for node in group.nodes if node.id in expected}
    expected_requests = {(key, command) for key in keys
                         for command in ("show cdp neighbors detail", "show lldp neighbors detail")}
    assert not result.pairs and len(result.rows) == 2
    for row in result.rows:
        assert isinstance(row.peer, k.Unknown) and row.peer.reason is k.UnknownReason.NOT_OBSERVABLE
        requests = tuple((need.node, need.operation) for need in row.peer.next_evidence)
        assert set(requests) == expected_requests and requests == tuple(sorted(expected_requests))
