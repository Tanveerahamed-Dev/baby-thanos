"""Actual synthetic admission/discovery/trunk/link builders feed conditional checks."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.synthetic import SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, bind_reader, bind_writer
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as trunk
from atlas_brain.packs.l2.vlan_trunk import check

P = "Gi1/0/1"


def bundle(native=("10", "20"), allowed=("10,30", "10,30"), missing_b=False):
    files, captures = {}, []
    for index, node in enumerate(("a", "b")):
        if missing_b and node == "b":
            continue
        peer = "b" if node == "a" else "a"
        outputs = (
            ("iosxe.show_cdp_neighbors_detail", "-------------------------\nDevice ID: sw-" + peer
             + "\nPlatform: synthetic-switch, Capabilities: Switch\nInterface: " + P
             + ", Port ID (outgoing port): " + P + "\n"),
            (trunk.OP, "Port Mode Encapsulation Status Native vlan\n" + P
             + " on 802.1q trunking " + native[index] + "\nPort Vlans allowed on trunk\n"
             + P + " " + allowed[index] + "\n"))
        for operation, text in outputs:
            path = node + "." + operation + ".txt"
            files[path] = text.encode()
            captures.append({"path": path, "node": node, "operation": operation,
                             "sha256": sha256(files[path]).hexdigest()})
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in ("a", "b")],
                "captures": captures}
    return admit_members({**files, "p2.json": json.dumps(manifest).encode()})


def produce(group, skip_trunk=()):
    store = FactStore()
    for node in group.nodes:
        discovery.build_node(group, node, store)
        if node.id not in skip_trunk:
            trunk.build_node(group, node, store)
    link.build_group(group, store)
    return store


def rows(result):
    return {row.check: row for row in result.rows}


def rewrite(group, original, change):
    reader, target = bind_reader(original, step=check.STEP), FactStore()
    writers = {link.PEER: bind_writer(target, step=link.STEP),
               trunk.NATIVE: bind_writer(target, step=trunk.STEP)}
    writers[trunk.ALLOWED] = writers[trunk.NATIVE]
    for node in group.nodes:
        for port in node.ports:
            subject = endpoint(node, port)
            for fact in check.STEP.reads:
                value = reader.read(fact=fact, subject=subject)
                writers[fact].write(fact=fact, subject=subject, value=change(node, fact, value))
    return target


def test_native_counterexample_cites_both_ends_and_never_claims_equal_health():
    group = bundle()
    store = produce(group)
    result = check.build_group(group, store)
    actual = rows(result)
    assert actual[check.NATIVE_CHECK].state == "problem" and actual[check.NATIVE_CHECK].reason is None
    assert actual[check.ALLOWED_CHECK].state == "unknown"
    assert actual[check.ALLOWED_CHECK].reason is k.UnknownReason.AS_OF_MISSING
    assert check.STEP.reads == tuple(sorted((link.PEER, trunk.NATIVE, trunk.ALLOWED)))
    assert check.STEP.produces == () and check.STEP.scope == "estate"
    assert order_steps((check.STEP, link.STEP, trunk.STEP, discovery.STEP))[-1] == check.STEP
    bound = bind_reader(store, step=check.STEP)
    captures = {c.id: c for c in group.captures}
    for row in result.rows:
        fact = trunk.NATIVE if row.check == check.NATIVE_CHECK else trunk.ALLOWED
        assert set(row.evidence) == {k.FactRef(fact=f, subject=s)
                                    for f in (link.PEER, fact) for s in (row.left, row.right)}
        assert all(isinstance(ref, k.FactRef) for ref in row.evidence)
        cited_nodes = set()
        for ref in row.evidence:
            state = bound.read(fact=ref.fact, subject=ref.subject)
            for evidence in state.evidence:
                if isinstance(evidence, k.EvidenceRef):
                    capture = captures[evidence.capture]
                    span = evidence.locator
                    raw = capture.raw[span.start:span.end] if isinstance(span, k.ByteSpan) else capture.raw
                    assert sha256(raw).hexdigest() == evidence.excerpt_sha256
                    cited_nodes.add(capture.source)
        assert cited_nodes == {node.key for node in group.nodes}
        assert {need.node for need in row.next_evidence} == {node.key for node in group.nodes}
        assert all(need.operation == trunk.OP for need in row.next_evidence)
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    assert result.coverage.evidence == group.declaration.evidence
    assert len(result.endpoints) == 2
    assert result.denominator == (("declared_endpoints", 2), ("reciprocal_pairs", 1), ("unresolved_endpoints", 0))
    for point in result.endpoints:
        assert bound.read(fact=trunk.NATIVE, subject=point.subject) is point.native


@pytest.mark.parametrize("native,allowed", [(("10", "10"), ("10,1-3,2,9", "1-3,9-10")),
                                           (("1", "1"), ("none", "none"))])
def test_equal_printed_inputs_are_unknown_without_time_and_view_proof(native, allowed):
    group = bundle(native, allowed)
    result = check.build_group(group, produce(group))
    assert len(result.rows) == 2
    assert all(row.state == "unknown" and row.reason is k.UnknownReason.AS_OF_MISSING for row in result.rows)


def test_blank_native_never_becomes_one():
    group = bundle(("", "1"))
    result = check.build_group(group, produce(group))
    row = rows(result)[check.NATIVE_CHECK]
    assert row.state == "unknown" and row.reason is k.UnknownReason.FIELD_NOT_PRINTED
    assert any(isinstance(point.native, k.Unknown) for point in result.endpoints)


@pytest.mark.parametrize("left,right", [("10,30", "10,20"), ("none", "1,3-4")])
def test_allowed_asymmetry_reports_canonical_directional_differences(left, right):
    group = bundle(("10", "10"), (left, right))
    result = check.build_group(group, produce(group))
    row = rows(result)[check.ALLOWED_CHECK]
    points = {point.subject: point for point in result.endpoints}
    assert row.state == "problem" and row.reason is None
    a_only, b_only = (("30", "20") if left != "none" else ("none", "1,3-4"))
    assert (row.left_only, row.right_only) == (
        (a_only, b_only) if points[row.left].node.id == "a" else (b_only, a_only))
    assert rows(result)[check.NATIVE_CHECK].reason is k.UnknownReason.AS_OF_MISSING


def test_blank_allowed_is_unknown_while_none_is_an_explicit_observed_empty_set():
    group = bundle(("10", "10"), ("none", ""))
    result = check.build_group(group, produce(group))
    assert rows(result)[check.ALLOWED_CHECK].state == "unknown"
    assert any(isinstance(point.allowed, k.Known) and point.allowed.value == "none" for point in result.endpoints)
    assert any(isinstance(point.allowed, k.Unknown) for point in result.endpoints)


def test_missing_end_preserves_every_declared_endpoint_and_both_checks():
    group = bundle(missing_b=True)
    result = check.build_group(group, produce(group))
    assert len(result.rows) == 4 and len(result.endpoints) == 2
    assert result.denominator == (("declared_endpoints", 2), ("reciprocal_pairs", 0), ("unresolved_endpoints", 2))
    assert all(row.state == "unknown" and row.right is None for row in result.rows)
    assert {row.reason for row in result.rows} == {
        k.UnknownReason.PEER_NOT_COLLECTED, k.UnknownReason.NOT_COLLECTED}
    for point in result.endpoints:
        own = [row for row in result.rows if row.left == point.subject]
        assert {row.check for row in own} == set(check.CHECKS)
        assert all(row.next_evidence for row in own)
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN


def test_order_and_raw_capture_availability_cannot_change_stored_fact_comparisons():
    group = bundle()
    expected = check.build_group(group, produce(group))
    reordered = replace(group, nodes=tuple(reversed(group.nodes)), captures=tuple(reversed(group.captures)))
    assert check.build_group(reordered, produce(reordered)) == expected
    assert check.build_group(replace(group, captures=()), produce(group)) == expected


def test_missing_producer_barrier_precedes_every_comparison(monkeypatch):
    group = bundle()
    store = produce(group, skip_trunk=("b",))
    monkeypatch.setattr(check, "_comparison", lambda *args: pytest.fail("evaluated before read barrier"))
    with pytest.raises(ValueError, match="missing_fact:"):
        check.build_group(group, store)
    with pytest.raises(ValueError, match="missing_producer:"):
        order_steps((check.STEP,))


@pytest.mark.parametrize("kind", ["integer_peer", "outside_peer", "self_peer", "observed_peer",
                                  "boolean_native", "noncanonical_allowed"])
def test_invalid_stored_payload_or_peer_contract_refuses(kind):
    group = bundle()
    store = produce(group)
    a = group.nodes[0]
    def change(node, fact, value):
        if node.id != "a":
            return value
        if fact == link.PEER:
            if kind == "integer_peer":
                return replace(value, value=7)
            if kind == "outside_peer":
                return replace(value, value="interface:unlisted")
            if kind == "self_peer":
                return replace(value, value=endpoint(a, P))
            if kind == "observed_peer":
                return replace(value, basis=k.Basis.OBSERVED)
        if fact == trunk.NATIVE and kind == "boolean_native":
            return replace(value, value=True)
        if fact == trunk.ALLOWED and kind == "noncanonical_allowed":
            return replace(value, value="30,10")
        return value
    with pytest.raises(ValueError, match="invalid_"):
        check.build_group(group, rewrite(group, store, change))
