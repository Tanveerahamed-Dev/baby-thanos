"""Generated trunk tables; synthetic parser oracles, not platform qualification."""
import json
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.synthetic import SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.vlan_trunk import build as trunk

HEADER = b"Port Mode Encapsulation Status Native vlan\n"
NATIVE_ROW = b"Gi1/0/1 on 802.1q trunking 10\n"
ALLOWED_HEADER = b"Port Vlans allowed on trunk\n"
ALLOWED_ROW = b"Gi1/0/1 1-3,9,10\n"
ACTIVE = b"Port Vlans allowed and active in management domain\nGi1/0/1 2\n"
FORWARD = b"Port Vlans in spanning tree forwarding state and not pruned\nGi1/0/1 3\n"
GOOD = HEADER + NATIVE_ROW + ALLOWED_HEADER + ALLOWED_ROW + ACTIVE + FORWARD


def bundle(raw, ports=("Gi1/0/1",), operation=trunk.OP):
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": "a", "discovery_id": "sw-a", "ports": list(ports)},
                          {"id": "b", "discovery_id": "sw-b", "ports": ["Gi1/0/1"]}],
                "captures": [{"path": "a.txt", "node": "a", "operation": operation,
                              "sha256": sha256(raw).hexdigest()}]}
    return admit_members({"p2.json": json.dumps(manifest).encode(), "a.txt": raw})


def reader(store):
    consumer = StepSpec(id=StepId("l1.link/trunk"), pack=k.PackId("l1.link"), kind="derive",
                        scope="estate", reads=(trunk.ALLOWED, trunk.NATIVE), produces=(), evaluator="l1.link.test")
    return bind_reader(store, step=consumer)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_owned_facts_bind_exact_columns_and_declared_subjects(ending):
    raw = GOOD.replace(b"\n", ending)
    group, store = bundle(raw), FactStore()
    node = group.nodes[0]
    result = trunk.build_node(group, node, store)
    row, = result.rows
    capture, = group.captures
    assert result.quality == "complete" and (row.native.value, row.allowed.value) == (10, "1-3,9-10")
    assert row.allowed.raw == "1-3,9,10" and row.subject == endpoint(node, "Gi1/0/1")
    assert trunk.STEP.produces == tuple(f.id for f in trunk.FACTS) == (trunk.ALLOWED, trunk.NATIVE)
    assert tuple(f.value_type for f in trunk.FACTS) == ("text", "integer") and trunk.STEP.reads == ()
    bound = reader(store)
    for identifier, fact in ((trunk.NATIVE, row.native), (trunk.ALLOWED, row.allowed)):
        assert bound.read(fact=identifier, subject=row.subject) is fact
        assert fact.basis is k.Basis.OBSERVED
        assert group.declaration.evidence[0] in fact.evidence and node.declaration.evidence[0] in fact.evidence
        refs = [ref for ref in fact.evidence if isinstance(ref, k.EvidenceRef)]
        assert refs and all(isinstance(ref.locator, k.ByteSpan) for ref in refs)
        for ref in refs:
            excerpt = raw[ref.locator.start:ref.locator.end]
            assert ref.capture == capture.id and ref.excerpt_sha256 == sha256(excerpt).hexdigest()
        if identifier == trunk.ALLOWED:
            assert any(raw[ref.locator.start:ref.locator.end] == ALLOWED_ROW.rstrip(b"\n") for ref in refs)
        first = refs[0].locator
        assert raw[first.start:first.end] == fact.raw.encode()
    _, parsed = result.parses[0]
    assert parsed.quality == "complete"
    assert b"".join(raw[line.span.start:line.span.end] for line in parsed.lines) == raw == capture.raw
    assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
    assert isinstance(capture.collected_utc, k.Unknown)


@pytest.mark.parametrize("token,canonical", [("all", "1-4094"), ("none", "none"),
    ("4094", "4094"), ("10,1-3,2,9", "1-3,9-10")])
def test_explicit_allowed_semantics_are_bounded_and_canonical(token, canonical):
    group = bundle(GOOD.replace(ALLOWED_ROW, ("Gi1/0/1 " + token + "\n").encode()))
    row, = trunk.build_node(group, group.nodes[0], FactStore()).rows
    assert isinstance(row.allowed, k.Known) and row.allowed.value == canonical and row.allowed.raw == token


@pytest.mark.parametrize("token", ["", "0", "4095", "03", "4-2", "1,", "1--2", "1-4,all", "None", "1 2"])
def test_partial_or_invalid_allowed_list_never_becomes_positive(token):
    group = bundle(GOOD.replace(ALLOWED_ROW, ("Gi1/0/1 " + token + "\n").encode()))
    result = trunk.build_node(group, group.nodes[0], FactStore())
    assert result.quality == "partial" and isinstance(result.rows[0].allowed, k.Unknown)


@pytest.mark.parametrize("token", ["", "0", "4095", "01"])
def test_native_missing_or_invalid_never_defaults_to_one(token):
    raw = GOOD.replace(NATIVE_ROW, ("Gi1/0/1 on 802.1q trunking " + token + "\n").encode())
    group = bundle(raw)
    result = trunk.build_node(group, group.nodes[0], FactStore())
    assert result.quality == "partial" and isinstance(result.rows[0].native, k.Unknown)


@pytest.mark.parametrize("old,new", [(b"trunking", b"not-trunking"), (b"trunking", b"routed"),
    (b"trunking", b"unsupported"), (b"on 802.1q", b"off 802.1q"), (b"on 802.1q", b"on negotiate"),
    (b"on 802.1q", b"on isl")])
def test_nontrunking_or_inconsistent_status_never_gives_trunk_facts(old, new):
    group = bundle(GOOD.replace(NATIVE_ROW, NATIVE_ROW.replace(old, new)))
    row, = trunk.build_node(group, group.nodes[0], FactStore()).rows
    assert isinstance(row.native, k.Unknown) and isinstance(row.allowed, k.Unknown)


@pytest.mark.parametrize("raw,reason", [
    (GOOD.replace(NATIVE_ROW, NATIVE_ROW * 2), k.UnknownReason.CONFLICTING_EVIDENCE),
    (GOOD.replace(ALLOWED_ROW, ALLOWED_ROW * 2), k.UnknownReason.CONFLICTING_EVIDENCE),
    (GOOD.replace(ACTIVE, ACTIVE + b"Gi1/0/1 4\n"), k.UnknownReason.CONFLICTING_EVIDENCE),
    (GOOD + b"Gi1/0/1 4\n", k.UnknownReason.CONFLICTING_EVIDENCE),
    (GOOD + b"unmodelled tail\n", k.UnknownReason.PARSE_PARTIAL),
    (GOOD + ALLOWED_HEADER + ALLOWED_ROW, k.UnknownReason.CONFLICTING_EVIDENCE),
    (GOOD.replace(ACTIVE, ACTIVE.replace(b" 2\n", b" 4095\n")), k.UnknownReason.PARSE_PARTIAL),
    (b"", k.UnknownReason.EMPTY_UNREGISTERED), (b"% Invalid input\n", k.UnknownReason.CAPTURE_ERROR),
    (GOOD + b"[truncated]\n", k.UnknownReason.CAPTURE_TRUNCATED),
])
def test_incomplete_duplicate_and_mixed_input_preserves_unknown_and_targeted_need(raw, reason):
    group = bundle(raw, ports=("Gi1/0/1", "Gi1/0/2"))
    result = trunk.build_node(group, group.nodes[0], FactStore())
    assert result.quality == "partial" and len(result.rows) == 2
    for row in result.rows:
        for fact in (row.native, row.allowed):
            assert isinstance(fact, k.Unknown) and fact.reason is reason
            need, = fact.next_evidence
            assert need.node == group.nodes[0].key and need.operation == trunk.OP
            assert need.resolves == (trunk.ALLOWED, trunk.NATIVE) and need.reruns == (str(trunk.STEP.id),)


def test_missing_native_or_allowed_row_and_uncollected_node_keep_all_declared_writes():
    group, store = bundle(HEADER + NATIVE_ROW, ports=("Gi1/0/1", "Gi1/0/2")), FactStore()
    result = trunk.build_node(group, group.nodes[0], store)
    first, missing = result.rows
    assert isinstance(first.native, k.Known) and first.allowed.reason is k.UnknownReason.FIELD_NOT_PRINTED
    assert missing.native.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    other = trunk.build_node(group, group.nodes[1], store).rows[0]
    assert other.native.reason is k.UnknownReason.NOT_COLLECTED and other.subject != first.subject
    bound = reader(store)
    for row in (*result.rows, other):
        assert bound.read(fact=trunk.NATIVE, subject=row.subject) is row.native
        assert bound.read(fact=trunk.ALLOWED, subject=row.subject) is row.allowed


@pytest.mark.parametrize("raw", [GOOD.replace(b"Gi1/0/1", b"Gi1/0/2"), GOOD + b"Gi1/0/2 broken\n"])
def test_extra_observed_local_port_refuses_before_any_store_mutation(raw):
    group, store = bundle(raw), FactStore()
    with pytest.raises(AdmissionRefused, match="synthetic_undeclared_port"):
        trunk.build_node(group, group.nodes[0], store)
    assert not store.values and not store.owners
