"""Admitted schema-2 config intent uses its own owner, registry and byte proofs."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.synthetic import CONFIG_COMMAND, CONFIG_OPERATION, CONFIG_SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.vlan_trunk import build as operational
from atlas_brain.packs.l2.vlan_trunk import config_build as configured

P, Q = "Gi1/0/1", "Gi1/0/2"
CONFIG = (b"template BASE\n switchport mode trunk\n switchport trunk native vlan 10\n!\n"
          b"template EDGE\n source template BASE\n switchport trunk allowed vlan 10,20\n!\n"
          b"interface Gi1/0/1\n source template EDGE\n!\nend\n")
TRUNK = (b"Port Mode Encapsulation Status Native vlan\nGi1/0/1 on 802.1q trunking 99\n"
         b"Port Vlans allowed on trunk\nGi1/0/1 100\n")


def bundle(raw=CONFIG, ports=(P,), source="a", show=False):
    files = {"config.txt": raw}
    references = [{"path": "config.txt", "node": source, "operation": CONFIG_OPERATION,
                   "sha256": sha256(raw).hexdigest()}]
    if show:
        files["trunk.txt"] = TRUNK
        references.append({"path": "trunk.txt", "node": "a", "operation": operational.OP,
                           "sha256": sha256(TRUNK).hexdigest()})
    manifest = {"schema": CONFIG_SCHEMA, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": "a", "discovery_id": "sw-a", "ports": list(ports)},
                          {"id": "b", "discovery_id": "sw-b", "ports": [P]}], "captures": references}
    return admit_members({**files, "p2.json": json.dumps(manifest).encode()})


def reader(store, observed=False):
    reads = tuple(sorted(configured.IDS + (operational.STEP.produces if observed else ())))
    step = StepSpec(id=StepId("l2.vlan_trunk/config_project"), pack=configured.PACK,
                    kind="derive", scope="estate", reads=reads, produces=(),
                    evaluator="l2.vlan_trunk.config_test")
    return bind_reader(store, step=step)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_inherited_configured_facts_are_owned_once_and_keep_complete_lineage(ending):
    raw = CONFIG.replace(b"\n", ending)
    group, store = bundle(raw), FactStore()
    node = group.nodes[0]
    result = configured.build_node(group, node, store)
    row, = result.rows
    capture, = group.captures
    assert result.quality == "complete" and result.parses[0][0] == capture.id
    assert result.parses[0][1].quality == "complete"
    assert (row.local_port, row.subject) == (P, endpoint(node, P))
    assert (row.mode.value, row.native.value, row.allowed.value) == ("trunk", 10, "10,20")
    assert configured.OP == CONFIG_OPERATION and configured.COMMAND == CONFIG_COMMAND
    assert configured.STEP.id == "l2.vlan_trunk/parse_config" and configured.STEP.reads == ()
    assert configured.IDS == tuple(spec.id for spec in configured.FACTS) == configured.STEP.produces
    assert [(spec.id, spec.value_type) for spec in configured.FACTS] == [
        (configured.ALLOWED, "text"), (configured.MODE, "text"), (configured.NATIVE, "integer")]
    bound = reader(store)
    required = {b"template BASE", b"template EDGE", b"interface Gi1/0/1", b"BASE", b"EDGE"}
    for identifier, fact in ((configured.MODE, row.mode), (configured.NATIVE, row.native),
                             (configured.ALLOWED, row.allowed)):
        assert bound.read(fact=identifier, subject=row.subject) is fact
        assert fact.basis is k.Basis.CONFIGURED
        assert group.declaration.evidence[0] in fact.evidence and node.declaration.evidence[0] in fact.evidence
        refs = [ref for ref in fact.evidence if isinstance(ref, k.EvidenceRef)]
        assert refs and all(isinstance(ref.locator, k.ByteSpan) for ref in refs)
        excerpts = set()
        for ref in refs:
            assert ref.capture == capture.id and 0 <= ref.locator.start < ref.locator.end <= len(raw)
            excerpt = raw[ref.locator.start:ref.locator.end]
            assert sha256(excerpt).hexdigest() == ref.excerpt_sha256
            excerpts.add(excerpt)
        assert required <= excerpts
    assert capture.raw == raw and capture.read_scope is k.ReadScope.UNKNOWN
    assert capture.view is k.ViewConsistency.UNKNOWN and isinstance(capture.collected_utc, k.Unknown)


def test_configured_and_operational_operands_are_distinct_and_never_overwrite_each_other():
    group, store = bundle(show=True), FactStore()
    node = group.nodes[0]
    observed = operational.build_node(group, node, store).rows[0]
    intent = configured.build_node(group, node, store).rows[0]
    assert (observed.native.value, observed.allowed.value) == (99, "100")
    assert (intent.native.value, intent.allowed.value) == (10, "10,20")
    assert set(configured.IDS).isdisjoint(operational.STEP.produces)
    bound = reader(store, observed=True)
    assert bound.read(fact=operational.NATIVE, subject=observed.subject) is observed.native
    assert bound.read(fact=operational.ALLOWED, subject=observed.subject) is observed.allowed
    assert bound.read(fact=configured.NATIVE, subject=intent.subject) is intent.native
    assert {ref.capture for ref in intent.native.evidence if isinstance(ref, k.EvidenceRef)} == {
        capture.id for capture in group.captures if capture.operation == CONFIG_OPERATION}


def test_uncollected_node_still_receives_every_declared_configured_fact_and_targeted_need():
    group, store = bundle(source="b", ports=(P, Q)), FactStore()
    node = group.nodes[0]
    result = configured.build_node(group, node, store)
    assert result.quality == "partial" and result.parses == () and len(result.rows) == 2
    bound = reader(store)
    for row in result.rows:
        for identifier, fact in ((configured.MODE, row.mode), (configured.NATIVE, row.native),
                                 (configured.ALLOWED, row.allowed)):
            assert bound.read(fact=identifier, subject=row.subject) is fact
            assert fact.reason is k.UnknownReason.NOT_COLLECTED
            need, = fact.next_evidence
            assert need.node == node.key and need.operation == CONFIG_OPERATION
            assert need.resolves == configured.IDS and need.reruns == (str(configured.STEP.id),)


@pytest.mark.parametrize("replacement,reason", [
    (b" source template EDGE merge\n", k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (b" strange-command value\n", k.UnknownReason.PARSE_PARTIAL),
])
def test_parser_poison_is_preserved_in_all_fields_and_all_expected_endpoints(replacement, reason):
    raw = CONFIG.replace(b" source template EDGE\n", replacement)
    group, store = bundle(raw, ports=(P, Q)), FactStore()
    result = configured.build_node(group, group.nodes[0], store)
    assert result.quality == "partial" and len(result.rows) == 2
    assert all(isinstance(fact, k.Unknown) and fact.reason is reason and fact.next_evidence
               for row in result.rows for fact in (row.mode, row.native, row.allowed))


def test_unmentioned_interface_and_omitted_mode_do_not_become_configured_trunks():
    raw = b"interface Gi1/0/1\n switchport trunk native vlan 10\n!\nend\n"
    group = bundle(raw, ports=(P, Q))
    result = configured.build_node(group, group.nodes[0], FactStore())
    assert all(fact.reason is k.UnknownReason.DEFAULT_UNKNOWN
               for fact in (result.rows[0].mode, result.rows[0].native, result.rows[0].allowed))
    assert result.rows[1].mode.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE


def test_extra_local_port_refuses_before_any_owner_or_value_mutation():
    group, store = bundle(CONFIG.replace(b"interface Gi1/0/1", b"interface Gi1/0/99")), FactStore()
    with pytest.raises(AdmissionRefused, match="synthetic_undeclared_port"):
        configured.build_node(group, group.nodes[0], store)
    assert not store.values and not store.owners


def test_schema_one_cannot_activate_configured_intent_producer():
    group, store = bundle(), FactStore()
    with pytest.raises(ValueError, match="^configured_group_schema_required$"):
        configured.build_node(replace(group, schema="atlas-brain.synthetic-p2/1"), group.nodes[0], store)
    assert not store.values and not store.owners


def test_duplicate_supplied_configurations_conflict_before_one_write_per_fact():
    group = bundle()
    changed = replace(group, captures=group.captures * 2)
    store = FactStore()
    result = configured.build_node(changed, group.nodes[0], store)
    assert len(result.parses) == 2
    for row in result.rows:
        assert all(isinstance(fact, k.Unknown) and fact.reason is k.UnknownReason.CONFLICTING_EVIDENCE
                   for fact in (row.mode, row.native, row.allowed))


@pytest.mark.parametrize("change", [{"id": "outside"}, {"group": "other"}])
def test_node_membership_and_group_namespace_are_checked_before_writing(change):
    group, store = bundle(), FactStore()
    node = replace(group.nodes[0], **change)
    with pytest.raises(ValueError, match="^configured_node_outside_group$"):
        configured.build_node(group, node, store)
    assert not store.values and not store.owners
