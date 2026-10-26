"""Generated thin discovery forms; these are synthetic oracles, not device qualification."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import AdmissionRefused
from atlas_brain.evidence.synthetic import SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.discovery import build as discovery

CDP = (b"-------------------------\nDevice ID: sw-b\n"
       b"Platform: synthetic-switch, Capabilities: Switch\n"
       b"Interface: Gi1/0/1, Port ID (outgoing port): Gi1/0/1\n")
LLDP = (b"Local Intf: Gi1/0/1\nPort id: Gi1/0/1\n"
        b"System Name: sw-b\nEnabled Capabilities: B\n")
CDP_OP, LLDP_OP = "iosxe.show_cdp_neighbors_detail", "iosxe.show_lldp_neighbors_detail"


def bundle(records, ports=("Gi1/0/1",)):
    files = {str(index) + ".txt": raw for index, (_, raw) in enumerate(records)}
    manifest = {"schema": SCHEMA, "group": "demo",
                "semantic_group": "declared_synthetic",
                "nodes": [{"id": "a", "discovery_id": "sw-a", "ports": list(ports)},
                          {"id": "b", "discovery_id": "sw-b", "ports": ["Gi1/0/1"]}],
                "captures": [{"path": path, "node": "a", "operation": records[index][0],
                              "sha256": sha256(raw).hexdigest()}
                             for index, (path, raw) in enumerate(files.items())]}
    return admit_members({**files, "p2.json": json.dumps(manifest).encode()})


def read(store):
    consumer = StepSpec(id=StepId("l1.link/pair"), pack=k.PackId("l1.link"), kind="derive",
                        scope="estate", reads=discovery.IDS, produces=(), evaluator="l1.link.test")
    return bind_reader(store, step=consumer)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_protocol_agreement_uses_shared_store_and_exact_field_and_local_spans(ending):
    raws = [(CDP_OP, CDP.replace(b"\n", ending)), (LLDP_OP, LLDP.replace(b"\n", ending))]
    group = bundle(raws)
    node, other = group.nodes
    store = FactStore()
    result = discovery.build_node(group, node, store)
    assert result.quality == "complete" and all(p.quality == "complete" for _, p in result.parses)
    row, = result.rows
    assert row.subject == endpoint(node, "Gi1/0/1")
    assert (row.device_id.value, row.remote_port.value, row.bridge_capable.value) == ("sw-b", "Gi1/0/1", True)
    assert tuple(f.id for f in discovery.FACTS) == discovery.STEP.produces == discovery.IDS
    assert {f.id: f.value_type for f in discovery.FACTS} == {discovery.DEVICE_ID: "text", discovery.REMOTE_PORT: "text", discovery.BRIDGE: "boolean"}
    reader = read(store)
    by_id = {capture.id: capture for capture in group.captures}
    for fact_id, fact in ((discovery.DEVICE_ID, row.device_id), (discovery.REMOTE_PORT, row.remote_port), (discovery.BRIDGE, row.bridge_capable)):
        assert reader.read(fact=fact_id, subject=row.subject) is fact
        refs = [ref for ref in fact.evidence if isinstance(ref, k.EvidenceRef)]
        assert {ref.capture for ref in refs} == set(by_id)
        assert all(isinstance(ref.locator, k.ByteSpan) for ref in refs)
        excerpts = []
        for ref in refs:
            excerpt = by_id[ref.capture].raw[ref.locator.start:ref.locator.end]
            assert sha256(excerpt).hexdigest() == ref.excerpt_sha256
            excerpts.append(excerpt)
        assert excerpts.count(b"Gi1/0/1") >= 2
        assert group.declaration.evidence[0] in fact.evidence and node.declaration.evidence[0] in fact.evidence
    assert {c.raw for c in group.captures} == {raw for _, raw in raws}
    assert result == discovery.build_node(replace(group, captures=tuple(reversed(group.captures))), node, FactStore())
    missing = discovery.build_node(group, other, store).rows[0]
    assert missing.subject != row.subject and missing.device_id.reason is k.UnknownReason.NOT_COLLECTED
    assert reader.read(fact=discovery.DEVICE_ID, subject=row.subject) is row.device_id


@pytest.mark.parametrize("raw", [CDP + CDP, CDP + CDP.replace(b"sw-b", b"sw-c")])
def test_duplicate_same_protocol_is_conflict_even_when_identical(raw):
    group = bundle([(CDP_OP, raw)])
    row, = discovery.build_node(group, group.nodes[0], FactStore()).rows
    assert all(isinstance(fact, k.Unknown) and fact.reason is k.UnknownReason.CONFLICTING_EVIDENCE
               for fact in (row.device_id, row.remote_port, row.bridge_capable))


@pytest.mark.parametrize("raw", [LLDP.replace(b"sw-b", b"sw-c"),
    LLDP.replace(b"Port id: Gi1/0/1", b"Port id: Gi1/0/2"), LLDP.replace(b"Capabilities: B", b"Capabilities: T")])
def test_protocol_disagreement_poison_endpoint(raw):
    group = bundle([(CDP_OP, CDP), (LLDP_OP, raw)])
    row, = discovery.build_node(group, group.nodes[0], FactStore()).rows
    assert row.device_id.reason is k.UnknownReason.CONFLICTING_EVIDENCE
    refs = [ref for ref in row.device_id.evidence if isinstance(ref, k.EvidenceRef)]
    assert {ref.capture for ref in refs} == {c.id for c in group.captures}


@pytest.mark.parametrize("raw,reason", [(b"", k.UnknownReason.EMPTY_UNREGISTERED),
    (b"% Invalid input\n", k.UnknownReason.CAPTURE_ERROR),
    (b"[truncated]\n", k.UnknownReason.CAPTURE_TRUNCATED),
    (CDP + b"unmodelled body\n", k.UnknownReason.PARSE_PARTIAL),
    (CDP.replace(b"Switch\n", b"Switch Phone\n"), k.UnknownReason.PARSE_PARTIAL),
    (CDP.replace(b"Platform: synthetic-switch, Capabilities: Switch\n", b""), k.UnknownReason.PARSE_PARTIAL)])
def test_one_bad_collected_protocol_poison_all_declared_ports(raw, reason):
    group = bundle([(CDP_OP, raw), (LLDP_OP, LLDP)], ports=("Gi1/0/1", "Gi1/0/2"))
    result = discovery.build_node(group, group.nodes[0], FactStore())
    assert result.quality == "partial" and len(result.rows) == 2
    for row in result.rows:
        assert all(isinstance(fact, k.Unknown) and fact.reason is reason
                   for fact in (row.device_id, row.remote_port, row.bridge_capable))
        assert {n.operation for n in row.device_id.next_evidence} == {
            "show cdp neighbors detail", "show lldp neighbors detail"}
        assert all(n.node == group.nodes[0].key for n in row.device_id.next_evidence)


@pytest.mark.parametrize("operation,raw", [(CDP_OP, CDP.replace(b"Switch\n", b"Host\n")),
    (LLDP_OP, LLDP.replace(b"Capabilities: B", b"Capabilities: W")),
    (LLDP_OP, LLDP.replace(b"Capabilities: B", b"Capabilities: T"))])
def test_explicit_non_switch_roles_are_never_positive_bridge(operation, raw):
    group = bundle([(operation, raw)])
    row, = discovery.build_node(group, group.nodes[0], FactStore()).rows
    assert isinstance(row.bridge_capable, k.Known) and row.bridge_capable.value is False


def test_exact_port_population_refuses_extras_and_preserves_unobserved_endpoints():
    raw = CDP.replace(b"Interface: Gi1/0/1", b"Interface: Gi1/0/2")
    group = bundle([(CDP_OP, raw)])
    with pytest.raises(AdmissionRefused, match="synthetic_undeclared_port"):
        discovery.build_node(group, group.nodes[0], FactStore())
    group = bundle([(CDP_OP, raw)], ports=("Gi1/0/1", "Gi1/0/2"))
    result = discovery.build_node(group, group.nodes[0], FactStore())
    assert result.rows[0].device_id.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert result.rows[1].device_id.value == "sw-b"


def test_discovery_does_not_shorten_or_casefold_peer_or_port_identifiers():
    raw = CDP.replace(b"sw-b", b"SW-B.example").replace(b"port): Gi1/0/1", b"port): GigabitEthernet1/0/1")
    group = bundle([(CDP_OP, raw)])
    row, = discovery.build_node(group, group.nodes[0], FactStore()).rows
    assert row.device_id.value == "SW-B.example" and row.remote_port.value == "GigabitEthernet1/0/1"


@pytest.mark.parametrize("operation,raw", [
    (CDP_OP, CDP.replace(b"Device ID: sw-b\n", b"")),
    (CDP_OP, CDP.replace(b"Platform:", b"-------------------------\nPlatform:")),
    (LLDP_OP, LLDP.replace(b"Port id:", b"-------------------------\nPort id:")),
    (CDP_OP, CDP.replace(b"Interface: Gi1/0/1, Port ID (outgoing port): Gi1/0/1\n", b"")),
    (CDP_OP, CDP.replace(b"port): Gi1/0/1", b"port): ")),
    (CDP_OP, (b"-------------------------\nDevice ID: sw-b\n"
     b"Interface: Gi1/0/1, Port ID (outgoing port): Gi1/0/1\n"
     b"Platform: synthetic-switch, Capabilities: Switch\n")),
    (LLDP_OP, LLDP.replace(b"Enabled Capabilities: B\n", b"")),
    (LLDP_OP, LLDP + b"System Name: sw-c\n"),
])
def test_missing_fields_and_wrong_transitions_cannot_preserve_earlier_known_claim(operation, raw):
    group = bundle([(operation, raw)])
    result = discovery.build_node(group, group.nodes[0], FactStore())
    assert result.quality == "partial"
    row, = result.rows
    assert all(isinstance(fact, k.Unknown) and fact.reason is k.UnknownReason.PARSE_PARTIAL
               for fact in (row.device_id, row.remote_port, row.bridge_capable))


@pytest.mark.parametrize("role", [b"B,T", b"B, T", b"B,W", b"B, W"])
def test_mixed_bridge_and_phone_or_ap_roles_remain_unknown(role):
    group = bundle([(LLDP_OP, LLDP.replace(b"Capabilities: B", b"Capabilities: " + role))])
    row, = discovery.build_node(group, group.nodes[0], FactStore()).rows
    assert all(isinstance(fact, k.Unknown) and fact.reason is k.UnknownReason.PARSE_PARTIAL
               for fact in (row.device_id, row.remote_port, row.bridge_capable))


@pytest.mark.parametrize("operation,raw", [
    (CDP_OP, CDP.replace(b"Interface: Gi1/0/1, Port ID", b"Interface: Gi1/0/2, Bad ID")),
    (CDP_OP, b"-------------------------\nInterface: Gi1/0/2, malformed\n"),
    (LLDP_OP, LLDP.replace(b"System Name:", b"Local Intf: Gi1/0/2\nSystem Name:")),
])
def test_unmatched_local_mentions_refuse_before_any_fact_write(operation, raw):
    group, store = bundle([(operation, raw)]), FactStore()
    node = group.nodes[0]
    with pytest.raises(AdmissionRefused, match="synthetic_undeclared_port"):
        discovery.build_node(group, node, store)
    with pytest.raises(ValueError, match="missing_fact:"):
        read(store).read(fact=discovery.DEVICE_ID, subject=endpoint(node, "Gi1/0/1"))


def test_catalogue_fact_contracts_match_declared_outputs():
    assert tuple(spec.id for spec in discovery.FACTS) == discovery.IDS == discovery.STEP.produces
    assert tuple((spec.id, spec.value_type) for spec in discovery.FACTS) == (
        (discovery.BRIDGE, "boolean"), (discovery.DEVICE_ID, "text"), (discovery.REMOTE_PORT, "text"))
    assert all(spec.pack == discovery.STEP.pack and spec.subject == "interface"
               and spec.step == discovery.STEP.id for spec in discovery.FACTS)
