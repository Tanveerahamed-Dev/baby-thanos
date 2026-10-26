"""Schema-bound configuration proof edges, independent of parser truth."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import (
    CONFIG_COMMAND,
    CONFIG_OPERATION,
    CONFIG_SCHEMA,
    SCHEMA,
    admit_members,
    endpoint,
)
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader, bind_writer
from atlas_brain.runner.p2_evidence import project_fact, project_needs, resolve_evidence
from atlas_brain.runner.records import RunnerRefused

P = "Gi1/0/1"
IDS = tuple(k.FactId("l2.vlan_trunk.configured_" + name) for name in ("allowed", "mode", "native"))
RAW = (b"interface Gi1/0/1\n switchport mode trunk\n"
       b" switchport trunk native vlan 10\n switchport trunk allowed vlan 10,20\n!\nend\n")


def bundle(schema=CONFIG_SCHEMA):
    op = CONFIG_OPERATION if schema == CONFIG_SCHEMA else "iosxe.show_interfaces_trunk"
    raw = RAW if schema == CONFIG_SCHEMA else b"Port Mode Encapsulation Status Native vlan\n"
    manifest = {"schema": schema, "semantic_group": "declared_synthetic", "group": "demo",
                "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [P]} for node in ("a", "b")],
                "captures": [{"path": "config.txt", "node": "a", "operation": op, "sha256": sha256(raw).hexdigest()}]}
    return admit_members({"p2.json": canonical(manifest), "config.txt": raw})


def reader(store=None):
    step = StepSpec(id=StepId("l2.vlan_trunk/config_project_test"), pack=k.PackId("l2.vlan_trunk"),
                    kind="derive", scope="estate", reads=IDS, produces=(), evaluator="l2.vlan_trunk.config.proof_test")
    return bind_reader(store if store is not None else FactStore(), step=step)


def field(group):
    capture, = group.captures
    start = capture.raw.index(b"10")
    return k.EvidenceRef(capture=capture.id, locator=k.ByteSpan(start=start, end=start + 2),
                         role=k.EvidenceRole.SUBJECT, excerpt_sha256=sha256(b"10").hexdigest())


def need(group, operation=CONFIG_OPERATION):
    return k.EvidenceNeed(node=group.nodes[0].key, operation=operation, params=(),
                          resolves=tuple(str(f) for f in IDS),
                          reruns=("l2.vlan_trunk/check_config", "l2.vlan_trunk/parse_config"),
                          after_s=None, unprintable=())


def test_config_known_retains_schema_bound_capture_and_registry_custody():
    group = bundle()
    proof = field(group)
    state = k.Known(value=10, basis=k.Basis.CONFIGURED, raw="10",
                    evidence=(proof,) + group.declaration.evidence + group.nodes[0].declaration.evidence)
    projected = project_fact(group, reader(), state)
    assert (projected["state"], projected["basis"], projected["value"]) == ("known", "configured", 10)
    capture = next(record for record in projected["evidence"] if record["kind"] == "capture")
    assert capture["operation"] == CONFIG_OPERATION and capture["rendered"] == CONFIG_COMMAND
    assert capture["path"] == "config.txt" and capture["source"] == group.nodes[0].key
    assert capture["capture_sha256"] == sha256(RAW).hexdigest()
    assert capture["sha256"] == sha256(RAW[capture["start"]:capture["end"]]).hexdigest()
    assert capture["read_scope"] == capture["view"] == "unknown"
    registries = [record for record in projected["evidence"] if record["kind"] == "registry"]
    assert {record["citation"] for record in registries} == {"/group", "/nodes/0"}
    assert all(record["table_digest"] == sha256(group.raw).hexdigest() for record in registries)


@pytest.mark.parametrize("plant", ["schema_field", "schema_raw", "source", "operation", "rendered",
                                   "identity", "whole_hash", "span_hash", "bounds"])
def test_config_capture_proof_cannot_be_rebound(plant):
    group = bundle()
    capture, = group.captures
    proof = field(group)
    if plant == "schema_field":
        group = replace(group, schema=SCHEMA)
    elif plant == "schema_raw":
        group = replace(group, raw=group.raw.replace(CONFIG_SCHEMA.encode(), SCHEMA.encode()))
    elif plant == "source":
        group = replace(group, captures=(replace(capture, source=group.nodes[1].key),))
    elif plant == "operation":
        group = replace(group, captures=(replace(capture, operation="iosxe.show_interfaces_trunk"),))
    elif plant == "rendered":
        group = replace(group, captures=(replace(capture, rendered="show startup-config"),))
    elif plant == "identity":
        changed = replace(capture, id=k.CaptureId("cap:forged"))
        group, proof = replace(group, captures=(changed,)), replace(proof, capture=changed.id)
    elif plant == "whole_hash":
        changed = replace(capture, raw=RAW.replace(b"10", b"20"))
        group = replace(group, captures=(changed,))
    elif plant == "span_hash":
        proof = replace(proof, excerpt_sha256="0" * 64)
    else:
        proof = replace(proof, locator=k.ByteSpan(start=0, end=len(RAW) + 1))
    with pytest.raises(RunnerRefused):
        resolve_evidence(group, reader(), (proof,))


@pytest.mark.parametrize("operation", [CONFIG_OPERATION, CONFIG_COMMAND])
def test_config_next_evidence_is_closed_and_schema_bound(operation):
    group = bundle()
    item, = project_needs(group, (need(group, operation),))
    assert item == {"node": str(group.nodes[0].key), "operation": CONFIG_OPERATION,
                    "rendered": CONFIG_COMMAND, "params": [], "resolves": list(IDS),
                    "reruns": ["l2.vlan_trunk/check_config", "l2.vlan_trunk/parse_config"],
                    "after_s": None, "unprintable": []}
    legacy = bundle(SCHEMA)
    with pytest.raises(RunnerRefused, match="p2_evidence_operation"):
        project_needs(legacy, (need(legacy, operation),))
    with pytest.raises(RunnerRefused, match="p2_evidence_registry_group"):
        project_needs(replace(group, schema=SCHEMA), (need(group, operation),))


@pytest.mark.parametrize("plant", ["foreign_node", "params", "startup"])
def test_config_needs_cannot_expand_collection_scope(plant):
    group = bundle()
    request = need(group)
    if plant == "foreign_node":
        request = replace(request, node=k.EntityKey("node:other:a"))
    elif plant == "params":
        request = replace(request, params=(("interface", P),))
    else:
        request = replace(request, operation="show startup-config")
    with pytest.raises(RunnerRefused):
        project_needs(group, (request,))


def test_config_fact_chain_uses_declared_reader_and_original_leaf_proof():
    group, store = bundle(), FactStore()
    subject = endpoint(group.nodes[0], P)
    step = StepSpec(id=StepId("l2.vlan_trunk/parse_config"), pack=k.PackId("l2.vlan_trunk"),
                    kind="parse_build", scope="device", reads=(), produces=IDS, evaluator="l2.vlan_trunk.config.test")
    state = k.Known(value=10, basis=k.Basis.CONFIGURED, raw="10",
                    evidence=(field(group),) + group.nodes[0].declaration.evidence)
    bind_writer(store, step=step).write(fact=IDS[2], subject=subject, value=state)
    reference = k.FactRef(fact=IDS[2], subject=subject)
    projected, = resolve_evidence(group, reader(store), (reference,))
    assert projected["kind"] == "fact" and projected["fact"] == IDS[2]
    assert projected["state"]["basis"] == "configured" and projected["state"]["value"] == 10
    capture = next(ref for ref in projected["state"]["evidence"] if ref["kind"] == "capture")
    assert capture["operation"] == CONFIG_OPERATION and capture["sha256"] == sha256(b"10").hexdigest()
    with pytest.raises(RunnerRefused, match="p2_evidence_fact_unreadable"):
        resolve_evidence(group, reader(), (reference,))


def test_config_proof_order_and_duplicate_references_are_canonical():
    group = bundle()
    refs = (field(group),) + group.declaration.evidence + group.nodes[0].declaration.evidence
    expected = canonical(resolve_evidence(group, reader(), refs))
    changed = replace(group, nodes=tuple(reversed(group.nodes)), captures=tuple(reversed(group.captures)))
    assert canonical(resolve_evidence(changed, reader(), tuple(reversed(refs)) + refs)) == expected
