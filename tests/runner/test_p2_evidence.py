"""Generated synthetic evidence only; projection does not derive network facts."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import SCHEMA, admit_members, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactStore, bind_reader, bind_writer
from atlas_brain.runner.p2_evidence import project_fact, resolve_evidence
from atlas_brain.runner.records import RunnerRefused

IDS = ("l1.link.peer", "l2.discovery.bridge_capable", "l2.discovery.device_id",
       "l2.discovery.remote_port", "l2.vlan_trunk.allowed", "l2.vlan_trunk.native")


def bundle(group="pair", count=1):
    raws = {node + ".txt": ("Device ID: synth-" + node + "\n").encode() for node in ("a", "b")}
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "group": group,
                "nodes": [{"id": node, "discovery_id": "synth-" + node,
                           "ports": [f"Gi1/0/{i + 1}" for i in range(count)]} for node in ("b", "a")],
                "captures": [{"path": path, "node": path[0], "operation": "iosxe.show_cdp_neighbors_detail",
                              "sha256": sha256(raw).hexdigest()} for path, raw in raws.items()]}
    return admit_members({**raws, "p2.json": canonical(manifest)})


def subject(group, node="a", port="Gi1/0/1"):
    return endpoint(next(item for item in group.nodes if item.id == node), port)


def witness(group, node="a", role=k.EvidenceRole.SUBJECT):
    source = next(item.key for item in group.nodes if item.id == node)
    capture = next(item for item in group.captures if item.source == source)
    return k.EvidenceRef(capture=capture.id, locator=k.ByteSpan(start=0, end=len(capture.raw)),
                         role=role, excerpt_sha256=sha256(capture.raw).hexdigest())


def known(value, *evidence):
    return k.Known(value=value, basis=k.Basis.DERIVED, evidence=evidence, raw=None)


def reader(entries=(), reads=IDS):
    store = FactStore()
    for ref, state in entries:
        pack = ref.fact.rpartition(".")[0]
        step = StepSpec(id=pack + "/populate", pack=pack, kind="parse_build", scope="estate",
                        reads=(), produces=(ref.fact,), evaluator=pack + ".synthetic")
        bind_writer(store, step=step).write(fact=ref.fact, subject=ref.subject, value=state)
    step = StepSpec(id="l1.link/project", pack="l1.link", kind="check", scope="estate",
                    reads=tuple(sorted(reads)), produces=(), evaluator="l1.link.project")
    delegate = bind_reader(store, step=step)
    class ReadOnly:
        def read(self, **kwargs):
            return delegate.read(**kwargs)
    return ReadOnly()


def leaves(records):
    return [leaf for item in records for leaf in
            ([item] if item["kind"] == "capture" else
             leaves(item["state"]["evidence"]) if item["kind"] == "fact" else [])]


def test_fact_chain_preserves_both_ends_roles_operands_and_order():
    group = bundle()
    a, b = subject(group), subject(group, "b")
    da, db = (k.FactRef(fact="l2.discovery.device_id", subject=end) for end in (a, b))
    peer = k.FactRef(fact="l1.link.peer", subject=a)
    na, nb = (k.FactRef(fact="l2.vlan_trunk.native", subject=end) for end in (a, b))
    wa, wb = witness(group), witness(group, "b", k.EvidenceRole.WITNESS)
    handle = reader(((da, known("synth-b", wa)), (db, known("synth-a", wb)),
                     (peer, known(b, da, db)), (na, known(1, wa)), (nb, known(1, wb))))
    result = project_fact(group, handle, known(True, peer, na, nb))
    assert len(result["evidence"]) == 3 and result["value"] is True
    assert result == project_fact(group, handle, known(True, nb, na, peer, peer))
    refs = leaves(result["evidence"])
    assert {item["capture"] for item in refs} == {wa.capture, wb.capture}
    assert {item["role"] for item in refs} == {"subject", "witness"}
    assert {item["source"] for item in refs} == {node.key for node in group.nodes}
    for item in refs:
        capture = next(cap for cap in group.captures if cap.id == item["capture"])
        assert item["sha256"] == sha256(capture.raw[item["start"]:item["end"]]).hexdigest()
        assert item["capture_sha256"] == sha256(capture.raw).hexdigest()
        assert item["operation"] == "iosxe.show_cdp_neighbors_detail"
        assert item["rendered"] == "show cdp neighbors detail" and item["read_scope"] == "unknown"


@pytest.mark.parametrize("change", [
    {"capture": "missing"}, {"capture": "p2.json"}, {"excerpt_sha256": "0" * 64},
    {"locator": k.ByteSpan(start=0, end=10000)}, {"locator": k.FieldPointer(pointer="/group")},
])
def test_capture_corruption_refuses(change):
    group = bundle()
    with pytest.raises(RunnerRefused):
        resolve_evidence(group, reader(), (replace(witness(group), **change),))


def test_capture_identity_command_and_whole_capture_validation():
    group = bundle()
    capture = group.captures[0]
    ref = next(witness(group, node.id) for node in group.nodes if node.key == capture.source)
    assert resolve_evidence(group, reader(), (replace(ref, locator=k.WholeCapture()),))[0]["locator"] == "whole_capture"
    assert resolve_evidence(replace(group, captures=(replace(capture, operation=capture.rendered),)),
                            reader(), (ref,))[0]["operation"] == capture.operation
    for captures in ((capture, capture), (replace(capture, operation="unknown"),),
                     (replace(capture, rendered="show arbitrary"),), (replace(capture, source="node:other:a"),)):
        with pytest.raises(RunnerRefused):
            resolve_evidence(replace(group, captures=captures), reader(), (ref,))
    raw = b"Device ID: changed\n"
    changed = replace(group, captures=(replace(capture, raw=raw),))
    with pytest.raises(RunnerRefused, match="capture_registry"):
        resolve_evidence(changed, reader(), (replace(ref, excerpt_sha256=sha256(raw).hexdigest()),))
    with pytest.raises(RunnerRefused, match="capture_registry"):
        resolve_evidence(replace(group, raw=group.raw.replace(b"a.txt", b"c.txt")), reader(), (ref,))


def test_registry_pointer_uses_raw_order_and_never_becomes_capture():
    group = bundle()
    node = group.nodes[0]
    result = resolve_evidence(group, reader(), node.declaration.evidence)[0]
    assert result["kind"] == "registry" and result["citation"] == "/nodes/1"
    assert result["value"]["id"] == node.id and "capture" not in result
    assert resolve_evidence(group, reader(), group.declaration.evidence)[0]["value"] == group.id


@pytest.mark.parametrize("change", [
    {"table_digest": "0" * 64}, {"citation": "/nodes/0"}, {"citation": "/nodes/01"},
    {"citation": "/nodes/1/id"}, {"row_id": "b"}, {"table": "synthetic_p2.other"},
])
def test_registry_corruption_refuses(change):
    group = bundle()
    with pytest.raises(RunnerRefused):
        resolve_evidence(group, reader(), (replace(group.nodes[0].declaration.evidence[0], **change),))


def test_registry_rehash_still_requires_strict_json_and_admitted_node_agreement():
    group = bundle()
    for raw in (b'{"schema":1,"schema":2}', group.raw.replace(b"synth-a", b"synth-c")):
        ref = replace(group.nodes[0].declaration.evidence[0], table_digest=sha256(raw).hexdigest())
        with pytest.raises(RunnerRefused):
            resolve_evidence(replace(group, raw=raw), reader(), (ref,))


def test_missing_undeclared_cross_group_and_cyclic_fact_refs_refuse():
    group = bundle()
    ref = k.FactRef(fact="l1.link.peer", subject=subject(group))
    for handle, bad in ((reader(), ref), (reader(((ref, known("x", witness(group))),), reads=()), ref),
                        (reader(), replace(ref, subject=subject(bundle("other")))),
                        (reader(), replace(ref, subject="interface:undeclared"))):
        with pytest.raises(RunnerRefused):
            resolve_evidence(group, handle, (bad,))
    with pytest.raises(RunnerRefused, match="fact_cycle"):
        resolve_evidence(group, reader(((ref, known("x", ref)),)), (ref,))


def test_fact_depth_is_bounded():
    group = bundle(count=35)
    refs = [k.FactRef(fact="l1.link.peer", subject=subject(group, port=f"Gi1/0/{i + 1}")) for i in range(35)]
    handle = reader(tuple((ref, known("x", refs[i + 1] if i < 34 else witness(group))) for i, ref in enumerate(refs)))
    with pytest.raises(RunnerRefused, match="fact_depth"):
        resolve_evidence(group, handle, (refs[0],))


def test_unknown_metadata_next_evidence_and_read_scope_are_preserved():
    group = bundle()
    need = k.EvidenceNeed(node=group.nodes[0].key, operation="show cdp neighbors detail",
                          params=(), resolves=("l1.link.peer",), reruns=("l1.link/check",),
                          after_s=4, unprintable=("hidden",))
    state = k.Unknown(reason=k.UnknownReason.SCOPE_LIMITED, detail="scope_unknown", evidence=(witness(group),),
                      candidates=(subject(group),), next_evidence=(need,))
    result = project_fact(group, reader(), state)
    assert result["reason"] == "scope_limited" and result["detail"] == "scope_unknown"
    assert result["candidates"] == list(state.candidates) and result["evidence"][0]["read_scope"] == "unknown"
    assert result["next_evidence"] == [{"node": need.node, "operation": "iosxe.show_cdp_neighbors_detail",
        "rendered": "show cdp neighbors detail", "params": [], "resolves": ["l1.link.peer"],
        "reruns": ["l1.link/check"], "after_s": 4, "unprintable": ["hidden"]}]
    for change in ({"node": "node:other:a"}, {"params": (("x", "literal"),)}, {"operation": "show arbitrary"}):
        with pytest.raises(RunnerRefused):
            project_fact(group, reader(), replace(state, next_evidence=(replace(need, **change),)))


@pytest.mark.parametrize("value", [None, 1.5, object(), (("x", None),)])
def test_unsupported_values_refuse(value):
    group = bundle()
    with pytest.raises(RunnerRefused):
        project_fact(group, reader(), known(value, witness(group)))


def test_unsupported_states_refuse_and_json_scalars_survive():
    group = bundle()
    ref = witness(group, role=k.EvidenceRole.ABSENCE_WITNESS)
    for state in (k.Absent(kind="configured_line", basis=k.Basis.CONFIGURED, evidence=(ref,)),
                  k.NotApplicable(reason=k.NAReason.DECLARED_EXCLUSION, evidence=(ref,))):
        with pytest.raises(RunnerRefused):
            project_fact(group, reader(), state)
    assert project_fact(group, reader(), known((1, "x", True), ref))["value"] == [1, "x", True]
