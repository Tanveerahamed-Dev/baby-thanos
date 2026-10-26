"""Recursive P3 projections are owner-state copies, never new conclusions."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA, adjacency_subject, sample_subject
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactStore, bind_reader, bind_writer
from atlas_brain.packs.l2.mtu import build as l2_mtu
from atlas_brain.packs.l3.mtu import build as l3_mtu
from atlas_brain.packs.l3.ospf import specs as ospf
from atlas_brain.runner import p2, p2_evidence
from atlas_brain.runner.p3_evidence import project_fact, project_needs, resolve_evidence
from atlas_brain.runner.records import RunnerRefused


def bundle(timed=True, multiple=False):
    raw = b"Neighbor ID Pri State Dead Time Address Interface\n"
    files = {"a.txt": b"Device ID: sw-b\n", "b.txt": b"Device ID: sw-a\n", "sample.txt": raw}
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "sw-" + n, "ports": ["Gi1/0/1", "Gi1/0/2"] if multiple else ["Gi1/0/1"]} for n in ("a", "b")],
        "captures": [{"path": n + ".txt", "node": n, "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(files[n + ".txt"]).hexdigest()} for n in ("a", "b")]}
    files["p2.json"] = canonical(base)
    def point(n, index):
        return {"node": n, "port": "Gi1/0/1", "process": 1, "router_id": f"192.0.2.{index}",
                "address": f"198.51.100.{index}", "vrf": "default"}
    time = {"unit": "unix_us", "clock": "collector:test", "earliest": 0, "latest": 1, "bound": "collector_recorded"}
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "base_sha256": sha256(files["p2.json"]).hexdigest(),
        "adjacencies": [{"id": "ab", "domain": "demo", "area": 0, "left": point("a", 1), "right": point("b", 2)}],
        "samples": [{"id": "first", "time": time if timed else None,
                     "captures": [{"path": "sample.txt", "node": "a", "operation": "iosxe.show_ip_ospf_neighbor",
                                   "sha256": sha256(raw).hexdigest()}]}]}
    if multiple:
        manifest["adjacencies"].append({"id": "other", "domain": "demo", "area": 0,
            "left": dict(point("a", 1), port="Gi1/0/2", address="198.51.100.3"),
            "right": dict(point("b", 2), port="Gi1/0/2", address="198.51.100.4")})
        files.pop("sample.txt")
        manifest["samples"] = []
        for index in range(2):
            captures = []
            for node in ("a", "b"):
                path = f"round{index}-{node}.txt"
                files[path] = raw
                captures.append({"path": path, "node": node, "operation": "iosxe.show_ip_ospf_neighbor",
                                 "sha256": sha256(raw).hexdigest()})
            manifest["samples"].append({"id": f"round{index}", "time": time, "captures": captures})
    return admit_members({**files, "p3.json": canonical(manifest)})



def reader(entries=(), reads=None):
    store = FactStore()
    for ref, value in entries:
        pack = ref.fact.rpartition(".")[0]
        step = StepSpec(id=pack + "/populate", pack=pack, kind="parse_build", scope="estate",
                        reads=(), produces=(ref.fact,), evaluator=pack + ".populate")
        bind_writer(store, step=step).write(fact=ref.fact, subject=ref.subject, value=value)
    declared = tuple(sorted({ref.fact for ref, _ in entries})) if reads is None else reads
    step = StepSpec(id="l3.ospf/project", pack="l3.ospf", kind="derive", scope="estate",
                    reads=declared, produces=(), evaluator="l3.ospf.project")
    return bind_reader(store, step=step)


def witness(group, role=k.EvidenceRole.SUBJECT, baseline=False, node="a", sample=0):
    capture = group.base.captures[0] if baseline else next(c for c in group.samples[sample].captures
        if c.source == next(n.key for n in group.base.nodes if n.id == node))
    return k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=role, excerpt_sha256=capture.bytes_sha256)


def known(value, *evidence):
    return k.Known(value=value, basis=k.Basis.DERIVED, raw=None, evidence=evidence)


def subject(group):
    adjacency = group.adjacencies[0]
    return sample_subject(adjacency, adjacency.left, group.samples[0])


def chain_refs(group, count):
    adjacency, sample = group.adjacencies[0], group.samples[0]
    facts = tuple(sorted(ospf.IDS + (l2_mtu.MTU, l3_mtu.MTU)))
    refs = [k.FactRef(fact=fact, subject=adjacency_subject(adjacency)) for fact in ospf.SETTLE.produces]
    refs += [k.FactRef(fact=fact, subject=sample_subject(adjacency, adjacency.left, sample)) for fact in facts]
    refs += [k.FactRef(fact=fact, subject=endpoint(node, adjacency.left.port))
             for node in group.base.nodes for fact in p2.FACT_IDS]
    assert count <= len(refs)
    return refs[:count]


@pytest.mark.parametrize("fact,value", [(ospf.IGNORE, True), (l2_mtu.MTU, 1500),
                                       (l3_mtu.MTU, 1500), (ospf.STATE, "EXSTART")])
def test_known_primitive_and_recursive_sample_proof_keep_owner_value_and_basis(fact, value):
    group = bundle()
    ref = k.FactRef(fact=fact, subject=subject(group))
    state = known(value, witness(group), *group.samples[0].declaration.evidence)
    result = resolve_evidence(group, reader(((ref, state),)), (ref,))[0]
    assert result["state"]["value"] == value and type(result["state"]["value"]) is type(value)
    assert result["state"]["basis"] == "derived"
    assert {r["kind"] for r in result["state"]["evidence"]} == {"capture", "registry"}


def test_not_applicable_retains_positive_counter_evidence_and_parent_subject():
    group = bundle()
    ref = k.FactRef(fact=ospf.PERSISTENT, subject=adjacency_subject(group.adjacencies[0]))
    counter = witness(group, k.EvidenceRole.COUNTER_EVIDENCE)
    state = k.NotApplicable(reason=k.NAReason.FEATURE_NOT_ENABLED, evidence=(counter,))
    projected = resolve_evidence(group, reader(((ref, state),)), (ref,))[0]["state"]
    assert projected["state"] == "not_applicable" and projected["reason"] == "feature_not_enabled"
    assert projected["evidence"][0]["role"] == "counter_evidence"


def test_unknown_retains_reason_and_next_collection_constraints():
    group = bundle(timed=False)
    need = k.EvidenceNeed(node=group.adjacencies[0].left.node.key, operation="iosxe.show_ip_ospf_neighbor",
        params=(), resolves=(ospf.STATE,), reruns=(str(ospf.SETTLE.id),), after_s=120,
        unprintable=("collector_time_required",))
    state = k.Unknown(reason=k.UnknownReason.SINGLE_SAMPLE, detail="second_sample_required", evidence=(witness(group),),
                      candidates=(subject(group),), next_evidence=(need,))
    projected = project_fact(group, reader(), state)
    assert (projected["state"], projected["reason"], projected["detail"]) == ("unknown", "single_sample", "second_sample_required")
    assert projected["next_evidence"] == project_needs(group, (need,))
    assert projected["next_evidence"][0]["after_s"] == 120 and projected["candidates"] == [subject(group)]


@pytest.mark.parametrize("value", [None, 1.5, ("nested",)])
def test_nonprimitive_known_values_are_refused(value):
    group = bundle()
    with pytest.raises(RunnerRefused, match="p3_evidence_value"):
        project_fact(group, reader(), known(value, witness(group)))


def test_absent_is_refused_until_a_p3_absence_scope_contract_exists():
    group = bundle()
    state = k.Absent(kind="configured_line", basis=k.Basis.CONFIGURED,
                     evidence=(witness(group, k.EvidenceRole.ABSENCE_WITNESS),))
    with pytest.raises(RunnerRefused, match="p3_evidence_state"):
        project_fact(group, reader(), state)


def test_fact_reads_require_both_declared_subject_and_reader_permission():
    group = bundle()
    ref = k.FactRef(fact=ospf.STATE, subject=subject(group))
    entries = ((ref, known("EXSTART", witness(group))),)
    for handle, reference in ((reader(), ref), (reader(entries, reads=()), ref),
                              (reader(entries), replace(ref, subject="ospf_sample:foreign"))):
        with pytest.raises(RunnerRefused):
            resolve_evidence(group, handle, (reference,))


def test_cycles_refuse_and_reference_permutations_are_canonical():
    group = bundle()
    ref = k.FactRef(fact=ospf.STATE, subject=subject(group))
    with pytest.raises(RunnerRefused, match="fact_cycle"):
        resolve_evidence(group, reader(((ref, known("x", ref)),)), (ref,))
    refs = (witness(group),) + group.samples[0].declaration.evidence + group.base.declaration.evidence
    changed = replace(group, base=replace(group.base, nodes=tuple(reversed(group.base.nodes)),
                                         captures=tuple(reversed(group.base.captures))))
    assert canonical(resolve_evidence(group, reader(), refs)) == canonical(resolve_evidence(
        changed, reader(), tuple(reversed(refs)) + refs))


@pytest.mark.parametrize("count", [32, 33])
def test_p3_fact_depth_limit_is_inclusive(count):
    group = bundle(multiple=True)
    refs = chain_refs(group, count)
    leaf = witness(group, baseline=True)
    entries = tuple((ref, known("x", refs[i + 1] if i + 1 < count else leaf)) for i, ref in enumerate(refs))
    if count == 32:
        assert resolve_evidence(group, reader(entries), (refs[0],))
    else:
        with pytest.raises(RunnerRefused, match="fact_depth"):
            resolve_evidence(group, reader(entries), (refs[0],))


def test_baseline_fact_delegation_keeps_bytes():
    group = bundle()
    base_subject = endpoint(group.base.nodes[0], "Gi1/0/1")
    peer = k.FactRef(fact="l1.link.peer", subject=base_subject)
    device = k.FactRef(fact="l2.discovery.device_id", subject=base_subject)
    baseline = ((peer, known("peer", device)), (device, known("sw-b", witness(group, baseline=True))))
    assert resolve_evidence(group, reader(baseline), (peer,)) == p2_evidence.resolve_evidence(group.base, reader(baseline), (peer,))


@pytest.mark.parametrize("fact,kind,value", [(ospf.STATE, "base", "x"), ("l1.link.peer", "sample", "x"),
    (ospf.STATE, "adjacency", True), (l2_mtu.MTU, "adjacency", True), (l3_mtu.MTU, "adjacency", True),
    (ospf.PERSISTENT, "sample", True), (ospf.SPAN, "sample", True)])
def test_fact_ids_cannot_cross_base_sample_or_adjacency_subject_kinds(fact, kind, value):
    group = bundle()
    target = (endpoint(group.base.nodes[0], "Gi1/0/1") if kind == "base" else
              adjacency_subject(group.adjacencies[0]) if kind == "adjacency" else subject(group))
    ref = k.FactRef(fact=fact, subject=target)
    with pytest.raises(RunnerRefused, match="p3_evidence_fact_subject"):
        resolve_evidence(group, reader(((ref, known(value, witness(group))),)), (ref,))


@pytest.mark.parametrize("fact,value", [(ospf.PERSISTENT, True), (ospf.SPAN, 120000000)])
def test_actual_settled_fact_ids_require_and_accept_adjacency_subjects(fact, value):
    group = bundle()
    ref = k.FactRef(fact=fact, subject=adjacency_subject(group.adjacencies[0]))
    result = resolve_evidence(group, reader(((ref, known(value, witness(group))),)), (ref,))[0]
    assert result["state"]["value"] == value and type(result["state"]["value"]) is type(value)


def test_unregistered_p3_fact_id_is_refused_even_when_reader_permits_it():
    group = bundle()
    ref = k.FactRef(fact="l3.ospf.unregistered", subject=subject(group))
    with pytest.raises(RunnerRefused, match="p3_evidence_fact_subject"):
        resolve_evidence(group, reader(((ref, known(True, witness(group))),)), (ref,))


@pytest.mark.parametrize("plant", ["other_round", "opposite_node", "sample_registry", "adjacency_registry"])
def test_hash_valid_unrelated_leaves_cannot_prove_the_parent_sample(plant):
    group = bundle(multiple=True)
    ref = k.FactRef(fact=ospf.STATE, subject=subject(group))
    leaves = {"other_round": witness(group, sample=1), "opposite_node": witness(group, node="b"),
        "sample_registry": group.samples[1].declaration.evidence[0],
        "adjacency_registry": group.adjacencies[1].declaration.evidence[0]}
    with pytest.raises(RunnerRefused, match="parent_relevance"):
        resolve_evidence(group, reader(((ref, known("EXSTART", leaves[plant])),)), (ref,))


def test_all_end_settled_leaves_and_own_sample_declarations_remain_usable():
    group = bundle(multiple=True)
    ref = k.FactRef(fact=ospf.PERSISTENT, subject=adjacency_subject(group.adjacencies[0]))
    proof = tuple(witness(group, node=node, sample=index) for index in range(2) for node in ("a", "b"))
    proof += group.adjacencies[0].declaration.evidence + tuple(r for s in group.samples for r in s.declaration.evidence)
    assert resolve_evidence(group, reader(((ref, known(True, *proof)),)), (ref,))
    wrong = group.adjacencies[1].declaration.evidence[0]
    with pytest.raises(RunnerRefused, match="parent_relevance"):
        resolve_evidence(group, reader(((ref, known(True, wrong)),)), (ref,))


@pytest.mark.parametrize("plant", ["same", "round", "node", "adjacency"])
def test_recursive_fact_edges_stay_within_the_immediate_parent_context(plant):
    group = bundle(multiple=True)
    a, b = group.adjacencies
    first, second = group.samples
    parent = k.FactRef(fact=ospf.PERSISTENT if plant == "adjacency" else ospf.IGNORE,
                      subject=adjacency_subject(a) if plant == "adjacency" else sample_subject(a, a.left, first))
    child = k.FactRef(fact=ospf.STATE, subject=sample_subject(b if plant == "adjacency" else a,
        b.left if plant == "adjacency" else a.right if plant == "node" else a.left, second if plant == "round" else first))
    entries = ((parent, known(True, child)), (child, known("EXSTART", witness(group, node="b" if plant == "node" else "a",
                                                                            sample=1 if plant == "round" else 0))))
    if plant == "same":
        assert resolve_evidence(group, reader(entries), (parent,))
    else:
        with pytest.raises(RunnerRefused, match="parent_relevance"):
            resolve_evidence(group, reader(entries), (parent,))


@pytest.mark.parametrize("fact", [ospf.STATE, "l2.discovery.unregistered"])
def test_delegated_p2_subtree_cannot_launder_foreign_fact_ids_on_base_subjects(fact):
    group = bundle()
    base = endpoint(group.base.nodes[0], "Gi1/0/1")
    peer, child = k.FactRef(fact="l1.link.peer", subject=base), k.FactRef(fact=fact, subject=base)
    entries = ((peer, known("peer", child)), (child, known("EXSTART", witness(group, baseline=True))))
    with pytest.raises(RunnerRefused, match="p3_evidence_fact_subject"):
        resolve_evidence(group, reader(entries), (peer,))
