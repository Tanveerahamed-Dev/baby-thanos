"""Isolated projected metadata with stub facts; no owner-analysis or authentication claim."""
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.runner.p3_manifest_custody import validate
from atlas_brain.runner.records import RunnerRefused


def fixture():
    base, side, raw = (sha256(label.encode()).hexdigest() for label in ("base", "side", "opaque bytes"))
    def digest(prefix, value):
        return prefix + sha256(canonical(value)).hexdigest()
    def known(value, basis, proof, raw=None):
        return dict(state="known", value=value, basis=basis, evidence=proof, raw=raw)
    def registry(table, identifier, citation, value):
        return dict(kind="registry", table=table, row_id=identifier, citation=citation, value=value,
                    table_digest=base if table.startswith("synthetic_p2") else side)
    port, operation, command = "GigabitEthernet1", "iosxe.show_running_config_all", "show running-config all"
    nodes = [dict(id=n, key="node:demo:" + n, discovery_id="sw-" + n, ports=[port],
        declaration=known(n, "declared", [registry("synthetic_p2.nodes", n, "/nodes/" + str(i),
            dict(id=n, discovery_id="sw-" + n, ports=[port]))], n)) for i, n in enumerate(("a", "b"))]
    points = [dict(node=n, port=port, process=i + 1, router_id="192.0.2." + str(i + 1),
                   address="198.51.100." + str(i + 1), vrf="default") for i, n in enumerate(("a", "b"))]
    scopes = [("node:demo:" + p["node"], port, p["process"], p["router_id"], p["address"], p["vrf"]) for p in points]
    context = ("atlas-brain.synthetic-p3/1", "link", "lab", 0, *scopes)
    adj_ref = registry("synthetic_p3.adjacencies", "link", "/adjacencies/0",
                       dict(id="link", domain="lab", area=0, left=points[0], right=points[1]))
    adj_subject = digest("ospf_adjacency:", context)
    captures = []
    def capture(ref, sample=None):
        identity = digest("cap:", ("atlas-brain.synthetic-p3/1", side, base, sample, ref["node"], ref["path"], ref["operation"], raw)
                          if sample else ("atlas-brain.synthetic-p2/1", "demo", base, ref["path"], ref["node"], ref["operation"], raw))
        rendered = command if sample else "show cdp neighbors detail"
        proof = dict(kind="capture", capture=identity, source="node:demo:" + ref["node"], path=ref["path"],
            operation=ref["operation"], rendered=rendered, role="subject", sha256=raw, capture_sha256=raw,
            integrity="complete", read_scope="unknown", view="unknown", locator="whole_capture")
        if sample:
            proof.update(sample=sample, collected_utc=None)
        captures.append(dict(id=identity, source=proof["source"], sample=sample, operation=ref["operation"], rendered=rendered,
            sha256=raw, integrity="complete", read_scope="unknown", view="unknown", parse="complete",
            owner="l3.ospf/parse_samples" if sample else "l2.discovery/parse", evidence=[proof]))
        return proof
    capture(dict(node="a", path="cdp.txt", operation="iosxe.show_cdp_neighbors_detail", sha256=raw))
    samples = []
    for index, name in enumerate(("first", "second")):
        refs, rows = [], []
        for point, scope in zip(points, scopes):
            ref = dict(node=point["node"], path=name + point["node"] + ".txt", operation=operation, sha256=raw)
            refs.append(ref)
            state = known(False, "configured", [capture(ref, name)], "no ip ospf mtu-ignore")
            rows.append(dict(adjacency="link", node=point["node"], port=port,
                subject=digest("ospf_sample:", context + (scope, name)), facts={"l3.ospf.mtu_ignore": state}))
        value = dict(id=name, time=None, captures=refs)
        samples.append(dict(id=name, endpoints=rows,
            declaration=known(name, "declared", [registry("synthetic_p3.samples", name, "/samples/" + str(index), value)], name)))
    controls = [dict(kind="fact", fact="l3.ospf.mtu_ignore", subject=sample["endpoints"][1]["subject"],
                     state=sample["endpoints"][1]["facts"]["l3.ospf.mtu_ignore"]) for sample in samples]
    need = dict(node="node:demo:b", operation=operation, rendered=command, params=[], resolves=["check"], reruns=["rerun"], after_s=None, unprintable=[])
    hops = [dict(id=name, state=known(True, "derived", controls if name == "receiving_control" else [adj_ref]))
            for name in ("peer_context", "ip_mtu", "sampled_persistence", "receiving_control", "candidate")]
    return dict(base_registry_sha256=base, registry_sha256=side, nodes=nodes, samples=samples, captures=captures,
        group=dict(id="demo", semantic_group="declared_synthetic", declaration=known("demo", "declared",
            [registry("synthetic_p2.groups", "demo", "/group", "demo")], "demo")),
        endpoints=[dict(node=p["node"], port=port, subject=digest("interface:", (scope[0], port)), facts={}) for p, scope in zip(points, scopes)],
        adjacencies=[dict(id="link", subject=adj_subject, declaration=known("link", "declared", [adj_ref], "link"), facts={})],
        findings=[dict(check="l3.ospf.mtu_cause_candidate", adjacency="link", subject=adj_subject, state="problem", reason=None,
            interpretation="conditional_mtu_ospf_candidate", receiving_endpoint=digest("interface:", (scopes[1][0], port)),
            hops=hops, evidence=[adj_ref], next_evidence=[need])],
        coverage=dict(state="unknown", reason="denominator_open", detail=None, candidates=[], evidence=[adj_ref], next_evidence=[need]))


@pytest.mark.parametrize("family", ["group", "nodes", "samples", "adjacencies"])
def test_empty_declaration_witness_never_counts_as_registry_binding(family):
    payload = fixture()
    validate(payload)
    (payload[family] if family == "group" else payload[family][0])["declaration"]["evidence"] = [{}]
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        validate(payload)


@pytest.mark.parametrize("field,value", [("source", "node:demo:b"), ("sample", "second"), ("owner", "l2.mtu/parse_samples")])
def test_existing_valid_labels_cannot_be_rebound_to_unchanged_capture_identity(field, value):
    payload = fixture()
    payload["captures"][1][field] = value
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        validate(payload)
