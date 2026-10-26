"""Pure P3 projection: owned facts, conditional chain and explicit declared scope."""
import json
from hashlib import sha256
from typing import cast

from atlas_brain.evidence.p3_records import P3Group, adjacency_subject, sample_subject
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactReader, StoredState, bind_reader
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.mtu import build as l2_mtu
from atlas_brain.packs.l3.mtu import build as l3_mtu
from atlas_brain.packs.l3.ospf import specs as s
from atlas_brain.runner import p3_pipeline
from atlas_brain.runner.p3_evidence import project_fact, project_needs, resolve_evidence
from atlas_brain.runner.records import RunnerRefused

SCHEMA = "atlas-brain.p3-demo/1"
BASE_FACTS = tuple(sorted(discovery.IDS + (link.PEER,)))
FACT_IDS = tuple(sorted(BASE_FACTS + p3_pipeline.SAMPLE_FACTS + s.SETTLE.produces))
PROJECT = StepSpec(id=StepId("l3.ospf/project"), pack=s.PACK, kind="derive", scope="estate",
                   reads=FACT_IDS, produces=(), evaluator="l3.ospf.project")
STEPS = p3_pipeline.STEPS + (PROJECT,)
INTERPRETATION = "conditional_mtu_ospf_candidate"
SCOPE = "declared_synthetic_default_vrf_point_to_point"
TIMING = "supplied_collector_windows"


def _state(value: StoredState) -> str:
    if isinstance(value, k.Known):
        return "known(" + json.dumps(value.value, ensure_ascii=True) + ")"
    if isinstance(value, k.Unknown):
        return "unknown(" + str(value.reason) + ")"
    if isinstance(value, k.NotApplicable):
        return "not_applicable(" + str(value.reason) + ")"
    raise RunnerRefused("p3_summary_state")



def _owned(group: P3Group, reader: FactReader, fact: k.FactId, subject: k.EntityKey) -> dict[str, object]:
    """Keep the immediate fact parent so leaf scope cannot be laundered."""
    records = resolve_evidence(group, reader, (k.FactRef(fact=fact, subject=subject),))
    if (len(records) != 1 or records[0].get("kind") != "fact"
            or records[0].get("fact") != fact or records[0].get("subject") != subject
            or not isinstance(records[0].get("state"), dict)):
        raise RunnerRefused("p3_fact_projection")
    return cast(dict[str, object], records[0]["state"])


def analyse_group(group: P3Group) -> tuple[dict[str, object], tuple[str, ...]]:
    """Run the complete owner pipeline, then project only through the declared reader."""
    catalogue = build_catalogue(entity_kinds=link.KINDS + s.KINDS,
        facts=discovery.FACTS + link.FACTS + l2_mtu.FACTS + l3_mtu.FACTS + s.FACTS + s.SETTLED_FACTS,
        relations=link.RELATIONS + s.RELATIONS, steps=order_steps(STEPS))
    result = p3_pipeline.run(group)
    reader = bind_reader(result.store, step=PROJECT)
    nodes = [{"id": node.id, "key": str(node.key), "discovery_id": node.discovery_id, "ports": list(node.ports),
              "declaration": project_fact(group, reader, cast(StoredState, node.declaration))}
             for node in sorted(group.base.nodes, key=lambda node: node.id)]
    endpoints = [{"node": node.id, "port": port, "subject": str(endpoint(node, port)),
                  "facts": {str(fact): _owned(group, reader, fact, endpoint(node, port))
                            for fact in BASE_FACTS}}
                 for node in sorted(group.base.nodes, key=lambda node: node.id) for port in sorted(node.ports)]
    samples: list[dict[str, object]] = []
    for sample in sorted(group.samples, key=lambda item: item.id):
        points: list[dict[str, object]] = []
        for adjacency in sorted(group.adjacencies, key=lambda item: item.id):
            for point in sorted((adjacency.left, adjacency.right), key=lambda item: (item.node.id, item.port)):
                subject = sample_subject(adjacency, point, sample)
                points.append({"adjacency": adjacency.id, "node": point.node.id, "port": point.port,
                    "subject": str(subject), "facts": {str(fact): _owned(group, reader, fact, subject) for fact in p3_pipeline.SAMPLE_FACTS}})
        samples.append({"id": sample.id, "declaration": project_fact(group, reader, cast(StoredState, sample.declaration)),
                        "endpoints": points})
    adjacencies: list[dict[str, object]] = []
    for adjacency in sorted(group.adjacencies, key=lambda item: item.id):
        subject = adjacency_subject(adjacency)
        adjacencies.append({"id": adjacency.id, "subject": str(subject),
            "declaration": project_fact(group, reader, cast(StoredState, adjacency.declaration)),
            "facts": {str(fact): _owned(group, reader, fact, subject)
                      for fact in s.SETTLE.produces}})
    expected = {adjacency_subject(adjacency) for adjacency in group.adjacencies}
    if len(result.findings.rows) != len(expected) or {row.subject for row in result.findings.rows} != expected:
        raise RunnerRefused("p3_finding_population")
    findings: list[dict[str, object]] = []
    lines = [f"P3 schema={SCHEMA} semantic_group=declared_synthetic variant_support=allowlisted",
             f"interpretation={INTERPRETATION} scope={SCOPE} timing={TIMING}",
             "MTU mismatch -> sampled OSPF EXSTART/EXCHANGE persistence; unique cause is not proven"]
    for row in sorted(result.findings.rows, key=lambda item: item.adjacency.id):
        hops = [{"id": hop.id, "state": project_fact(group, reader, cast(StoredState, hop.state))} for hop in row.hops]
        finding: dict[str, object] = {"check": p3_pipeline.r1.CHECK, "adjacency": row.adjacency.id,
            "subject": str(row.subject), "state": row.state, "reason": str(row.reason) if row.reason is not None else None,
            "interpretation": INTERPRETATION, "receiving_endpoint": row.receiving_endpoint,
            "hops": hops, "evidence": resolve_evidence(group, reader, row.evidence),
            "next_evidence": project_needs(group, row.next_evidence)}
        findings.append(finding)
        chain = " -> ".join(hop.id + "=" + _state(cast(StoredState, hop.state)) for hop in row.hops)
        lines.append(f"R1 adjacency={row.adjacency.id} state={row.state} {chain}")
        if row.next_evidence:
            lines.append("next_evidence=" + json.dumps(project_needs(group, row.next_evidence), ensure_ascii=True, sort_keys=True))
    captures_by_id = {capture.id: capture for capture in group.base.captures}
    captures_by_id.update((capture.id, capture) for sample in group.samples for capture in sample.captures)
    captures: list[dict[str, object]] = []
    for receipt in result.receipts:
        capture = captures_by_id[receipt.capture]
        captures.append({"id": str(capture.id), "source": str(capture.source), "sample": receipt.sample,
            "operation": capture.operation, "rendered": capture.rendered, "sha256": capture.bytes_sha256,
            "integrity": str(capture.integrity), "read_scope": str(capture.read_scope), "view": str(capture.view),
            "parse": receipt.parse.quality, "owner": str(receipt.owner),
            "evidence": resolve_evidence(group, reader, capture.integrity_evidence)})
    payload: dict[str, object] = {"schema": SCHEMA,
        "group": {"id": group.base.id, "semantic_group": "declared_synthetic",
                  "declaration": project_fact(group, reader, cast(StoredState, group.base.declaration))},
        "variant_support": "allowlisted", "interpretation": INTERPRETATION, "scope": SCOPE, "timing": TIMING,
        "base_registry_sha256": sha256(group.base.raw).hexdigest(), "registry_sha256": sha256(group.raw).hexdigest(),
        "nodes": nodes, "endpoints": endpoints, "samples": samples, "adjacencies": adjacencies,
        "findings": findings, "coverage": project_fact(group, reader, result.findings.coverage),
        "denominator": dict(result.findings.denominator), "catalogue_digest": catalogue_digest(catalogue),
        "captures": captures}
    return payload, tuple(lines)
