"""Pure declared-synthetic P2 analysis; no filesystem or current-link qualification."""
import json
from hashlib import sha256

from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.evidence.synthetic import OPERATIONS, SyntheticGroup
from atlas_brain.kernel import states as k
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactReader, FactStore, StoredState, bind_reader
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as trunk
from atlas_brain.packs.l2.vlan_trunk import check
from atlas_brain.runner.p2_evidence import project_fact, project_needs, resolve_evidence
from atlas_brain.runner.records import RunnerRefused

SCHEMA = "atlas-brain.p2-demo/1"
FACT_IDS = tuple(sorted(discovery.IDS + trunk.STEP.produces + (link.PEER,)))
PROJECT = StepSpec(id=StepId("l2.vlan_trunk/project"), pack=trunk.PACK, kind="derive", scope="estate",
                   reads=FACT_IDS, produces=(), evaluator="l2.vlan_trunk.project")
STEPS = (discovery.STEP, trunk.STEP, link.STEP, check.STEP, PROJECT)


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p2_" + code)


def _parse_all(group: SyntheticGroup, store: FactStore) -> dict[str, ParseResult]:
    _need(trunk.OP not in discovery.OPERATIONS, "ambiguous_parser")
    owners: dict[str | None, str] = {operation: str(discovery.STEP.id) for operation in discovery.OPERATIONS}
    owners[trunk.OP] = str(trunk.STEP.id)
    expected = {str(capture.id): capture for capture in group.captures}
    _need(len(expected) == len(group.captures), "duplicate_capture")
    nodes = {node.key for node in group.nodes}
    _need(all(capture.source in nodes and capture.operation in owners for capture in group.captures), "unowned_capture")
    parsed: list[tuple[str, str, str, ParseResult]] = []
    for node in sorted(group.nodes, key=lambda node: node.id):
        for owner, result in ((discovery.STEP, discovery.build_node(group, node, store)),
                              (trunk.STEP, trunk.build_node(group, node, store))):
            parsed.extend((str(identity), str(owner.id), str(node.key), parse) for identity, parse in result.parses)
    _need(len(parsed) == len(expected) and {identity for identity, _, _, _ in parsed} == set(expected), "parse_coverage")
    _need(all(owner == owners[expected[identity].operation] for identity, owner, _, _ in parsed), "parse_owner")
    _need(all(source == str(expected[identity].source) for identity, _, source, _ in parsed), "parse_source")
    return {identity: parse for identity, _, _, parse in parsed}


def _point(point: check.Endpoint) -> dict[str, object]:
    return {"node": point.node.id, "port": point.port, "subject": str(point.subject)}


def _show(state: StoredState) -> str:
    if isinstance(state, k.Known):
        return json.dumps(state.value, ensure_ascii=True)
    if isinstance(state, k.Unknown):
        return "unknown(" + str(state.reason) + ")"
    raise RunnerRefused("p2_summary_state")


def _finding(group: SyntheticGroup, reader: FactReader, row: check.Comparison,
             points: dict[str, check.Endpoint]) -> tuple[dict[str, object], str]:
    _need(row.check in check.CHECKS, "unknown_check")
    left, right = points[str(row.left)], points[str(row.right)] if row.right is not None else None
    evidence = resolve_evidence(group, reader, row.evidence)
    result: dict[str, object] = {
        "check": row.check, "left": _point(left), "right": _point(right) if right is not None else None,
        "state": row.state, "reason": str(row.reason) if row.reason is not None else None,
        "evidence": evidence, "next_evidence": project_needs(group, row.next_evidence),
    }
    if row.left_only is not None:
        result["left_only"] = row.left_only
    if row.right_only is not None:
        result["right_only"] = row.right_only
    fact = trunk.NATIVE if row.check == check.NATIVE_CHECK else trunk.ALLOWED
    description = left.node.id + "/" + left.port + "=" + _show(reader.read(fact=fact, subject=left.subject))
    if right is not None:
        description += " vs " + right.node.id + "/" + right.port + "=" + _show(reader.read(fact=fact, subject=right.subject))
    reason = " reason=" + str(row.reason) if row.reason is not None else ""
    line = row.check + " " + description + ": " + row.state + reason
    return result, line + " evidence=" + json.dumps(evidence, ensure_ascii=True, sort_keys=True)


def analyse_group(group: SyntheticGroup) -> tuple[dict[str, object], tuple[str, ...]]:
    """Run every node parser before either estate builder; project through a reader."""
    steps = order_steps(STEPS)
    digest = catalogue_digest(build_catalogue(entity_kinds=link.KINDS,
        facts=discovery.FACTS + trunk.FACTS + link.FACTS, relations=link.RELATIONS, steps=steps))
    store = FactStore()
    parses = _parse_all(group, store)  # Instance barrier: all capture ids checked before pairing.
    link.build_group(group, store)
    result = check.build_group(group, store)
    reader = bind_reader(store, step=PROJECT)
    points = {str(point.subject): point for point in result.endpoints}
    endpoint_records = [
        {**_point(point), "facts": {str(fact): project_fact(group, reader, reader.read(fact=fact, subject=point.subject))
                                  for fact in FACT_IDS}}
        for point in sorted(result.endpoints, key=lambda point: (point.node.id, point.port))
    ]
    findings: list[dict[str, object]] = []
    lines = ["P2 group=" + group.id + " semantic_group=declared_synthetic variant_support=allowlisted"]
    for row in sorted(result.rows, key=lambda row: (row.left, row.right or "", row.check)):
        finding, line = _finding(group, reader, row, points)
        findings.append(finding)
        lines.append(line)
    captures: list[dict[str, object]] = []
    for capture in sorted(group.captures, key=lambda capture: capture.id):
        operation = capture.operation
        _need(operation in OPERATIONS, "unowned_capture")
        if operation is None:
            raise RunnerRefused("p2_unowned_capture")
        collected = capture.collected_utc
        if not isinstance(collected, k.Unknown):
            raise RunnerRefused("p2_unexpected_collector_time")
        captures.append({"id": str(capture.id), "source": str(capture.source), "operation": operation,
                         "rendered": OPERATIONS[operation], "sha256": capture.bytes_sha256,
                         "integrity": str(capture.integrity), "read_scope": str(capture.read_scope),
                         "view": str(capture.view), "parse": parses[str(capture.id)].quality,
                         "collected_utc": project_fact(group, reader, collected),
                         "evidence": resolve_evidence(group, reader, capture.integrity_evidence)})
    nodes = [{"id": node.id, "key": str(node.key), "discovery_id": node.discovery_id,
              "ports": list(node.ports), "declaration": project_fact(group, reader, node.declaration)}
             for node in sorted(group.nodes, key=lambda node: node.id)]
    payload: dict[str, object] = {
        "schema": SCHEMA, "group": {"id": group.id, "semantic_group": "declared_synthetic",
                                   "declaration": project_fact(group, reader, group.declaration)},
        "variant_support": "allowlisted", "registry_sha256": sha256(group.raw).hexdigest(),
        "nodes": nodes, "endpoints": endpoint_records, "findings": findings,
        "coverage": project_fact(group, reader, result.coverage), "denominator": dict(result.denominator),
        "catalogue_digest": digest, "captures": captures,
    }
    return payload, tuple(lines)
