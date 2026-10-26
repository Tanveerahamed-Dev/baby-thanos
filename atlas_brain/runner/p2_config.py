"""Schema-2 declared-synthetic analysis keeps configured and operational bases apart."""
import json
from hashlib import sha256
from typing import cast

from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.evidence.synthetic import (
    CONFIG_SCHEMA,
    SyntheticGroup,
    endpoint,
    operation_map,
)
from atlas_brain.kernel import states as k
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactReader, FactStore, StoredState, bind_reader
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.vlan_trunk import build as trunk
from atlas_brain.packs.l2.vlan_trunk import check, config_build, config_check
from atlas_brain.runner.p2_evidence import project_fact, project_needs, resolve_evidence
from atlas_brain.runner.records import RunnerRefused

SCHEMA = "atlas-brain.p2-demo/2"
FACT_IDS = tuple(sorted(discovery.IDS + trunk.STEP.produces + config_build.IDS + (link.PEER,)))
PROJECT = StepSpec(id=StepId("l2.vlan_trunk/project_config"), pack=trunk.PACK, kind="derive",
                   scope="estate", reads=FACT_IDS, produces=(), evaluator="l2.vlan_trunk.project_config")
STEPS = (discovery.STEP, trunk.STEP, config_build.STEP, link.STEP, check.STEP, config_check.STEP, PROJECT)
SUMMARY_FACTS = {check.NATIVE_CHECK: str(trunk.NATIVE), check.ALLOWED_CHECK: str(trunk.ALLOWED),
                 config_check.NATIVE_CHECK: str(config_build.NATIVE),
                 config_check.ALLOWED_CHECK: str(config_build.ALLOWED)}


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p2_config_" + code)


def _parse_all(group: SyntheticGroup, store: FactStore) -> dict[str, ParseResult]:
    owners = {operation: str(discovery.STEP.id) for operation in discovery.OPERATIONS}
    _need(trunk.OP not in owners and config_build.OP not in owners and trunk.OP != config_build.OP, "ambiguous_parser")
    owners[trunk.OP], owners[config_build.OP] = str(trunk.STEP.id), str(config_build.STEP.id)
    expected = {str(capture.id): capture for capture in group.captures}
    _need(len(expected) == len(group.captures), "duplicate_capture")
    nodes = {node.key for node in group.nodes}
    _need(all(capture.source in nodes and capture.operation in owners for capture in group.captures), "unowned_capture")
    parsed: list[tuple[str, str, str, ParseResult]] = []
    for node in sorted(group.nodes, key=lambda node: node.id):
        for owner, result in ((discovery.STEP, discovery.build_node(group, node, store)),
                              (trunk.STEP, trunk.build_node(group, node, store)),
                              (config_build.STEP, config_build.build_node(group, node, store))):
            parsed.extend((str(identity), str(owner.id), str(node.key), parse) for identity, parse in result.parses)
    _need(len(parsed) == len(expected) and {identity for identity, _, _, _ in parsed} == set(expected), "parse_coverage")
    for identity, owner, source, _ in parsed:
        capture = expected[identity]
        _need(capture.operation is not None and owner == owners[capture.operation], "parse_owner")
        _need(source == str(capture.source), "parse_source")
    return {identity: parse for identity, _, _, parse in parsed}


def _point(point: config_check.Endpoint) -> dict[str, object]:
    return {"node": point.node.id, "port": point.port, "subject": str(point.subject)}


def _show(state: StoredState) -> str:
    if isinstance(state, k.Known):
        return json.dumps(state.value, ensure_ascii=True)
    if isinstance(state, k.Unknown):
        return "unknown(" + str(state.reason) + ")"
    raise RunnerRefused("p2_config_summary_state")


def _finding(group: SyntheticGroup, reader: FactReader, row: check.Comparison,
             points: dict[str, config_check.Endpoint]) -> tuple[dict[str, object], str]:
    _need(row.check in SUMMARY_FACTS, "unknown_check")
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
    fact = cast("k.FactId", SUMMARY_FACTS[row.check])
    description = left.node.id + "/" + left.port + "=" + _show(reader.read(fact=fact, subject=left.subject))
    if right is not None:
        description += " vs " + right.node.id + "/" + right.port + "=" + _show(reader.read(fact=fact, subject=right.subject))
    reason = " reason=" + str(row.reason) if row.reason is not None else ""
    line = row.check + " " + description + ": " + row.state + reason
    return result, line + " evidence=" + json.dumps(evidence, ensure_ascii=True, sort_keys=True)


def analyse_group(group: SyntheticGroup) -> tuple[dict[str, object], tuple[str, ...]]:
    """Finish every node producer before either basis-specific estate comparison."""
    _need(group.schema == CONFIG_SCHEMA, "group_schema")
    steps = order_steps(STEPS)
    digest = catalogue_digest(build_catalogue(entity_kinds=link.KINDS, relations=link.RELATIONS,
        facts=discovery.FACTS + trunk.FACTS + config_build.FACTS + link.FACTS, steps=steps))
    store = FactStore()
    parses = _parse_all(group, store)
    link.build_group(group, store)
    observed, configured = check.build_group(group, store), config_check.build_group(group, store)
    reader = bind_reader(store, step=PROJECT)
    points = {str(point.subject): point for point in configured.endpoints}
    expected = {str(endpoint(node, port)) for node in group.nodes for port in node.ports}
    _need(len(points) == len(configured.endpoints) == len(observed.endpoints) == len(expected)
          and set(points) == {str(point.subject) for point in observed.endpoints} == expected, "endpoint_coverage")
    endpoints = [
        {**_point(point), "facts": {str(fact): project_fact(group, reader, reader.read(fact=fact, subject=point.subject))
                                  for fact in FACT_IDS}}
        for point in sorted(configured.endpoints, key=lambda point: (point.node.id, point.port))
    ]
    findings: list[dict[str, object]] = []
    lines = ["P2 schema=" + SCHEMA + " group=" + group.id + " semantic_group=declared_synthetic variant_support=allowlisted",
             "configuration basis=configured interpretation=supplied_statements_only comparison=configuration_only_no_cross_basis_inference"]
    for row in sorted(observed.rows + configured.rows, key=lambda row: (row.left, row.right or "", row.check)):
        finding, line = _finding(group, reader, row, points)
        findings.append(finding)
        lines.append(line)
    operations = operation_map(group.schema)
    captures: list[dict[str, object]] = []
    for capture in sorted(group.captures, key=lambda capture: capture.id):
        operation = capture.operation
        if operation is None or operation not in operations:
            raise RunnerRefused("p2_config_unowned_capture")
        collected = capture.collected_utc
        if not isinstance(collected, k.Unknown):
            raise RunnerRefused("p2_config_unexpected_collector_time")
        captures.append({"id": str(capture.id), "source": str(capture.source), "operation": operation,
                         "rendered": operations[operation], "sha256": capture.bytes_sha256,
                         "integrity": str(capture.integrity), "read_scope": str(capture.read_scope),
                         "view": str(capture.view), "parse": parses[str(capture.id)].quality,
                         "collected_utc": project_fact(group, reader, collected),
                         "evidence": resolve_evidence(group, reader, capture.integrity_evidence)})
    nodes = [{"id": node.id, "key": str(node.key), "discovery_id": node.discovery_id,
              "ports": list(node.ports), "declaration": project_fact(group, reader, cast("StoredState", node.declaration))}
             for node in sorted(group.nodes, key=lambda node: node.id)]
    payload: dict[str, object] = {
        "schema": SCHEMA, "group": {"id": group.id, "semantic_group": "declared_synthetic",
                                   "declaration": project_fact(group, reader, cast("StoredState", group.declaration))},
        "variant_support": "allowlisted", "registry_sha256": sha256(group.raw).hexdigest(),
        "nodes": nodes, "endpoints": endpoints, "findings": findings,
        "coverage": project_fact(group, reader, observed.coverage), "denominator": dict(observed.denominator),
        "configuration": {"basis": "configured", "interpretation": "supplied_statements_only",
                          "comparison": "configuration_only_no_cross_basis_inference",
                          "coverage": project_fact(group, reader, configured.coverage),
                          "denominator": dict(configured.denominator)},
        "catalogue_digest": digest, "captures": captures,
    }
    return payload, tuple(lines)
