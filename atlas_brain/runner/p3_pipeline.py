"""P3 instance barrier: every capture receipt precedes every estate consumer."""
from dataclasses import dataclass

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.p3_records import P3Group, sample_subject
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.mtu import build as l2_mtu
from atlas_brain.packs.l3.mtu import build as l3_mtu
from atlas_brain.packs.l3.ospf import build as ospf
from atlas_brain.packs.l3.ospf import ignore, interface, neighbor, r1, settle
from atlas_brain.packs.l3.ospf import specs as s
from atlas_brain.runner.records import RunnerRefused

SAMPLE_FACTS = tuple(sorted((l2_mtu.MTU, l3_mtu.MTU) + s.IDS))
STEPS = (discovery.STEP, l2_mtu.STEP, l3_mtu.STEP, s.STEP, link.STEP, s.SETTLE, r1.STEP)


@dataclass(frozen=True, slots=True, kw_only=True)
class Receipt:
    capture: k.CaptureId
    owner: StepId
    node: k.EntityKey
    sample: str | None
    parse: ParseResult


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    store: FactStore
    receipts: tuple[Receipt, ...]
    links: link.LinkResult
    settled: settle.Result
    findings: r1.Result


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p3_" + code)


def parse_all(group: P3Group, store: FactStore) -> tuple[Receipt, ...]:
    """Include absent operations in the fact matrix and every supplied capture in custody."""
    owners = {l2_mtu.OP: l2_mtu.STEP.id, l3_mtu.OP: l3_mtu.STEP.id,
              neighbor.OP: s.STEP.id, interface.OP: s.STEP.id, ignore.OP: s.STEP.id}
    _need(len(owners) == 5 and set(owners).isdisjoint(discovery.OPERATIONS), "ambiguous_parser")
    nodes = {node.key for node in group.base.nodes}
    participating = {point.node.key for adjacency in group.adjacencies for point in (adjacency.left, adjacency.right)}
    _need(len(nodes) == len(group.base.nodes) and participating <= nodes, "node_population")
    _need(len({sample.id for sample in group.samples}) == len(group.samples), "sample_population")
    expected: dict[k.CaptureId, tuple[Capture, StepId, str | None]] = {}
    for capture in group.base.captures:
        _need(capture.source in nodes and capture.operation in discovery.OPERATIONS, "unowned_base_capture")
        _need(capture.id not in expected, "duplicate_capture")
        expected[capture.id] = (capture, discovery.STEP.id, None)
    for sample in group.samples:
        for capture in sample.captures:
            operation = capture.operation
            _need(capture.source in participating and operation in owners, "unowned_sample_capture")
            if operation is None:
                raise RunnerRefused("p3_unowned_sample_capture")
            _need(capture.id not in expected, "duplicate_capture")
            expected[capture.id] = (capture, owners[operation], sample.id)
    receipts: list[Receipt] = []
    for node in sorted(group.base.nodes, key=lambda item: item.id):
        discovery_result = discovery.build_node(group.base, node, store)
        _need(len(discovery_result.rows) == len(node.ports)
              and {row.local_port for row in discovery_result.rows} == set(node.ports), "discovery_population")
        receipts.extend(Receipt(capture=identity, owner=discovery.STEP.id, node=node.key, sample=None, parse=parsed)
                        for identity, parsed in discovery_result.parses)
    for sample in sorted(group.samples, key=lambda item: item.id):
        for node in sorted(group.base.nodes, key=lambda item: item.id):
            subjects = {sample_subject(adjacency, point, sample) for adjacency in group.adjacencies
                        for point in (adjacency.left, adjacency.right) if point.node.key == node.key}
            for step, result in ((l2_mtu.STEP, l2_mtu.build_sample(group, sample, node, store)),
                                 (l3_mtu.STEP, l3_mtu.build_sample(group, sample, node, store)),
                                 (s.STEP, ospf.build_sample(group, sample, node, store))):
                _need(len(result.rows) == len(subjects) and {row.subject for row in result.rows} == subjects,
                      "sample_fact_population")
                _need(all(k.FactRef(fact=fact, subject=subject) in store.values
                          for subject in subjects for fact in step.produces), "sample_fact_population")
                receipts.extend(Receipt(capture=identity, owner=step.id, node=node.key, sample=sample.id, parse=parsed)
                                for identity, parsed in result.parses)
    _need(len(receipts) == len(expected) and {item.capture for item in receipts} == set(expected), "parse_coverage")
    for item in receipts:
        capture, owner, sample_id = expected[item.capture]
        _need(item.owner == owner, "parse_owner")
        _need(item.node == capture.source, "parse_source")
        _need(item.sample == sample_id, "parse_sample")
    return tuple(sorted(receipts, key=lambda item: str(item.capture)))


def run(group: P3Group) -> Result:
    """No pairing, settlement or correlation executes before the instance barrier."""
    order_steps(STEPS)
    store = FactStore()
    receipts = parse_all(group, store)
    links = link.build_group(group.base, store)
    settled = settle.build_group(group, store)
    findings = r1.build_group(group, store)
    return Result(store=store, receipts=receipts, links=links, settled=settled, findings=findings)
