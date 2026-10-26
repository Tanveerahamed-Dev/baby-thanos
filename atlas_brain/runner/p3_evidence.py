"""P3 projection preserves owner states and checked recursive proof edges."""
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_records import P3Group, adjacency_subject, sample_subject
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, StoredState
from atlas_brain.packs.l2.mtu import build as l2_mtu
from atlas_brain.packs.l3.mtu import build as l3_mtu
from atlas_brain.packs.l3.ospf import specs as ospf
from atlas_brain.runner import p2, p2_evidence
from atlas_brain.runner.p3_refs import RefResolver
from atlas_brain.runner.records import RunnerRefused

SAMPLE_FACTS = frozenset(ospf.IDS + (l2_mtu.MTU, l3_mtu.MTU))
SETTLED_FACTS = frozenset(ospf.SETTLE.produces)


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p3_evidence_" + code)


def _bounded(records: list[dict[str, object]], depth: int) -> None:
    """A delegated P2 subtree still shares the caller's total depth budget."""
    for row in records:
        if row["kind"] == "fact":
            _need(depth < 32, "fact_depth")
            state = cast(dict[str, object], row["state"])
            _bounded(cast(list[dict[str, object]], state["evidence"]), depth + 1)


class _Projector:
    def __init__(self, group: P3Group, reader: FactReader) -> None:
        self.group, self.reader = group, reader
        self.leaves = RefResolver(group, reader)
        self.base_subjects = {endpoint(node, port) for node in group.base.nodes for port in node.ports}
        self.adjacency_subjects = {adjacency_subject(adjacency) for adjacency in group.adjacencies}
        self.sample_subjects = {sample_subject(adjacency, point, sample) for adjacency in group.adjacencies
                                for point in (adjacency.left, adjacency.right) for sample in group.samples}

        self.allowed: dict[k.EntityKey, tuple[set[k.CaptureId], set[k.Evidence]]] = {}
        self.children: dict[k.EntityKey, set[k.EntityKey]] = {}
        for adjacency in group.adjacencies:
            points = (adjacency.left, adjacency.right)
            common = group.base.declaration.evidence + adjacency.declaration.evidence
            nodes = {point.node.key for point in points}
            captures = group.base.captures + tuple(c for sample in group.samples for c in sample.captures)
            declarations = common + tuple(ref for point in points for ref in point.node.declaration.evidence)
            declarations += tuple(ref for sample in group.samples for ref in sample.declaration.evidence)
            self.allowed[adjacency_subject(adjacency)] = (
                {c.id for c in captures if c.source in nodes}, set(declarations))
            self.children[adjacency_subject(adjacency)] = {adjacency_subject(adjacency)} | {
                endpoint(point.node, point.port) for point in points} | {
                sample_subject(adjacency, point, sample) for sample in group.samples for point in points}
            for sample in group.samples:
                for point in points:
                    self.children[sample_subject(adjacency, point, sample)] = {
                        sample_subject(adjacency, point, sample), endpoint(point.node, point.port)}
                    self.allowed[sample_subject(adjacency, point, sample)] = (
                        {c.id for c in sample.captures if c.source == point.node.key},
                        set(common + point.node.declaration.evidence + sample.declaration.evidence))

    def project(self, state: StoredState, chain: tuple[k.FactRef, ...]) -> dict[str, object]:
        _need(type(state) in (k.Known, k.Unknown, k.NotApplicable), "state")
        result: dict[str, object] = {"evidence": self.resolve(state.evidence, chain)}
        if isinstance(state, k.Known):
            _need(type(state.value) in (str, int, bool), "value")
            try:
                canonical(state.value)
            except (TypeError, ValueError, UnicodeError) as error:
                raise RunnerRefused("p3_evidence_value") from error
            result.update(state="known", basis=str(state.basis), value=state.value, raw=state.raw)
        elif isinstance(state, k.Unknown):
            result.update(state="unknown", reason=str(state.reason), detail=state.detail,
                          candidates=list(state.candidates),
                          next_evidence=[self.leaves.need(need) for need in state.next_evidence])
        elif isinstance(state, k.NotApplicable):
            result.update(state="not_applicable", reason=str(state.reason))
        return result

    def resolve(self, evidence: tuple[k.Evidence, ...], chain: tuple[k.FactRef, ...]) -> list[dict[str, object]]:
        _need(len(chain) <= 32, "fact_depth")
        records: dict[bytes, dict[str, object]] = {}
        for ref in evidence:
            projected: dict[str, object]
            if type(ref) in (k.EvidenceRef, k.RegistryRef):
                if chain:
                    captures, declarations = self.allowed[chain[-1].subject]
                    _need(ref.capture in captures if isinstance(ref, k.EvidenceRef)
                          else ref in declarations, "parent_relevance")
                projected = self.leaves.resolve(cast(k.EvidenceRef | k.RegistryRef, ref))
            elif type(ref) is k.FactRef:
                _need(not chain or ref.subject in self.children[chain[-1].subject], "parent_relevance")
                _need(ref not in chain, "fact_cycle")
                if ref.subject in self.base_subjects:
                    _need(ref.fact in p2.FACT_IDS, "fact_subject")
                    delegated = p2_evidence.resolve_evidence(self.group.base, self.reader, (ref,))
                    _bounded(delegated, len(chain))
                    projected = delegated[0]
                else:
                    _need(ref.fact in SAMPLE_FACTS and ref.subject in self.sample_subjects
                          or ref.fact in SETTLED_FACTS and ref.subject in self.adjacency_subjects, "fact_subject")
                    try:
                        state = self.reader.read(fact=ref.fact, subject=ref.subject)
                    except ValueError as error:
                        raise RunnerRefused("p3_evidence_fact_unreadable") from error
                    projected = {"kind": "fact", "fact": str(ref.fact), "subject": str(ref.subject),
                                 "state": self.project(state, chain + (ref,))}
            else:
                raise RunnerRefused("p3_evidence_reference")
            records[canonical(projected)] = projected
        return [records[key] for key in sorted(records)]


class _NoFacts:
    """Collection-need projection permits no fact reads, including during delegation."""
    def read(self, *, fact: k.FactId, subject: k.EntityKey) -> StoredState:
        raise RunnerRefused("p3_evidence_fact_unreadable")


def resolve_evidence(group: P3Group, reader: FactReader,
                     evidence: tuple[k.Evidence, ...]) -> list[dict[str, object]]:
    return _Projector(group, reader).resolve(evidence, ())


def project_fact(group: P3Group, reader: FactReader, state: StoredState) -> dict[str, object]:
    return _Projector(group, reader).project(state, ())


def project_needs(group: P3Group, needs: tuple[k.EvidenceNeed, ...]) -> list[dict[str, object]]:
    resolver = RefResolver(group, cast(FactReader, _NoFacts()))
    return [resolver.need(need) for need in needs]
