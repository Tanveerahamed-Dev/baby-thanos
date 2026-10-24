"""Exact candidate partitions and coverage that cannot claim vacuous health."""
from dataclasses import InitVar, dataclass
from typing import Literal

from .states import (
    EntityKey,
    Evidence,
    NAReason,
    UnknownReason,
    evidence_tuple,
    require,
)


def ordered(values: tuple[str, ...]) -> None:
    require(type(values) is tuple and all(type(v) is str and bool(v) for v in values), 'invalid_keys')
    require(values == tuple(sorted(set(values))), 'unordered_or_duplicate_keys')


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpectedSet:
    population: str
    candidates: InitVar[tuple[EntityKey, ...]]
    members: tuple[EntityKey, ...]
    member_evidence: tuple[tuple[EntityKey, tuple[Evidence, ...]], ...]
    exclusions: tuple[tuple[EntityKey, NAReason, tuple[Evidence, ...]], ...]
    unresolved: tuple[tuple[EntityKey, UnknownReason], ...]
    closed: bool
    lower_bound_nodes: tuple[EntityKey, ...]
    closure_evidence: tuple[Evidence, ...]

    def __post_init__(self, candidates: tuple[EntityKey, ...]) -> None:
        require(bool(self.population) and type(self.closed) is bool, 'invalid_population')
        require(all(type(v) is tuple for v in (self.member_evidence, self.exclusions, self.unresolved)), 'invalid_partition_records')
        for rows, width in ((self.member_evidence, 2), (self.exclusions, 3), (self.unresolved, 2)):
            require(all(type(row) is tuple and len(row) == width for row in rows), 'invalid_partition_row')
        excluded = tuple(e[0] for e in self.exclusions)
        unresolved = tuple(u[0] for u in self.unresolved)
        for keys in (candidates, self.members, excluded, unresolved, self.lower_bound_nodes):
            ordered(keys)
        partition = self.members + excluded + unresolved
        require(tuple(sorted(partition)) == candidates, 'candidate_partition_mismatch')
        require(tuple(e[0] for e in self.member_evidence) == self.members, 'member_evidence_mismatch')
        for _, evidence in self.member_evidence:
            evidence_tuple(evidence, nonempty=True)
        for _, reason, evidence in self.exclusions:
            require(type(reason) is NAReason, 'invalid_exclusion_reason')
            evidence_tuple(evidence, nonempty=True)
        for _, reason in self.unresolved:
            require(type(reason) is UnknownReason, 'invalid_applicability_reason')
        evidence_tuple(self.closure_evidence, nonempty=self.closed)
        require(not self.closed or not self.lower_bound_nodes, 'closed_population_has_lower_bounds')


@dataclass(frozen=True, slots=True, kw_only=True)
class CoverageSummary:
    expected: int
    excluded: int
    unresolved: int
    closed: bool
    state: Literal['none_expected', 'populated', 'unknown']
    reason: UnknownReason | None
    closure_evidence: tuple[Evidence, ...]


def coverage(expected: ExpectedSet) -> CoverageSummary:
    state: Literal['none_expected', 'populated', 'unknown'] = 'populated'
    reason: UnknownReason | None = None
    if not expected.closed or expected.unresolved:
        state, reason = 'unknown', UnknownReason.DENOMINATOR_OPEN
    elif not expected.members:
        state = 'none_expected'
    return CoverageSummary(expected=len(expected.members), excluded=len(expected.exclusions),
                           unresolved=len(expected.unresolved), closed=expected.closed,
                           state=state, reason=reason, closure_evidence=expected.closure_evidence)
