"""Conditional declared-synthetic VLAN counterexamples; equal untimed ends stay unknown."""
from dataclasses import dataclass
from typing import Literal, cast

from atlas_brain.evidence.synthetic import Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, StoredState, bind_reader
from atlas_brain.packs.l1.link.build import PEER
from atlas_brain.packs.l2.vlan_trunk import build as trunk

NATIVE_CHECK = "l2.vlan_trunk.native_mismatch"
ALLOWED_CHECK = "l2.vlan_trunk.allowed_asymmetry"
CHECKS = (ALLOWED_CHECK, NATIVE_CHECK)
STEP = StepSpec(id=StepId("l2.vlan_trunk/check"), pack=trunk.PACK, kind="check", scope="estate",
                reads=tuple(sorted((PEER, trunk.NATIVE, trunk.ALLOWED))), produces=(),
                evaluator="l2.vlan_trunk.check.build_group")


@dataclass(frozen=True, slots=True, kw_only=True)
class Endpoint:
    node: Node
    port: str
    subject: k.EntityKey
    peer: k.Known[str] | k.Unknown
    native: k.Known[int] | k.Unknown
    allowed: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Comparison:
    check: str
    left: k.EntityKey
    right: k.EntityKey | None
    state: Literal["problem", "unknown"]
    reason: k.UnknownReason | None
    evidence: tuple[k.Evidence, ...]
    next_evidence: tuple[k.EvidenceNeed, ...]
    left_only: str | None = None
    right_only: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckResult:
    rows: tuple[Comparison, ...]
    endpoints: tuple[Endpoint, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _state[T](value: StoredState, expected: type[T]) -> k.Known[T] | k.Unknown:
    if isinstance(value, k.Unknown):
        return value
    if not isinstance(value, k.Known) or type(value.value) is not expected:
        raise ValueError("invalid_trunk_check_input")
    return cast("k.Known[T]", value)


def _need(node: Node, operation: str, resolves: tuple[str, ...], reruns: tuple[str, ...]) -> k.EvidenceNeed:
    return k.EvidenceNeed(node=node.key, operation=operation, params=(), resolves=resolves,
                          reruns=reruns, after_s=None, unprintable=())


def _vlans(value: str) -> set[int]:
    result: set[int] = set()
    if value != "none":
        for token in value.split(","):
            ends = token.split("-")
            result.update(range(int(ends[0]), int(ends[-1]) + 1))
    return result


def _canonical(values: set[int]) -> str:
    value = trunk.canonical_allowed(",".join(str(v) for v in sorted(values))) if values else "none"
    k.require(value is not None, "invalid_allowed_difference")
    return cast(str, value)


def _comparison(left: Endpoint, right: Endpoint, fact: k.FactId, check: str) -> Comparison:
    a, b = ((left.native, right.native) if fact == trunk.NATIVE else (left.allowed, right.allowed))
    evidence = tuple(k.FactRef(fact=identifier, subject=point.subject)
                     for identifier in (PEER, fact) for point in (left, right))
    needs = tuple(_need(node, trunk.OP, (str(fact),), (check,))
                  for node in sorted((left.node, right.node), key=lambda node: node.key))
    gap = next((state for state in (a, b) if isinstance(state, k.Unknown)), None)
    reason: k.UnknownReason | None = k.UnknownReason.AS_OF_MISSING
    verdict: Literal["problem", "unknown"] = "unknown"
    left_only: str | None = None
    right_only: str | None = None
    if gap is not None:
        reason = gap.reason
    elif isinstance(a, k.Known) and isinstance(b, k.Known) and a.value != b.value:
        reason, verdict = None, "problem"
        if fact == trunk.ALLOWED:
            av, bv = _vlans(cast(str, a.value)), _vlans(cast(str, b.value))
            left_only, right_only = _canonical(av - bv), _canonical(bv - av)
    return Comparison(check=check, left=left.subject, right=right.subject,
                      state=verdict, reason=reason,
                      evidence=evidence, next_evidence=needs, left_only=left_only, right_only=right_only)


def build_group(group: SyntheticGroup, store: FactStore) -> CheckResult:
    """Read the entire matrix before validating or evaluating; never write facts."""
    reader = bind_reader(store, step=STEP)
    matrix: list[tuple[Node, str, k.EntityKey, StoredState, StoredState, StoredState]] = []
    for node in sorted(group.nodes, key=lambda node: node.key):
        for port in sorted(node.ports):
            subject = endpoint(node, port)
            matrix.append((node, port, subject, reader.read(fact=PEER, subject=subject),
                           reader.read(fact=trunk.NATIVE, subject=subject),
                           reader.read(fact=trunk.ALLOWED, subject=subject)))
    points: dict[k.EntityKey, Endpoint] = {}
    for node, port, subject, peer, native, allowed in matrix:
        p, n, a = _state(peer, str), _state(native, int), _state(allowed, str)
        k.require(not isinstance(n, k.Known) or 1 <= n.value <= 4094, "invalid_native_fact")
        k.require(not isinstance(a, k.Known) or trunk.canonical_allowed(a.value) == a.value,
                  "invalid_allowed_fact")
        points[subject] = Endpoint(node=node, port=port, subject=subject, peer=p, native=n, allowed=a)
    for point in points.values():
        if isinstance(point.peer, k.Known):
            other = points.get(k.EntityKey(point.peer.value))
            k.require(point.peer.basis is k.Basis.DERIVED and other is not None
                      and other.node.key != point.node.key and isinstance(other.peer, k.Known)
                      and other.peer.value == point.subject, "invalid_reciprocal_peer")
    rows: list[Comparison] = []
    reciprocal_pairs = unresolved_endpoints = 0
    for subject in sorted(points):
        point = points[subject]
        if isinstance(point.peer, k.Unknown):
            unresolved_endpoints += 1
            for check, fact in ((NATIVE_CHECK, trunk.NATIVE), (ALLOWED_CHECK, trunk.ALLOWED)):
                needs = point.peer.next_evidence or (
                    _need(point.node, "show cdp neighbors detail", (str(PEER),), (check,)),)
                rows.append(Comparison(check=check, left=subject, right=None, state="unknown",
                                       reason=point.peer.reason,
                                       evidence=(k.FactRef(fact=PEER, subject=subject),
                                                 k.FactRef(fact=fact, subject=subject)),
                                       next_evidence=needs))
        elif subject < point.peer.value:
            reciprocal_pairs += 1
            other = points[k.EntityKey(point.peer.value)]
            rows.extend((_comparison(point, other, trunk.NATIVE, NATIVE_CHECK),
                         _comparison(point, other, trunk.ALLOWED, ALLOWED_CHECK)))
    needs = tuple(_need(node, trunk.OP, (str(trunk.ALLOWED), str(trunk.NATIVE)), CHECKS)
                  for node in sorted(group.nodes, key=lambda node: node.key))
    coverage = k.Unknown(reason=k.UnknownReason.DENOMINATOR_OPEN, detail="declared_synthetic_scope_only",
                         evidence=group.declaration.evidence, candidates=(), next_evidence=needs)
    denominator = (("declared_endpoints", len(points)), ("reciprocal_pairs", reciprocal_pairs),
                   ("unresolved_endpoints", unresolved_endpoints))
    return CheckResult(rows=tuple(sorted(rows, key=lambda row: (row.left, row.right or "", row.check))),
                       endpoints=tuple(points[subject] for subject in sorted(points)),
                       denominator=denominator, coverage=coverage)
