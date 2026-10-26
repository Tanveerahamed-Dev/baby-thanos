"""Configured-intent comparisons only; operational observations are never operands."""
from dataclasses import dataclass
from typing import Literal, cast

from atlas_brain.evidence.synthetic import CONFIG_SCHEMA, Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, StoredState, bind_reader
from atlas_brain.packs.l1.link.build import PEER
from atlas_brain.packs.l2.vlan_trunk import build as observed
from atlas_brain.packs.l2.vlan_trunk import config_build as config
from atlas_brain.packs.l2.vlan_trunk.check import (
    Comparison,
    canonical_vlan_set,
    vlan_members,
)

NATIVE_CHECK = "l2.vlan_trunk.configured_native_mismatch"
ALLOWED_CHECK = "l2.vlan_trunk.configured_allowed_asymmetry"
CHECKS = (ALLOWED_CHECK, NATIVE_CHECK)
STEP = StepSpec(id=StepId("l2.vlan_trunk/check_config"), pack=config.PACK, kind="check", scope="estate",
                reads=tuple(sorted((PEER,) + config.IDS)), produces=(), evaluator="l2.vlan_trunk.config_check.build_group")


@dataclass(frozen=True, slots=True, kw_only=True)
class Endpoint:
    node: Node
    port: str
    subject: k.EntityKey
    peer: k.Known[str] | k.Unknown
    mode: k.Known[str] | k.Unknown
    native: k.Known[int] | k.Unknown
    allowed: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckResult:
    rows: tuple[Comparison, ...]
    endpoints: tuple[Endpoint, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _state[T](state: StoredState, expected: type[T], *, configured: bool = True) -> k.Known[T] | k.Unknown:
    if isinstance(state, k.Unknown):
        return state
    if not isinstance(state, k.Known) or type(state.value) is not expected:
        raise ValueError("invalid_config_check_input")
    if configured:
        k.require(state.basis is k.Basis.CONFIGURED, "invalid_configured_basis")
    return cast("k.Known[T]", state)


def _need(node: Node, facts: tuple[str, ...]) -> k.EvidenceNeed:
    return k.EvidenceNeed(node=node.key, operation=config.OP, params=(), resolves=tuple(sorted(facts)),
                          reruns=tuple(sorted((str(STEP.id), str(config.STEP.id)))),
                          after_s=None, unprintable=())


def _comparison(left: Endpoint, right: Endpoint, fact: k.FactId, identifier: str,
                a: k.Known[int] | k.Known[str] | k.Unknown,
                b: k.Known[int] | k.Known[str] | k.Unknown) -> Comparison:
    refs = tuple(k.FactRef(fact=f, subject=p.subject) for f in (PEER, config.MODE, fact) for p in (left, right))
    needs = tuple(_need(node, (str(config.MODE), str(fact)))
                  for node in sorted((left.node, right.node), key=lambda n: n.key))
    mode_gap = next((m for m in (left.mode, right.mode) if isinstance(m, k.Unknown)), None)
    operand_gap = next((value for value in (a, b) if isinstance(value, k.Unknown)), None)
    reason: k.UnknownReason | None = k.UnknownReason.AS_OF_MISSING
    state: Literal["problem", "unknown"] = "unknown"
    left_only: str | None = None
    right_only: str | None = None
    if mode_gap is not None:
        reason = mode_gap.reason
    elif any(cast("k.Known[str]", p.mode).value != "trunk" for p in (left, right)):
        reason = k.UnknownReason.NOT_OBSERVABLE
    elif operand_gap is not None:
        reason = operand_gap.reason
    elif isinstance(a, k.Known) and isinstance(b, k.Known) and a.value != b.value:
        state, reason = "problem", None
        if fact == config.ALLOWED:
            av, bv = vlan_members(cast(str, a.value)), vlan_members(cast(str, b.value))
            left_only, right_only = canonical_vlan_set(av - bv), canonical_vlan_set(bv - av)
    return Comparison(check=identifier, left=left.subject, right=right.subject, state=state, reason=reason,
                      evidence=refs, next_evidence=needs, left_only=left_only, right_only=right_only)


def build_group(group: SyntheticGroup, store: FactStore) -> CheckResult:
    """Read every declared endpoint before any evaluation; never write or reparse."""
    k.require(group.schema == CONFIG_SCHEMA, "configured_group_schema_required")
    reader = bind_reader(store, step=STEP)
    matrix: list[tuple[Node, str, str, StoredState, StoredState, StoredState, StoredState]] = []
    for node in sorted(group.nodes, key=lambda node: node.key):
        for port in sorted(node.ports):
            subject = str(endpoint(node, port))
            key = cast("k.EntityKey", subject)
            matrix.append((node, port, subject, reader.read(fact=PEER, subject=key),
                           reader.read(fact=config.MODE, subject=key), reader.read(fact=config.NATIVE, subject=key),
                           reader.read(fact=config.ALLOWED, subject=key)))
    points: dict[str, Endpoint] = {}
    for node, port, subject, peer, mode, native, allowed in matrix:
        p, m = _state(peer, str, configured=False), _state(mode, str)
        n, a = _state(native, int), _state(allowed, str)
        k.require(not isinstance(m, k.Known) or m.value in ("trunk", "access", "routed"), "invalid_config_mode")
        k.require(not isinstance(n, k.Known) or 1 <= n.value <= 4094, "invalid_config_native")
        k.require(not isinstance(a, k.Known) or observed.canonical_allowed(a.value) == a.value, "invalid_config_allowed")
        points[subject] = Endpoint(node=node, port=port, subject=cast("k.EntityKey", subject),
                                   peer=p, mode=m, native=n, allowed=a)
    for point in points.values():
        if isinstance(point.peer, k.Known):
            other = points.get(point.peer.value)
            k.require(point.peer.basis is k.Basis.DERIVED and other is not None
                      and other.node.key != point.node.key and isinstance(other.peer, k.Known)
                      and other.peer.value == point.subject, "invalid_config_peer")
    rows: list[Comparison] = []
    pairs = unresolved = 0
    for subject in sorted(points):
        point = points[subject]
        if isinstance(point.peer, k.Unknown):
            unresolved += 1
            for identifier, fact in ((NATIVE_CHECK, config.NATIVE), (ALLOWED_CHECK, config.ALLOWED)):
                needs = point.peer.next_evidence + (_need(point.node, (str(config.MODE), str(fact))),)
                rows.append(Comparison(check=identifier, left=point.subject, right=None, state="unknown",
                    reason=point.peer.reason, evidence=tuple(k.FactRef(fact=f, subject=point.subject)
                    for f in (PEER, config.MODE, fact)), next_evidence=needs))
        elif subject < point.peer.value:
            pairs += 1
            other = points[point.peer.value]
            rows.extend((_comparison(point, other, config.NATIVE, NATIVE_CHECK, point.native, other.native),
                         _comparison(point, other, config.ALLOWED, ALLOWED_CHECK, point.allowed, other.allowed)))
    coverage = k.Unknown(reason=k.UnknownReason.DENOMINATOR_OPEN, detail="declared_synthetic_config_scope_only",
        evidence=group.declaration.evidence, candidates=(),
        next_evidence=tuple(_need(node, tuple(str(f) for f in config.IDS)) for node in sorted(group.nodes, key=lambda n: n.key)))
    denominator = (("declared_endpoints", len(points)), ("reciprocal_pairs", pairs), ("unresolved_endpoints", unresolved))
    return CheckResult(rows=tuple(sorted(rows, key=lambda r: (r.left, r.right or "", r.check))),
                       endpoints=tuple(points[s] for s in sorted(points)), denominator=denominator, coverage=coverage)
