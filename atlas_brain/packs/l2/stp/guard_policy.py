"""Caller-declared guard comparison intent; no observed mode, peers, checks or healthy result."""
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Literal

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded, Budgets
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.stp import build

SCHEMA = "atlas-brain.declared-stp-guard-policy/1"
TABLE = "declared_stp_guard_policies"
MAX_POLICIES = 64


@dataclass(frozen=True, slots=True, kw_only=True)
class GuardParticipant:
    target_id: str
    vlan: int
    declared_mode: Literal["pvst", "rpvst", "mst"] | None
    position: Literal["designated_downstream", "upstream"] | None


@dataclass(frozen=True, slots=True, kw_only=True)
class GuardPolicy:
    id: str
    domain: str | None
    expectation: Literal["same_reported_root_guard"]
    participants: tuple[GuardParticipant, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class BoundParticipant:
    target: p4.Target
    port: str
    vlan: int
    subject: k.EntityKey
    declared_mode: str | None
    position: str | None
    evidence: tuple[k.RegistryRef, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class GuardComparison:
    policy_id: str
    domain: str | None
    participants: tuple[BoundParticipant, BoundParticipant]
    status: Literal["conditional", "unknown"]
    gaps: tuple[str, ...]
    declaration: k.Known[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class GuardPlan:
    envelope: p4.Envelope
    context: str
    registration_sha256: str
    registry_sha256: str
    base_registry_sha256: str
    raw: bytes
    sha256: str
    rows: tuple[GuardComparison, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _need(condition: bool, code: str) -> None:
    k.require(condition, "stp_guard_policy_" + code)


def _identifier(value: object, maximum: int) -> bool:
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0," + str(maximum - 1) + "}", value, re.ASCII) is not None


def plan_for_declared_scope(envelope: p4.Envelope, budgets: Budgets, policies: tuple[GuardPolicy, ...]) -> GuardPlan:
    """Trusted after exact composition-profile validation; this hook is not standalone admission."""
    _need(type(budgets) is Budgets and type(policies) is tuple, "input")
    _need(len(policies) <= MAX_POLICIES, "count")
    _need(all(type(item) is GuardPolicy for item in policies), "input")
    for item in policies:
        _need(_identifier(item.id, 32) and (item.domain is None or _identifier(item.domain, 64)), "identifier")
        _need(type(item.expectation) is str and item.expectation == "same_reported_root_guard", "intent")
        _need(type(item.participants) is tuple and len(item.participants) == 2
              and all(type(point) is GuardParticipant for point in item.participants), "participant")
        for point in item.participants:
            _need(_identifier(point.target_id, 32) and type(point.vlan) is int and 1 <= point.vlan <= 4094
                  and (point.declared_mode is None or type(point.declared_mode) is str and point.declared_mode in ("pvst", "rpvst", "mst"))
                  and (point.position is None or type(point.position) is str and point.position in ("designated_downstream", "upstream")), "participant")
    _need(len({item.id for item in policies}) == len(policies), "duplicate")
    declared: dict[str, tuple[p4.Target, build.Target, str, tuple[int, ...], str, tuple[k.RegistryRef, ...]]] = {}
    for item in build.declared_root_guard_targets(envelope, budgets):
        match item:
            case build.DeclaredRootGuard(source=p4.Target(id=identifier, node=Node(id=node_id)) as source,
                                         target=build.Target(port=port, vlans=vlans) as target, evidence=refs):
                declared[identifier] = (source, target, port, vlans, node_id, refs)
            case _:
                raise ValueError("stp_guard_policy_selector")
    records: list[dict[str, object]] = []
    bound_rows: list[tuple[GuardPolicy, tuple[BoundParticipant, BoundParticipant], tuple[str, ...]]] = []
    seen: set[tuple[k.EntityKey, ...]] = set()
    for item in sorted(policies, key=lambda item: item.id):
        bound: list[BoundParticipant] = []
        encoded: list[dict[str, object]] = []
        nodes: list[str] = []
        for point in sorted(item.participants, key=lambda point: (point.target_id, point.vlan)):
            _need(point.target_id in declared, "selector")
            source, target, port, vlans, node_id, refs = declared[point.target_id]
            _need(point.vlan in vlans, "selector")
            subject = build.subject(target, point.vlan)
            bound.append(BoundParticipant(target=source, port=port, vlan=point.vlan, subject=subject,
                declared_mode=point.declared_mode, position=point.position, evidence=refs))
            nodes.append(node_id)
            encoded.append({"target_id": point.target_id, "vlan": point.vlan, "declared_mode": point.declared_mode,
                "position": point.position, "node": node_id, "port": port, "subject": str(subject),
                "declarations": [asdict(ref) for ref in refs]})
        left, right = bound
        _need((nodes[0], left.port) != (nodes[1], right.port) and left.subject != right.subject, "selector")
        key = tuple(sorted((left.subject, right.subject)))
        _need(key not in seen, "duplicate")
        seen.add(key)
        gaps = tuple(sorted(name for name, present in (
            ("domain_missing", item.domain is None), ("vlan_mismatch", left.vlan != right.vlan),
            ("same_node", nodes[0] == nodes[1]), ("mode_missing", any(point.declared_mode is None for point in bound)),
            ("mode_mismatch", left.declared_mode is not None and right.declared_mode is not None and left.declared_mode != right.declared_mode),
            ("mode_unsupported", any(point.declared_mode == "mst" for point in bound)),
            ("position_missing", any(point.position is None for point in bound)),
            ("position_ineligible", any(point.position == "upstream" for point in bound))) if present))
        records.append({"id": item.id, "domain": item.domain, "expectation": item.expectation, "participants": encoded})
        bound_rows.append((item, (left, right), gaps))
    registry, base = sha256(envelope.raw).hexdigest(), sha256(envelope.base.raw).hexdigest()
    raw = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic", "context": envelope.context,
        "registration_sha256": envelope.registration_sha256, "registry_sha256": registry,
        "base_registry_sha256": base, "policies": records})
    total = len(envelope.raw) + len(envelope.base.raw) + sum(len(member.raw) for member in envelope.captures)
    total += sum(len(capture.raw) for capture in envelope.base.captures) + len(raw)
    if len(raw) > budgets.artifact_bytes or total > budgets.bundle_bytes or 3 + len(envelope.captures) + len(envelope.base.captures) > budgets.artifacts:
        raise BudgetExceeded("guard_policy")
    digest = sha256(raw).hexdigest()
    rows: list[GuardComparison] = []
    for index, (item, participants, gaps) in enumerate(bound_rows):
        ref = k.RegistryRef(table=TABLE, row_id=item.id, table_digest=digest, citation=f"/policies/{index}")
        declaration = k.Known(value=item.id, raw=item.id, basis=k.Basis.DECLARED, evidence=(ref,))
        rows.append(GuardComparison(policy_id=item.id, domain=item.domain, participants=participants,
                    status="unknown" if gaps else "conditional", gaps=gaps, declaration=declaration))
    evidence = tuple(ref for row in rows for ref in row.declaration.evidence) or envelope.declaration.evidence
    coverage = k.Unknown(reason=k.UnknownReason.DENOMINATOR_OPEN, detail="caller_declared_guard_policy_only",
                         evidence=evidence, candidates=(), next_evidence=())
    return GuardPlan(envelope=envelope, context=envelope.context, registration_sha256=envelope.registration_sha256,
        registry_sha256=registry, base_registry_sha256=base, raw=raw, sha256=digest, rows=tuple(rows),
        denominator=(("declared_policies", len(policies)), ("declared_participant_occurrences", 2 * len(policies))), coverage=coverage)
