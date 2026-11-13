"""Source-bound DECLARED logical gateways; no redundancy, anycast or health finding."""
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Literal

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded, Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build

TABLE = "declared_fhrp_gateways"
SCHEMA = "atlas-brain.declared-fhrp-gateway-policy/1"


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayPolicy:
    id: str
    domain: str | None
    vlan: int
    address_family: Literal["ipv4"]
    protocol: Literal["hsrp"]
    group: str
    participants: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayKey:
    envelope_sha256: str
    domain: str
    vlan: int
    address_family: str
    protocol: str
    group: str


@dataclass(frozen=True, slots=True, kw_only=True)
class BoundParticipant:
    target_id: str
    node: k.EntityKey
    interface: str
    group: str
    subject: k.EntityKey


@dataclass(frozen=True, slots=True, kw_only=True)
class Gateway:
    policy_id: str
    key: GatewayKey | None
    participants: tuple[BoundParticipant, ...]
    binding: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Plan:
    envelope: p4.Envelope
    raw: bytes
    sha256: str
    rows: tuple[Gateway, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _need(condition: bool, code: str) -> None:
    k.require(condition, "fhrp_gateway_policy_" + code)


def _identifier(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value, re.ASCII) is not None


def plan_for_declared_scope(
    envelope: p4.Envelope, budgets: Budgets, policies: tuple[GatewayPolicy, ...], domains: tuple[build.Target, ...],
) -> Plan:
    """Trust the application's original owner targets; metadata objects are not origin tokens."""
    _need(type(policies) is tuple and len(policies) <= 64 and all(type(p) is GatewayPolicy for p in policies)
          and type(domains) is tuple and all(type(domain) is build.Target for domain in domains), "input")
    sources = tuple(source for source in envelope.targets if source.operation == build.hsrp.OP)
    by_node = {domain.node.key: domain for domain in domains}
    _need(len(by_node) == len(domains) == len(sources) and set(by_node) == {s.node.key for s in sources}, "selector")
    targets = {source.id: by_node[source.node.key] for source in sources}
    _need(len(targets) == len(sources) and all(targets[s.id].node is s.node
          and targets[s.id].context == envelope.context for s in sources), "selector")
    for item in policies:
        _need(_identifier(item.id) and (item.domain is None or _identifier(item.domain))
              and type(item.vlan) is int and 1 <= item.vlan <= 4094 and type(item.address_family) is str
              and item.address_family == "ipv4" and type(item.protocol) is str and item.protocol == "hsrp"
              and type(item.group) is str and re.fullmatch(r"0|[1-9][0-9]{0,3}", item.group, re.ASCII) is not None
              and int(item.group) <= 4095, "value")
        _need(type(item.participants) is tuple and 1 <= len(item.participants) <= 128
              and all(type(p) is tuple and len(p) == 2 and all(type(v) is str for v in p) for p in item.participants), "selector")
    registry, base = sha256(envelope.raw).hexdigest(), sha256(envelope.base.raw).hexdigest()
    scope = sha256(canonical((p4.SCHEMA, envelope.registration_sha256, registry, base, envelope.context))).hexdigest()
    selected: list[tuple[GatewayPolicy, GatewayKey | None, tuple[BoundParticipant, ...]]] = []
    keys: set[GatewayKey] = set()
    subjects: set[k.EntityKey] = set()
    identifiers: set[str] = set()
    for item in sorted(policies, key=lambda policy: policy.id):
        _need(item.id not in identifiers, "duplicate")
        identifiers.add(item.id)
        points: list[BoundParticipant] = []
        for target_id, interface in sorted(item.participants):
            _need(target_id in targets and (interface, item.group) in targets[target_id].groups, "selector")
            target = targets[target_id]
            subject = build.subject(target, interface, item.group)
            _need(subject not in subjects, "duplicate")
            subjects.add(subject)
            points.append(BoundParticipant(target_id=target_id, node=target.node.key, interface=interface,
                                           group=item.group, subject=subject))
        key = None if item.domain is None else GatewayKey(envelope_sha256=scope, domain=item.domain, vlan=item.vlan,
            address_family=item.address_family, protocol=item.protocol, group=item.group)
        _need(key is None or key not in keys, "duplicate")
        if key is not None:
            keys.add(key)
        selected.append((item, key, tuple(points)))
    raw = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic", "context": envelope.context,
        "registration_sha256": envelope.registration_sha256, "registry_sha256": registry, "base_registry_sha256": base,
        "gateways": [{**asdict(item), "key": None if key is None else asdict(key),
                      "participants": [asdict(point) for point in points]} for item, key, points in selected]})
    inputs = (envelope.raw, envelope.base.raw) + tuple(m.raw for m in envelope.captures) + tuple(c.raw for c in envelope.base.captures)
    if len(raw) > budgets.artifact_bytes or sum(map(len, inputs)) + len(raw) > budgets.bundle_bytes or len(inputs) + 1 > budgets.artifacts:
        raise BudgetExceeded("fhrp_gateway_policy")
    digest = sha256(raw).hexdigest()
    rows: list[Gateway] = []
    for index, (item, key, participants) in enumerate(selected):
        refs = (k.RegistryRef(table=TABLE, row_id=item.id, table_digest=digest, citation=f"/gateways/{index}"),)
        binding: k.Known[str] | k.Unknown = k.Known(value=item.id, basis=k.Basis.DECLARED, raw=item.id, evidence=refs)
        if key is None:
            needs = tuple(k.EvidenceNeed(node=p.node, operation=build.hsrp.OP,
                params=(("group", p.group), ("interface", p.interface)), resolves=(), reruns=(str(build.SOURCE_STEP.id),),
                after_s=None, unprintable=("declared_l2_domain",)) for p in participants)
            binding = k.Unknown(reason=k.UnknownReason.JOIN_UNPROVEN, detail="declared_gateway_domain_missing",
                                evidence=refs, candidates=(), next_evidence=needs)
        rows.append(Gateway(policy_id=item.id, key=key, participants=participants, binding=binding))
    coverage = k.Unknown(reason=k.UnknownReason.DENOMINATOR_OPEN, detail="caller_declared_fhrp_gateways_only",
        evidence=tuple(ref for row in rows for ref in row.binding.evidence) or envelope.declaration.evidence,
        candidates=(), next_evidence=())
    return Plan(envelope=envelope, raw=raw, sha256=digest, rows=tuple(rows), coverage=coverage,
        denominator=(("declared_gateways", len(rows)), ("declared_participant_occurrences", sum(len(r.participants) for r in rows))))
