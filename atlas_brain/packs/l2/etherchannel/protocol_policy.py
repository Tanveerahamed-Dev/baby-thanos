"""Source-bound declared protocol pairs; no comparison verdict or standalone admission."""
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Literal

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded, Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build

TABLE = "declared_etherchannel_protocol_policies"


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtocolPolicy:
    id: str
    expectation: Literal["same_reported_protocol"]
    participants: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Bound:
    target_id: str
    node: k.EntityKey
    group: str
    subject: k.EntityKey


@dataclass(frozen=True, slots=True, kw_only=True)
class Comparison:
    policy_id: str
    participants: tuple[Bound, Bound]
    declaration: k.Known[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Plan:
    envelope: p4.Envelope
    raw: bytes
    sha256: str
    rows: tuple[Comparison, ...]
    denominator: tuple[tuple[str, int], ...]
    coverage: k.Unknown


def _need(condition: bool, code: str) -> None:
    k.require(condition, "etherchannel_protocol_policy_" + code)


def plan_for_declared_scope(envelope: p4.Envelope, budgets: Budgets, policies: tuple[ProtocolPolicy, ...], domains: tuple[build.Target, ...]) -> Plan:
    """Trust original owner domains after source closure; this metadata is not admission authority."""
    _need(type(policies) is tuple and len(policies) <= 64 and all(type(p) is ProtocolPolicy for p in policies), "input")
    _need(type(domains) is tuple and all(type(domain) is build.Target for domain in domains), "input")
    sources = tuple(source for source in envelope.targets if source.operation == build.parse_summary.OP)
    by_node = {domain.node.key: domain for domain in domains}
    _need(len(by_node) == len(domains) == len(sources) and set(by_node) == {s.node.key for s in sources}, "selector")
    targets = {source.id: by_node[source.node.key] for source in sources}
    _need(len(targets) == len(sources) and all(targets[s.id].node is s.node
          and targets[s.id].context == envelope.context for s in sources), "selector")
    for policy in policies:
        _need(type(policy.id) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", policy.id, re.ASCII) is not None
              and type(policy.expectation) is str and policy.expectation == "same_reported_protocol", "value")
        _need(type(policy.participants) is tuple and len(policy.participants) == 2
              and all(type(p) is tuple and len(p) == 2 and all(type(v) is str for v in p) for p in policy.participants), "selector")
    selected: list[tuple[str, tuple[Bound, Bound]]] = []
    seen: set[tuple[k.EntityKey, ...]] = set()
    for policy in sorted(policies, key=lambda policy: policy.id):
        points: list[Bound] = []
        for target_id, group in sorted(policy.participants):
            _need(target_id in targets and group in targets[target_id].groups, "selector")
            target = targets[target_id]
            points.append(Bound(target_id=target_id, node=target.node.key, group=group, subject=build.subject(target, group)))
        left, right = points
        _need(left.node != right.node and left.subject != right.subject, "selector")
        key = tuple(sorted((left.subject, right.subject)))
        _need(key not in seen and policy.id not in {identifier for identifier, _ in selected}, "duplicate")
        seen.add(key)
        selected.append((policy.id, (left, right)))
    raw = canonical({"schema": "atlas-brain.declared-etherchannel-protocol-policy/1", "semantic_group": "declared_synthetic",
        "context": envelope.context,
        "registration_sha256": envelope.registration_sha256, "registry_sha256": sha256(envelope.raw).hexdigest(),
        "base_registry_sha256": sha256(envelope.base.raw).hexdigest(), "policies": [
            {"id": identifier, "expectation": "same_reported_protocol", "participants": [asdict(p) for p in points]}
            for identifier, points in selected]})
    inputs = (envelope.raw, envelope.base.raw) + tuple(m.raw for m in envelope.captures) + tuple(c.raw for c in envelope.base.captures)
    if len(raw) > budgets.artifact_bytes or sum(map(len, inputs)) + len(raw) > budgets.bundle_bytes or len(inputs) + 1 > budgets.artifacts:
        raise BudgetExceeded("etherchannel_protocol_policy")
    digest = sha256(raw).hexdigest()
    rows = tuple(Comparison(policy_id=identifier, participants=points, declaration=k.Known(value=identifier,
        basis=k.Basis.DECLARED, raw=identifier, evidence=(k.RegistryRef(table=TABLE, row_id=identifier,
            table_digest=digest, citation=f"/policies/{i}"),))) for i, (identifier, points) in enumerate(selected))
    coverage = k.Unknown(reason=k.UnknownReason.DENOMINATOR_OPEN, detail="caller_declared_protocol_pairs_only",
        evidence=tuple(ref for row in rows for ref in row.declaration.evidence) or envelope.declaration.evidence,
        candidates=(), next_evidence=())
    return Plan(envelope=envelope, raw=raw, sha256=digest, rows=rows, coverage=coverage,
        denominator=(("declared_policies", len(rows)), ("declared_participant_occurrences", 2 * len(rows))))
