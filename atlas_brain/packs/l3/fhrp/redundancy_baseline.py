"""Declared HSRP baseline premises only; callers retain original input custody.

This pure phase reads no observations. Current comparisons and policy references
are not admission, origin, population, absence or publication seals.
"""
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import admission
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp.reported_presence_context import capture_context
from atlas_brain.packs.l3.fhrp.version_inputs import validate_fhrp_target_graph

SCHEMA = "atlas-brain.declared-fhrp-redundancy-baseline/1"
STEP = "l3.fhrp/prepare_redundancy_baseline"
TABLE = "declared_fhrp_redundancy_baseline"
type State = k.Known[str] | k.Unknown
type Expected = tuple[policy.BoundParticipant, ...] | None
type Entry = tuple[int, policy.GatewayKey, Expected, tuple[str, ...]]


@dataclass(frozen=True, slots=True, kw_only=True)
class Requirement:
    scope: policy.Gateway
    baseline_key: policy.GatewayKey | None
    expected_participants: Expected
    declared_anycast_permissions: tuple[str, ...]
    baseline: State
    population: State
    binding: State
    primary_gap: k.Unknown | None


@dataclass(frozen=True, slots=True, kw_only=True)
class BaselinePreparation:
    scope: policy.Plan
    policies: tuple[policy.GatewayPolicy, ...]
    domains: tuple[build.Target, ...]
    baseline_raw: bytes | None
    baseline_sha256: str | None
    rows: tuple[Requirement, ...]
    denominator: tuple[tuple[str, int | None], ...]


def _need(condition: bool) -> None:
    k.require(condition, "fhrp_redundancy_baseline")


def _list(value: object, minimum: int, maximum: int) -> list[object]:
    _need(type(value) is list)
    rows = cast(list[object], value)
    _need(minimum <= len(rows) <= maximum)
    return rows


def _unknown(reason: k.UnknownReason, detail: str, refs: tuple[k.Evidence, ...],
             points: tuple[policy.BoundParticipant, ...]) -> k.Unknown:
    needs = tuple(k.EvidenceNeed(node=p.node, operation=build.hsrp.OP,
        params=(("group", p.group), ("interface", p.interface)), resolves=(), reruns=(STEP,),
        after_s=None, unprintable=(detail,)) for p in points)
    return k.Unknown(reason=reason, detail=detail, evidence=refs, candidates=(), next_evidence=needs)


def prepare_redundancy_baseline(
    envelope: p4.Envelope, budgets: admission.Budgets, policies: tuple[policy.GatewayPolicy, ...],
    domains: tuple[build.Target, ...], baseline_raw: bytes | None,
) -> BaselinePreparation:
    """Use original pre-exposure owner domains/policies; do not admit supplied carriers."""
    capture_context(envelope, budgets)
    _need(type(domains) is tuple and all(type(domain) is build.Target for domain in domains)
          and type(policies) is tuple and 1 <= len(policies) <= 64
          and (baseline_raw is None or type(baseline_raw) is bytes))
    for domain in domains:
        validate_fhrp_target_graph(domain)
    inputs = (envelope.raw, envelope.base.raw) + tuple(m.raw for m in envelope.captures) + tuple(c.raw for c in envelope.base.captures)
    if baseline_raw is not None and len(baseline_raw) > budgets.artifact_bytes:
        raise admission.BudgetExceeded("fhrp_redundancy_baseline")
    scope = policy.plan_for_declared_scope(envelope, budgets, policies, domains)
    extra = (scope.raw,) + (() if baseline_raw is None else (baseline_raw,))
    if (sum(map(len, inputs + extra)) > budgets.bundle_bytes or len(inputs + extra) > budgets.artifacts):
        raise admission.BudgetExceeded("fhrp_redundancy_baseline")
    digest = None if baseline_raw is None else sha256(baseline_raw).hexdigest()
    entries: dict[str, Entry] = {}
    if baseline_raw is not None:
        data = admission.record(admission.strict_json(baseline_raw, budgets.nesting_depth, budgets.numeric_digits),
            ("schema", "semantic_group", "context", "registry_sha256", "base_registry_sha256", "registration_sha256", "requirements"))
        try:
            encoded = canonical(data)
        except (TypeError, ValueError) as error:
            raise ValueError("fhrp_redundancy_baseline") from error
        _need(encoded == baseline_raw and data["schema"] == SCHEMA and data["semantic_group"] == "declared_synthetic"
              and data["context"] == envelope.context and data["registry_sha256"] == sha256(envelope.raw).hexdigest()
              and data["base_registry_sha256"] == sha256(envelope.base.raw).hexdigest()
              and data["registration_sha256"] == envelope.registration_sha256)
        requested = {p.id: p for p in policies}
        targets = {t.id: t for t in envelope.targets if t.operation == build.hsrp.OP}
        owners = {domain.node.key: domain for domain in domains}
        envelope_key = sha256(canonical((p4.SCHEMA, envelope.registration_sha256,
            sha256(envelope.raw).hexdigest(), sha256(envelope.base.raw).hexdigest(), envelope.context))).hexdigest()
        keys: set[policy.GatewayKey] = set()
        identifiers: list[str] = []
        for index, value in enumerate(_list(data["requirements"], 0, 64)):
            row = admission.record(value, ("id", "domain", "vlan", "address_family", "protocol", "group", "expected_participants", "permitted_alternatives"))
            identity, domain_name = admission.string(row, "id"), admission.string(row, "domain")
            _need(identity in requested and identity not in entries
                  and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", domain_name, re.ASCII) is not None)
            original = requested[identity]
            _need(type(row["vlan"]) is int and row["vlan"] == original.vlan
                  and row["address_family"] == original.address_family == "ipv4"
                  and row["protocol"] == original.protocol == "hsrp" and row["group"] == original.group
                  and (original.domain is None or domain_name == original.domain))
            declared_key = policy.GatewayKey(envelope_sha256=envelope_key, domain=domain_name, vlan=original.vlan,
                address_family=original.address_family, protocol=original.protocol, group=original.group)
            _need(declared_key not in keys)
            keys.add(declared_key)
            expected: Expected = None
            if row["expected_participants"] is not None:
                selectors = tuple((admission.string(p, "target_id"), admission.string(p, "interface"))
                    for p in (admission.record(item, ("target_id", "interface")) for item in _list(row["expected_participants"], 1, 128)))
                _need(selectors == tuple(sorted(set(selectors))))
                points: list[policy.BoundParticipant] = []
                for target_id, interface in selectors:
                    _need(target_id in targets)
                    target = owners[targets[target_id].node.key]
                    _need((interface, original.group) in target.groups)
                    points.append(policy.BoundParticipant(target_id=target_id, node=target.node.key, interface=interface,
                        group=original.group, subject=build.subject(target, interface, original.group)))
                expected = tuple(points)
            permissions: list[str] = []
            for item in _list(row["permitted_alternatives"], 0, 1):
                alternative = admission.record(item, ("id", "requirement_id", "mechanism"))
                name = admission.string(alternative, "id")
                _need(re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name, re.ASCII) is not None
                      and alternative["requirement_id"] == identity and alternative["mechanism"] == "declared_anycast")
                permissions.append(name)
            entries[identity] = (index, declared_key, expected, tuple(permissions))
            identifiers.append(identity)
        _need(identifiers == sorted(identifiers))
    rows: list[Requirement] = []
    for gateway in scope.rows:
        entry = entries.get(gateway.policy_id)
        refs = gateway.binding.evidence
        baseline: State = _unknown(k.UnknownReason.NO_BASELINE, "declared_redundancy_baseline_missing", refs, gateway.participants)
        population: State = _unknown(k.UnknownReason.DENOMINATOR_OPEN, "closed_expected_fhrp_population_required", refs, gateway.participants)
        joining = gateway.binding
        expected = None
        key: policy.GatewayKey | None = None
        alternatives: tuple[str, ...] = ()
        if entry is not None:
            index, key, expected, alternatives = entry
            _need(digest is not None)
            declaration = k.RegistryRef(table=TABLE, row_id=gateway.policy_id,
                table_digest=cast(str, digest), citation=f"/requirements/{index}")
            baseline = k.Known(value=gateway.policy_id, raw=gateway.policy_id, basis=k.Basis.DECLARED, evidence=(declaration,))
            population = _unknown(k.UnknownReason.DENOMINATOR_OPEN, "closed_expected_fhrp_population_required",
                refs + (declaration,), gateway.participants)
            if expected is not None:
                population = k.Known(value=gateway.policy_id, raw=gateway.policy_id, basis=k.Basis.DECLARED,
                    evidence=(k.RegistryRef(table=TABLE, row_id=gateway.policy_id,
                        table_digest=cast(str, digest), citation=f"/requirements/{index}/expected_participants"),))
                if not isinstance(joining, k.Unknown) and expected != gateway.participants:
                    joining = _unknown(k.UnknownReason.JOIN_UNPROVEN, "declared_gateway_binding_unproven",
                        refs + (declaration,), expected)
        primary = next((state for state in (baseline, population, joining) if isinstance(state, k.Unknown)), None)
        rows.append(Requirement(scope=gateway, baseline_key=key, expected_participants=expected,
            declared_anycast_permissions=alternatives, baseline=baseline, population=population,
            binding=joining, primary_gap=primary))
    enumerated = sum(len(row.expected_participants) for row in rows if row.expected_participants is not None)
    opened = sum(row.expected_participants is None for row in rows)
    return BaselinePreparation(scope=scope, policies=policies, domains=domains, baseline_raw=baseline_raw,
        baseline_sha256=digest, rows=tuple(rows), denominator=(("requested_requirements", len(rows)),
            ("declared_binding_participant_occurrences", scope.denominator[1][1]),
            ("enumerated_baseline_participant_occurrences", enumerated),
            ("expected_participant_occurrences", None if opened else enumerated),
            ("requirements_with_open_expected_population", opened)))
