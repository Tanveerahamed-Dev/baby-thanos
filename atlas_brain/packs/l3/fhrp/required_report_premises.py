"""Current declared premises against original pre-parser inputs; comparison data, never admission."""
from dataclasses import dataclass

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import redundancy_baseline as baseline
from atlas_brain.packs.l3.fhrp import required_report_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import validate_version_state_graph

type Cell = tuple[baseline.Requirement,policy.Gateway,baseline.State,baseline.State,baseline.State,k.Unknown | None]


@dataclass(frozen=True,slots=True,kw_only=True)
class Retained:
    prepared: baseline.BaselinePreparation
    inputs: profile.Inputs
    domains: tuple[build.Target,...]
    scope_raw: bytes
    baseline_raw: bytes | None
    policies: tuple[policy.GatewayPolicy,...]
    cells: tuple[Cell,...]


def _need(condition: bool) -> None:
    k.require(condition,"fhrp_required_premises")


def _key(value: policy.GatewayKey | None) -> None:
    if value is None:return
    _need(type(value) is policy.GatewayKey and type(value.vlan) is int
        and all(type(item) is str for item in (value.envelope_sha256,value.domain,value.address_family,value.protocol,value.group)))


def _points(value: tuple[policy.BoundParticipant,...] | None) -> None:
    if value is None:return
    _need(type(value) is tuple and all(type(point) is policy.BoundParticipant for point in value))
    for point in value:
        _need(all(type(item) is str for item in
            (point.target_id,point.node,point.interface,point.group,point.subject)))


def _graph(prepared: baseline.BaselinePreparation) -> None:
    _need(type(prepared) is baseline.BaselinePreparation and type(prepared.scope) is policy.Plan)
    scope=prepared.scope
    _need(type(scope.raw) is bytes and type(scope.sha256) is str and type(scope.rows) is tuple
        and type(prepared.rows) is tuple and len(scope.rows)==len(prepared.rows)
        and (prepared.baseline_raw is None or type(prepared.baseline_raw) is bytes)
        and (prepared.baseline_sha256 is None or type(prepared.baseline_sha256) is str)
        and type(scope.coverage) is k.Unknown)
    for denominator in (scope.denominator,prepared.denominator):
        _need(type(denominator) is tuple and all(type(item) is tuple and len(item)==2
            and type(item[0]) is str and (item[1] is None or type(item[1]) is int) for item in denominator))
    validate_version_state_graph(scope.coverage)
    for gateway,row in zip(scope.rows,prepared.rows,strict=True):
        _need(type(gateway) is policy.Gateway and type(row) is baseline.Requirement and row.scope is gateway
            and type(gateway.policy_id) is str and type(row.declared_anycast_permissions) is tuple
            and all(type(item) is str for item in row.declared_anycast_permissions))
        _key(gateway.key)
        _key(row.baseline_key)
        _points(gateway.participants)
        _points(row.expected_participants)
        for state in (gateway.binding,row.baseline,row.population,row.binding):
            validate_version_state_graph(state)
        _need(row.primary_gap is None or type(row.primary_gap) is k.Unknown
            and any(row.primary_gap is state for state in (row.baseline,row.population,row.binding)))


def retain(envelope: p4.Envelope,budgets: Budgets,domains: tuple[build.Target,...],inputs: profile.Inputs) -> Retained:
    """Call only inside the actual owning pack's genuine prepare, before parser exposure."""
    _need(type(inputs) is profile.Inputs)
    prepared=baseline.prepare_redundancy_baseline(envelope,budgets,inputs.policies,domains,inputs.baseline_raw)
    _graph(prepared)
    return Retained(prepared=prepared,inputs=inputs,domains=domains,scope_raw=prepared.scope.raw,
        baseline_raw=inputs.baseline_raw,policies=inputs.policies,
        cells=tuple((row,row.scope,row.baseline,row.population,row.binding,row.primary_gap) for row in prepared.rows))


def close(held: Retained,envelope: p4.Envelope,budgets: Budgets,inputs: profile.Inputs) -> baseline.BaselinePreparation:
    """Caller first closes actual live execution; this rechecks all current original declared premises."""
    _need(type(held) is Retained and type(inputs) is profile.Inputs and inputs is held.inputs
        and inputs.policies is held.policies and inputs.baseline_raw is held.baseline_raw
        and type(held.scope_raw) is bytes and type(held.cells) is tuple)
    current=held.prepared
    _graph(current)
    _need(current.scope.envelope is envelope and current.policies is held.policies and current.domains is held.domains
        and current.baseline_raw is held.baseline_raw and current.scope.raw==held.scope_raw)
    _need(len(current.rows)==len(held.cells) and all(type(cell) is tuple and len(cell)==6 for cell in held.cells))
    for row,(original,gateway,declared,population,binding,primary) in zip(current.rows,held.cells,strict=True):
        _need(row is original and row.scope is gateway and row.baseline is declared and row.population is population
            and row.binding is binding and row.primary_gap is primary)
    fresh=baseline.prepare_redundancy_baseline(envelope,budgets,inputs.policies,held.domains,inputs.baseline_raw)
    _graph(fresh)
    _need(fresh.scope.raw==held.scope_raw and fresh.baseline_raw is held.baseline_raw
        and current.scope==fresh.scope and current.rows==fresh.rows and current.denominator==fresh.denominator
        and current.baseline_sha256==fresh.baseline_sha256)
    return current
