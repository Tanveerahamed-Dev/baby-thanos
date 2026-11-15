"""Mixed VRRP input correspondence only; local metadata never grants admission, execution or origin."""
from dataclasses import dataclass
from typing import cast

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets, record, strict_json
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import CompiledPackSet
from atlas_brain.packs.l3.fhrp import global_parse as context
from atlas_brain.packs.l3.fhrp import vrrp_inputs as local
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.runner.pack_receipts import CaptureRequest


@dataclass(frozen=True, slots=True, kw_only=True)
class MixedVRRPInputs:
    envelope: p4.Envelope
    budgets: Budgets
    compiled: CompiledPackSet
    targets: tuple[p4.Target, ...]
    domains: tuple[local.VRRPTarget, ...]
    requests: tuple[CaptureRequest, ...]
    vrrp: local.VRRPInputs
    declarations: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]
    subjects: tuple[k.EntityKey, ...]


def _need(condition: bool, code: str) -> None:
    k.require(condition, "fhrp_mixed_vrrp_" + code)


def _groups(value: object) -> tuple[tuple[str, str], ...]:
    _need(type(value) is list and 1 <= len(cast(list[object], value)) <= 128
          and all(type(pair) is list and len(cast(list[object], pair)) == 2
              and all(type(item) is str for item in cast(list[object], pair)) for pair in cast(list[object], value)), "groups")
    return tuple(sorted((cast(list[str], pair)[0], cast(list[str], pair)[1]) for pair in cast(list[object], value)))


def _select(envelope: p4.Envelope, budgets: Budgets) -> tuple[tuple[p4.Target, ...], tuple[local.VRRPTarget, ...]]:
    selected = tuple(target for target in envelope.targets if target.operation == profile.parser.OP)
    domains: list[local.VRRPTarget] = []
    seen: set[k.EntityKey] = set()
    for target in selected:
        _need(target.owner == profile.STEP.id and target.node.key not in seen, "target")
        params = record(strict_json(target.params, budgets.nesting_depth, budgets.numeric_digits), ("groups",))
        domains.append(local.VRRPTarget(context=envelope.context, node=target.node, groups=_groups(params["groups"])))
        seen.add(target.node.key)
    return selected, tuple(domains)


def _members(envelope: p4.Envelope, selected: tuple[p4.Target, ...]) -> dict[str, p4.CaptureMember]:
    targets = {target.id: target for target in selected}
    owned = tuple(member for member in envelope.captures if member.target.operation == profile.parser.OP)
    _need(len({member.id for member in owned}) == len(owned)
          and len({member.target.node.key for member in owned}) == len(owned)
          and all(member.target is targets.get(member.target.id) for member in owned), "capture")
    return {member.id: member for member in owned}


def _bound(
    envelope: p4.Envelope, budgets: Budgets, inputs: local.VRRPInputs,
) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    selected, domains = _select(envelope, budgets)
    expected = {(domain.context, domain.node.key): domain for domain in domains}
    actual = {(domain.context, domain.node.key): domain for domain in inputs.targets}
    _need(len(actual) == len(inputs.targets) == len(expected) == len(domains) and set(actual) == set(expected)
          and all(actual[key].node is domain.node and actual[key].groups == domain.groups
              for key, domain in expected.items()), "population")
    members = _members(envelope, selected)
    requests = {request.capture.id: request for request in inputs.requests}
    _need(len(requests) == len(inputs.requests) == len(members) and set(requests) == set(members), "capture")
    by_node = {target.node.key: target for target in selected}
    for request in inputs.requests:
        capture = request.capture
        member = members[capture.id]
        _need(member.target is by_node.get(capture.source) and capture.raw is member.raw
              and capture.id == member.id and capture.source == member.target.node.key
              and capture.bytes_sha256 == member.sha256 and request.context == envelope.context, "capture")
    declarations: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]] = {}
    for domain in inputs.targets:
        refs = domain.node.declaration.evidence + envelope.declaration.evidence + by_node[domain.node.key].declaration.evidence
        _need(all(type(ref) is k.RegistryRef for ref in refs), "declaration")
        declarations[domain.context, domain.node.key] = cast(tuple[k.RegistryRef, ...], refs)
    return declarations


def _mixed_vrrp_correspondence(
    envelope: p4.Envelope, budgets: Budgets, inputs: local.VRRPInputs,
) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    """Close the current complete declared VRRP subset; no facts or origin tokens."""
    _need(type(inputs) is local.VRRPInputs, "input")
    local.validate_vrrp_inputs(inputs)
    declarations = _bound(envelope, budgets, inputs)
    return declarations


def validate_mixed_vrrp_correspondence(
    envelope: p4.Envelope, budgets: Budgets, inputs: local.VRRPInputs,
) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    compiled = context.validate_mixed_context(envelope, budgets)
    declarations = _mixed_vrrp_correspondence(envelope, budgets, inputs)
    _need(compiled == context.validate_mixed_context(envelope, budgets)
          and inputs.registration_sha256 != compiled.registration_sha256, "registration")
    local.validate_vrrp_inputs(inputs)
    _need(declarations == _bound(envelope, budgets, inputs), "declaration")
    return declarations


def validate_root_mixed_vrrp_correspondence(
    envelope: p4.Envelope, budgets: Budgets, inputs: local.VRRPInputs,
) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    compiled = context.validate_root_mixed_context(envelope, budgets)
    declarations = _mixed_vrrp_correspondence(envelope, budgets, inputs)
    _need(compiled == context.validate_root_mixed_context(envelope, budgets)
          and inputs.registration_sha256 != compiled.registration_sha256, "registration")
    local.validate_vrrp_inputs(inputs)
    _need(declarations == _bound(envelope, budgets, inputs), "declaration")
    return declarations


type _MixedVrrpParts = tuple[tuple[p4.Target, ...], tuple[local.VRRPTarget, ...], tuple[CaptureRequest, ...], local.VRRPInputs]


def _mixed_vrrp_candidates(envelope: p4.Envelope, budgets: Budgets) -> _MixedVrrpParts:
    selected, domains = _select(envelope, budgets)
    members = _members(envelope, selected)
    requests = tuple(local.prepare_vrrp_request(capture_id=member.id, source=member.target.node.key,
        context=envelope.context, raw=member.raw) for member in members.values())
    inputs = local.retain_vrrp_inputs(domains, requests)
    return selected, domains, requests, inputs


def _finish_mixed_vrrp_inputs(
    envelope: p4.Envelope, budgets: Budgets, compiled: CompiledPackSet, parts: _MixedVrrpParts,
    declarations: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]],
) -> MixedVRRPInputs:
    selected, domains, requests, inputs = parts
    local.validate_vrrp_inputs(inputs)
    _need(declarations == _bound(envelope, budgets, inputs), "declaration")
    current = tuple(target for target in envelope.targets if target.operation == profile.parser.OP)
    _need(len(current) == len(selected) and all(any(target is original for original in current) for target in selected), "target")
    subjects = tuple(sorted(local.subject(domain, interface, group)
        for domain in domains for interface, group in domain.groups))
    _need(len(set(subjects)) == len(subjects), "population")
    return MixedVRRPInputs(envelope=envelope, budgets=budgets, compiled=compiled,
        targets=selected, domains=domains, requests=requests, vrrp=inputs, declarations=declarations, subjects=subjects)


def prepare_mixed_vrrp_inputs(envelope: p4.Envelope, budgets: Budgets) -> MixedVRRPInputs:
    compiled = context.validate_mixed_context(envelope, budgets)
    parts = _mixed_vrrp_candidates(envelope, budgets)
    declarations = validate_mixed_vrrp_correspondence(envelope, budgets, parts[3])
    _need(compiled == context.validate_mixed_context(envelope, budgets), "registration")
    return _finish_mixed_vrrp_inputs(envelope, budgets, compiled, parts, declarations)


def prepare_root_mixed_vrrp_inputs(envelope: p4.Envelope, budgets: Budgets) -> MixedVRRPInputs:
    compiled = context.validate_root_mixed_context(envelope, budgets)
    parts = _mixed_vrrp_candidates(envelope, budgets)
    declarations = validate_root_mixed_vrrp_correspondence(envelope, budgets, parts[3])
    _need(compiled == context.validate_root_mixed_context(envelope, budgets), "registration")
    return _finish_mixed_vrrp_inputs(envelope, budgets, compiled, parts, declarations)
