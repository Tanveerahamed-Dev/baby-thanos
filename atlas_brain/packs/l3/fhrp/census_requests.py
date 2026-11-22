"""Original census request preparation for the named FHRP folder. No parser dispatch."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import (
    BudgetExceeded,
    Budgets,
    record,
    strict_json,
    string,
)
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import census_request_anchors as request_anchors
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census
from atlas_brain.packs.l3.fhrp import reported_presence_context as context
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.packs.l3.fhrp import required_report_census_profile as profile
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner.p4_pipeline import Prepared
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Handler

_MAX_BYTES = 680_000
_MAX_LINES = 4_098
type MemberInput = tuple[p4.CaptureMember, k.CaptureId, k.EntityKey, str, bytes]
type _ScopeSelection = tuple[p4.Target, p4.Target, str, str, MemberInput | None]
@dataclass(frozen=True, slots=True, kw_only=True)
class Scope:
    target: p4.Target
    source: p4.Target
    interface: str
    key: str
    member: p4.CaptureMember | None
    request: CaptureRequest | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Plan:
    """Retained inspection data from preparation, before any parser or writer."""

    envelope: p4.Envelope
    budgets: Budgets
    brief: state.StateOwner
    brief_bindings: custody.PlanBindings
    scopes: tuple[Scope, ...]
    request_values: tuple[context.RequestValue, ...]


def _declarations() -> tuple[PackDeclaration, ...]:
    return (stp.DECLARATION, ec.DECLARATION, profile.declaration())


def _need(condition: bool, code: str) -> None:
    k.require(condition, "hsrp_census_" + code)


def _check_member(member: p4.CaptureMember, budgets: Budgets) -> None:
    raw = member.raw
    count = len(raw)
    if count > min(budgets.artifact_bytes, _MAX_BYTES):
        raise BudgetExceeded(member.path)
    lines = raw.count(b"\n") + int(count > 0 and not raw.endswith(b"\n"))
    if lines > _MAX_LINES:
        raise BudgetExceeded(member.path)


def _request(inputs: MemberInput, context_id: str, command: str) -> CaptureRequest:
    _, capture_id, node_key, operation, raw = inputs
    capture = Capture(
        id=capture_id, source=node_key, operation=operation,
        rendered=command, codec="utf-8", raw=raw,
        integrity=k.IntegrityState.UNKNOWN_FORMAT if raw else k.IntegrityState.EMPTY,
        lines=text_lines(raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN,
    )
    return CaptureRequest(capture=capture, context=context_id)


def _close_request(request: CaptureRequest, inputs: MemberInput, context_id: str, command: str) -> None:
    values = request_anchors.request_coordinates(request)
    _, identity, node, operation, raw = inputs
    _need(values[:5] == (identity, node, operation, context_id, command) and values[5] is raw, "request")


def _derive_scopes(
    envelope: p4.Envelope, budgets: Budgets, brief: state.StateOwner, held: custody.PlanBindings,
) -> tuple[str, str, tuple[_ScopeSelection, ...]]:
    """Derive the whole census inventory from the original declarations before creating requests."""
    compiled = compile_packs(_declarations())
    _ready_brief(held, brief, envelope, budgets)
    _need(envelope.registration_sha256 == compiled.registration_sha256, "profile")
    operation = census.OP
    _need(type(operation) is str and operation == "synthetic.hsrp_ipv4_interface_census", "profile")
    step = next(binding.step for binding in compiled.operations if binding.operation == operation)
    context_id, command = envelope.context, census.COMMAND
    _need(type(command) is str and command == "synthetic hsrp ipv4 interface census v1", "profile")

    targets = {target.id: target for target in envelope.targets}
    members: dict[str, MemberInput] = {}
    for member in envelope.captures:
        if member.target.operation == operation:
            _need(member.target.id not in members, "duplicate_member")
            _check_member(member, budgets)
            members[member.target.id] = (member, member.id, member.target.node.key, operation, member.raw)

    identity = (p4.SCHEMA, envelope.registration_sha256, sha256(envelope.raw).hexdigest(),
                sha256(envelope.base.raw).hexdigest(), context_id)
    selected: list[_ScopeSelection] = []
    for target in envelope.targets:
        if target.operation != operation:
            continue
        params = record(strict_json(target.params, budgets.nesting_depth, budgets.numeric_digits), ("source_target", "interface"))
        source_id, interface = string(params, "source_target"), string(params, "interface")
        source = targets.get(source_id)
        if source is None:
            raise ValueError("hsrp_census_source_target")
        _need(target.owner == step and source.operation == "iosxe.show_standby_brief"
              and source.owner == "l3.fhrp/parse_hsrp_brief" and source.node is target.node, "source_target")
        node = target.node.key
        domain = held.indexed.get((context_id, node))
        if domain is None:
            raise ValueError("hsrp_census_source_target")
        _need(domain.node is source.node and any(interface == name for name, _ in domain.groups), "interface")
        subject = canonical(("atlas-brain.hsrp-census-scope/1", *identity, source.id, target.id,
                             node, interface, "ipv4", "hsrp", "all"))
        selected.append((target, source, interface, sha256(subject).hexdigest(), members.get(target.id)))
    return context_id, command, tuple(selected)


def _scoped_requests(
    scopes: tuple[Scope, ...], selected: tuple[_ScopeSelection, ...], context_id: str, command: str,
) -> tuple[CaptureRequest, ...]:
    _need(type(scopes) is tuple and len(scopes) == len(selected), "plan_scopes")
    requests: list[CaptureRequest] = []
    for scope, (target, source, interface, key, member) in zip(scopes, selected, strict=True):
        _need(type(scope) is Scope and scope.target is target and scope.source is source
              and type(scope.interface) is str and scope.interface == interface
              and type(scope.key) is str and scope.key == key, "plan_scopes")
        request = scope.request
        if member is None:
            _need(scope.member is None and request is None, "plan_scopes")
        else:
            if scope.member is not member[0] or request is None:
                raise ValueError("hsrp_census_plan_scopes")
            _close_request(request, member, context_id, command)
            requests.append(request)
    return tuple(requests)


@dataclass(frozen=True, slots=True)
class _TargetCoordinates:
    target: p4.Target
    node: Node
    node_identity: tuple[str, str]
    definition: tuple[str, str, str]
    params: bytes


@dataclass(frozen=True, slots=True)
class _CaptureCoordinates:
    member: p4.CaptureMember
    target: p4.Target
    identity: tuple[str, str, str]
    raw: bytes


@dataclass(frozen=True, slots=True)
class _EnvelopeCoordinates:
    base: SyntheticGroup
    raw: bytes
    base_raw: bytes
    scope: tuple[str, str]
    targets: tuple[p4.Target, ...]
    definitions: tuple[_TargetCoordinates, ...]
    captures: tuple[p4.CaptureMember, ...]
    members: tuple[_CaptureCoordinates, ...]


def _envelope_coordinates(envelope: p4.Envelope) -> _EnvelopeCoordinates:
    """Capture current typed coordinates without resolving declarations again."""
    _need(type(envelope) is p4.Envelope and type(envelope.base) is SyntheticGroup
          and type(envelope.raw) is bytes and type(envelope.base.raw) is bytes
          and type(envelope.context) is str and type(envelope.registration_sha256) is str
          and type(envelope.targets) is tuple and type(envelope.captures) is tuple, "plan_scopes")
    definitions: list[_TargetCoordinates] = []
    for target in envelope.targets:
        _need(type(target) is p4.Target and type(target.node) is Node
              and type(target.id) is str and type(target.operation) is str and type(target.owner) is str
              and type(target.node.group) is str and type(target.node.id) is str and type(target.params) is bytes,
              "plan_scopes")
        node = target.node
        definitions.append(_TargetCoordinates(target, node, (node.group, node.id),
                                              (target.id, target.operation, target.owner), target.params))
    members: list[_CaptureCoordinates] = []
    for member in envelope.captures:
        _need(type(member) is p4.CaptureMember and type(member.target) is p4.Target
              and type(member.id) is str and type(member.path) is str and type(member.sha256) is str
              and type(member.raw) is bytes, "plan_scopes")
        members.append(_CaptureCoordinates(member, member.target, (member.id, member.path, member.sha256), member.raw))
    return _EnvelopeCoordinates(envelope.base, envelope.raw, envelope.base.raw,
                                (envelope.context, envelope.registration_sha256), envelope.targets, tuple(definitions),
                                envelope.captures, tuple(members))


def _close_envelope_coordinates(envelope: p4.Envelope, original: _EnvelopeCoordinates) -> None:
    current = _envelope_coordinates(envelope)
    _need(current.base is original.base and current.raw is original.raw and current.base_raw is original.base_raw
          and current.scope == original.scope and current.targets is original.targets
          and len(current.definitions) == len(original.definitions), "plan_scopes")
    _need(all(a.target is b.target and a.node is b.node and a.node_identity == b.node_identity
              and a.definition == b.definition and a.params is b.params
              for a, b in zip(current.definitions, original.definitions, strict=True)), "plan_scopes")
    _need(current.captures is original.captures and len(current.members) == len(original.members), "plan_scopes")
    _need(all(a.member is b.member and a.target is b.target and a.identity == b.identity and a.raw is b.raw
              for a, b in zip(current.members, original.members, strict=True)), "plan_scopes")


retain_envelope_coordinates = _envelope_coordinates
close_envelope_coordinates = _close_envelope_coordinates


def validate_census_scopes(plan: Plan, budgets: Budgets) -> None:
    """Recheck a freshly prepared census inventory without admitting or materializing requests."""
    _need(type(plan) is Plan and type(budgets) is Budgets and plan.budgets is budgets
          and type(plan.scopes) is tuple and type(plan.request_values) is tuple, "plan_scopes")
    envelope, brief, held = plan.envelope, plan.brief, plan.brief_bindings
    scopes, before = plan.scopes, plan.request_values
    _need(all(type(row) is tuple and len(row) == 4 and type(row[0]) is str
              and type(row[1]) is CaptureRequest and type(row[2]) is Capture and type(row[3]) is bytes
              for row in before), "plan_scopes")

    def close_plan() -> None:
        _need(type(plan) is Plan and plan.envelope is envelope and plan.brief is brief
              and plan.brief_bindings is held and plan.budgets is budgets
              and plan.scopes is scopes and plan.request_values is before, "plan_scopes")

    context_id, command, selected = _derive_scopes(envelope, budgets, brief, held)
    close_plan()
    declared = _envelope_coordinates(envelope)
    current = _scoped_requests(scopes, selected, context_id, command)
    anchors = tuple(request_anchors.retain_live_request(request) for request in current)
    values = context.request_values(current)
    _ready_brief(held, brief, envelope, budgets)
    close_plan()
    _close_envelope_coordinates(envelope, declared)
    checked = _scoped_requests(scopes, selected, context_id, command)
    _need(len(current) == len(checked) and all(a is b for a, b in zip(current, checked, strict=True)),
          "plan_scopes")
    expected = {key: (request, capture) for key, request, capture, _ in before}
    for request, anchor in zip(checked, anchors, strict=True):
        original = expected.get(anchor.identity)
        _need(original is not None and request is original[0] and request.capture is original[1], "plan_scopes")
        request_anchors.validate_live_request(request, anchor)
    _need(len(values) == len(before) and all(
        a[0] == b[0] and a[1] is b[1] and a[2] is b[2] and a[3] == b[3]
        for a, b in zip(values, before, strict=True)
    ), "plan_scopes")


def prepare_census_inputs(
    envelope: p4.Envelope, budgets: Budgets, brief: state.StateOwner, held: custody.PlanBindings,
) -> Plan:
    """Use the actual admitted envelope and original BRIEF prepare, with no external admission authority."""
    context_id, command, selected = _derive_scopes(envelope, budgets, brief, held)
    scopes: list[Scope] = []
    for target, source, interface, key, member in selected:
        request = None if member is None else _request(member, context_id, command)
        scopes.append(Scope(target=target, source=source, interface=interface, key=key,
                            member=None if member is None else member[0], request=request))
    _ready_brief(held, brief, envelope, budgets)
    original_scopes = tuple(scopes)
    requests = _scoped_requests(original_scopes, selected, context_id, command)
    anchors = tuple(request_anchors.retain_live_request(request) for request in requests)
    values = context.request_values(requests)
    _ready_brief(held, brief, envelope, budgets)
    checked = _scoped_requests(original_scopes, selected, context_id, command)
    _need(all(a is b for a, b in zip(checked, requests, strict=True)), "plan_scopes")
    for request, anchor in zip(checked, anchors, strict=True):
        request_anchors.validate_live_request(request, anchor)
    return Plan(envelope=envelope, budgets=budgets, brief=brief, brief_bindings=held, scopes=original_scopes,
                request_values=values)

def _ready_brief(held: custody.PlanBindings, brief: state.StateOwner, envelope: p4.Envelope, budgets: Budgets) -> None:
    custody.validate_plan(held, brief, envelope, budgets)
    _need(brief.finished is False and not held.produced, "brief_consumed")


def prepare_census_folder(root: Path, budgets: Budgets) -> Plan:
    """Admit and prepare one named folder. Returned comparison material is not an execution receipt."""
    envelope = p4.admit_folder(root, budgets, declarations=_declarations())
    pointers, values = context.capture_context(envelope, budgets)
    binding = state.BINDING
    _need(type(binding) is OperationBinding and type(binding.operation) is str and type(binding.step) is str
          and binding.operation == "iosxe.show_standby_brief" and binding.step == "l3.fhrp/parse_hsrp_brief",
          "brief_binding")
    operation, step = binding.operation, binding.step
    pack = StandbyBriefPack[object](budgets)
    batch = StandbyBriefPack[object].prepare(pack, envelope)
    _need(type(pack) is StandbyBriefPack and type(batch) is Prepared, "brief_prepared")
    _need(pack.budgets is budgets and pack.attempted is True and pack.finished is False, "brief_prepared")
    _need(type(batch.handlers) is tuple and len(batch.handlers) == 1 and type(batch.handlers[0]) is Handler,
          "brief_handler")
    handler = batch.handlers[0]
    _need(handler.binding is binding and state.BINDING is binding and type(binding) is OperationBinding
          and type(binding.operation) is str and type(binding.step) is str
          and binding.operation == operation and binding.step == step, "brief_binding")
    brief = handler.parser
    if type(brief) is not state.StateOwner:
        raise ValueError("hsrp_census_brief_owner")
    batch_targets, batch_requests = batch.targets, batch.requests
    held = custody.retain_plan(brief, envelope, budgets)
    _need(type(batch) is Prepared and batch.targets is batch_targets and batch.requests is batch_requests,
          "brief_prepared")
    _need(len(pointers) == len(held.context_pointers) and all(
        before is after for before, after in zip(pointers, held.context_pointers, strict=True)
    ) and values == held.context_values, "prepare_custody")
    targets = tuple(target for target in envelope.targets if target.operation == operation)
    _need(type(batch_targets) is tuple and len(batch_targets) == len(targets) and all(
        before is after for before, after in zip(batch_targets, targets, strict=True)
    ), "brief_targets")
    _need(batch_requests is held.requests, "brief_requests")
    return prepare_census_inputs(envelope, budgets, brief, held)
