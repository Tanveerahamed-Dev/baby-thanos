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


def prepare_census_inputs(
    envelope: p4.Envelope, budgets: Budgets, brief: state.StateOwner, held: custody.PlanBindings,
) -> Plan:
    """Use the actual admitted envelope and original BRIEF prepare, with no external admission authority."""
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
    selected: list[tuple[p4.Target, p4.Target, str, str, MemberInput | None]] = []
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

    scopes: list[Scope] = []
    for target, source, interface, key, member in selected:
        request = None if member is None else _request(member, context_id, command)
        scopes.append(Scope(target=target, source=source, interface=interface, key=key,
                            member=None if member is None else member[0], request=request))
    _ready_brief(held, brief, envelope, budgets)
    requests: list[CaptureRequest] = []
    for scope, (_, _, _, _, member) in zip(scopes, selected, strict=True):
        request = scope.request
        if request is None or member is None:
            _need(request is None and member is None, "request")
            continue
        _close_request(request, member, context_id, command)
        requests.append(request)
    prepared = tuple(requests)
    originals = tuple(request_anchors.retain_live_request(request) for request in prepared)
    values = context.request_values(prepared)
    _ready_brief(held, brief, envelope, budgets)
    for request, original in zip(prepared, originals, strict=True):
        request_anchors.validate_live_request(request, original)
    return Plan(envelope=envelope, budgets=budgets, brief=brief, brief_bindings=held, scopes=tuple(scopes),
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
