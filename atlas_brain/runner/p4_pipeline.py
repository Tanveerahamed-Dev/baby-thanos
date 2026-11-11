"""One trusted P4 composition admits a whole folder and executes its validated parser batch."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration, compile_packs
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Executed, Handler, execute_parsers


@dataclass(frozen=True, slots=True, kw_only=True)
class Prepared[T]:
    targets: tuple[p4.Target, ...]
    handlers: tuple[Handler[T], ...]
    requests: tuple[CaptureRequest, ...]


class Pack[T]:
    """Trusted preparation classifies inputs without running parsers or writing facts."""

    def declaration(self) -> PackDeclaration:
        raise NotImplementedError("p4_pipeline_declaration")

    def prepare(self, envelope: p4.Envelope) -> Prepared[T]:
        raise NotImplementedError("p4_pipeline_prepare")


@dataclass(frozen=True, slots=True, kw_only=True)
class Result[T]:
    envelope: p4.Envelope
    executed: tuple[Executed[T], ...]


def _pack[T](value: Pack[T] | None) -> Pack[T]:
    if not isinstance(value, Pack):
        raise TypeError("p4_pipeline_pack")
    return value


def _check_capture(request: CaptureRequest, member: p4.CaptureMember, context: str) -> None:
    capture, target = request.capture, member.target
    k.require(request.context == context and capture.id == member.id and capture.source == target.node.key
              and capture.operation == target.operation and type(capture.raw) is bytes and capture.raw == member.raw
              and capture.bytes_sha256 == member.sha256, "p4_pipeline_capture")
    try:
        expected_lines = text_lines(member.raw, capture.codec)
    except (ValueError, LookupError) as error:
        raise ValueError("p4_pipeline_capture_lines") from error
    k.require(all(type(line.span.start) is int and type(line.span.end) is int for line in capture.lines)
              and capture.lines == expected_lines, "p4_pipeline_capture_lines")


def _preflight[T](
    declaration: PackDeclaration, batch: Prepared[T], envelope: p4.Envelope,
    targets: dict[str, p4.Target], members: dict[k.CaptureId, p4.CaptureMember],
) -> tuple[tuple[Handler[T], ...], tuple[CaptureRequest, ...]]:
    k.require(type(batch) is Prepared, "p4_pipeline_prepared")
    k.require(type(batch.targets) is tuple and all(type(item) is p4.Target for item in batch.targets),
              "p4_pipeline_targets")
    k.require(type(batch.handlers) is tuple and all(type(item) is Handler for item in batch.handlers),
              "p4_pipeline_handlers")
    k.require(type(batch.requests) is tuple and all(type(item) is CaptureRequest for item in batch.requests),
              "p4_pipeline_requests")
    operations = {binding.operation for binding in declaration.operations}
    owned_targets = {item.id for item in envelope.targets if item.operation in operations}
    k.require(len(batch.targets) == len(owned_targets) and {item.id for item in batch.targets} == owned_targets
              and all(item is targets[item.id] for item in batch.targets), "p4_pipeline_target_claims")
    handlers: tuple[Handler[T], ...] = tuple(Handler(binding=item.binding, parser=item.parser) for item in batch.handlers)
    k.require(len(handlers) == len(declaration.operations)
              and {item.binding for item in handlers} == set(declaration.operations), "p4_pipeline_handler_claims")
    owned_members = {item.id for item in envelope.captures if item.target.id in owned_targets}
    requests = tuple(CaptureRequest(capture=item.capture, context=item.context) for item in batch.requests)
    k.require(len(requests) == len(owned_members) and {item.capture.id for item in requests} == owned_members,
              "p4_pipeline_member_claims")
    for request in requests:
        _check_capture(request, members[request.capture.id], envelope.context)
    return handlers, requests


def execute_p4_folder[T](root: Path, budgets: Budgets, *, packs: tuple[Pack[T], ...]) -> Result[T]:
    """Prepare all packs against one admitted envelope before dispatching any parser."""
    k.require(type(packs) is tuple, "p4_pipeline_packs")
    adapters = tuple(_pack(pack) for pack in packs)
    k.require(all(pack is not previous for index, pack in enumerate(adapters) for previous in adapters[:index]),
              "p4_pipeline_duplicate_pack_instance")
    declarations = tuple(pack.declaration() for pack in adapters)
    compiled = compile_packs(declarations)
    envelope = p4.admit_folder(root, budgets, declarations=declarations)
    k.require(type(envelope) is p4.Envelope and envelope.registration_sha256 == compiled.registration_sha256,
              "p4_pipeline_registration")
    k.require(type(envelope.context) is str and bool(envelope.context), "p4_pipeline_context")
    owners = {binding.operation: binding.step for binding in compiled.operations}
    k.require(type(envelope.targets) is tuple and all(type(item) is p4.Target for item in envelope.targets),
              "p4_pipeline_envelope_targets")
    targets = {item.id: item for item in envelope.targets}
    k.require(len(targets) == len(envelope.targets) and all(item.operation in owners and item.owner == owners[item.operation]
              for item in envelope.targets), "p4_pipeline_envelope_targets")
    k.require(type(envelope.captures) is tuple and all(type(item) is p4.CaptureMember and type(item.raw) is bytes
              and type(item.target) is p4.Target for item in envelope.captures), "p4_pipeline_envelope_members")
    members = {item.id: item for item in envelope.captures}
    k.require(len(members) == len(envelope.captures) and all(item.target.id in targets and item.target is targets[item.target.id]
              for item in envelope.captures), "p4_pipeline_envelope_members")

    prepared = tuple(pack.prepare(envelope) for pack in adapters)
    handlers: list[Handler[T]] = []
    requests: list[CaptureRequest] = []
    for declaration, batch in zip(declarations, prepared, strict=True):
        checked_handlers, checked_requests = _preflight(declaration, batch, envelope, targets, members)
        handlers.extend(checked_handlers)
        requests.extend(checked_requests)
    executed = execute_parsers(declarations, tuple(handlers), tuple(requests))
    return Result(envelope=envelope, executed=executed)
