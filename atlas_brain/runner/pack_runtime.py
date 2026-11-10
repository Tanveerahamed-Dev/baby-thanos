"""Run statically supplied capture parsers and return their validated receipts.

Application code supplies the parsers and declarations. StepSpec evaluator
labels stay declarative. Each parser supplies the association between its rich
value and its parse record. A batch returns only after receipt validation.
"""
from dataclasses import dataclass

from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import StepId
from atlas_brain.runner.pack_receipts import (
    CaptureRequest,
    ParseReceipt,
    validate_receipts,
)


# Immutable pairing lets narrow parser result types compose in application unions.
type Parsed[T] = tuple[T, ParseResult]


class Parser[T]:
    """An application parser implements this method for its registered operation."""

    def parse(self, request: CaptureRequest) -> Parsed[T]:
        raise NotImplementedError('pack_runtime_unimplemented')


def _checked_parser[T](value: Parser[T] | None) -> Parser[T]:
    if not isinstance(value, Parser):
        raise TypeError('pack_runtime_parser')
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class Handler[T]:
    binding: OperationBinding
    parser: Parser[T]

    def __post_init__(self) -> None:
        k.require(type(self.binding) is OperationBinding, 'pack_runtime_binding')
        _checked_parser(self.parser)


@dataclass(frozen=True, slots=True, kw_only=True)
class Executed[T]:
    receipt: ParseReceipt
    value: T


def execute_parsers[T](
    declarations: tuple[PackDeclaration, ...],
    handlers: tuple[Handler[T], ...],
    requests: tuple[CaptureRequest, ...],
) -> tuple[Executed[T], ...]:
    """Preflight the whole batch, then call each requested parser in capture ID order.

    Parser exceptions propagate. Earlier calls may already have run when a later
    call fails. Only supplied captures participate in this execution stage.
    """
    compiled = compile_packs(declarations)
    k.require(type(handlers) is tuple and all(type(item) is Handler for item in handlers),
              'pack_runtime_handlers')
    k.require(type(requests) is tuple and all(type(item) is CaptureRequest for item in requests),
              'pack_runtime_requests')
    owners = {binding.operation: binding.step for binding in compiled.operations}
    checked_handlers = tuple(Handler(binding=item.binding, parser=item.parser) for item in handlers)
    by_operation = {item.binding.operation: item for item in checked_handlers}
    k.require(len(by_operation) == len(handlers), 'pack_runtime_duplicate_handler')
    k.require(set(by_operation) == set(owners), 'pack_runtime_handler_coverage')
    for operation in sorted(owners):
        k.require(by_operation[operation].binding.step == owners[operation], 'pack_runtime_handler_owner')

    snapshots = tuple(CaptureRequest(capture=item.capture, context=item.context) for item in requests)
    k.require(len({item.capture.id for item in snapshots}) == len(snapshots), 'pack_runtime_duplicate_capture')
    plan: list[tuple[CaptureRequest, Parser[T], StepId]] = []
    for request in sorted(snapshots, key=lambda item: item.capture.id):
        operation = request.capture.operation
        if operation is None or operation not in owners:
            raise ValueError('pack_runtime_unregistered_operation')
        plan.append((request, by_operation[operation].parser, owners[operation]))

    receipts: list[ParseReceipt] = []
    values: dict[k.CaptureId, T] = {}
    for request, parser, owner in plan:
        parsed = parser.parse(request)
        k.require(type(parsed) is tuple and len(parsed) == 2, 'pack_runtime_result')
        k.require(type(parsed[1]) is ParseResult, 'pack_runtime_parse')
        receipts.append(ParseReceipt(capture=request.capture, context=request.context, owner=owner,
                                     registration_sha256=compiled.registration_sha256, parse=parsed[1]))
        values[request.capture.id] = parsed[0]
    validated = validate_receipts(declarations, requests, tuple(receipts))
    return tuple(Executed(receipt=item, value=values[item.capture.id]) for item in validated)
