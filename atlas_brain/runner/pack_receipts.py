"""Registration-backed custody for supplied, already-admitted capture requests.

Trusted declarations come from the application, never from evidence or file code.
This barrier checks receipt metadata, not input admission, parser execution,
payload semantics or proof spans. Empty coverage and uncollected operations
establish neither network health nor population closure.
"""
from dataclasses import dataclass

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration, compile_packs
from atlas_brain.model.specs import StepId


def _context(value: str | None) -> None:
    k.require(value is None or type(value) is str and bool(value), 'pack_receipts_context')


@dataclass(frozen=True, slots=True, kw_only=True)
class CaptureRequest:
    """An admitted input and its opaque application context, not CLI scope.context."""

    capture: Capture
    context: str | None

    def __post_init__(self) -> None:
        k.require(type(self.capture) is Capture, 'pack_receipts_capture')
        _context(self.context)


@dataclass(frozen=True, slots=True, kw_only=True)
class ParseReceipt:
    """Preserve the full input snapshot and opaque parser payload."""

    capture: Capture
    owner: StepId
    context: str | None
    registration_sha256: str
    parse: ParseResult

    def __post_init__(self) -> None:
        k.require(type(self.capture) is Capture, 'pack_receipts_capture')
        k.require(type(self.owner) is str and bool(self.owner), 'pack_receipts_owner')
        _context(self.context)
        k.digest(self.registration_sha256)
        k.require(type(self.parse) is ParseResult, 'pack_receipts_parse')


def validate_receipts(
    declarations: tuple[PackDeclaration, ...],
    requests: tuple[CaptureRequest, ...],
    receipts: tuple[ParseReceipt, ...],
) -> tuple[ParseReceipt, ...]:
    """Check declarations, shapes, unique IDs, ownership, coverage and snapshots.

    Request and receipt validation is capture-ID ordered. Registered operations
    absent from requests require no receipt. Returned records and their parser
    payloads are the original objects; successful custody is not parse validity.
    """
    compiled = compile_packs(declarations)
    k.require(type(requests) is tuple and all(type(item) is CaptureRequest for item in requests),
              'pack_receipts_requests')
    k.require(type(receipts) is tuple and all(type(item) is ParseReceipt for item in receipts),
              'pack_receipts_receipts')
    expected = {item.capture.id: item for item in requests}
    k.require(len(expected) == len(requests), 'pack_receipts_duplicate_capture')
    received = {item.capture.id for item in receipts}
    k.require(len(received) == len(receipts), 'pack_receipts_duplicate_receipt')
    owners = {binding.operation: binding.step for binding in compiled.operations}
    expected_owners: dict[k.CaptureId, StepId] = {}
    for identity in sorted(expected):
        operation = expected[identity].capture.operation
        if operation is None or operation not in owners:
            raise ValueError('pack_receipts_unregistered_operation')
        expected_owners[identity] = owners[operation]
    k.require(received == set(expected), 'pack_receipts_coverage')
    ordered = tuple(sorted(receipts, key=lambda item: item.capture.id))
    for item in ordered:
        request = expected[item.capture.id]
        k.require(item.capture == request.capture, 'pack_receipts_capture_mismatch')
        k.require(item.context == request.context, 'pack_receipts_context_mismatch')
        k.require(item.owner == expected_owners[item.capture.id], 'pack_receipts_owner_mismatch')
        k.require(item.registration_sha256 == compiled.registration_sha256,
                  'pack_receipts_registration_mismatch')
    return ordered
