"""Owning VERSION execution, candidate rows and Store production; no source admission."""
from dataclasses import asdict, dataclass
from hashlib import sha256

from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import (
    VersionInputs,
    retain_version_inputs,
    validate_version_inputs,
    validate_version_request,
)
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import (
    Executed,
    Handler,
    Parsed,
    Parser,
    execute_parsers,
)

type _Key = tuple[str, k.EntityKey]
type _Claims = tuple[tuple[parser.Row, tuple[k.ByteSpan, ...]], ...]


def _need(condition: bool, code: str) -> None:
    k.require(condition, "hsrp_version_" + code)


@dataclass(frozen=True, slots=True, kw_only=True)
class _Invocation:
    source: VersionInputs
    registration_sha256: str
    produced: dict[k.CaptureId, parser.Result]
    produced_values: dict[k.CaptureId, dict[str, object]]
    claims: dict[k.CaptureId, _Claims]
    owned: dict[k.CaptureId, Executed[parser.Result]]


def _state(value: _Invocation | None) -> _Invocation:
    _need(type(value) is _Invocation, "invocation")
    if value is None:
        raise ValueError("hsrp_version_invocation")
    return value


def _rows(state: _Invocation, outcomes: dict[_Key, tuple[Executed[parser.Result], _Claims]]) -> tuple[build.Row, ...]:
    rows: list[build.Row] = []
    for key in sorted(state.source.indexed):
        target, outcome = state.source.indexed[key], outcomes.get(key)
        out, claims = (None, ()) if outcome is None else outcome
        for interface, group in sorted(target.groups):
            candidates = () if out is None else tuple(row for row in out.value.rows if row.interface.raw == interface and row.group.raw == group)
            reason = k.UnknownReason.NOT_COLLECTED if out is None else out.value.reason
            rich = candidates[0] if len(candidates) == 1 else None
            reason = reason or (rich.reason if rich is not None else
                               k.UnknownReason.CONFLICTING_EVIDENCE if candidates else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
            evidence: tuple[k.Evidence, ...] = target.node.declaration.evidence
            if out is not None:
                capture = out.receipt.capture
                evidence += (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS,
                                          excerpt_sha256=capture.bytes_sha256),)
                evidence += tuple(k.EvidenceRef(capture=capture.id, locator=point, role=k.EvidenceRole.WITNESS,
                    excerpt_sha256=sha256(capture.raw[point.start:point.end]).hexdigest()) for original, points in claims
                    if any(original is candidate for candidate in candidates) for point in points)
            if reason is None and out is not None and rich is not None and rich.version is not None and rich.virtual_ip is not None:
                capture = out.receipt.capture
                points = next(points for original, points in claims if original is rich)
                refs = tuple(k.EvidenceRef(capture=capture.id, locator=point, role=k.EvidenceRole.SUBJECT,
                    excerpt_sha256=sha256(capture.raw[point.start:point.end]).hexdigest()) for point in points)
                value: k.Known[str] | k.Unknown = k.Known(value=rich.version.raw, raw=rich.version.raw,
                    basis=k.Basis.OBSERVED, evidence=target.node.declaration.evidence + refs)
            else:
                if reason is None:
                    raise ValueError("hsrp_version_value")
                need = k.EvidenceNeed(node=target.node.key, operation=parser.OP, params=(("group", group), ("interface", interface)),
                    resolves=(profile.REPORTED_PROTOCOL_VERSION,), reruns=(str(profile.STEP.id),), after_s=None, unprintable=("explicit_reported_protocol_version",))
                value = k.Unknown(reason=reason, detail="hsrp_version_unresolved", evidence=evidence, candidates=(), next_evidence=(need,))
            rows.append(build.Row(target=target, interface=interface, group=group, subject=build.subject(target, interface, group), value=value))
    return tuple(rows)


@dataclass(frozen=True, slots=True, kw_only=True)
class VersionResult:
    store: FactStore
    rows: tuple[build.Row, ...]
    executed: tuple[Executed[parser.Result], ...]
    registration_sha256: str


class VersionOwner(Parser[parser.Result]):
    inputs: _Invocation | None = None
    production_attempted: bool = False
    production: VersionResult | None = None

    @staticmethod
    def for_local(targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...]) -> VersionOwner:
        return LocalVersionOwner(targets, requests)

    def validate_registration(self) -> None:
        raise ValueError("hsrp_version_registration_context")

    def parse(self, request: CaptureRequest) -> Parsed[parser.Result]:
        self.validate_registration()
        validate_version_request(request)
        state = _state(self.inputs)
        _need(request.capture.id in state.source.expected and request.capture is state.source.expected[request.capture.id].capture
              and request.context == state.source.expected[request.capture.id].context and request.capture.id not in state.produced, "cache")
        value = parser.parse_capture(request.capture)
        _need(type(value) is parser.Result, "cache")
        parser.validate_claims(request.capture, value)
        state.produced[request.capture.id], state.produced_values[request.capture.id] = value, asdict(value)
        return value, value.parse

    def own[T](self, output: Executed[T]) -> Executed[parser.Result]:
        self.validate_registration()
        state = _state(self.inputs)
        _need(type(output) is Executed and type(output.receipt) is ParseReceipt
              and type(output.receipt.capture) is Capture, "receipt")
        receipt, identifier = output.receipt, output.receipt.capture.id
        _need(identifier in state.source.expected and identifier in state.produced
              and receipt.capture is state.source.expected[identifier].capture and receipt.owner == profile.STEP.id
              and receipt.context == state.source.expected[identifier].context and receipt.capture.operation == profile.BINDING.operation
              and receipt.registration_sha256 == state.registration_sha256, "receipt")
        validate_version_request(state.source.expected[identifier])
        value = state.produced[identifier]
        _need(output.value is value and receipt.parse is value.parse, "cache")
        state.claims[identifier] = parser.validate_claims(receipt.capture, value)
        _need(asdict(value) == state.produced_values[identifier], "cache")
        owned = Executed(receipt=receipt, value=value)
        state.owned[identifier] = owned
        return owned

    def canonical_rows[T](self, outputs: tuple[Executed[T], ...]) -> tuple[build.Row, ...]:
        self.validate_registration()
        state = _state(self.inputs)
        validate_version_inputs(state.source)
        _need(type(outputs) is tuple and len(outputs) == len(state.source.expected)
              and all(type(out) is Executed and type(out.receipt) is ParseReceipt for out in outputs)
              and {out.receipt.capture.id for out in outputs} == set(state.source.expected)
              and set(state.produced) == set(state.produced_values) == set(state.source.expected), "cache")
        state.claims.clear()
        state.owned.clear()
        outcomes: dict[_Key, tuple[Executed[parser.Result], _Claims]] = {}
        for output in outputs:
            out = self.own(output)
            key = (out.receipt.context or "", out.receipt.capture.source)
            target = state.source.indexed[key]
            _need(out.value.reason is not None or all((row.interface.raw, row.group.raw) in target.groups for row in out.value.rows), "population")
            outcomes[key] = out, state.claims[out.receipt.capture.id]
        return _rows(state, outcomes)


    def finish[T](self, outputs: tuple[Executed[T], ...]) -> VersionResult:
        """Consume this invocation once; close all candidate rows before any Writer."""
        _need(not self.production_attempted and self.production is None, "production_once")
        self.production_attempted = True
        rows = self.canonical_rows(outputs)
        state = _state(self.inputs)
        executed = tuple(state.owned[out.receipt.capture.id] for out in outputs)
        registration = state.registration_sha256
        store = FactStore()
        writer = bind_writer(store, step=profile.STEP)
        for row in rows:
            writer.write(fact=profile.REPORTED_PROTOCOL_VERSION, subject=row.subject, value=row.value)
        result = VersionResult(store=store, rows=rows, executed=executed, registration_sha256=registration)
        self.production = result
        return result


class LocalVersionOwner(VersionOwner):
    def __init__(self, targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...]) -> None:
        compiled = profile.compile_version_profile()
        self.inputs = _Invocation(source=retain_version_inputs(targets, requests), registration_sha256=compiled.registration_sha256,
                                  produced={}, produced_values={}, claims={}, owned={})

    def validate_registration(self) -> None:
        state = _state(self.inputs)
        _need(profile.compile_version_profile().registration_sha256 == state.registration_sha256, "profile")


@dataclass(frozen=True, slots=True, kw_only=True)
class VersionExecution:
    owner: VersionOwner
    executed: tuple[Executed[parser.Result], ...]


def execute_local_version_inputs(
    targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...],
) -> VersionExecution:
    owner = VersionOwner.for_local(targets, requests)
    outputs = execute_parsers((profile.DECLARATION,), (Handler(binding=profile.BINDING, parser=owner),), requests)
    return VersionExecution(owner=owner, executed=outputs)
