"""Owning VERSION execution, candidate rows and Store production; no source admission."""
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import cast

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactReader, FactStore, bind_writer
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import global_parse as global_inputs
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import (
    VersionInputs,
    retain_version_inputs,
    validate_version_inputs,
    validate_version_request,
    validate_version_state_graph,
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


def _rows(state: _Invocation, outcomes: dict[_Key, tuple[Executed[parser.Result], _Claims]], declarations: dict[_Key, tuple[k.RegistryRef, ...]]) -> tuple[build.Row, ...]:
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
            evidence: tuple[k.Evidence, ...] = declarations[key]
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
                    basis=k.Basis.OBSERVED, evidence=declarations[key] + refs)
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


@dataclass(frozen=True, slots=True, kw_only=True)
class _Production:
    result: VersionResult
    store: FactStore
    rows: tuple[build.Row, ...]
    cells: tuple[tuple[k.EntityKey, k.Known[str] | k.Unknown], ...]
    executed: tuple[Executed[parser.Result], ...]
    registration_sha256: str


class VersionOwner(Parser[parser.Result]):
    inputs: _Invocation | None = None
    production_attempted: bool = False
    production: VersionResult | None = None
    completed: _Production | None = None

    @staticmethod
    def for_local(targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...]) -> VersionOwner:
        return LocalVersionOwner(targets, requests)

    @staticmethod
    def for_global_state_version(envelope: p4.Envelope, budgets: Budgets, targets: tuple[build.Target, ...],
                                 requests: tuple[CaptureRequest, ...]) -> GlobalVersionOwner:
        return GlobalVersionOwner(envelope, budgets, targets, requests)

    def declaration_evidence(self) -> dict[_Key, tuple[k.RegistryRef, ...]]:
        return {key: cast(tuple[k.RegistryRef, ...], target.node.declaration.evidence)
                for key, target in _state(self.inputs).source.indexed.items()}

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
        return _rows(state, outcomes, self.declaration_evidence())


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
        self.completed = _Production(result=result, store=store, rows=rows,
            cells=tuple((row.subject, row.value) for row in rows), executed=executed, registration_sha256=registration)
        self.production = result
        return result


    def validate_values(self, result: VersionResult, reader: FactReader) -> None:
        """Close this actual production's canonical cells; no admission or recursive-proof seal."""
        completed = self.completed
        _need(type(completed) is _Production and type(result) is VersionResult, "value_source")
        if completed is None:
            raise ValueError("hsrp_version_value_source")
        _need(self.production is completed.result and result is completed.result
              and result.store is completed.store and type(result.store) is FactStore
              and result.rows is completed.rows and result.executed is completed.executed
              and type(result.registration_sha256) is str
              and result.registration_sha256 == completed.registration_sha256, "value_source")
        _need(type(reader) is FactReader and reader.store is completed.store and type(reader.step) is StepSpec, "reader")
        step = reader.step
        _need(all(type(value) is str for value in (step.id, step.pack, step.kind, step.scope, step.evaluator))
              and step.pack == profile.PACK and type(step.reads) is tuple
              and all(type(fact) is str for fact in step.reads) and step.reads == (profile.REPORTED_PROTOCOL_VERSION,)
              and type(step.produces) is tuple and not step.produces, "reader")
        StepSpec(id=step.id, pack=step.pack, kind=step.kind, scope=step.scope,
                 reads=step.reads, produces=step.produces, evaluator=step.evaluator)
        wanted = self.canonical_rows(completed.executed)
        state = _state(self.inputs)
        _need(result.registration_sha256 == state.registration_sha256 and type(result.rows) is tuple
              and all(type(row) is build.Row and all(type(value) is str for value in
              (row.subject, row.interface, row.group)) for row in result.rows), "value_population")
        actual = {row.subject: row for row in result.rows}
        expected = {row.subject: row for row in wanted}
        cells = dict(completed.cells)
        _need(len(actual) == len(result.rows) == len(expected) == len(wanted) == len(cells) == len(completed.cells)
              and set(actual) == set(expected) == set(cells), "value_population")
        store = completed.store
        references = {k.FactRef(fact=profile.REPORTED_PROTOCOL_VERSION, subject=subject) for subject in expected}
        _need(type(store.owners) is dict and type(store.values) is dict
              and all(type(fact) is str and type(step_id) is str for fact, step_id in store.owners.items())
              and store.owners == {profile.REPORTED_PROTOCOL_VERSION: profile.STEP.id}
              and all(type(ref) is k.FactRef and type(ref.fact) is str and type(ref.subject) is str for ref in store.values)
              and set(store.values) == references, "value_store")
        for subject, original in expected.items():
            row, value = actual[subject], actual[subject].value
            _need(row.target is original.target and row.interface == original.interface and row.group == original.group
                  and value is cells[subject], "value_cell")
            validate_version_state_graph(value)
            if isinstance(original.value, k.Known):
                _need(type(value) is k.Known, "value_cell")
                if not isinstance(value, k.Known):
                    raise TypeError("hsrp_version_value_cell")
                _need(type(value.value) is str and type(value.raw) is str and value.value == value.raw
                      and value.value in ("1", "2") and value.basis is k.Basis.OBSERVED
                      and value == original.value, "value_cell")
            else:
                _need(type(value) is k.Unknown and value == original.value, "value_cell")
            _need(store.values[k.FactRef(fact=profile.REPORTED_PROTOCOL_VERSION, subject=subject)] is value
                  and reader.read(fact=profile.REPORTED_PROTOCOL_VERSION, subject=subject) is value, "value_reader")


class LocalVersionOwner(VersionOwner):
    def __init__(self, targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...]) -> None:
        compiled = profile.compile_version_profile()
        self.inputs = _Invocation(source=retain_version_inputs(targets, requests), registration_sha256=compiled.registration_sha256,
                                  produced={}, produced_values={}, claims={}, owned={})

    def validate_registration(self) -> None:
        state = _state(self.inputs)
        _need(profile.compile_version_profile().registration_sha256 == state.registration_sha256, "profile")


class GlobalVersionOwner(VersionOwner):
    """Own one compound run's VERSION subset; envelope metadata is correspondence data."""

    def __init__(self, envelope: p4.Envelope, budgets: Budgets, targets: tuple[build.Target, ...],
                 requests: tuple[CaptureRequest, ...]) -> None:
        profile.compile_state_version_profile()
        source = retain_version_inputs(targets, requests)
        global_inputs.validate_state_version_correspondence(envelope, budgets, source)
        k.digest(envelope.registration_sha256)
        self.envelope, self.budgets = envelope, budgets
        self.inputs = _Invocation(source=source, registration_sha256=envelope.registration_sha256,
                                  produced={}, produced_values={}, claims={}, owned={})

    def validate_registration(self) -> None:
        state = _state(self.inputs)
        profile.compile_state_version_profile()
        global_inputs.validate_state_version_correspondence(self.envelope, self.budgets, state.source)
        _need(type(self.envelope.registration_sha256) is str
              and self.envelope.registration_sha256 == state.registration_sha256, "global_registration")

    def declaration_evidence(self) -> dict[_Key, tuple[k.RegistryRef, ...]]:
        return global_inputs.validate_state_version_correspondence(self.envelope, self.budgets, _state(self.inputs).source)


class PeerGlobalVersionOwner(VersionOwner):
    """Own the fixed STP/EC/FHRP peer run's VERSION subset; no source admission."""

    def __init__(self, envelope: p4.Envelope, budgets: Budgets, targets: tuple[build.Target, ...],
                 requests: tuple[CaptureRequest, ...]) -> None:
        global_inputs.validate_peer_state_version_context(envelope, budgets)
        source = retain_version_inputs(targets, requests)
        global_inputs.validate_peer_state_version_correspondence(envelope, budgets, source)
        k.digest(envelope.registration_sha256)
        self.envelope, self.budgets = envelope, budgets
        self.inputs = _Invocation(source=source, registration_sha256=envelope.registration_sha256,
            produced={}, produced_values={}, claims={}, owned={})

    def validate_registration(self) -> None:
        state = _state(self.inputs)
        global_inputs.validate_peer_state_version_context(self.envelope, self.budgets)
        global_inputs.validate_peer_state_version_correspondence(self.envelope, self.budgets, state.source)
        _need(type(self.envelope.registration_sha256) is str
              and self.envelope.registration_sha256 == state.registration_sha256, "global_registration")

    def declaration_evidence(self) -> dict[_Key, tuple[k.RegistryRef, ...]]:
        return global_inputs.validate_peer_state_version_correspondence(self.envelope, self.budgets, _state(self.inputs).source)


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
