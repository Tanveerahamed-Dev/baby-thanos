"""Actual local VRRP production and current Reader closure; no root, origin or deep-mutation seal."""
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import cast

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactReader, FactStore, bind_writer
from atlas_brain.packs.l3.fhrp import global_parse as global_inputs
from atlas_brain.packs.l3.fhrp import mixed_vrrp_inputs as mixed_inputs
from atlas_brain.packs.l3.fhrp import parse_vrrp as parser
from atlas_brain.packs.l3.fhrp import vrrp_inputs as inputs
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import validate_version_state_graph
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import (
    Executed,
    Handler,
    Parsed,
    Parser,
    execute_parsers,
)

type _Claims = tuple[tuple[parser.Row, tuple[k.ByteSpan, ...]], ...]
type _Subject = tuple[inputs.VRRPTarget, str, str, k.EntityKey]


def _need(condition: bool, code: str) -> None:
    k.require(condition, "vrrp_owner_" + code)


def _registration() -> tuple[bytes, bytes, str]:
    value = profile.compile_vrrp_profile()
    return value.catalogue_bytes, value.registration_bytes, value.registration_sha256


def _subjects(source: inputs.VRRPInputs) -> tuple[_Subject, ...]:
    return tuple((target, interface, group, inputs.subject(target, interface, group))
        for target in sorted(source.targets, key=lambda item: (item.context, item.node.key))
        for interface, group in sorted(target.groups))


def _refs(capture: Capture, points: tuple[k.ByteSpan, ...], role: k.EvidenceRole) -> tuple[k.EvidenceRef, ...]:
    return tuple(k.EvidenceRef(capture=capture.id, locator=point, role=role,
        excerpt_sha256=sha256(capture.raw[point.start:point.end]).hexdigest()) for point in points)


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    target: inputs.VRRPTarget
    interface: str
    group: str
    subject: k.EntityKey
    value: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class VRRPResult:
    store: FactStore
    rows: tuple[Row, ...]
    executed: tuple[Executed[parser.Result], ...]
    registration_sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class _Production:
    result: VRRPResult
    store: FactStore
    rows: tuple[Row, ...]
    cells: tuple[tuple[k.EntityKey, k.Known[str] | k.Unknown], ...]
    executed: tuple[Executed[parser.Result], ...]
    registration_sha256: str


def _rows(subjects: tuple[_Subject, ...], outcomes: dict[tuple[str, k.EntityKey], tuple[Executed[parser.Result], _Claims]],
          declarations: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]) -> tuple[Row, ...]:
    rows: list[Row] = []
    for target, interface, group, subject in subjects:
        outcome = outcomes.get((target.context, target.node.key))
        output, claims = (None, ()) if outcome is None else outcome
        candidates = tuple(row for row, _ in claims if row.interface.raw == interface and row.group.raw == group)
        rich = candidates[0] if len(candidates) == 1 else None
        reason = k.UnknownReason.NOT_COLLECTED if output is None else output.value.reason
        reason = reason or (rich.reason if rich is not None else k.UnknownReason.CONFLICTING_EVIDENCE
                           if candidates else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
        evidence: tuple[k.Evidence, ...] = declarations[target.context, target.node.key]
        points = tuple(point for row, witness in claims if row.interface.raw == interface and row.group.raw == group for point in witness)
        if reason is None:
            if output is None or rich is None or rich.state is None:
                raise ValueError("vrrp_owner_value")
            state = rich.state.value
            _need(type(state) is parser.VRRPState and rich.address_family == "ipv4"
                  and output.receipt.capture.integrity is k.IntegrityState.COMPLETE
                  and output.receipt.capture.error is None and output.value.parse.quality == "complete", "value")
            value: k.Known[str] | k.Unknown = k.Known(value=str(state), raw=rich.state.raw, basis=k.Basis.OBSERVED,
                evidence=evidence + _refs(output.receipt.capture, points, k.EvidenceRole.SUBJECT))
        else:
            if output is not None:
                capture = output.receipt.capture
                evidence += (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS,
                                          excerpt_sha256=capture.bytes_sha256),) + _refs(capture, points, k.EvidenceRole.WITNESS)
            need = k.EvidenceNeed(node=target.node.key, operation="iosxe.show_vrrp", params=(("group", group), ("interface", interface)),
                resolves=(profile.REPORTED_VRRP_STATE,), reruns=(profile.STEP.id,), after_s=None, unprintable=())
            value = k.Unknown(reason=reason, detail="vrrp_state_unresolved", evidence=evidence, candidates=(), next_evidence=(need,))
        rows.append(Row(target=target, interface=interface, group=group, subject=subject, value=value))
    return tuple(rows)


class VRRPOwner(Parser[parser.Result]):
    def __init__(self, targets: tuple[inputs.VRRPTarget, ...], requests: tuple[CaptureRequest, ...]) -> None:
        _receiver(self)
        self.inputs = inputs.retain_vrrp_inputs(targets, requests)
        self.registration = _registration()
        self.subjects = _subjects(self.inputs)
        self.produced: dict[k.CaptureId, parser.Result] = {}
        self.parsed: dict[k.CaptureId, ParseResult] = {}
        self.snapshots: dict[k.CaptureId, dict[str, object]] = {}
        self.executed: tuple[Executed[parser.Result], ...] | None = None
        self.production: VRRPResult | None = None
        self.completed: _Production | None = None
        self.attempted = self.running = self.production_attempted = False

    def validate_inputs(self) -> None:
        _receiver(self)
        inputs.validate_vrrp_inputs(self.inputs)
        if type(self) is _MIXED_VRRP_OWNER:
            _MIXED_VRRP_OWNER.validate_registration(self)
        elif type(self) is _ROOT_MIXED_VRRP_OWNER:
            _ROOT_MIXED_VRRP_OWNER.validate_registration(self)
        else:
            _need(self.registration == _registration() and self.inputs.registration_sha256 == self.registration[2], "registration")
        expected = _subjects(self.inputs)
        _need(type(self.subjects) is tuple and len(self.subjects) == len(expected)
              and all(type(held) is tuple and len(held) == 4 and held[0] is wanted[0]
                  and all(type(value) is str for value in held[1:]) and held[1:] == wanted[1:]
                  for held, wanted in zip(self.subjects, expected, strict=True)), "subjects")

    def validate_registration(self) -> None:
        _receiver(self)
        _need(self.registration == _registration() and self.inputs.registration_sha256 == self.registration[2], "registration")

    def declaration_evidence(self) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
        _LOCAL_VRRP_OWNER.validate_inputs(self)
        return {(target.context, target.node.key): cast(tuple[k.RegistryRef, ...], target.node.declaration.evidence)
                for target in self.inputs.targets}

    def parse(self, request: CaptureRequest) -> Parsed[parser.Result]:
        _LOCAL_VRRP_OWNER.validate_inputs(self)
        inputs.validate_vrrp_request(request)
        expected = {item.capture.id: item for item in self.inputs.requests}
        capture = request.capture
        _need(self.running and capture.id in expected and capture is expected[capture.id].capture
              and request.context == expected[capture.id].context and capture.id not in self.produced, "request")
        value = parser.parse_capture(capture)
        _need(type(value) is parser.Result, "cache")
        parser.validate_claims(capture, value)
        _LOCAL_VRRP_OWNER.validate_inputs(self)
        self.produced[capture.id], self.parsed[capture.id], self.snapshots[capture.id] = value, value.parse, asdict(value)
        return value, value.parse

    def canonical_rows(self) -> tuple[Row, ...]:
        """Reclose the owned batch without parsing, dispatch or Store production."""
        _receiver(self)
        _need(self.attempted and not self.running and type(self.executed) is tuple, "batch")
        _need(self.completed is None or type(self.completed) is _Production
              and self.executed is self.completed.executed, "batch")
        _LOCAL_VRRP_OWNER.validate_inputs(self)
        batch = self.executed
        if batch is None:
            raise ValueError("vrrp_owner_batch")
        expected = {item.capture.id: item for item in self.inputs.requests}
        _need(all(type(mapping) is dict and all(type(key) is str for key in mapping) for mapping in (self.produced, self.parsed, self.snapshots))
              and set(self.produced) == set(self.parsed) == set(self.snapshots) == set(expected), "cache")
        outcomes: dict[tuple[str, k.EntityKey], tuple[Executed[parser.Result], _Claims]] = {}
        found: set[str] = set()
        for output in batch:
            _need(type(output) is Executed and type(output.receipt) is ParseReceipt
                  and type(output.receipt.capture) is Capture and type(output.receipt.capture.id) is str, "receipt")
            receipt, capture = output.receipt, output.receipt.capture
            _need(capture.id in expected and capture.id not in found and capture is expected[capture.id].capture
                  and all(type(value) is str for value in (receipt.owner, receipt.context, receipt.registration_sha256))
                  and receipt.owner == profile.STEP.id and receipt.context == expected[capture.id].context
                  and receipt.registration_sha256 == self.registration[2], "receipt")
            cached, parsed = self.produced[capture.id], self.parsed[capture.id]
            _need(type(cached) is parser.Result and type(parsed) is ParseResult and output.value is cached
                  and receipt.parse is parsed and cached.parse is parsed, "cache")
            claims = parser.validate_claims(capture, cached)
            _need(len(claims) == len(cached.rows)
                  and all(row is actual for (row, _), actual in zip(claims, cached.rows, strict=True)), "claims")
            _need(cached.reason is not None or all((row.interface.raw, row.group.raw) in
                  next(target.groups for target in self.inputs.targets if target.context == receipt.context
                       and target.node.key == capture.source) for row, _ in claims), "population")
            outcomes[(receipt.context or "", capture.source)] = (output, claims)
            found.add(capture.id)
        _need(found == set(expected), "coverage")
        rows = _rows(self.subjects, outcomes, _declaration_context(self))
        _LOCAL_VRRP_OWNER.validate_inputs(self)
        _need(all(type(self.snapshots[key]) is dict and asdict(value) == self.snapshots[key] for key, value in self.produced.items()), "cache")
        return rows

    def finish(self) -> VRRPResult:
        _receiver(self)
        _need(self.attempted and not self.running and not self.production_attempted and self.production is None
              and self.completed is None and type(self.executed) is tuple, "production_once")
        self.production_attempted = True
        rows = _LOCAL_VRRP_OWNER.canonical_rows(self)
        batch = self.executed
        if batch is None:
            raise ValueError("vrrp_owner_batch")
        store = FactStore()
        writer = bind_writer(store, step=profile.STEP)
        for row in rows:
            writer.write(fact=profile.REPORTED_VRRP_STATE, subject=row.subject, value=row.value)
        result = VRRPResult(store=store, rows=rows, executed=batch, registration_sha256=self.registration[2])
        self.completed = _Production(result=result, store=store, rows=rows, cells=tuple((row.subject, row.value) for row in rows),
            executed=batch, registration_sha256=self.registration[2])
        self.production = result
        return result

    def validate_values(self, result: VRRPResult, reader: FactReader) -> None:
        """Close original production and all current Reader cells; no admission or value seal."""
        _receiver(self)
        completed = self.completed
        _need(type(completed) is _Production and type(result) is VRRPResult, "value_source")
        if completed is None:
            raise ValueError("vrrp_owner_value_source")
        _need(self.production_attempted and self.production is completed.result and result is completed.result
              and type(result.store) is FactStore and result.store is completed.store
              and result.rows is completed.rows and result.executed is completed.executed and self.executed is completed.executed
              and type(result.registration_sha256) is str and result.registration_sha256 == completed.registration_sha256,
              "value_source")
        _need(type(reader) is FactReader and reader.store is completed.store and type(reader.step) is StepSpec, "reader")
        step = reader.step
        _need(all(type(value) is str for value in (step.id, step.pack, step.kind, step.scope, step.evaluator))
              and step.pack == profile.PACK and type(step.reads) is tuple
              and all(type(fact) is str for fact in step.reads) and step.reads == (profile.REPORTED_VRRP_STATE,)
              and type(step.produces) is tuple and not step.produces, "reader")
        StepSpec(id=step.id, pack=step.pack, kind=step.kind, scope=step.scope,
                 reads=step.reads, produces=step.produces, evaluator=step.evaluator)
        wanted = _LOCAL_VRRP_OWNER.canonical_rows(self)
        _need(result.registration_sha256 == self.registration[2] and type(result.rows) is tuple
              and all(type(row) is Row and all(type(value) is str for value in
                  (row.subject, row.interface, row.group)) for row in result.rows), "value_population")
        actual, expected = {row.subject: row for row in result.rows}, {row.subject: row for row in wanted}
        cells = dict(completed.cells)
        _need(len(actual) == len(result.rows) == len(expected) == len(wanted) == len(cells) == len(completed.cells)
              and set(actual) == set(expected) == set(cells), "value_population")
        store = completed.store
        references = {k.FactRef(fact=profile.REPORTED_VRRP_STATE, subject=subject) for subject in expected}
        _need(type(store.owners) is dict and type(store.values) is dict
              and all(type(fact) is str and type(owner) is str for fact, owner in store.owners.items())
              and store.owners == {profile.REPORTED_VRRP_STATE: profile.STEP.id}
              and all(type(ref) is k.FactRef and type(ref.fact) is str and type(ref.subject) is str for ref in store.values)
              and set(store.values) == references, "value_store")
        for subject, original in expected.items():
            row, value = actual[subject], actual[subject].value
            _need(row.target is original.target and row.interface == original.interface and row.group == original.group
                  and value is cells[subject], "value_cell")
            validate_version_state_graph(value)
            _need(type(value) is type(original.value) and value == original.value, "value_cell")
            _need(store.values[k.FactRef(fact=profile.REPORTED_VRRP_STATE, subject=subject)] is value
                  and reader.read(fact=profile.REPORTED_VRRP_STATE, subject=subject) is value, "value_reader")


@dataclass(frozen=True, slots=True, kw_only=True)
class VRRPExecution:
    owner: VRRPOwner
    result: VRRPResult


def execute_local_vrrp_inputs(targets: tuple[inputs.VRRPTarget, ...], requests: tuple[CaptureRequest, ...]) -> VRRPExecution:
    owner = VRRPOwner(targets, requests)
    owner.attempted = owner.running = True
    try:
        batch = execute_parsers((profile.DECLARATION,), (Handler(binding=profile.BINDING, parser=owner),), owner.inputs.requests)
    finally:
        owner.running = False
    _LOCAL_VRRP_OWNER.validate_inputs(owner)
    owner.executed = batch
    return VRRPExecution(owner=owner, result=_LOCAL_VRRP_OWNER.finish(owner))


class MixedVRRPOwner(VRRPOwner):
    """Own the fixed mixed run's VRRP subset; current metadata is not an origin seal."""

    def __init__(self, envelope: p4.Envelope, budgets: Budgets,
                 targets: tuple[inputs.VRRPTarget, ...], requests: tuple[CaptureRequest, ...]) -> None:
        _need(type(self) is _MIXED_VRRP_OWNER, "receiver")
        compiled = global_inputs.validate_mixed_context(envelope, budgets)
        super().__init__(targets, requests)
        self.envelope, self.budgets = envelope, budgets
        self.registration = (compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256)
        _LOCAL_VRRP_OWNER.validate_inputs(self)

    def validate_registration(self) -> None:
        _need(type(self) is _MIXED_VRRP_OWNER, "receiver")
        compiled = global_inputs.validate_mixed_context(self.envelope, self.budgets)
        mixed_inputs.validate_mixed_vrrp_correspondence(self.envelope, self.budgets, self.inputs)
        _need(type(self.registration) is tuple and len(self.registration) == 3
              and type(self.registration[0]) is bytes and type(self.registration[1]) is bytes
              and type(self.registration[2]) is str and self.registration ==
                  (compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256)
              and self.envelope.registration_sha256 == self.registration[2]
              and self.inputs.registration_sha256 != self.registration[2], "mixed_registration")

    def declaration_evidence(self) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
        _need(type(self) is _MIXED_VRRP_OWNER, "receiver")
        return mixed_inputs.validate_mixed_vrrp_correspondence(self.envelope, self.budgets, self.inputs)


class RootMixedVRRPOwner(VRRPOwner):
    """Own the fixed Root9 mixed run's VRRP subset; current metadata is not an origin seal."""

    def __init__(self, envelope: p4.Envelope, budgets: Budgets,
                 targets: tuple[inputs.VRRPTarget, ...], requests: tuple[CaptureRequest, ...]) -> None:
        _need(type(self) is _ROOT_MIXED_VRRP_OWNER, "receiver")
        compiled = global_inputs.validate_root_mixed_context(envelope, budgets)
        super().__init__(targets, requests)
        self.envelope, self.budgets = envelope, budgets
        self.registration = (compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256)
        _LOCAL_VRRP_OWNER.validate_inputs(self)

    def validate_registration(self) -> None:
        _need(type(self) is _ROOT_MIXED_VRRP_OWNER, "receiver")
        compiled = global_inputs.validate_root_mixed_context(self.envelope, self.budgets)
        mixed_inputs.validate_root_mixed_vrrp_correspondence(self.envelope, self.budgets, self.inputs)
        _need(type(self.registration) is tuple and len(self.registration) == 3
              and type(self.registration[0]) is bytes and type(self.registration[1]) is bytes
              and type(self.registration[2]) is str and self.registration ==
                  (compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256)
              and self.envelope.registration_sha256 == self.registration[2]
              and self.inputs.registration_sha256 != self.registration[2], "mixed_registration")

    def declaration_evidence(self) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
        _need(type(self) is _ROOT_MIXED_VRRP_OWNER, "receiver")
        return mixed_inputs.validate_root_mixed_vrrp_correspondence(self.envelope, self.budgets, self.inputs)


_LOCAL_VRRP_OWNER = VRRPOwner
_MIXED_VRRP_OWNER = MixedVRRPOwner
_ROOT_MIXED_VRRP_OWNER = RootMixedVRRPOwner


def _receiver(owner: VRRPOwner) -> None:
    _need(type(owner) is _LOCAL_VRRP_OWNER or type(owner) is _MIXED_VRRP_OWNER or type(owner) is _ROOT_MIXED_VRRP_OWNER, "receiver")


def _declaration_context(owner: VRRPOwner) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    _receiver(owner)
    if type(owner) is _MIXED_VRRP_OWNER:
        return _MIXED_VRRP_OWNER.declaration_evidence(owner)
    if type(owner) is _ROOT_MIXED_VRRP_OWNER:
        return _ROOT_MIXED_VRRP_OWNER.declaration_evidence(owner)
    return _LOCAL_VRRP_OWNER.declaration_evidence(owner)
