"""Actual local VRRP state production; no root admission, Reader seal or global source."""
from dataclasses import asdict, dataclass
from hashlib import sha256

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l3.fhrp import parse_vrrp as parser
from atlas_brain.packs.l3.fhrp import vrrp_inputs as inputs
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
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


def _rows(subjects: tuple[_Subject, ...], outcomes: dict[tuple[str, k.EntityKey], tuple[Executed[parser.Result], _Claims]]) -> tuple[Row, ...]:
    rows: list[Row] = []
    for target, interface, group, subject in subjects:
        outcome = outcomes.get((target.context, target.node.key))
        output, claims = (None, ()) if outcome is None else outcome
        candidates = tuple(row for row, _ in claims if row.interface.raw == interface and row.group.raw == group)
        rich = candidates[0] if len(candidates) == 1 else None
        reason = k.UnknownReason.NOT_COLLECTED if output is None else output.value.reason
        reason = reason or (rich.reason if rich is not None else k.UnknownReason.CONFLICTING_EVIDENCE
                           if candidates else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
        evidence: tuple[k.Evidence, ...] = target.node.declaration.evidence
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
        self.inputs = inputs.retain_vrrp_inputs(targets, requests)
        self.registration = _registration()
        self.subjects = _subjects(self.inputs)
        self.produced: dict[k.CaptureId, parser.Result] = {}
        self.parsed: dict[k.CaptureId, ParseResult] = {}
        self.snapshots: dict[k.CaptureId, dict[str, object]] = {}
        self.executed: tuple[Executed[parser.Result], ...] | None = None
        self.production: VRRPResult | None = None
        self.attempted = self.running = self.production_attempted = False

    def validate_inputs(self) -> None:
        inputs.validate_vrrp_inputs(self.inputs)
        _need(self.registration == _registration() and self.inputs.registration_sha256 == self.registration[2], "registration")
        expected = _subjects(self.inputs)
        _need(type(self.subjects) is tuple and len(self.subjects) == len(expected)
              and all(type(held) is tuple and len(held) == 4 and held[0] is wanted[0]
                  and all(type(value) is str for value in held[1:]) and held[1:] == wanted[1:]
                  for held, wanted in zip(self.subjects, expected, strict=True)), "subjects")

    def parse(self, request: CaptureRequest) -> Parsed[parser.Result]:
        self.validate_inputs()
        inputs.validate_vrrp_request(request)
        expected = {item.capture.id: item for item in self.inputs.requests}
        capture = request.capture
        _need(self.running and capture.id in expected and capture is expected[capture.id].capture
              and request.context == expected[capture.id].context and capture.id not in self.produced, "request")
        value = parser.parse_capture(capture)
        _need(type(value) is parser.Result, "cache")
        parser.validate_claims(capture, value)
        self.validate_inputs()
        self.produced[capture.id], self.parsed[capture.id], self.snapshots[capture.id] = value, value.parse, asdict(value)
        return value, value.parse

    def finish(self) -> VRRPResult:
        _need(self.attempted and not self.running and not self.production_attempted and self.production is None
              and type(self.executed) is tuple, "production_once")
        self.production_attempted = True
        self.validate_inputs()
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
        rows = _rows(self.subjects, outcomes)
        self.validate_inputs()
        _need(all(type(self.snapshots[key]) is dict and asdict(value) == self.snapshots[key] for key, value in self.produced.items()), "cache")
        store = FactStore()
        writer = bind_writer(store, step=profile.STEP)
        for row in rows:
            writer.write(fact=profile.REPORTED_VRRP_STATE, subject=row.subject, value=row.value)
        result = VRRPResult(store=store, rows=rows, executed=batch, registration_sha256=self.registration[2])
        self.production = result
        return result


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
    owner.validate_inputs()
    owner.executed = batch
    return VRRPExecution(owner=owner, result=owner.finish())
