"""Closed VERSION input custody; retained graphs are comparison data, never admission."""
from dataclasses import asdict, dataclass

from atlas_brain.evidence.capture import Capture, CaptureMetadata, Scope
from atlas_brain.evidence.synthetic import Node
from atlas_brain.evidence.text import TextLine, text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import TimeInterval
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.runner import pack_receipts as custody
from atlas_brain.runner.pack_receipts import CaptureRequest, RetainedRequest

type TargetRetention = tuple[build.Target, Node, k.Known[str], dict[str, object]]


def _need(condition: bool, code: str) -> None:
    k.require(condition, "hsrp_version_inputs_" + code)


def _locator(value: k.ByteSpan | k.FieldPointer | k.XmlPath | k.WholeCapture) -> None:
    _need(type(value) in (k.ByteSpan, k.FieldPointer, k.XmlPath, k.WholeCapture), "locator")
    if isinstance(value, k.ByteSpan):
        k.ByteSpan(start=value.start, end=value.end)
    elif isinstance(value, k.FieldPointer):
        k.FieldPointer(pointer=value.pointer)
    elif isinstance(value, k.XmlPath):
        k.XmlPath(path=value.path)


def _evidence(values: tuple[k.Evidence, ...]) -> None:
    _need(type(values) is tuple and all(type(ref) in (k.EvidenceRef, k.FactRef, k.RegistryRef) for ref in values), "evidence")
    for ref in values:
        if isinstance(ref, k.EvidenceRef):
            _locator(ref.locator)
            k.EvidenceRef(capture=ref.capture, locator=ref.locator, role=ref.role, excerpt_sha256=ref.excerpt_sha256)
        elif isinstance(ref, k.FactRef):
            k.FactRef(fact=ref.fact, subject=ref.subject)
        else:
            k.RegistryRef(table=ref.table, row_id=ref.row_id, table_digest=ref.table_digest, citation=ref.citation)


def _unknown(value: k.Unknown) -> None:
    _need(type(value) is k.Unknown and type(value.next_evidence) is tuple
          and all(type(need) is k.EvidenceNeed for need in value.next_evidence)
          and type(value.candidates) is tuple and all(type(candidate) is str for candidate in value.candidates), "unknown")
    _evidence(value.evidence)
    for need in value.next_evidence:
        _need(all(type(values) is tuple and all(type(item) is str for item in values)
                  for values in (need.resolves, need.reruns, need.unprintable)), "need")
        k.EvidenceNeed(node=need.node, operation=need.operation, params=need.params, resolves=need.resolves,
                       reruns=need.reruns, after_s=need.after_s, unprintable=need.unprintable)
    k.Unknown(reason=value.reason, detail=value.detail, evidence=value.evidence,
              candidates=value.candidates, next_evidence=value.next_evidence)


def _capture(value: Capture) -> None:
    _need(type(value) is Capture and type(value.raw) is bytes and all(type(item) is str for item in
          (value.id, value.source, value.operation, value.rendered, value.codec))
          and type(value.integrity) is k.IntegrityState and type(value.read_scope) is k.ReadScope
          and type(value.view) is k.ViewConsistency and type(value.lines) is tuple
          and value.codec in ("utf-8", "ascii"), "capture")
    for line in value.lines:
        _need(type(line) is TextLine and type(line.text) is str and type(line.offsets) is tuple
              and all(type(offset) is int for offset in line.offsets) and type(line.decoding_errors) is bool
              and type(line.span) is k.ByteSpan, "line")
        k.ByteSpan(start=line.span.start, end=line.span.end)
    _need(value.lines == text_lines(value.raw, value.codec), "line")
    metadata = value.metadata
    if metadata is not None:
        _need(type(metadata) is CaptureMetadata and type(metadata.scope) is Scope, "metadata")
        scope = metadata.scope
        _need(type(scope.plane) is str, "scope")
        Scope(node=scope.node, vrf=scope.vrf, context=scope.context, vdc=scope.vdc, tenant=scope.tenant,
              afi=scope.afi, instance=scope.instance, plane=scope.plane)
        time = metadata.collected_utc
        if isinstance(time, TimeInterval):
            _need(type(time) is TimeInterval, "time")
            TimeInterval(earliest=time.earliest, latest=time.latest, clock=time.clock, bound=time.bound)
        else:
            _unknown(time)
        _evidence(metadata.integrity_evidence)
        _evidence(metadata.read_scope_evidence)
        CaptureMetadata(channel=metadata.channel, scope=scope, collected_utc=time, error=metadata.error,
            integrity_evidence=metadata.integrity_evidence, read_scope_evidence=metadata.read_scope_evidence, envelope=metadata.envelope)
    Capture(id=value.id, source=value.source, operation=value.operation, rendered=value.rendered, codec=value.codec,
        raw=value.raw, integrity=value.integrity, lines=value.lines, read_scope=value.read_scope, view=value.view, metadata=metadata)


def _target(value: build.Target) -> None:
    _need(type(value) is build.Target and type(value.context) is str and type(value.node) is Node, "target")
    node = value.node
    _need(all(type(item) is str for item in (node.group, node.id, node.discovery_id))
          and type(node.ports) is tuple and all(type(port) is str for port in node.ports), "target")
    declaration = node.declaration
    _need(type(declaration) is k.Known and type(declaration.value) is str and type(declaration.raw) is str
          and type(declaration.basis) is k.Basis, "target")
    _evidence(declaration.evidence)
    build.Target(context=value.context, node=node, groups=value.groups)


def validate_version_request(request: CaptureRequest) -> None:
    """Validate only the current request graph; no snapshot, admission or parser call."""
    _need(type(request) is CaptureRequest, "request")
    _capture(request.capture)
    CaptureRequest(capture=request.capture, context=request.context)
    capture = request.capture
    _need(capture.operation == "iosxe.show_standby_all" and capture.rendered == "show standby all"
          and capture.codec in ("utf-8", "ascii")
          and capture.scope == Scope(node=capture.source, plane="exec", context=None, vrf=None, instance=None, vdc=None, tenant=None, afi=None), "request")


@dataclass(frozen=True, slots=True, kw_only=True)
class VersionInputs:
    targets: tuple[build.Target, ...]
    requests: tuple[CaptureRequest, ...]
    indexed: dict[tuple[str, k.EntityKey], build.Target]
    expected: dict[k.CaptureId, CaptureRequest]
    retained_targets: tuple[TargetRetention, ...]
    retained_requests: tuple[RetainedRequest, ...]


def retain_version_inputs(targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...]) -> VersionInputs:
    """Retain current validated input graphs for comparison; metadata is not an origin token."""
    _need(type(targets) is tuple and all(type(item) is build.Target for item in targets)
          and type(requests) is tuple and all(type(item) is CaptureRequest for item in requests), "input")
    indexed: dict[tuple[str, k.EntityKey], build.Target] = {}
    for target in targets:
        _target(target)
        key = (target.context, target.node.key)
        _need(key not in indexed, "population")
        indexed[key] = target
    retained_targets = tuple((item, item.node, item.node.declaration, asdict(item)) for item in targets)
    supplied: set[tuple[str, k.EntityKey]] = set()
    for request in requests:
        validate_version_request(request)
        key = (request.context or "", request.capture.source)
        _need(key in indexed and key not in supplied, "population")
        supplied.add(key)
    retained_requests = custody.retain_requests(requests)
    return VersionInputs(targets=targets, requests=requests, indexed=indexed,
        expected={item.capture.id: item for item in requests}, retained_targets=retained_targets, retained_requests=retained_requests)


def validate_version_inputs(inputs: VersionInputs) -> None:
    """Close current graphs before detached comparisons; snapshots are not admission."""
    _need(type(inputs) is VersionInputs and type(inputs.targets) is tuple and type(inputs.requests) is tuple
          and type(inputs.retained_targets) is tuple and type(inputs.retained_requests) is tuple
          and type(inputs.indexed) is dict and type(inputs.expected) is dict, "input")
    _need(len(inputs.targets) == len(inputs.retained_targets) == len(inputs.indexed)
          and all(item is held[0] for item, held in zip(inputs.targets, inputs.retained_targets, strict=True)), "population")
    for item in inputs.targets:
        _target(item)
        _need(inputs.indexed.get((item.context, item.node.key)) is item, "population")
    for request in inputs.requests:
        validate_version_request(request)
    retained = {item.identity: item for item in inputs.retained_requests}
    _need(len(retained) == len(inputs.retained_requests) == len(inputs.requests) == len(inputs.expected)
          and len({request.capture.id for request in inputs.requests}) == len(inputs.requests)
          and all(request.capture.id in retained and inputs.expected.get(request.capture.id) is request
          and retained[request.capture.id].request is request and retained[request.capture.id].capture is request.capture
          for request in inputs.requests), "population")
    for item, node, declaration, value in inputs.retained_targets:
        _need(item.node is node and node.declaration is declaration and asdict(item) == value, "target")
    custody.validate_retained_requests(inputs.requests, inputs.retained_requests)


def validate_version_state_graph(value: k.Known[str] | k.Unknown) -> None:
    """Close only the current state graph; no canonical value or admission claim."""
    _need(type(value) in (k.Known, k.Unknown), "state")
    if isinstance(value, k.Known):
        _need(type(value.value) is str, "state")
        _evidence(value.evidence)
        k.Known(value=value.value, basis=value.basis, evidence=value.evidence, raw=value.raw)
    else:
        _unknown(value)
