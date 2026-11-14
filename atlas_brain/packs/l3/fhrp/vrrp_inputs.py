"""Validated VRRP comparison snapshots; no admission, execution or fact-production authority."""
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import validate_fhrp_request_graph
from atlas_brain.runner.pack_receipts import CaptureRequest


def _need(condition: bool, code: str) -> None:
    k.require(condition, "vrrp_inputs_" + code)


@dataclass(frozen=True, slots=True, kw_only=True)
class VRRPTarget:
    context: str
    node: Node
    groups: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _need(type(self.context) is str and bool(self.context) and type(self.node) is Node, "target")
        node = self.node
        _need(all(type(value) is str and bool(value) for value in (node.group, node.id, node.discovery_id))
              and all(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name, re.ASCII) is not None for name in (node.group, node.id))
              and type(node.ports) is tuple and all(type(port) is str and bool(port) for port in node.ports), "node")
        declaration = node.declaration
        _need(type(declaration) is k.Known and type(declaration.value) is str and type(declaration.raw) is str
              and declaration.value == declaration.raw == node.id and declaration.basis is k.Basis.DECLARED
              and type(declaration.evidence) is tuple and len(declaration.evidence) == 1, "node")
        ref = declaration.evidence[0]
        _need(type(ref) is k.RegistryRef and all(type(value) is str for value in
              (ref.table, ref.row_id, ref.table_digest, ref.citation)) and ref.table == "synthetic_p2.nodes"
              and ref.row_id == node.id and re.fullmatch(r"/nodes/(0|[1-9][0-9]*)", ref.citation, re.ASCII) is not None, "node")
        reference = cast(k.RegistryRef, ref)
        k.RegistryRef(table=reference.table, row_id=reference.row_id, table_digest=reference.table_digest, citation=reference.citation)
        _need(type(self.groups) is tuple and 1 <= len(self.groups) <= 128 and all(type(pair) is tuple and len(pair) == 2
              and all(type(value) is str for value in pair) for pair in self.groups), "population")
        _need(len(set(self.groups)) == len(self.groups) and all(group in ("100", "101")
              and re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]{0,63}", interface, re.ASCII) is not None
              for interface, group in self.groups), "population")


def subject(target: VRRPTarget, interface: str, group: str) -> k.EntityKey:
    _need(type(target) is VRRPTarget, "target")
    VRRPTarget(context=target.context, node=target.node, groups=target.groups)
    _need(type(interface) is str and type(group) is str and (interface, group) in target.groups, "population")
    value = canonical(("atlas-brain.vrrp-local/1", target.context, target.node.key, interface, "ipv4", "vrrp", group))
    return k.EntityKey("fhrp_local:" + sha256(value).hexdigest())


def validate_vrrp_request(request: CaptureRequest) -> None:
    """Close only current model/command/scope values, never source admission."""
    validate_fhrp_request_graph(request)
    capture = request.capture
    _need(type(request.context) is str and bool(request.context) and capture.operation == "iosxe.show_vrrp"
          and capture.rendered == "show vrrp" and capture.scope == Scope(node=capture.source, plane="exec",
              context=None, vrf=None, instance=None, vdc=None, tenant=None, afi=None), "request")


def _freeze(value: object) -> object:
    if type(value) in (type(None), bool, str):
        return value
    if type(value) is int:
        return ("integer", str(value))
    if type(value) is bytes:
        return ("bytes_sha256", sha256(value).hexdigest())
    if isinstance(value, StrEnum):
        return str(value)
    if type(value) in (tuple, list):
        return tuple(_freeze(item) for item in cast(tuple[object, ...] | list[object], value))
    if type(value) is dict:
        entries = cast(dict[str, object], value)
        _need(all(type(key) is str for key in entries), "snapshot")
        return tuple((key, _freeze(entries[key])) for key in sorted(entries))
    raise ValueError("vrrp_inputs_snapshot")


def _snapshot(value: VRRPTarget | CaptureRequest) -> bytes:
    return canonical(_freeze(asdict(value)))


def _population(targets: tuple[VRRPTarget, ...], requests: tuple[CaptureRequest, ...]) -> None:
    _need(type(targets) is tuple and all(type(item) is VRRPTarget for item in targets)
          and type(requests) is tuple and all(type(item) is CaptureRequest for item in requests), "population")
    for item in targets:
        VRRPTarget(context=item.context, node=item.node, groups=item.groups)
    for request in requests:
        validate_vrrp_request(request)
    keys = tuple((item.context, item.node.key) for item in targets)
    supplied = tuple((item.context, item.capture.source) for item in requests)
    _need(len(set(keys)) == len(keys) and len(set(supplied)) == len(supplied)
          and len({item.capture.id for item in requests}) == len(requests)
          and all(key in keys for key in supplied), "population")


@dataclass(frozen=True, slots=True, kw_only=True)
class VRRPInputs:
    targets: tuple[VRRPTarget, ...]
    requests: tuple[CaptureRequest, ...]
    registration_sha256: str
    retained_targets: tuple[tuple[VRRPTarget, Node, k.Known[str], bytes], ...]
    retained_requests: tuple[tuple[CaptureRequest, Capture, bytes], ...]


def retain_vrrp_inputs(targets: tuple[VRRPTarget, ...], requests: tuple[CaptureRequest, ...]) -> VRRPInputs:
    """Retain original pointers and immutable comparison bytes, not origin tokens."""
    registration = profile.compile_vrrp_profile().registration_sha256
    _population(targets, requests)
    return VRRPInputs(targets=targets, requests=requests, registration_sha256=registration,
        retained_targets=tuple((item, item.node, item.node.declaration, _snapshot(item)) for item in targets),
        retained_requests=tuple((item, item.capture, _snapshot(item)) for item in requests))


def validate_vrrp_inputs(inputs: VRRPInputs) -> None:
    """Revalidate finite current graphs before comparing snapshots; execution stays later."""
    _need(type(inputs) is VRRPInputs, "input")
    _population(inputs.targets, inputs.requests)
    _need(type(inputs.registration_sha256) is str
          and inputs.registration_sha256 == profile.compile_vrrp_profile().registration_sha256
          and type(inputs.retained_targets) is tuple and type(inputs.retained_requests) is tuple
          and len(inputs.retained_targets) == len(inputs.targets) and len(inputs.retained_requests) == len(inputs.requests), "input")
    for item, held in zip(inputs.targets, inputs.retained_targets, strict=True):
        _need(type(held) is tuple and len(held) == 4 and held[0] is item and held[1] is item.node
              and held[2] is item.node.declaration and type(held[3]) is bytes and held[3] == _snapshot(item), "target")
    for request, held in zip(inputs.requests, inputs.retained_requests, strict=True):
        _need(type(held) is tuple and len(held) == 3 and held[0] is request and held[1] is request.capture
              and type(held[2]) is bytes and held[2] == _snapshot(request), "request")
