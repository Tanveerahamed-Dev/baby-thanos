"""Finite current FHRP input comparisons; no origin or admission seal.

Values are detached primitives/bytes; pointers are comparison data only.
Callers retain original custody and reclose current inputs before each use.
"""
import json

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp.version_inputs import (
    validate_fhrp_request_graph,
    validate_version_state_graph,
)
from atlas_brain.runner import pack_receipts as receipts

type RequestValue = tuple[str,receipts.CaptureRequest,Capture,bytes]


def _need(condition: bool) -> None:
    k.require(condition,"hsrp_presence_context")


def _raw(value: object) -> dict[str,str]:
    if type(value) is not bytes:raise ValueError("hsrp_presence_context_snapshot")
    return {"$bytes":value.hex()}


def request_values(requests: tuple[receipts.CaptureRequest,...]) -> tuple[RequestValue,...]:
    """Close current requests before exact byte-aware snapshotting."""
    _need(type(requests) is tuple)
    for request in requests:validate_fhrp_request_graph(request)
    return tuple((held.identity,held.request,held.capture,
        json.dumps(held.value,sort_keys=True,separators=(",",":"),allow_nan=False,
            default=_raw).encode("utf-8")) for held in receipts.retain_requests(requests))


def _declaration(value: k.Known[str]) -> tuple[object,...]:
    _need(type(value) is k.Known and type(value.value) is str and type(value.raw) is str
        and value.basis is k.Basis.DECLARED and type(value.evidence) is tuple
        and all(type(ref) is k.RegistryRef for ref in value.evidence))
    validate_version_state_graph(value)
    return (value.value,value.raw,tuple((ref.table,ref.row_id,ref.table_digest,ref.citation)
        for ref in value.evidence if type(ref) is k.RegistryRef))


def capture_context(envelope: p4.Envelope, budgets: Budgets) -> tuple[tuple[object,...],tuple[object,...]]:
    """Close current finite inputs; return pointers and immutable comparison values."""
    _need(type(envelope) is p4.Envelope and type(envelope.base) is SyntheticGroup and type(budgets) is Budgets)
    base=envelope.base
    amounts=(budgets.bundle_bytes,budgets.artifact_bytes,budgets.artifacts,budgets.nesting_depth,
        budgets.numeric_digits,budgets.compression_ratio,budgets.archive_index_bytes)
    _need(all(type(item) is int and item>0 for item in amounts)
        and type(envelope.raw) is bytes and type(base.raw) is bytes
        and all(type(item) is str for item in (envelope.context,envelope.registration_sha256,base.id,base.schema))
        and type(base.nodes) is tuple and type(base.captures) is tuple
        and type(envelope.targets) is tuple and type(envelope.captures) is tuple)
    pointers: tuple[object,...]=(envelope,base,budgets,base.nodes,base.captures,envelope.targets,envelope.captures)
    nodes: list[object]=[]
    for node in base.nodes:
        _need(type(node) is Node and all(type(item) is str for item in (node.group,node.id,node.discovery_id))
            and type(node.ports) is tuple and all(type(port) is str for port in node.ports))
        pointers+=(node,node.declaration)
        nodes.append((node.group,node.id,node.discovery_id,node.ports,_declaration(node.declaration)))
    captures=request_values(tuple(receipts.CaptureRequest(capture=capture,context=None) for capture in base.captures))
    pointers+=tuple(item[2] for item in captures)
    targets: list[object]=[]
    for target in envelope.targets:
        _need(type(target) is p4.Target and all(type(item) is str for item in (target.id,target.operation,target.owner))
            and type(target.params) is bytes and any(target.node is node for node in base.nodes))
        pointers+=(target,target.declaration)
        targets.append((target.id,target.node.key,target.operation,target.owner,target.params,_declaration(target.declaration)))
    members: list[object]=[]
    for member in envelope.captures:
        _need(type(member) is p4.CaptureMember and type(member.raw) is bytes
            and all(type(item) is str for item in (member.id,member.path,member.sha256))
            and any(member.target is target for target in envelope.targets))
        pointers+=(member,member.target)
        members.append((member.id,member.path,member.sha256,member.raw))
    pointers+=(base.declaration,envelope.declaration)
    values=(envelope.raw,base.raw,envelope.context,envelope.registration_sha256,base.id,base.schema,amounts,
        _declaration(base.declaration),_declaration(envelope.declaration),tuple(nodes),
        tuple((item[0],item[3]) for item in captures),tuple(targets),tuple(members))
    return pointers,values


