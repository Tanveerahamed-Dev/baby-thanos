"""Closed HSRP Row comparison data, never Source/admission/proof authority.

Callers must supply and reclose their already-owned original plan, requests,
envelope, Stores and population. Retention compares bindings; it authenticates no
caller-provided plan. Exact graphs are checked before primitive serialization.
"""
import json
from dataclasses import dataclass

from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp.version_inputs import (
    validate_fhrp_target_graph,
    validate_version_state_graph,
)

type Index = dict[tuple[str,k.EntityKey],state.Target]
type Entry = tuple[tuple[str,k.EntityKey],state.Target,Node,k.Known[str],bytes]


def _need(condition: bool) -> None:
    k.require(condition,"hsrp_presence_graph")


def _index(indexed: Index) -> None:
    _need(type(indexed) is dict)
    _need(all(type(key) is tuple and len(key)==2 and all(type(item) is str for item in key)
        and type(target) is state.Target for key,target in indexed.items()))
    for target in indexed.values():validate_fhrp_target_graph(target)
    _need(all(key==(target.context,target.node.key) for key,target in indexed.items()))


def _reference(ref: k.Evidence) -> dict[str,object]:
    if isinstance(ref,k.RegistryRef):
        return {"table":ref.table,"row_id":ref.row_id,"table_digest":ref.table_digest,"citation":ref.citation}
    if isinstance(ref,k.FactRef):
        return {"fact":ref.fact,"subject":ref.subject}
    locator=ref.locator
    point: dict[str,object]
    if isinstance(locator,k.ByteSpan):point={"start":locator.start,"end":locator.end}
    elif isinstance(locator,k.FieldPointer):point={"pointer":locator.pointer}
    elif isinstance(locator,k.XmlPath):point={"path":locator.path}
    else:point={}
    return {"capture":ref.capture,"locator":point,"role":ref.role.value,"excerpt_sha256":ref.excerpt_sha256}


def _value(value: k.Known[str] | k.Unknown) -> dict[str,object]:
    evidence=[_reference(ref) for ref in value.evidence]
    if isinstance(value,k.Known):
        return {"value":value.value,"basis":value.basis.value,"evidence":evidence,"raw":value.raw}
    return {"reason":value.reason.value,"detail":value.detail,"evidence":evidence,"candidates":list(value.candidates),
        "next_evidence":[{"node":need.node,"operation":need.operation,"params":[list(pair) for pair in need.params],
            "resolves":list(need.resolves),"reruns":list(need.reruns),"after_s":need.after_s,
            "unprintable":list(need.unprintable)} for need in value.next_evidence]}


def _target_data(target: state.Target) -> dict[str,object]:
    node=target.node
    return {"context":target.context,"node":{"group":node.group,"id":node.id,"discovery_id":node.discovery_id,
        "ports":list(node.ports),"declaration":_value(node.declaration)},"groups":[list(pair) for pair in target.groups]}


def _bytes(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")


@dataclass(frozen=True,slots=True,kw_only=True)
class RetainedTargets:
    """Comparison values and original pointers, not admission or execution credentials."""
    indexed: Index
    entries: tuple[Entry,...]


def retain_targets(original_indexed: Index) -> RetainedTargets:
    """Call only at the trusted original-plan boundary, before callback exposure."""
    _index(original_indexed)
    return RetainedTargets(indexed=original_indexed,entries=tuple((key,target,target.node,target.node.declaration,
        _bytes(_target_data(target))) for key,target in sorted(original_indexed.items())))


def _bindings(original_indexed: Index, retained: RetainedTargets) -> tuple[state.Target,...]:
    _need(type(retained) is RetainedTargets and type(retained.entries) is tuple
        and type(original_indexed) is dict and retained.indexed is original_indexed)
    _need(all(type(entry) is tuple and len(entry)==5 and type(entry[0]) is tuple and len(entry[0])==2
        and all(type(item) is str for item in entry[0]) and type(entry[1]) is state.Target
        and type(entry[2]) is Node and type(entry[3]) is k.Known and type(entry[4]) is bytes for entry in retained.entries))
    _index(original_indexed)
    _need(tuple(sorted(original_indexed))==tuple(key for key,_,_,_,_ in retained.entries))
    for key,target,node,declaration,_ in retained.entries:
        _need(original_indexed[key] is target and target.node is node and node.declaration is declaration)
    return tuple(target for _,target,_,_,_ in retained.entries)


def source_rows_bytes(rows: tuple[state.Row,...], original_indexed: Index, retained: RetainedTargets) -> bytes:
    """Detach the entire strictly typed row tuple; no deepcopy, coercion or Source authorization."""
    targets=_bindings(original_indexed,retained)
    _need(type(rows) is tuple and all(type(row) is state.Row for row in rows))
    for row in rows:
        _need(type(row.interface) is str and type(row.group) is str and type(row.subject) is str
            and any(row.target is target for target in targets))
        validate_version_state_graph(row.value)
        if isinstance(row.value,k.Known):
            _need(type(row.value.raw) is str and row.value.basis is k.Basis.OBSERVED)
    # Every graph is closed before subject computation, comparisons or serialization.
    expected_subjects={state.subject(target,interface,group) for target in targets for interface,group in target.groups}
    _need(len(rows)==len(expected_subjects) and {row.subject for row in rows}==expected_subjects)
    for row in rows:
        _need((row.interface,row.group) in row.target.groups
            and row.subject==state.subject(row.target,row.interface,row.group))
    for _,target,_,_,expected in retained.entries:
        _need(_bytes(_target_data(target))==expected)
    return _bytes(tuple({"target":_target_data(row.target),"interface":row.interface,"group":row.group,
        "subject":row.subject,"value":_value(row.value)} for row in rows))
