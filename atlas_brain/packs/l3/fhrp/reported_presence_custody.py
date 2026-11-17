"""Original HSRP owner bindings for trusted callers; comparison data, never seals.

Capture plans only from the caller's actual prepare path, before callbacks;
capture execution bindings before Writer exposure. Callers retain the original
run/envelope, admitted bytes, budgets, registration, census and Source custody.
All current input graphs are reclosed on every call; pointers alone authorize
nothing. These helpers perform no admission, Reader, Writer or parser execution.
"""
from dataclasses import dataclass

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import brief_execution_graph as brief
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp.reported_presence_context import (
    RequestValue,
    capture_context,
    request_values,
)
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner import pack_receipts as receipts
from atlas_brain.runner.pack_runtime import Executed

type Proofs = dict[tuple[str,k.EntityKey],tuple[k.RegistryRef,...]]
type OutputValue[T] = tuple[Executed[T],receipts.ParseReceipt,Capture,T,ParseResult]
type ProducedValue = tuple[str,state.hsrp.Result,ParseResult]


def _need(condition: bool) -> None:
    k.require(condition,"hsrp_presence_custody")


def _proofs(proofs: Proofs) -> bytes:
    _need(type(proofs) is dict and all(type(key) is tuple and len(key)==2
        and all(type(item) is str for item in key) for key in proofs))
    _need(all(type(refs) is tuple and all(type(ref) is k.RegistryRef
        and all(type(item) is str for item in (ref.table,ref.row_id,ref.table_digest,ref.citation))
        for ref in refs) for refs in proofs.values()))
    return canonical(tuple((key,tuple((ref.table,ref.row_id,ref.table_digest,ref.citation) for ref in refs))
        for key,refs in sorted(proofs.items())))


@dataclass(frozen=True,slots=True,kw_only=True)
class PlanBindings:
    """Original pointers and immutable expectations, not arbitrary-plan authentication."""
    owner: state.StateOwner
    plan: tuple[type[object],object]
    requests: tuple[receipts.CaptureRequest,...]
    expected: dict[k.CaptureId,receipts.CaptureRequest]
    indexed: dict[tuple[str,k.EntityKey],state.Target]
    proofs: Proofs
    produced: dict[k.CaptureId,state.hsrp.Result]
    registration: str
    request_values: tuple[RequestValue,...]
    targets: graph.RetainedTargets
    proof_values: bytes
    context_pointers: tuple[object,...]
    context_values: tuple[object,...]


@dataclass(frozen=True,slots=True,kw_only=True)
class ExecutionBindings[T]:
    plan: PlanBindings
    execution: p4_pipeline.Result[T]
    outputs: tuple[Executed[T],...]
    envelope: object
    values: tuple[OutputValue[T],...]
    produced_values: tuple[ProducedValue,...]


def retain_plan(owner: state.StateOwner, envelope: p4.Envelope, budgets: Budgets) -> PlanBindings:
    """Use only at the caller-owned real prepare boundary, before callback exposure."""
    if type(owner) is not state.StateOwner:raise ValueError("hsrp_presence_custody")
    plan=owner.plan
    pointers,values=capture_context(envelope,budgets)
    proofs=plan.proofs
    if type(proofs) is not dict:raise ValueError("hsrp_presence_custody")
    held=PlanBindings(owner=owner,plan=(type(plan),plan),requests=plan.requests,expected=plan.expected,
        indexed=plan.indexed,proofs=proofs,produced=owner.produced,registration=owner.registration,
        request_values=request_values(plan.requests),targets=graph.retain_targets(plan.indexed),
        proof_values=_proofs(proofs),context_pointers=pointers,context_values=values)
    validate_plan(held,owner,envelope,budgets)
    return held


def validate_plan(held: PlanBindings, owner: state.StateOwner, envelope: p4.Envelope, budgets: Budgets) -> None:
    """Close current plan maps before serializers, equality, selection or owner.own."""
    _need(type(held) is PlanBindings and type(owner) is state.StateOwner and owner is held.owner)
    _need(type(owner.plan) is held.plan[0] and owner.plan is held.plan[1])
    _need(owner.plan.requests is held.requests
        and type(owner.plan.requests) is tuple and type(owner.plan.expected) is dict
        and owner.plan.expected is held.expected and type(owner.plan.indexed) is dict
        and owner.plan.indexed is held.indexed and type(owner.plan.proofs) is dict
        and owner.plan.proofs is held.proofs and type(owner.produced) is dict
        and owner.produced is held.produced and type(owner.finished) is bool
        and type(owner.registration) is str)
    _need(all(type(key) is str for key in held.expected)
        and all(type(key) is str and type(value) is state.hsrp.Result
            and type(value.parse) is ParseResult for key,value in held.produced.items()))
    pointers,values=capture_context(envelope,budgets)
    _need(len(pointers)==len(held.context_pointers) and all(a is b for a,b in zip(pointers,held.context_pointers,strict=True))
        and values==held.context_values)
    current=request_values(held.requests)
    _need(len(current)==len(held.request_values)==len(held.expected)
        and all(before[0]==after[0] and before[1] is after[1] and before[2] is after[2]
            and before[3]==after[3] and held.expected.get(k.CaptureId(before[0])) is before[1]
            for before,after in zip(held.request_values,current,strict=True)))
    actual=graph.retain_targets(held.indexed)
    _need(actual.indexed is held.targets.indexed and len(actual.entries)==len(held.targets.entries)
        and all(a[0]==b[0] and a[1] is b[1] and a[2] is b[2] and a[3] is b[3] and a[4]==b[4]
            for a,b in zip(actual.entries,held.targets.entries,strict=True)))
    k.digest(owner.registration)
    _need(owner.registration==held.registration==envelope.registration_sha256
        and _proofs(held.proofs)==held.proof_values)


def _execution[T](plan: PlanBindings, owner: state.StateOwner,
                  execution: p4_pipeline.Result[T], budgets: Budgets) -> tuple[Executed[T],...]:
    if type(execution) is not p4_pipeline.Result:raise ValueError("hsrp_presence_custody")
    validate_plan(plan,owner,execution.envelope,budgets)
    _need(type(execution.executed) is tuple and all(type(out) is Executed
        and type(out.receipt) is receipts.ParseReceipt and type(out.receipt.capture) is Capture
        and type(out.receipt.parse) is ParseResult for out in execution.executed))
    _need(set(owner.produced)==set(plan.expected))
    return execution.executed


def retain_execution[T](plan: PlanBindings, owner: state.StateOwner,
                        execution: p4_pipeline.Result[T], budgets: Budgets) -> ExecutionBindings[T]:
    """Use actual completed parsing, before the first Source Writer callback."""
    outputs=_execution(plan,owner,execution,budgets)
    brief.validate_brief_execution_graph(outputs)
    owned=tuple(state.StateOwner.own(owner,out) for out in outputs if out.receipt.capture.operation==state.hsrp.OP)
    _need(len(owned)==len(plan.expected))
    held=ExecutionBindings(plan=plan,execution=execution,outputs=outputs,envelope=execution.envelope,
        values=tuple((out,out.receipt,out.receipt.capture,out.value,out.receipt.parse) for out in outputs),
        produced_values=tuple((key,value,value.parse) for key,value in sorted(owner.produced.items())))
    close_execution(held,owner,execution,budgets)
    return held


def close_execution[T](held: ExecutionBindings[T], owner: state.StateOwner,
                       execution: p4_pipeline.Result[T], budgets: Budgets) -> tuple[Executed[state.hsrp.Result],...]:
    """Reclose every binding and graph, then call the actual original owner afresh."""
    _need(type(held) is ExecutionBindings)
    outputs=_execution(held.plan,owner,execution,budgets)
    _need(execution is held.execution and execution.envelope is held.envelope and outputs is held.outputs
        and len(outputs)==len(held.values)
        and all(out is before[0] and out.receipt is before[1] and out.receipt.capture is before[2]
            and out.value is before[3] and out.receipt.parse is before[4] for out,before in zip(outputs,held.values,strict=True)))
    _need(len(owner.produced)==len(held.produced_values) and all(
        owner.produced.get(k.CaptureId(key)) is value and type(value) is state.hsrp.Result and value.parse is parsed
        for key,value,parsed in held.produced_values))
    brief.validate_brief_execution_graph(outputs)
    return tuple(state.StateOwner.own(owner,out) for out in outputs if out.receipt.capture.operation==state.hsrp.OP)
