"""Actual fixed FHRP-only parser batch and current canonical outputs; no Store or admission seal."""
from dataclasses import asdict, dataclass
from pathlib import Path

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import CompiledPackSet
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import version_owner as version
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import VersionInputs, validate_fhrp_request_graph
from atlas_brain.runner import pack_receipts as custody
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt, RetainedRequest
from atlas_brain.runner.pack_runtime import Executed, Handler, execute_parsers

type _Key = tuple[str, k.EntityKey]
type _Outputs = tuple[Executed[brief.Result | all_hsrp.Result], ...]
type CanonicalOutputs = tuple[p4.Envelope, _Outputs, build.StateOwner, version.GlobalVersionOwner,
                              tuple[Executed[brief.Result], ...], _Outputs, Budgets]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Batch:
    envelope: p4.Envelope
    budgets: Budgets
    source: VersionInputs
    requests: tuple[CaptureRequest, ...]
    brief_requests: tuple[CaptureRequest, ...]
    declarations: dict[_Key, tuple[k.RegistryRef, ...]]
    first: CompiledPackSet
    admitted: CompiledPackSet
    identity: tuple[bytes, bytes, str]
    pointers: tuple[object, ...]
    envelope_value: dict[str, object]
    budget_value: dict[str, object]
    retained: tuple[RetainedRequest, ...]
    state: build.StateOwner
    plan: object
    held: dict[_Key, build.Target]
    proofs: dict[_Key, tuple[k.RegistryRef, ...]]
    owner: version.GlobalVersionOwner
    outputs: _Outputs


def _state_population(
    owner: build.StateOwner, source: VersionInputs, requests: tuple[CaptureRequest, ...], registration: str,
    held: dict[_Key, build.Target], proofs: dict[_Key, tuple[k.RegistryRef, ...]],
) -> None:
    plan, actual = owner.plan, owner.plan.proofs
    if actual is None:
        raise ValueError("hsrp_state_version_declaration")
    k.require(type(plan.indexed) is dict and set(plan.indexed) == set(held) == set(source.indexed)
              and all(type(key) is tuple and len(key) == 2 and all(type(value) is str for value in key) for key in plan.indexed)
              and all(plan.indexed[key] is target for key, target in held.items()), "hsrp_state_version_population")
    for key, target in held.items():
        domain = source.indexed[key]
        k.require(type(target) is build.Target and target.node is domain.node and target.context == domain.context
                  and type(target.context) is str and target.groups == domain.groups, "hsrp_state_version_population")
        build.Target(context=target.context, node=target.node, groups=target.groups)
    k.require(type(plan.expected) is dict and len(plan.expected) == len(requests)
              and all(plan.expected.get(request.capture.id) is request for request in requests)
              and plan.requests is requests and owner.registration == registration
              and type(owner.registration) is str and all(type(key) is str for key in plan.expected)
              and type(actual) is dict and set(actual) == set(proofs), "hsrp_state_version_population")
    for key, expected in proofs.items():
        refs = actual[key]
        k.require(type(refs) is tuple and all(type(ref) is k.RegistryRef and all(type(value) is str for value in
            (ref.table, ref.row_id, ref.table_digest, ref.citation)) for ref in refs)
            and refs == expected, "hsrp_state_version_declaration")


def _canonical_outputs(batch: _Batch) -> CanonicalOutputs:
    envelope, budgets, source = batch.envelope, batch.budgets, batch.source
    declarations, first, admitted, identity = batch.declarations, batch.first, batch.admitted, batch.identity
    pointers, envelope_value, budget_value = batch.pointers, batch.envelope_value, batch.budget_value
    requests, brief_requests, retained = batch.requests, batch.brief_requests, batch.retained
    state, plan, held, proofs, owner, outputs = batch.state, batch.plan, batch.held, batch.proofs, batch.owner, batch.outputs
    current = preparation.validate_state_version_correspondence(envelope, budgets, source)
    k.require(current == declarations and envelope is pointers[0] and budgets is pointers[1]
              and envelope.base is pointers[2] and envelope.base.nodes is pointers[3]
              and envelope.base.captures is pointers[4] and envelope.targets is pointers[5]
              and envelope.captures is pointers[6] and asdict(envelope) == envelope_value
              and asdict(budgets) == budget_value, "hsrp_state_version_envelope")
    for request in requests:
        validate_fhrp_request_graph(request)
    for request in brief_requests:
        preparation.validate_brief_request(request)
    custody.validate_retained_requests(brief_requests, retained)
    k.require(state.plan is plan, "hsrp_state_version_population")
    _state_population(state, source, brief_requests, identity[2], held, proofs)
    fresh = profile.compile_state_version_profile()
    k.require(identity == (first.catalogue_bytes, first.registration_bytes, first.registration_sha256)
              == (admitted.catalogue_bytes, admitted.registration_bytes, admitted.registration_sha256)
              == (fresh.catalogue_bytes, fresh.registration_bytes, fresh.registration_sha256)
              and envelope.registration_sha256 == identity[2], "hsrp_state_version_registration")
    k.require(type(outputs) is tuple and all(type(output) is Executed and type(output.receipt) is ParseReceipt
              and type(output.receipt.capture) is Capture for output in outputs), "hsrp_state_version_receipt")
    expected = {request.capture.id: request for request in requests}
    members = {member.id: member for member in envelope.captures}
    k.require(len(outputs) == len(expected) == len(members)
              and {output.receipt.capture.id for output in outputs} == set(expected), "hsrp_state_version_coverage")
    for output in outputs:
        receipt, capture = output.receipt, output.receipt.capture
        k.require(capture.id in expected and capture is expected[capture.id].capture
                  and type(receipt.owner) is str and type(receipt.context) is str
                  and type(receipt.registration_sha256) is str
                  and capture.source == members[capture.id].target.node.key
                  and capture.operation == members[capture.id].target.operation, "hsrp_state_version_receipt")
    custody.validate_receipts((profile.STATE_VERSION_DECLARATION,), requests, tuple(output.receipt for output in outputs))
    state_outputs = tuple(state.own(output) for output in outputs if output.receipt.capture.operation == brief.OP)
    for output in state_outputs:
        brief.validate_claims(output.receipt.capture, output.value)
    version_outputs = tuple(output for output in outputs if output.receipt.capture.operation == all_hsrp.OP)
    owner.canonical_rows(version_outputs)
    for request in brief_requests:
        preparation.validate_brief_request(request)
    return envelope, outputs, state, owner, state_outputs, version_outputs, budgets


class StateVersionExecution:
    """One real batch; current returned values are comparison data, never production authority."""

    def __init__(self, root: Path, budgets: Budgets) -> None:
        self.root, self.budgets = root, budgets
        self.attempted = False
        self.batch: _Batch | None = None

    def execute(self) -> StateVersionExecution:
        k.require(not self.attempted and self.batch is None, "hsrp_state_version_once")
        self.attempted = True
        root, budgets = self.root, self.budgets
        first = profile.compile_state_version_profile()
        identity = first.catalogue_bytes, first.registration_bytes, first.registration_sha256
        inputs = preparation.prepare_state_version_inputs(root, budgets)
        envelope, source = inputs.envelope, inputs.version
        domains, brief_requests, admitted = inputs.domains, inputs.requests, inputs.compiled
        declarations = preparation.validate_state_version_correspondence(envelope, budgets, source)
        k.require(identity == (admitted.catalogue_bytes, admitted.registration_bytes, admitted.registration_sha256)
                  and envelope.registration_sha256 == identity[2], "hsrp_state_version_registration")
        pointers = envelope, budgets, envelope.base, envelope.base.nodes, envelope.base.captures, envelope.targets, envelope.captures
        envelope_value, budget_value = asdict(envelope), asdict(budgets)
        requests = brief_requests + source.requests
        for request in requests:
            validate_fhrp_request_graph(request)
        for request in brief_requests:
            preparation.validate_brief_request(request)
        retained = custody.retain_requests(brief_requests)
        state = build.StateOwner(envelope, budgets, domains, brief_requests)
        plan, held = state.plan, dict(state.plan.indexed)
        proofs = {key: refs[1:3] for key, refs in declarations.items()}
        _state_population(state, source, brief_requests, identity[2], held, proofs)
        owner = version.VersionOwner.for_global_state_version(envelope, budgets, domains, source.requests)
        handlers = (Handler[brief.Result | all_hsrp.Result](binding=build.BINDING, parser=state),
                    Handler[brief.Result | all_hsrp.Result](binding=profile.BINDING, parser=owner))
        outputs = execute_parsers((profile.STATE_VERSION_DECLARATION,), handlers, requests)
        batch = _Batch(envelope=envelope, budgets=budgets, source=source, requests=requests,
            brief_requests=brief_requests, declarations=declarations, first=first, admitted=admitted, identity=identity,
            pointers=pointers, envelope_value=envelope_value, budget_value=budget_value, retained=retained,
            state=state, plan=plan, held=held, proofs=proofs, owner=owner, outputs=outputs)
        _canonical_outputs(batch)
        self.batch = batch
        return self

    def canonical_outputs(self) -> CanonicalOutputs:
        batch = self.batch
        k.require(type(batch) is _Batch, "hsrp_state_version_batch")
        if batch is None:
            raise ValueError("hsrp_state_version_batch")
        return _canonical_outputs(batch)


def execute_state_version_inputs(root: Path, budgets: Budgets) -> StateVersionExecution:
    return StateVersionExecution(root, budgets).execute()
