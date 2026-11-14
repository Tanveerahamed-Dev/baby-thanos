"""Current full-peer ledger and owning FHRP candidates; comparison data is not production authority."""
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build, peer_profile
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import state_version_execution as population
from atlas_brain.packs.l3.fhrp import version_inputs as inputs
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner import pack_receipts as custody
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import Executed

type Value = stp.stp.Result | ec.parse_summary.Result | brief.Result | all_hsrp.Result
type CanonicalPeerOutputs = tuple[tuple[Executed[brief.Result], ...], tuple[Executed[all_hsrp.Result], ...]]


def canonical_peer_state_version_outputs(
    execution: pipe.Result[Value], state: build.StateOwner, owner: vo.PeerGlobalVersionOwner, budgets: Budgets,
) -> CanonicalPeerOutputs:
    """Reclose current actual captures/caches; readiness, origin and every Store remain outside."""
    k.require(type(execution) is pipe.Result and type(state) is build.StateOwner
              and type(owner) is vo.PeerGlobalVersionOwner, "fhrp_peer_outputs")
    envelope = execution.envelope
    compiled = preparation.validate_peer_state_version_context(envelope, budgets)
    identity = compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256
    k.require(owner.envelope is envelope and owner.budgets is budgets, "fhrp_peer_invocation")
    outputs = execution.executed
    k.require(type(outputs) is tuple and all(type(output) is Executed and type(output.receipt) is ParseReceipt
              and type(output.value) in (stp.stp.Result, ec.parse_summary.Result, brief.Result, all_hsrp.Result)
              for output in outputs), "fhrp_peer_outputs")
    for output in outputs:
        receipt = output.receipt
        k.require(all(type(value) is str for value in
            (receipt.owner, receipt.context, receipt.registration_sha256)), "fhrp_peer_receipt")
        inputs.validate_fhrp_request_graph(CaptureRequest(capture=receipt.capture, context=receipt.context))
    requests = state.plan.requests
    k.require(type(requests) is tuple and all(type(request) is CaptureRequest for request in requests),
              "fhrp_peer_population")
    for request in requests:
        preparation.validate_brief_request(request)
    members = {member.id: member for member in envelope.captures}
    k.require(len(outputs) == len(members)
              and {output.receipt.capture.id for output in outputs} == set(members), "fhrp_peer_coverage")
    for output in outputs:
        receipt, capture = output.receipt, output.receipt.capture
        member = members[capture.id]
        k.require(receipt.owner == member.target.owner and receipt.context == envelope.context
                  and receipt.registration_sha256 == identity[2] and receipt.parse is output.value.parse
                  and capture.source == member.target.node.key and capture.operation == member.target.operation
                  and capture.raw is member.raw and capture.bytes_sha256 == member.sha256, "fhrp_peer_receipt")
    actual_requests = tuple(CaptureRequest(capture=output.receipt.capture, context=output.receipt.context) for output in outputs)
    custody.validate_receipts(peer_profile.DECLARATIONS, actual_requests, tuple(output.receipt for output in outputs))
    version_outputs = tuple(output for output in outputs if output.receipt.capture.operation == all_hsrp.OP)
    owner.canonical_rows(version_outputs)
    retained = owner.inputs
    if retained is None:
        raise ValueError("fhrp_peer_inputs")
    source = retained.source
    k.require(type(state.plan.indexed) is dict and all(type(key) is tuple and len(key) == 2
              and all(type(value) is str for value in key) for key in state.plan.indexed)
              and all(type(target) is build.Target for target in state.plan.indexed.values())
              and type(state.plan.expected) is dict and all(type(key) is str for key in state.plan.expected),
              "fhrp_peer_population")
    held = dict(state.plan.indexed)
    declarations = preparation.validate_peer_state_version_correspondence(envelope, budgets, source)
    proofs = {key: refs[1:3] for key, refs in declarations.items()}
    population.validate_state_version_population(state, source, requests, identity[2], held, proofs)
    state_outputs = tuple(state.own(output) for output in outputs if output.receipt.capture.operation == brief.OP)
    for output in state_outputs:
        brief.validate_claims(output.receipt.capture, output.value)
        claims = build.reported_state_proofs(output)
        target = state.plan.indexed[output.receipt.context or "", output.receipt.capture.source]
        k.require(output.value.reason is not None or all(
            (row.interface.raw, row.group.raw) in target.groups for row, _ in claims), "hsrp_undeclared_subject")
    current = preparation.validate_peer_state_version_context(envelope, budgets)
    k.require(identity == (compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256)
              == (current.catalogue_bytes, current.registration_bytes, current.registration_sha256)
              and owner.envelope is envelope and owner.budgets is budgets, "fhrp_peer_registration")
    return state_outputs, tuple(owner.own(output) for output in version_outputs)
