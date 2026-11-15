"""One fixed mixed parser batch; no Store production, global proofs, report or health claim."""
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Scope
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import CompiledPackSet, PackDeclaration
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import (
    build,
    global_parse,
    mixed_profile,
    mixed_vrrp_inputs,
    state_version_execution,
    version_profile,
    vrrp_profile,
)
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import parse_vrrp as vrrp
from atlas_brain.packs.l3.fhrp.version_inputs import validate_fhrp_request_graph
from atlas_brain.packs.l3.fhrp.version_owner import MixedGlobalVersionOwner
from atlas_brain.packs.l3.fhrp.vrrp_owner import MixedVRRPOwner, VRRPOwner
from atlas_brain.runner import p4_pipeline as pipeline
from atlas_brain.runner import pack_receipts as receipts
from atlas_brain.runner.pack_runtime import Executed, Handler

type FhrpValue = brief.Result | all_hsrp.Result | vrrp.Result
type Value = stp.stp.Result | ec.parse_summary.Result | FhrpValue


class MixedFhrpPack[Peer](pipeline.Pack[FhrpValue | Peer]):
    def __init__(self, budgets: Budgets) -> None:
        self.budgets, self.attempted = budgets, False
        self.hsrp: global_parse.StateVersionInputs | None = None
        self.vrrp_inputs: mixed_vrrp_inputs.MixedVRRPInputs | None = None
        self.state: build.StateOwner | None = None
        self.version: MixedGlobalVersionOwner | None = None
        self.vrrp_owner: MixedVRRPOwner | None = None

    def declaration(self) -> PackDeclaration:
        return mixed_profile.FHRP_DECLARATION

    def prepare(self, envelope: p4.Envelope) -> pipeline.Prepared[FhrpValue | Peer]:
        k.require(not self.attempted and self.hsrp is None and self.vrrp_inputs is None
                  and self.state is None and self.version is None and self.vrrp_owner is None, "fhrp_mixed_pack_once")
        self.attempted = True
        hsrp = global_parse.prepare_mixed_hsrp_inputs(envelope, self.budgets)
        local = mixed_vrrp_inputs.prepare_mixed_vrrp_inputs(envelope, self.budgets)
        state = build.StateOwner(envelope, self.budgets, hsrp.domains, hsrp.requests)
        version = MixedGlobalVersionOwner(envelope, self.budgets, hsrp.domains, hsrp.version.requests)
        owner = MixedVRRPOwner(envelope, self.budgets, local.domains, local.requests)
        self.hsrp, self.vrrp_inputs = hsrp, local
        self.state, self.version, self.vrrp_owner = state, version, owner
        owner.attempted = owner.running = True
        return pipeline.Prepared[FhrpValue | Peer](targets=hsrp.targets + local.targets,
            handlers=(Handler[FhrpValue | Peer](binding=build.BINDING, parser=state),
                Handler[FhrpValue | Peer](binding=version_profile.BINDING, parser=version),
                Handler[FhrpValue | Peer](binding=vrrp_profile.BINDING, parser=owner)),
            requests=hsrp.requests + hsrp.version.requests + local.requests)


@dataclass(frozen=True, slots=True, kw_only=True)
class MixedExecution:
    execution: pipeline.Result[Value]
    tree: stp.RootGuardPack[ec.parse_summary.Result | FhrpValue]
    channel: SummaryPack[stp.stp.Result | FhrpValue]
    fhrp: MixedFhrpPack[stp.stp.Result | ec.parse_summary.Result]
    budgets: Budgets
    limits: tuple[int, ...]
    compiled: CompiledPackSet
    vrrp_executed: tuple[Executed[vrrp.Result], ...]


def _limits(budgets: Budgets) -> tuple[int, ...]:
    k.require(type(budgets) is Budgets, "fhrp_mixed_execution_budget")
    values = (budgets.bundle_bytes, budgets.artifact_bytes, budgets.artifacts, budgets.nesting_depth,
        budgets.numeric_digits, budgets.compression_ratio, budgets.archive_index_bytes)
    k.require(all(type(value) is int and value > 0 for value in values), "fhrp_mixed_execution_budget")
    return values


def _validate_parts(
    execution: pipeline.Result[Value], tree: stp.RootGuardPack[ec.parse_summary.Result | FhrpValue],
    channel: SummaryPack[stp.stp.Result | FhrpValue],
    fhrp: MixedFhrpPack[stp.stp.Result | ec.parse_summary.Result],
    budgets: Budgets, limits: tuple[int, ...], compiled: CompiledPackSet,
) -> tuple[Executed[vrrp.Result], ...]:
    k.require(type(tree) is stp.RootGuardPack and type(channel) is SummaryPack
              and type(fhrp) is MixedFhrpPack, "fhrp_mixed_execution_owner")
    k.require(tree.producer.declaration is stp.DECLARATION and tree.producer.step is stp.STEP
              and tree.producer.binding is stp.BINDING and tree.producer.roots is False, "fhrp_mixed_execution_current")
    k.require(type(execution) is pipeline.Result and type(execution.executed) is tuple
              and all(type(output) is Executed and type(output.receipt) is receipts.ParseReceipt for output in execution.executed), "fhrp_mixed_execution_output")
    k.require(type(limits) is tuple and len(limits) == 7 and all(type(value) is int and value > 0 for value in limits)
              and type(compiled) is CompiledPackSet and limits == _limits(budgets)
              and type(compiled.catalogue_bytes) is bytes and type(compiled.registration_bytes) is bytes
              and type(compiled.registration_sha256) is str
              and compiled == global_parse.validate_mixed_context(execution.envelope, budgets), "fhrp_mixed_execution_current")
    owner, version, state = fhrp.vrrp_owner, fhrp.version, fhrp.state
    if (type(owner) is not MixedVRRPOwner or type(version) is not MixedGlobalVersionOwner
            or type(state) is not build.StateOwner):
        raise ValueError("fhrp_mixed_execution_owner")
    plan, channel_run, hsrp, local = tree.plan, channel.run, fhrp.hsrp, fhrp.vrrp_inputs
    k.require(plan is not None and channel_run is not None and hsrp is not None and local is not None, "fhrp_mixed_execution_owner")
    if plan is None or channel_run is None or hsrp is None or local is None:
        raise ValueError("fhrp_mixed_execution_owner")
    k.require(execution.envelope is tree.envelope is channel_run.envelope is hsrp.envelope is local.envelope
              is owner.envelope is version.envelope and all(pack.budgets is budgets for pack in (tree, channel, fhrp)), "fhrp_mixed_execution_current")
    k.require(all(type(value) is str and value == compiled.registration_sha256
        for value in (tree.registration, channel_run.registration, channel.owner.registration)), "fhrp_mixed_execution_current")
    requests = plan.requests + channel.owner.plan.requests + hsrp.requests + hsrp.version.requests + local.requests
    for request in requests:
        validate_fhrp_request_graph(request)
        k.require(request.capture.scope == Scope(node=request.capture.source, plane="exec", vrf=None, context=None,
            instance=None, vdc=None, tenant=None, afi=None), "fhrp_mixed_execution_scope")
    caches = ((tree.produced, plan.requests), (channel.owner.produced, channel.owner.plan.requests), (state.produced, hsrp.requests))
    k.require(all(type(cache) is dict and all(type(key) is str for key in cache)
                  and set(cache) == {request.capture.id for request in requests} for cache, requests in caches),
              "fhrp_mixed_execution_cache")
    for output in execution.executed:
        validate_fhrp_request_graph(receipts.CaptureRequest(capture=output.receipt.capture, context=output.receipt.context))
        k.require(all(type(value) is str for value in (output.receipt.owner, output.receipt.registration_sha256)), "fhrp_mixed_execution_output")
    expected = {request.capture.id: request for request in requests}
    members = {member.id: member for member in execution.envelope.captures}
    receipts.validate_receipts(mixed_profile.DECLARATIONS, requests, tuple(output.receipt for output in execution.executed))
    k.require(len(expected) == len(members) == len(execution.executed) and set(expected) == set(members), "fhrp_mixed_execution_output")
    outputs: list[Executed[vrrp.Result]] = []
    classes = {stp.stp.OP: stp.stp.Result, ec.parse_summary.OP: ec.parse_summary.Result,
        brief.OP: brief.Result, all_hsrp.OP: all_hsrp.Result, vrrp.OP: vrrp.Result}
    for output in execution.executed:
        capture = output.receipt.capture
        member = members[capture.id]
        k.require(capture is expected[capture.id].capture and capture.raw is member.raw
                  and capture.source == member.target.node.key and capture.operation == member.target.operation
                  and type(output.value) is classes[member.target.operation] and output.receipt.parse is output.value.parse, "fhrp_mixed_execution_output")
        if capture.operation == stp.stp.OP:
            k.require(capture.id in tree.produced and output.value is tree.produced[capture.id], "fhrp_mixed_execution_cache")
        elif capture.operation == ec.parse_summary.OP:
            channel.owner.own(output)
        elif capture.operation == brief.OP:
            state.own(output)
        if output.receipt.capture.operation == vrrp.OP:
            if type(output.value) is not vrrp.Result:
                raise TypeError("fhrp_mixed_execution_output")
            outputs.append(Executed(receipt=output.receipt, value=output.value))
    declarations = global_parse.validate_mixed_hsrp_correspondence(execution.envelope, budgets, hsrp.version)
    k.require(declarations == hsrp.declarations
              and mixed_vrrp_inputs.validate_mixed_vrrp_correspondence(execution.envelope, budgets, local.vrrp)
              == local.declarations, "fhrp_mixed_execution_current")
    k.require(type(hsrp.domains) is tuple and len(hsrp.domains) == len(hsrp.version.targets)
              and all(type(actual) is build.Target and actual.node is wanted.node and actual == wanted
                  for actual, wanted in zip(hsrp.domains, hsrp.version.targets, strict=True)), "fhrp_mixed_execution_current")
    for target in hsrp.domains:
        build.Target(context=target.context, node=target.node, groups=target.groups)
    state_version_execution.validate_state_version_population(state, hsrp.version, hsrp.requests,
        compiled.registration_sha256, dict(state.plan.indexed),
        {key: refs[1:3] for key, refs in declarations.items()})
    return tuple(outputs)


def _canonical(source: pipeline.Result[Value],
    fhrp: MixedFhrpPack[stp.stp.Result | ec.parse_summary.Result],
    batch: tuple[Executed[vrrp.Result], ...],
) -> None:
    owner, version = fhrp.vrrp_owner, fhrp.version
    if owner is None or version is None:
        raise ValueError("fhrp_mixed_execution_owner")
    k.require(owner.executed is batch, "fhrp_mixed_execution_output")
    VRRPOwner.canonical_rows(owner)
    MixedGlobalVersionOwner.canonical_rows(version,
        tuple(output for output in source.executed if output.receipt.capture.operation == all_hsrp.OP))


def validate_mixed_execution(source: MixedExecution, budgets: Budgets) -> None:
    """Compare current source/cache data; no parsing, dispatch, Store or origin authority."""
    k.require(type(source) is MixedExecution and source.budgets is budgets, "fhrp_mixed_execution_current")
    checked = _validate_parts(source.execution, source.tree, source.channel, source.fhrp,
        budgets, source.limits, source.compiled)
    plan, channel, execution = source.tree.plan, source.channel, source.execution
    if plan is None:
        raise ValueError("fhrp_mixed_execution_owner")
    tree_targets = stp.declared_root_guard_targets(execution.envelope, budgets)
    tree_domains = {(row.target.context, row.target.node.key, stp.stp.command(row.target.port)): row.target for row in tree_targets}
    fresh = SummaryPack[Value](budgets)
    fresh.prepare(execution.envelope)
    for actual, wanted, size in ((plan.indexed, tree_domains, 3), (channel.owner.plan.indexed, fresh.owner.plan.indexed, 2)):
        k.require(type(actual) is dict and all(type(key) is tuple and len(key) == size
                  and all(type(value) is str for value in key) for key in actual) and set(actual) == set(wanted), "fhrp_mixed_execution_current")
    k.require(all(type(plan.indexed[key]) is stp.Target and plan.indexed[key].node is target.node and plan.indexed[key] == target
                  for key, target in tree_domains.items()) and all(type(channel.owner.plan.indexed[key]) is ec.Target
                  and channel.owner.plan.indexed[key].node is target.node and channel.owner.plan.indexed[key] == target
                  for key, target in fresh.owner.plan.indexed.items()), "fhrp_mixed_execution_current")
    for tree_target in plan.indexed.values():
        stp.Target(context=tree_target.context, node=tree_target.node, port=tree_target.port, vlans=tree_target.vlans)
    for channel_target in channel.owner.plan.indexed.values():
        ec.Target(context=channel_target.context, node=channel_target.node, groups=channel_target.groups, ports=channel_target.ports)
    for proofs in (plan.proofs, channel.owner.plan.proofs):
        k.require(type(proofs) is dict and all(type(key) is tuple and all(type(value) is str for value in key) and type(refs) is tuple
                  and all(type(ref) is k.RegistryRef and all(type(value) is str for value in (ref.table, ref.row_id, ref.table_digest, ref.citation))
                      for ref in refs) for key, refs in (proofs or {}).items()), "fhrp_mixed_execution_current")
    k.require(plan.proofs == {(row.target.context, row.target.node.key, stp.stp.command(row.target.port)): row.evidence[1:]
                  for row in tree_targets} and channel.owner.plan.proofs == fresh.owner.plan.proofs, "fhrp_mixed_execution_current")
    batch = source.vrrp_executed
    k.require(type(batch) is tuple and len(batch) == len(checked)
              and all(type(actual) is Executed and actual.receipt is wanted.receipt and actual.value is wanted.value
                  for actual, wanted in zip(batch, checked, strict=True)), "fhrp_mixed_execution_output")
    _canonical(source.execution, source.fhrp, batch)


def execute_mixed_inputs(root: Path, budgets: Budgets) -> MixedExecution:
    k.require(isinstance(cast(object, root), Path), "fhrp_mixed_execution_input")
    limits, compiled = _limits(budgets), mixed_profile.compile_mixed_profile()
    tree = stp.RootGuardPack[ec.parse_summary.Result | FhrpValue](budgets)
    channel = SummaryPack[stp.stp.Result | FhrpValue](budgets)
    fhrp = MixedFhrpPack[stp.stp.Result | ec.parse_summary.Result](budgets)
    packs: tuple[pipeline.Pack[Value], ...] = (tree, channel, fhrp)
    try:
        execution = pipeline.execute_p4_folder(root, budgets, packs=packs)
    finally:
        if fhrp.vrrp_owner is not None:
            fhrp.vrrp_owner.running = False
    batch = _validate_parts(execution, tree, channel, fhrp, budgets, limits, compiled)
    owner = fhrp.vrrp_owner
    if owner is None:
        raise ValueError("fhrp_mixed_execution_owner")
    owner.executed = batch
    _canonical(execution, fhrp, batch)
    return MixedExecution(execution=execution, tree=tree, channel=channel, fhrp=fhrp,
        budgets=budgets, limits=limits, compiled=compiled, vrrp_executed=batch)
