"""Fresh fixed peer execution and Store production; no source, proof or checker authority."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp_build
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import peer_canonical, peer_profile
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp.peer_pack import PeerStateVersionPack
from atlas_brain.runner import p4_pipeline as pipeline

type Value = stp.stp.Result | ec.parse_summary.Result | brief.Result | all_hsrp.Result


@dataclass(frozen=True, slots=True, kw_only=True)
class PeerStateVersionExecution:
    execution: pipeline.Result[Value]
    tree: stp.RootGuardPack[ec.parse_summary.Result | brief.Result | all_hsrp.Result]
    channel: SummaryPack[stp.stp.Result | brief.Result | all_hsrp.Result]
    fhrp: PeerStateVersionPack[stp.stp.Result | ec.parse_summary.Result]


def _inputs(root: object, budgets: object) -> None:
    if not isinstance(root, Path) or type(budgets) is not Budgets:
        raise ValueError("fhrp_peer_input")
    k.require(all(type(value) is int and value > 0 for value in
        (budgets.bundle_bytes, budgets.artifact_bytes, budgets.artifacts, budgets.nesting_depth,
         budgets.numeric_digits, budgets.compression_ratio, budgets.archive_index_bytes)), "fhrp_peer_budget")


def execute_peer_state_version_inputs(root: Path, budgets: Budgets) -> PeerStateVersionExecution:
    """Own fresh admission and one full batch; callers still own every Store finish and proof."""
    _inputs(root, budgets)
    first = peer_profile.compile_peer_state_version_profile()
    identity = first.catalogue_bytes, first.registration_bytes, first.registration_sha256
    tree = stp.RootGuardPack[ec.parse_summary.Result | brief.Result | all_hsrp.Result](budgets)
    channel = SummaryPack[stp.stp.Result | brief.Result | all_hsrp.Result](budgets)
    fhrp = PeerStateVersionPack[stp.stp.Result | ec.parse_summary.Result](budgets)
    packs: tuple[pipeline.Pack[Value], ...] = (tree, channel, fhrp)
    execution = pipeline.execute_p4_folder(root, budgets, packs=packs)
    current = peer_profile.compile_peer_state_version_profile()
    k.require(identity == (first.catalogue_bytes, first.registration_bytes, first.registration_sha256)
              == (current.catalogue_bytes, current.registration_bytes, current.registration_sha256)
              and execution.envelope.registration_sha256 == identity[2], "fhrp_peer_registration")
    return PeerStateVersionExecution(execution=execution, tree=tree, channel=channel, fhrp=fhrp)


@dataclass(frozen=True, slots=True, kw_only=True)
class PeerStateVersionComponent:
    execution: pipeline.Result[Value]
    tree: stp.Result
    channel: ec.Result
    state: fhrp_build.Result
    version: vo.VersionResult
    tree_owner: stp.RootGuardPack[ec.parse_summary.Result | brief.Result | all_hsrp.Result]
    channel_owner: ec.ProtocolOwner
    state_owner: fhrp_build.StateOwner
    version_owner: vo.PeerGlobalVersionOwner


def _budget_values(budgets: Budgets) -> tuple[int, ...]:
    return (budgets.bundle_bytes, budgets.artifact_bytes, budgets.artifacts, budgets.nesting_depth,
            budgets.numeric_digits, budgets.compression_ratio, budgets.archive_index_bytes)


def _component_inputs(
    root: Path, budgets: Budgets, expected: tuple[int, ...], prepared: PeerStateVersionExecution,
    owner: vo.PeerGlobalVersionOwner,
) -> None:
    _inputs(root, budgets)
    k.require(_budget_values(budgets) == expected and owner.budgets is budgets
              and all(pack.budgets is budgets for pack in (prepared.tree, prepared.channel, prepared.fhrp)),
              "fhrp_peer_component_budget")


def _component_pair(
    execution: pipeline.Result[Value], state: fhrp_build.StateOwner, owner: vo.PeerGlobalVersionOwner, budgets: Budgets,
) -> peer_canonical.CanonicalPeerOutputs:
    outputs = peer_canonical.canonical_peer_state_version_outputs(execution, state, owner, budgets)
    k.require(state.finished is False and owner.production_attempted is False and owner.production is None,
              "fhrp_peer_component_once")
    k.require(type(fhrp_build.REPORTED_STATE) is str and fhrp_build.REPORTED_STATE == "l3.fhrp.reported_state",
              "fhrp_peer_component_fact")
    return outputs


def build_peer_state_version_component(root: Path, budgets: Budgets) -> PeerStateVersionComponent:
    """Own one fresh four-Store run; late failure may leave earlier Stores without a component."""
    _inputs(root, budgets)
    expected = _budget_values(budgets)
    prepared = execute_peer_state_version_inputs(root, budgets)
    k.require(type(prepared) is PeerStateVersionExecution and type(prepared.tree) is stp.RootGuardPack
              and type(prepared.channel) is SummaryPack and type(prepared.fhrp) is PeerStateVersionPack,
              "fhrp_peer_component")
    execution, state, owner = prepared.execution, prepared.fhrp.state, prepared.fhrp.owner
    if state is None or owner is None:
        raise ValueError("fhrp_peer_component")
    k.require(type(state) is fhrp_build.StateOwner and type(owner) is vo.PeerGlobalVersionOwner,
              "fhrp_peer_component")
    tree_owner = prepared.tree
    _component_inputs(root, budgets, expected, prepared, owner)
    _component_pair(execution, state, owner, budgets)
    _component_inputs(root, budgets, expected, prepared, owner)
    tree = tree_owner.finish(execution)
    _component_inputs(root, budgets, expected, prepared, owner)
    channel_owner = prepared.channel.owner
    channel = prepared.channel.finish(execution)
    _component_inputs(root, budgets, expected, prepared, owner)
    state_outputs, version_outputs = _component_pair(execution, state, owner, budgets)
    _component_inputs(root, budgets, expected, prepared, owner)
    state_result = state.finish(state_outputs)
    _component_inputs(root, budgets, expected, prepared, owner)
    version_result = owner.finish(version_outputs)
    _component_inputs(root, budgets, expected, prepared, owner)
    return PeerStateVersionComponent(execution=execution, tree=tree, channel=channel,
        state=state_result, version=version_result, tree_owner=tree_owner, channel_owner=channel_owner,
        state_owner=state, version_owner=owner)
