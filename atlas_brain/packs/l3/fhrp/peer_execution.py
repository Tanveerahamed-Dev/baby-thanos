"""Fresh fixed full-peer parser execution; returned data supplies no Store or source seal."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import peer_profile
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
