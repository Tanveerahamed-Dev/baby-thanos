"""Fixed ordinary-protocol FHRP peer preparation; no Store or source result."""
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner import p4_pipeline as pipeline
from atlas_brain.runner.pack_runtime import Handler


class PeerStateVersionPack[Peer](pipeline.Pack[brief.Result | all_hsrp.Result | Peer]):
    """Prepare both fixed operations once against the caller's original full envelope."""

    def __init__(self, budgets: Budgets) -> None:
        self.budgets = budgets
        self.attempted = False
        self.inputs: preparation.StateVersionInputs | None = None
        self.state: build.StateOwner | None = None
        self.owner: vo.PeerGlobalVersionOwner | None = None

    def declaration(self) -> PackDeclaration:
        return profile.STATE_VERSION_DECLARATION

    def prepare(self, envelope: p4.Envelope) -> pipeline.Prepared[brief.Result | all_hsrp.Result | Peer]:
        k.require(not self.attempted and self.inputs is None and self.state is None and self.owner is None,
                  "fhrp_peer_pack_once")
        self.attempted = True
        source = preparation.prepare_peer_state_version_inputs(envelope, self.budgets)
        state = build.StateOwner(envelope, self.budgets, source.domains, source.requests)
        owner = vo.PeerGlobalVersionOwner(envelope, self.budgets, source.domains, source.version.requests)
        handlers = (Handler[brief.Result | all_hsrp.Result | Peer](binding=build.BINDING, parser=state),
                    Handler[brief.Result | all_hsrp.Result | Peer](binding=profile.BINDING, parser=owner))
        batch = pipeline.Prepared[brief.Result | all_hsrp.Result | Peer](targets=source.targets, handlers=handlers,
            requests=source.requests + source.version.requests)
        self.inputs, self.state, self.owner = source, state, owner
        return batch
