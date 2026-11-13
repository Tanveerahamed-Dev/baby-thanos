"""Owning Store production from one current FHRP execution; no folder/source admission seal."""
from dataclasses import dataclass

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import state_version_execution as execution
from atlas_brain.packs.l3.fhrp import version_owner as version
from atlas_brain.runner.pack_runtime import Executed


@dataclass(frozen=True, slots=True, kw_only=True)
class FhrpStateVersionComponent:
    envelope: p4.Envelope
    executed: tuple[Executed[brief.Result | all_hsrp.Result], ...]
    state: build.Result
    version: version.VersionResult
    state_owner: build.StateOwner
    version_owner: version.VersionOwner


def _state_fact() -> None:
    k.require(type(build.REPORTED_STATE) is str and build.REPORTED_STATE == "l3.fhrp.reported_state",
              "hsrp_state_version_fact")


class StateVersionProduction:
    """Consume an actual execution once; reclose all candidates before the first Writer."""

    def __init__(self, source: execution.StateVersionExecution) -> None:
        k.require(type(source) is execution.StateVersionExecution, "hsrp_state_version_execution")
        self.source = source
        self.attempted = False
        self.result: FhrpStateVersionComponent | None = None

    def finish(self) -> FhrpStateVersionComponent:
        k.require(not self.attempted and self.result is None, "hsrp_state_version_once")
        self.attempted = True
        _state_fact()
        envelope, outputs, state, owner, state_outputs, version_outputs, budgets = self.source.canonical_outputs()
        k.require(owner.envelope is envelope and owner.budgets is budgets, "hsrp_state_version_invocation")
        k.require(owner.production_attempted is False and owner.production is None, "hsrp_state_version_once")
        _state_fact()
        state_result = state.finish(state_outputs)
        version_result = owner.finish(version_outputs)
        result = FhrpStateVersionComponent(envelope=envelope, executed=outputs, state=state_result,
            version=version_result, state_owner=state, version_owner=owner)
        self.result = result
        return result
