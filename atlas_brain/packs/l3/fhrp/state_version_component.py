"""Fresh fixed FHRP-only STATE+VERSION production; prepared carriers are not accepted."""
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import state_version_execution as execution
from atlas_brain.packs.l3.fhrp.state_version_production import (
    FhrpStateVersionComponent,
    StateVersionProduction,
)


class StateVersionRun:
    """One attempted fresh invocation, including preparation and batch failures."""

    def __init__(self, root: Path, budgets: Budgets) -> None:
        self.root, self.budgets = root, budgets
        self.attempted = False
        self.result: FhrpStateVersionComponent | None = None

    def build(self) -> FhrpStateVersionComponent:
        k.require(not self.attempted and self.result is None, "hsrp_state_version_once")
        self.attempted = True
        source = execution.execute_state_version_inputs(self.root, self.budgets)
        result = StateVersionProduction(source).finish()
        self.result = result
        return result


def build_fhrp_state_version_component(root: Path, budgets: Budgets) -> FhrpStateVersionComponent:
    return StateVersionRun(root, budgets).build()
