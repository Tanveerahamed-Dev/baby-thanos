"""Fresh local VERSION production through one actual owning parser invocation."""
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp.version_owner import VersionResult as Result
from atlas_brain.packs.l3.fhrp.version_owner import execute_local_version_inputs
from atlas_brain.runner.pack_receipts import CaptureRequest


def build_reported_version(
    targets: tuple[build.Target, ...], requests: tuple[CaptureRequest, ...],
) -> Result:
    execution = execute_local_version_inputs(targets, requests)
    return execution.owner.finish(execution.executed)
