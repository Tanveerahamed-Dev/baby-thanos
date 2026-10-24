"""Bind an extraction to owned capture provenance; no implicit clock conversion."""
from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource
from atlas_brain.packs.platform.system.parsers.show_version import (
    SystemFields,
    extract_fields,
)


def build_capture(capture: Capture) -> SystemFields:
    if type(capture) is not Capture:
        raise TypeError("capture_record_required")
    if capture.operation != "iosxe.show_version" or capture.rendered != "show version":
        raise ValueError("unsupported_system_operation")
    if capture.codec not in ("utf-8", "ascii"):
        raise ValueError("unsupported_system_codec")
    if capture.error is not None and capture.integrity is not k.IntegrityState.ERROR:
        raise ValueError("capture_error_integrity_mismatch")
    observed = extract_fields(capture.raw, capture.id, integrity=capture.integrity)
    if isinstance(observed.uptime, k.Unknown):
        boot = observed.uptime
    elif isinstance(capture.collected_utc, k.Unknown):
        boot = capture.collected_utc
    elif capture.collected_utc.bound is BoundSource.UNBOUNDED:
        boot = k.Unknown(reason=k.UnknownReason.AS_OF_MISSING, detail="unbounded_collector_time",
                         evidence=capture.integrity_evidence, candidates=(), next_evidence=())
    else:
        boot = k.Unknown(reason=k.UnknownReason.NOT_OBSERVABLE, detail="uptime_clock_bound_unqualified",
                         evidence=observed.uptime.evidence, candidates=(), next_evidence=())
    return SystemFields(uptime=observed.uptime, image=observed.image, reload_reason=observed.reload_reason,
                        boot_epoch=boot, parse=observed.parse)
