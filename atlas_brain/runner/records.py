"""Runner records and stable refusal codes; integers only, no floats."""
import json
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.kernel.states import digest, require
from atlas_brain.packs.platform.system.build import build_capture

EXIT_OK = 0
EXIT_REFUSED = 2
DEFAULT_WORKERS = 4


class RunnerRefused(ValueError):
    """The run is refused; the argument is a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def system_facts(capture: Capture) -> tuple[dict[str, object], tuple[str, ...]]:
    """Project the owning pack's facts, retaining every raw-byte evidence reference."""
    fields = build_capture(capture)
    facts: dict[str, object] = {}
    lines: list[str] = [f"{capture.id} parse: {fields.parse.quality}"]
    for name, fact in (("uptime", fields.uptime), ("image", fields.image),
                       ("reload_reason", fields.reload_reason), ("boot_epoch", fields.boot_epoch)):
        evidence: list[dict[str, str | int]] = []
        locations: list[str] = []
        for ref in fact.evidence:
            if not isinstance(ref, k.EvidenceRef) or ref.capture != capture.id:
                raise RunnerRefused("invalid_fact_evidence")
            record: dict[str, str | int] = {"capture": str(ref.capture), "sha256": ref.excerpt_sha256}
            if isinstance(ref.locator, k.ByteSpan):
                record.update(locator="bytes", start=ref.locator.start, end=ref.locator.end)
                location = f"span={ref.locator.start}..{ref.locator.end}"
            elif isinstance(ref.locator, k.WholeCapture):
                record["locator"] = "whole_capture"
                location = "whole_capture"
            else:
                raise RunnerRefused("invalid_fact_evidence")
            evidence.append(record)
            locations.append(f"capture={ref.capture} {location}")
        projected: dict[str, object] = {"evidence": evidence}
        if isinstance(fact, k.Known):
            value = (fact.value if isinstance(fact.value, str)
                     else [[count, str(unit)] for count, unit in fact.value])
            projected.update(state="known", basis=str(fact.basis), value=value)
            rendered = "known value=" + json.dumps(value, ensure_ascii=True)
        else:
            projected.update(state="unknown", reason=str(fact.reason))
            rendered = f"unknown({fact.reason})"
            if fact.detail is not None:
                projected["detail"] = fact.detail
                rendered += f" detail={fact.detail}"
        facts[name] = projected
        lines.append(f"{capture.id} {name}: {rendered} {'; '.join(locations)}")
    return facts, tuple(lines)


@dataclass(frozen=True, slots=True, kw_only=True)
class RunResult:
    """Public API result: the manifest facts a caller needs, never the run bytes."""

    out: Path
    evidence_files: int
    evidence_digest: str
    steps: int
    egress_denied: int

    def __post_init__(self) -> None:
        require(type(self.evidence_files) is int and self.evidence_files >= 0, "invalid_evidence_files")
        digest(self.evidence_digest)
        require(type(self.steps) is int and self.steps >= 0, "invalid_step_count")
        require(type(self.egress_denied) is int and self.egress_denied >= 0, "invalid_denied_count")
