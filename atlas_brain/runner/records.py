"""Runner records and stable refusal codes; integers only, no floats."""
import json
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.kernel.states import digest, require
from atlas_brain.packs.l1.interface import build as interface_pack
from atlas_brain.packs.platform.system.build import build_capture

EXIT_OK = 0
EXIT_REFUSED = 2
DEFAULT_WORKERS = 4


class RunnerRefused(ValueError):
    """The run is refused; the argument is a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def next_evidence(needs: tuple[k.EvidenceNeed, ...]) -> list[dict[str, object]]:
    return [{"node": str(need.node), "operation": need.operation, "resolves": need.resolves,
             "reruns": need.reruns} for need in needs]


def fact_record[T](capture: Capture | None, fact: k.Known[T] | k.Unknown) -> tuple[dict[str, object], str]:
    evidence: list[dict[str, str | int]] = []
    locations: list[str] = []
    for ref in fact.evidence:
        if not isinstance(ref, k.EvidenceRef) or capture is None or ref.capture != capture.id:
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
        projected.update(state="known", basis=str(fact.basis), value=fact.value)
        rendered = "known value=" + json.dumps(fact.value, ensure_ascii=True)
    else:
        projected.update(state="unknown", reason=str(fact.reason))
        rendered = f"unknown({fact.reason})"
        if fact.detail is not None:
            projected["detail"] = fact.detail
            rendered += f" detail={fact.detail}"
        if fact.next_evidence:
            projected["next_evidence"] = next_evidence(fact.next_evidence)
            rendered += " next_evidence=" + ",".join(need.operation for need in fact.next_evidence)
    return projected, rendered + " " + "; ".join(locations)


def system_facts(capture: Capture) -> tuple[dict[str, object], tuple[str, ...]]:
    fields = build_capture(capture)
    facts: dict[str, object] = {}
    lines = [f"{capture.id} parse: {fields.parse.quality}"]
    for name, fact in (("uptime", fields.uptime), ("image", fields.image),
                       ("reload_reason", fields.reload_reason), ("boot_epoch", fields.boot_epoch)):
        facts[name], description = fact_record(capture, fact)
        lines.append(f"{capture.id} {name}: {description}")
    return facts, tuple(lines)


def capture_facts(capture: Capture) -> tuple[dict[str, object], tuple[str, ...]]:
    if capture.operation == "iosxe.show_version":
        return system_facts(capture)
    result = interface_pack.build_capture(capture)
    coverage, description = fact_record(capture, result.coverage)
    lines = [f"{capture.id} l1.interface parse: {result.parse.quality} observed={result.observed}",
             f"{capture.id} coverage: {description}"]
    interfaces: list[dict[str, object]] = []
    for item in result.interfaces:
        row: dict[str, object] = {}
        for name, fact in (("name", item.name), ("admin", item.admin), ("oper", item.oper)):
            row[name], description = fact_record(capture, fact)
            lines.append(f"{capture.id} {item.name.value} {name}: {description}")
        check: dict[str, object] = {"id": interface_pack.CHECK, "state": item.verdict,
                                   "next_evidence": next_evidence(item.next_evidence)}
        if item.reason is not None:
            check["reason"] = str(item.reason)
        row["check"] = check
        interfaces.append(row)
        admin = item.admin.value if isinstance(item.admin, k.Known) else "unknown"
        oper = item.oper.value if isinstance(item.oper, k.Known) else "unknown"
        request = " next_evidence=" + ",".join(need.operation for need in item.next_evidence) if item.next_evidence else ""
        lines.append(f"{capture.id} {interface_pack.CHECK}: {item.name.value} admin {admin} / oper {oper}: {item.verdict}{request}")
    return {"pack": "l1.interface", "operation": capture.rendered, "parse": result.parse.quality,
            "denominator": {"scope": "observed_in_capture", "count": result.observed},
            "coverage": coverage, "interfaces": interfaces}, tuple(lines)


def missing_interfaces() -> tuple[dict[str, object], str]:
    return fact_record(None, interface_pack.missing_evidence())


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
