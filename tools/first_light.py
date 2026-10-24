"""P0a first light: show exactly what the inherited IOS-XE show-version parser extracts.

This is a diagnostic/demo entry point, not product surface: it builds one Capture from a raw
``show version`` capture, runs the inherited ``platform.system`` pack build, and prints the
resulting facts with their evidence references. The planned product entry point
(``python -m atlas_brain.runner analyse``) lands with the runner PR; until then this tool proves
the evidence -> fact -> summary path end to end and is safe to run on any file.

Usage:
    uv run python -m tools.first_light --demo
    uv run python -m tools.first_light --file path/to/show-version.txt --out out/
"""
import json
import sys
from hashlib import sha256
from pathlib import Path

from atlas_brain.evidence.capture import (
    Capture,
    CaptureMetadata,
    Channel,
    Scope,
    unrecorded_time,
)
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.platform.system.build import build_capture

SAMPLE = (
    b"sw-a uptime is 1 day, 2 hours, 3 minutes\n"
    b'System image file is "bootflash:packages.conf"\n'
    b"Last reload reason: PowerOn\n"
)
EXIT_OK = 0
EXIT_INPUT = 2


def build_capture_for(raw: bytes, *, source: str = "node:sw-a") -> Capture:
    """Bind raw CLI bytes to a capture record with an explicit integrity witness."""
    capture_id = k.CaptureId("first-light-capture")
    entity = k.EntityKey(source)
    witness = k.EvidenceRef(
        capture=capture_id,
        locator=k.WholeCapture(),
        role=k.EvidenceRole.SUBJECT,
        excerpt_sha256=sha256(raw).hexdigest(),
    )
    metadata = CaptureMetadata(
        channel=Channel.CLI,
        scope=Scope(
            node=entity,
            vrf=None,
            context=None,
            vdc=None,
            tenant=None,
            afi=None,
            instance=None,
            plane="exec",
        ),
        collected_utc=unrecorded_time(witness),
        error=None,
        integrity_evidence=(witness,),
        read_scope_evidence=(),
        envelope=None,
    )
    return Capture(
        id=capture_id,
        source=entity,
        operation="iosxe.show_version",
        rendered="show version",
        codec="utf-8",
        raw=raw,
        integrity=k.IntegrityState.COMPLETE if raw else k.IntegrityState.EMPTY,
        lines=text_lines(raw, "utf-8"),
        read_scope=k.ReadScope.UNKNOWN,
        view=k.ViewConsistency.SINGLE_RESPONSE,
        metadata=metadata,
    )


def _where(evidence: tuple[k.Evidence, ...]) -> str:
    if not evidence:
        return ""
    first = evidence[0]
    locator = first.locator
    if isinstance(locator, k.ByteSpan):
        where = f"span {locator.start}..{locator.end}"
    elif isinstance(locator, k.WholeCapture):
        where = "whole-capture"
    else:
        where = type(locator).__name__
    return f" capture={first.capture} {where}"


def _format_value(value: object) -> str:
    if isinstance(value, tuple):
        parts: list[str] = []
        for item in value:
            if isinstance(item, tuple) and len(item) == 2:
                count, unit = item
                name = getattr(unit, "value", unit)
                parts.append(f"{count} {name}" if count == 1 else f"{count} {name}s")
            else:
                parts.append(str(item))
        return ", ".join(parts)
    return repr(value)


def _fact_line(label: str, state: object) -> list[str]:
    if isinstance(state, k.Known):
        return [f"{label:<14}= {_format_value(state.value)}  [known; {len(state.evidence)} evidence ref]{_where(state.evidence)}"]
    if isinstance(state, k.Unknown):
        detail = "" if state.detail is None else f" detail={state.detail}"
        return [f"{label:<14}= unknown({state.reason}){detail}  [honest: not decidable from this evidence]"]
    if isinstance(state, k.Absent):
        return [f"{label:<14}= absent  [{len(state.evidence)} evidence ref]"]
    if isinstance(state, k.NotApplicable):
        return [f"{label:<14}= not_applicable({state.reason})"]
    return [f"{label:<14}= <unexpected state {type(state).__name__}>"]


def render(raw: bytes, *, source: str = "node:sw-a") -> tuple[str, dict[str, object]]:
    """Return (ascii summary, json-serialisable summary) for one capture; deterministic."""
    capture = build_capture_for(raw, source=source)
    fields = build_capture(capture)
    lines = [
        "Baby Thanos - first light (P0a): inherited IOS-XE show-version extraction",
        f"capture: {capture.id}  source: {capture.source}  operation: {capture.operation}  integrity: {capture.integrity}",
    ]
    states = (
        ("uptime", fields.uptime),
        ("image", fields.image),
        ("reload_reason", fields.reload_reason),
        ("boot_epoch", fields.boot_epoch),
    )
    for label, state in states:
        lines.extend(_fact_line(label, state))
    known = sum(1 for _, state in states if isinstance(state, k.Known))
    unknown = sum(1 for _, state in states if isinstance(state, k.Unknown))
    lines.append(f"parse          = {fields.parse.quality}")
    lines.append(
        f"verdict: {known} known, {unknown} unknown, {len(states) - known - unknown} absent/not_applicable"
        " - nothing observed was turned into a default."
    )
    facts: dict[str, object] = {}
    for label, state in states:
        if isinstance(state, k.Known):
            facts[label] = {"state": "known", "value": state.value, "evidence_refs": len(state.evidence)}
        elif isinstance(state, k.Unknown):
            facts[label] = {
                "state": "unknown",
                "reason": str(state.reason),
                "detail": state.detail,
                "evidence_refs": len(state.evidence),
            }
        elif isinstance(state, k.Absent):
            facts[label] = {"state": "absent", "evidence_refs": len(state.evidence)}
        else:
            facts[label] = {"state": "not_applicable", "reason": str(state.reason), "evidence_refs": len(state.evidence)}
    summary: dict[str, object] = {
        "capture": str(capture.id),
        "operation": capture.operation,
        "integrity": str(capture.integrity),
        "parse_quality": fields.parse.quality,
        "facts": facts,
    }
    return "\n".join(lines) + "\n", summary


def run(*, raw: bytes, out: Path | None) -> str:
    text, summary = render(raw)
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "first-light-summary.txt").write_text(text, encoding="utf-8")
        (out / "first-light-summary.json").write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    return text


def main(argv: list[str]) -> int:
    out: Path | None = None
    path: Path | None = None
    arguments = list(argv)
    while arguments:
        argument = arguments.pop(0)
        if argument == "--demo":
            continue
        if argument == "--file":
            if not arguments:
                print("first-light: --file needs a path", file=sys.stderr)
                return EXIT_INPUT
            path = Path(arguments.pop(0))
        elif argument == "--out":
            if not arguments:
                print("first-light: --out needs a directory", file=sys.stderr)
                return EXIT_INPUT
            out = Path(arguments.pop(0))
        elif argument in ("-h", "--help"):
            print(__doc__)
            return EXIT_OK
        else:
            print(f"first-light: unknown argument {argument!r}", file=sys.stderr)
            return EXIT_INPUT
    if path is None:
        raw = SAMPLE
    else:
        try:
            raw = path.read_bytes()
        except OSError as error:
            print(f"first-light: cannot read {path}: {error}", file=sys.stderr)
            return EXIT_INPUT
    sys.stdout.write(run(raw=raw, out=out))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
