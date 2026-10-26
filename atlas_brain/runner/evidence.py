"""Bounded raw CLI-folder admission; file identity never supplies device facts."""
import re
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from atlas_brain.evidence.admission import (
    AdmissionRefused,
    BudgetExceeded,
    Budgets,
    folder_members,
)
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.p3_admission import admit_members as admit_p3
from atlas_brain.evidence.p3_records import P3Group
from atlas_brain.evidence.synthetic import SyntheticGroup, admit_members
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k

from .records import RunnerRefused


def require_evidence(root: Path) -> None:
    """Distinguish missing, unreadable and linked evidence roots without host paths."""
    try:
        info = root.lstat()
        if root.is_symlink() or root.is_junction():
            raise RunnerRefused("evidence_linked_root")
        if not stat.S_ISDIR(info.st_mode):
            raise RunnerRefused("evidence_dir_missing")
    except (FileNotFoundError, NotADirectoryError) as error:
        raise RunnerRefused("evidence_dir_missing") from error
    except OSError as error:
        raise RunnerRefused("evidence_unreadable") from error


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceInput:
    captures: tuple[Capture, ...]
    group: SyntheticGroup | None
    p3: P3Group | None = None


def analyse_evidence(root: Path, *, budgets: Budgets | None = None) -> tuple[Capture, ...]:
    """Preserve the raw-capture API; grouped input requires its declaration context."""
    admitted = analyse_input(root, budgets=budgets)
    if admitted.group is not None or admitted.p3 is not None:
        raise RunnerRefused("evidence_group_context_required")
    return admitted.captures


def analyse_input(root: Path, *, budgets: Budgets | None = None) -> EvidenceInput:
    """Admit the whole folder before returning captures; never silently skip a member."""
    require_evidence(root)
    limits = budgets if budgets is not None else Budgets(
        bundle_bytes=16 * 1024 * 1024, artifact_bytes=4 * 1024 * 1024, artifacts=128,
    )
    try:
        members = folder_members(root, limits)
    except AdmissionRefused as error:
        raise RunnerRefused("evidence_" + str(error)) from error
    except BudgetExceeded as error:
        raise RunnerRefused("evidence_budget_exceeded") from error
    except OSError as error:
        raise RunnerRefused("evidence_unreadable") from error
    if not members:
        raise RunnerRefused("evidence_empty")
    if sum(len(raw) for raw in members.values()) > limits.bundle_bytes:
        raise RunnerRefused("evidence_budget_exceeded")
    if "p3.json" in members:
        try:
            p3 = admit_p3(members)
        except AdmissionRefused as error:
            raise RunnerRefused("evidence_" + str(error)) from error
        except BudgetExceeded as error:
            raise RunnerRefused("evidence_budget_exceeded") from error
        p3_captures = p3.base.captures + tuple(capture for sample in p3.samples for capture in sample.captures)
        return EvidenceInput(captures=tuple(sorted(p3_captures, key=lambda capture: str(capture.id))), group=None, p3=p3)
    if "p2.json" in members:
        try:
            group = admit_members(members)
        except AdmissionRefused as error:
            raise RunnerRefused("evidence_" + str(error)) from error
        except BudgetExceeded as error:
            raise RunnerRefused("evidence_budget_exceeded") from error
        return EvidenceInput(captures=group.captures, group=group)
    captures: list[Capture] = []
    for name, raw in sorted(members.items()):
        try:
            name_bytes = name.encode("utf-8")
        except UnicodeError as error:
            raise RunnerRefused("evidence_unsafe_member_name") from error
        if not raw.strip():
            raise RunnerRefused("evidence_capture_empty")
        try:
            text = raw.decode("utf-8")
        except UnicodeError as error:
            raise RunnerRefused("evidence_invalid_encoding") from error
        kind = _interface_kind(text)
        if kind is None:
            _require_system_text(text)
        command, integrity = kind if kind is not None else ("show version", k.IntegrityState.COMPLETE)
        operations = {"show version": "iosxe.show_version", "show interfaces": "iosxe.show_interfaces",
                      "show ip interface brief": "iosxe.show_ip_interface_brief"}
        identity = sha256(name_bytes + b"\0" + raw).hexdigest()
        captures.append(Capture(
            id=k.CaptureId("cap:" + identity),
            source=k.EntityKey("node:file:" + sha256(name_bytes).hexdigest()),
            operation=operations[command], rendered=command, codec="utf-8", raw=raw,
            # COMPLETE describes the supplied file, not a verified collection session.
            # Capture's legacy metadata bridge binds its whole-byte SHA and missing time.
            integrity=integrity, lines=text_lines(raw, "utf-8"),
            read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN,
        ))
    return EvidenceInput(captures=tuple(captures), group=None)


def _require_system_text(text: str) -> None:
    lines = [line.removesuffix("\r") for line in text.split("\n") if line.strip()]
    if any(line.lstrip().startswith("%") or "Command authorization failed" in line for line in lines):
        raise RunnerRefused("evidence_capture_error")
    if any(marker in text.lower() for marker in ("--more--", "<--- more --->", "[truncated]", "--(more)--")):
        raise RunnerRefused("evidence_capture_incomplete")
    if ("\r" in text.replace("\r\n", "") or any(
            ord(char) < 32 and char not in "\t\r\n" or char in "\x7f\u0085\u2028\u2029" for char in text)):
        raise RunnerRefused("evidence_invalid_text")
    if not lines:
        raise RunnerRefused("evidence_unsupported_capture")
    # Inspect one response envelope; the Capture always retains the original bytes.
    prompt = r"[A-Za-z0-9_.:-]+[>#]"
    opening = re.fullmatch("(" + prompt + r") ?show version", lines[0], re.ASCII)
    if opening:
        lines = lines[1:]
    if lines and re.fullmatch(prompt, lines[-1], re.ASCII):
        if opening and lines[-1] != opening[1]:
            raise RunnerRefused("evidence_unsupported_capture")
        lines = lines[:-1]
    if not lines:
        raise RunnerRefused("evidence_unsupported_capture")
    patterns = (
        r"[A-Za-z0-9_.-]+ uptime is .+",
        r'System image file is "[^"]+"',
        r"Last reload reason: .+",
    )
    contexts = (
        r"(?:end|!|\^c?)",
        r"[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*",
        r"(?:building configuration|current configuration|banner(?:[ \t]|$)|(?:do[ \t]+)?sh(?:ow|o)?[ \t]).*",
        r"(?:cisco (?:nexus operating system|ios[- ]xr)|nx-os software|arista networks eos|junos software).*",
    )
    for line in lines:
        # A hostname such as "show" in an exact uptime record is not a command.
        if (not any(re.fullmatch(pattern, line, re.ASCII) for pattern in patterns)
                and any(re.fullmatch(pattern, line.strip().casefold(), re.ASCII) for pattern in contexts)):
            raise RunnerRefused("evidence_unsupported_capture")
    banner = r"Cisco IOS XE Software(?:[, \t].*)?"
    if any(line.lstrip().casefold().startswith("cisco ios xe software") for line in lines[1:]):
        raise RunnerRefused("evidence_unsupported_capture")
    records = all(any(re.fullmatch(pattern, line, re.ASCII) for line in lines) for pattern in patterns)
    fragment = records and all(
        any(re.fullmatch(pattern, line, re.ASCII) for pattern in patterns) for line in lines
    )
    if not (re.fullmatch(banner, lines[0], re.ASCII) or fragment):
        raise RunnerRefused("evidence_unsupported_capture")


def _interface_kind(text: str) -> tuple[str, k.IntegrityState] | None:
    lines = [line.removesuffix("\r") for line in text.split("\n") if line.strip()]
    raw_first = lines[0] if lines else ""  # Retained lines have not been stripped.
    prompt = r"[A-Za-z0-9_.:-]+[>#]"
    opening = re.fullmatch("(" + prompt + r") ?(show interfaces|show ip interface brief)", lines[0], re.ASCII) if lines else None
    brief = r"Interface[ \t]+IP-Address[ \t]+OK\?[ \t]+Method[ \t]+Status[ \t]+Protocol[ \t]*"
    detail = r"[A-Za-z][A-Za-z-]*[0-9][A-Za-z0-9./:-]* is (?:up|down|administratively down)(?:, line protocol is.*)?"
    bare = (len(lines) > 1 and raw_first == "show interfaces"
            and re.fullmatch(detail, lines[1], re.ASCII) is not None)
    command = (opening[2] if opening else "show ip interface brief" if lines and re.fullmatch(brief, lines[0], re.ASCII)
               else "show interfaces" if bare or lines and re.fullmatch(detail, lines[0], re.ASCII) else "")
    if not command:
        return None
    if ("\r" in text.replace("\r\n", "") or any(
            ord(char) < 32 and char not in "\t\r\n" or char in "\x7f\u0085\u2028\u2029" for char in text)):
        raise RunnerRefused("evidence_invalid_text")
    if opening or bare:
        lines = lines[1:]
    if lines and re.fullmatch(prompt, lines[-1], re.ASCII):
        if opening and lines[-1] != opening[1]:
            raise RunnerRefused("evidence_unsupported_capture")
        lines = lines[:-1]
    contexts = (
        r"(?:end|!|\^c?)",
        r"[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*",
        r"(?:building configuration|current configuration|banner(?:[ \t]|$)|(?:do[ \t]+)?sh(?:ow|o)?[ \t]).*",
        r"(?:cisco (?:ios|nexus operating system)|nx-os software|arista networks eos|junos software).*",
        r"(?:[a-z0-9_.-]+ uptime is |system image file is |last reload reason:).*",
    )
    for index, line in enumerate(lines):
        diagnostic_caret = (opening is not None and line.strip() == "^" and index + 1 < len(lines)
                            and lines[index + 1].strip().casefold() == "% invalid input detected at '^' marker.")
        if not diagnostic_caret and any(re.fullmatch(pattern, line.strip().casefold(), re.ASCII) for pattern in contexts):
            raise RunnerRefused("evidence_unsupported_capture")
    detail_context = (detail + r"|Sdwan-system-intf is (?:up|down|administratively down)"
                      r"(?:, line protocol is.*)?")
    other = brief if command == "show interfaces" else detail_context
    if (any(re.fullmatch(other, line.strip(), re.ASCII) for line in lines)
            or command == "show ip interface brief" and any(re.fullmatch(brief, line.strip(), re.ASCII) for line in lines[1:])):
        raise RunnerRefused("evidence_unsupported_capture")
    integrity = k.IntegrityState.COMPLETE if lines else k.IntegrityState.EMPTY
    if any(line.lstrip().startswith("%") or line.strip().casefold() in ("command authorization failed", "command authorization failed.") for line in lines):
        integrity = k.IntegrityState.ERROR
    elif any(line.strip().casefold() in ("[truncated]", "<output truncated>", "--more--", "<--- more --->", "--(more)--") for line in lines):
        integrity = k.IntegrityState.TRUNCATED
    return command, integrity
