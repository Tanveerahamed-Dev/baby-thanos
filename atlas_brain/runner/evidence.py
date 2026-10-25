"""Bounded raw CLI-folder admission; file identity never supplies device facts."""
import re
import stat
from hashlib import sha256
from pathlib import Path

from atlas_brain.evidence.admission import (
    AdmissionRefused,
    BudgetExceeded,
    Budgets,
    folder_members,
)
from atlas_brain.evidence.capture import Capture
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


def analyse_evidence(root: Path, *, budgets: Budgets | None = None) -> tuple[Capture, ...]:
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
        _require_system_text(text)
        identity = sha256(name_bytes + b"\0" + raw).hexdigest()
        captures.append(Capture(
            id=k.CaptureId("cap:" + identity),
            source=k.EntityKey("node:file:" + sha256(name_bytes).hexdigest()),
            operation="iosxe.show_version", rendered="show version", codec="utf-8", raw=raw,
            # COMPLETE describes the supplied file, not a verified collection session.
            # Capture's legacy metadata bridge binds its whole-byte SHA and missing time.
            integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
            read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN,
        ))
    return tuple(captures)


def _require_system_text(text: str) -> None:
    lines = text.splitlines()
    if any(line.lstrip().startswith("%") or "Command authorization failed" in line for line in lines):
        raise RunnerRefused("evidence_capture_error")
    if any(marker in text.lower() for marker in ("--more--", "<--- more --->", "[truncated]", "--(more)--")):
        raise RunnerRefused("evidence_capture_incomplete")
    if any(ord(char) < 32 and char not in "\t\r\n" or ord(char) == 127 for char in text):
        raise RunnerRefused("evidence_invalid_text")
    banner = any(line.startswith("Cisco IOS XE Software") for line in lines)
    patterns = (
        r"[A-Za-z0-9_.-]+ uptime is .+",
        r'System image file is "[^"]+"',
        r"Last reload reason: .+",
    )
    records = all(any(re.fullmatch(pattern, line, re.ASCII) for line in lines) for pattern in patterns)
    fragment = records and all(
        not line.strip() or any(re.fullmatch(pattern, line, re.ASCII) for pattern in patterns)
        or re.fullmatch(r"[A-Za-z0-9_.:-]+[>#](?: ?show version)?", line, re.ASCII)
        for line in lines
    )
    if not (banner or fragment):
        raise RunnerRefused("evidence_unsupported_capture")
