"""Ordered byte rules with exhaustive line and enumerated-token accounting."""
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal, final

from atlas_brain.kernel.states import (
    ByteSpan,
    CaptureId,
    EvidenceRef,
    EvidenceRole,
    Unknown,
    UnknownReason,
)

from .patterns import compile_pattern


@dataclass(frozen=True, slots=True)
class Captured:
    raw: str
    span: ByteSpan
    value: str | Unknown


def _is_enum(value: object) -> bool:
    return isinstance(value, StrEnum)


@final
@dataclass(frozen=True, slots=True)
class TokenMap:
    entries: tuple[tuple[str, StrEnum], ...]

    def __post_init__(self) -> None:
        if (type(self.entries) is not tuple or not self.entries
                or any(type(row) is not tuple for row in self.entries)
                or any(type(k) is not str for k, _ in self.entries)
                or len(dict(self.entries)) != len(self.entries)
                or any(not _is_enum(v) for _, v in self.entries)
                or len({type(v) for _, v in self.entries}) != 1):
            raise ValueError("token map requires unique rows from one closed enum")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("closed_token_map")

    @classmethod
    def closed(cls, entries: Mapping[str, StrEnum]) -> TokenMap:
        return cls(tuple(sorted(entries.items())))

    def resolve(self, field: Captured, capture: CaptureId) -> Captured:
        evidence = (EvidenceRef(capture=capture, locator=field.span,
                    role=EvidenceRole.SUBJECT,
                    excerpt_sha256=sha256(field.raw.encode("utf-8", "surrogateescape")).hexdigest()),)
        rows = dict(self.entries)
        value: StrEnum | Unknown
        if field.raw in rows:
            value = rows[field.raw]
        else:
            value = Unknown(reason=UnknownReason.PARSE_PARTIAL, detail="unmapped_token",
                            evidence=evidence, candidates=(), next_evidence=())
        return Captured(field.raw, field.span, value)


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    state: str
    pattern: str
    kind: Literal["record", "ignore", "enter_state", "leave_state"]
    target: str
    reason: str
    fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Record:
    rule_id: str
    span: ByteSpan
    fields: tuple[tuple[str, Captured], ...]


@dataclass(frozen=True, slots=True)
class LineAccounting:
    span: ByteSpan
    status: Literal["consumed", "ignored", "unrecognised"]
    rule_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    records: tuple[Record, ...]
    lines: tuple[LineAccounting, ...]
    tokens: tuple[tuple[str, Captured], ...]
    quality: Literal["complete", "partial"]


def _cited_blank(rule: Rule) -> bool:
    """Only blank separators are ignorable; other lines need consumed spans.

    Cite a pinned public source and line, never an arbitrary explanation.
    The engine stays offline; source content is checked in fixture review.
    """
    prefix = "https://github.com/"
    url, separator, fragment = rule.reason.rpartition("#")
    parts = url.removeprefix(prefix).split("/")
    lines = fragment.removeprefix("L").split("-L")
    return (
        rule.pattern in ("", r"[ \t]*+") and not rule.fields
        and url.startswith(prefix) and bool(separator) and len(parts) >= 5
        and all(part not in ("", ".", "..") and "%" not in part for part in parts)
        and parts[2] == "blob" and len(parts[3]) == 40
        and all(char in "0123456789abcdef" for char in parts[3])
        and fragment.startswith("L") and 1 <= len(lines) <= 2
        and all(line.isascii() and line.isdigit() and not line.startswith("0") for line in lines)
        and (len(lines) == 1 or int(lines[0]) <= int(lines[1]))
    )

def _literal_marker(pattern: str) -> bool:
    """A rule without values can recognise only a nonempty literal marker."""
    escaped = False
    for char in pattern:
        if escaped:
            if char not in r".^$*+?{}[]\|()# -":
                return False
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in ".^$*+?{}[]|()":
            return False
    return bool(pattern) and not escaped

def run_rules(raw: bytes, capture: CaptureId, rules: tuple[Rule, ...],
              token_maps: tuple[tuple[str, TokenMap], ...]) -> ParseResult:
    """LF-only physical lines; first full matching rule in the current state wins."""
    if len({r.rule_id for r in rules}) != len(rules) or not capture:
        raise ValueError("duplicate rule id or missing capture")
    if any(type(mapping) is not TokenMap for _, mapping in token_maps):
        raise ValueError("only closed token maps are admitted")
    maps = dict(token_maps)
    if len(maps) != len(token_maps) or not set(maps) <= {f for r in rules for f in r.fields}:
        raise ValueError("duplicate token map")
    states = {r.state for r in rules} | {"start"}
    compiled = tuple((rule, compile_pattern(rule.pattern)) for rule in rules)
    for rule, pattern in compiled:
        if (not rule.rule_id or not rule.state or rule.target not in states
                or rule.kind not in ("record", "ignore", "enter_state", "leave_state")
                or (rule.kind == "ignore" and not _cited_blank(rule))
                or (rule.kind != "ignore" and not rule.fields and not _literal_marker(rule.pattern))
                or (rule.kind in ("record", "ignore") and rule.target != rule.state)
                or set(rule.fields) != set(pattern.groupindex)
                or len(rule.fields) != pattern.groups):
            raise ValueError("invalid rule shape, target, ignore citation or fields")
    records: list[Record] = []
    tokens: list[tuple[str, Captured]] = []
    accounting: list[LineAccounting] = []
    state, offset, partial = "start", 0, False
    while offset < len(raw):
        lf = raw.find(b"\n", offset)
        end = len(raw) if lf < 0 else lf + 1
        content_end = end
        if lf >= 0:
            content_end -= 1
            if raw[content_end - 1:content_end] == b"\r" and content_end > offset:
                content_end -= 1
        content = raw[offset:content_end]
        line_span = ByteSpan(start=offset, end=end)
        for rule, pattern in compiled:
            if rule.state != state:
                continue
            match = pattern.fullmatch(content)
            if match is None:
                continue
            fields: list[tuple[str, Captured]] = []
            for name in rule.fields:
                start, stop = match.span(name)
                if start < 0:
                    raise ValueError("optional groups require explicit alternate record rules")
                span = ByteSpan(start=offset + start, end=offset + stop)
                text = raw[span.start:span.end].decode("utf-8", "surrogateescape")
                field = Captured(text, span, text)
                if name in maps:
                    field = maps[name].resolve(field, capture)
                    tokens.append((name, field))
                    partial = partial or isinstance(field.value, Unknown)
                fields.append((name, field))
            if fields or rule.kind == "record":
                records.append(Record(rule.rule_id, ByteSpan(start=offset, end=content_end), tuple(fields)))
            status = "ignored" if rule.kind == "ignore" else "consumed"
            accounting.append(LineAccounting(line_span, status, rule.rule_id, rule.reason))
            state = rule.target
            break
        else:
            accounting.append(LineAccounting(line_span, "unrecognised", "", ""))
            partial = True
        offset = end
    return ParseResult(tuple(records), tuple(accounting), tuple(tokens), "partial" if partial else "complete")
