"""Resolve captured static single-parent chains without defaults or precedence guesses."""
from dataclasses import dataclass
from typing import cast

from atlas_brain.evidence.parsekit.rules import Captured
from atlas_brain.evidence.synthetic import Node, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.vlan_trunk.config_parse import (
    ConfigDocument,
    ConfigSection,
    canonical_value,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigValue[T]:
    value: T
    raw: str | None
    spans: tuple[k.ByteSpan, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigGap:
    reason: k.UnknownReason
    detail: str
    spans: tuple[k.ByteSpan, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigRow:
    port: str
    mode: ConfigValue[str] | ConfigGap
    native: ConfigValue[int] | ConfigGap
    allowed: ConfigValue[str] | ConfigGap


def _spans(sections: tuple[ConfigSection, ...]) -> tuple[k.ByteSpan, ...]:
    spans = {section.header for section in sections}
    spans.update(field.span for section in sections for _, field in section.entries)
    return tuple(sorted(spans, key=lambda span: (span.start, span.end)))


def _chain(index: dict[tuple[str, str], tuple[ConfigSection, ...]],
           port: str) -> tuple[ConfigSection, ...] | ConfigGap:
    key = ("interface", port)
    seen: set[tuple[str, str]] = set()
    chain: list[ConfigSection] = []
    edges = 0
    while True:
        if key in seen:
            return ConfigGap(reason=k.UnknownReason.INHERITANCE_UNRESOLVED, detail="config_template_cycle",
                             spans=_spans(tuple(chain)))
        seen.add(key)
        candidates = index.get(key, ())
        if not candidates:
            reason = k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE if not chain else k.UnknownReason.INHERITANCE_UNRESOLVED
            return ConfigGap(reason=reason, detail="config_section_not_collected", spans=_spans(tuple(chain)))
        if len(candidates) != 1:
            return ConfigGap(reason=k.UnknownReason.CONFLICTING_EVIDENCE, detail="config_duplicate_section",
                             spans=_spans(tuple(chain) + candidates))
        section = candidates[0]
        chain.append(section)
        for name in ("mode", "native", "allowed"):
            if sum(key == name for key, _ in section.entries) > 1:
                return ConfigGap(reason=k.UnknownReason.CONFLICTING_EVIDENCE, detail="config_duplicate_attribute",
                                 spans=_spans(tuple(chain)))
        parents = tuple(field for name, field in section.entries if name == "source")
        if len(parents) > 1:
            return ConfigGap(reason=k.UnknownReason.INHERITANCE_UNRESOLVED, detail="config_multiple_parents",
                             spans=_spans(tuple(chain)))
        if not parents:
            return tuple(chain)
        edges += 1
        if edges > 16:
            return ConfigGap(reason=k.UnknownReason.BUDGET_EXCEEDED, detail="config_parent_edges_exceed_16",
                             spans=_spans(tuple(chain)))
        key = ("template", parents[0].raw)


def _field[T](sections: tuple[ConfigSection, ...], name: str, expected: type[T]) -> ConfigValue[T] | ConfigGap:
    fields: tuple[Captured, ...] = tuple(field for section in sections for key, field in section.entries if key == name)
    spans = _spans(sections)
    if not fields:
        return ConfigGap(reason=k.UnknownReason.DEFAULT_UNKNOWN, detail="configured_" + name + "_not_printed", spans=spans)
    values: list[T] = []
    for field in fields:
        value = canonical_value(name, str(field.value))
        if type(value) is not expected:
            return ConfigGap(reason=k.UnknownReason.PARSE_PARTIAL, detail="configured_" + name + "_invalid", spans=spans)
        values.append(cast(T, value))
    if any(value != values[0] for value in values):
        return ConfigGap(reason=k.UnknownReason.CONFLICTING_EVIDENCE,
                         detail="configured_" + name + "_conflicting_layers", spans=spans)
    raw = fields[0].raw if all(field.raw == fields[0].raw for field in fields) else None
    return ConfigValue(value=values[0], raw=raw, spans=spans)


def resolve(document: ConfigDocument, node: Node) -> tuple[ConfigRow, ...]:
    if document.capture.source != node.key:
        raise ValueError("config_capture_source")
    grouped: dict[tuple[str, str], list[ConfigSection]] = {}
    for section in document.sections:
        if section.kind == "interface":
            endpoint(node, section.name.raw)
        grouped.setdefault((section.kind, section.name.raw), []).append(section)
    index = {key: tuple(sections) for key, sections in grouped.items()}
    rows: list[ConfigRow] = []
    for port in sorted(node.ports):
        chain = _chain(index, port)
        mode: ConfigValue[str] | ConfigGap
        native: ConfigValue[int] | ConfigGap
        allowed: ConfigValue[str] | ConfigGap
        if document.reason is not None:
            gap = ConfigGap(reason=document.reason, detail=document.detail,
                            spans=(k.ByteSpan(start=0, end=len(document.capture.raw)),))
            mode = native = allowed = gap
        elif isinstance(chain, ConfigGap):
            mode = native = allowed = chain
        else:
            mode = _field(chain, "mode", str)
            if isinstance(mode, ConfigGap):
                native = allowed = mode
            elif mode.value != "trunk":
                native = allowed = ConfigGap(reason=k.UnknownReason.NOT_OBSERVABLE,
                                             detail="configured_mode_not_trunk", spans=mode.spans)
            else:
                native, allowed = _field(chain, "native", int), _field(chain, "allowed", str)
        rows.append(ConfigRow(port=port, mode=mode, native=native, allowed=allowed))
    return tuple(rows)
