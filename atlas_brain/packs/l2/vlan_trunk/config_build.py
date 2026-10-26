"""Single-owner configured intent; operational trunk operands remain independent."""
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.evidence.synthetic import CONFIG_SCHEMA, Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l2.vlan_trunk import config_parse as parser
from atlas_brain.packs.l2.vlan_trunk import config_resolve as resolver

OP, COMMAND = parser.OP, parser.COMMAND
PACK = k.PackId("l2.vlan_trunk")
MODE = k.FactId("l2.vlan_trunk.configured_mode")
NATIVE = k.FactId("l2.vlan_trunk.configured_native")
ALLOWED = k.FactId("l2.vlan_trunk.configured_allowed")
IDS = (ALLOWED, MODE, NATIVE)
STEP = StepSpec(id=StepId("l2.vlan_trunk/parse_config"), pack=PACK, kind="parse_build",
                scope="device", reads=(), produces=IDS, evaluator="l2.vlan_trunk.config_build_node")
FACTS = (
    FactSpec(id=ALLOWED, pack=PACK, subject="interface", value_type="text", step=STEP.id),
    FactSpec(id=MODE, pack=PACK, subject="interface", value_type="text", step=STEP.id),
    FactSpec(id=NATIVE, pack=PACK, subject="interface", value_type="integer", step=STEP.id),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigFields:
    local_port: str
    subject: k.EntityKey
    mode: k.Known[str] | k.Unknown
    native: k.Known[int] | k.Unknown
    allowed: k.Known[str] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigResult:
    rows: tuple[ConfigFields, ...]
    parses: tuple[tuple[k.CaptureId, ParseResult], ...]
    quality: Literal["complete", "partial"]


def _ref(capture: Capture, span: k.ByteSpan | k.WholeCapture) -> k.EvidenceRef:
    raw = capture.raw[span.start:span.end] if isinstance(span, k.ByteSpan) else capture.raw
    return k.EvidenceRef(capture=capture.id, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(raw).hexdigest())


def build_node(group: SyntheticGroup, node: Node, store: FactStore) -> ConfigResult:
    """Parse/resolve all supplied configuration before registering or writing facts."""
    k.require(group.schema == CONFIG_SCHEMA, "configured_group_schema_required")
    k.require(node in group.nodes and node.group == group.id, "configured_node_outside_group")
    captures = tuple(sorted((capture for capture in group.captures
                             if capture.source == node.key and capture.operation == OP), key=lambda c: str(c.id)))
    documents = tuple(parser.parse_capture(capture, node) for capture in captures)
    resolved = tuple(resolver.resolve(document, node) for document in documents)
    declaration = group.declaration.evidence + node.declaration.evidence
    needs = (k.EvidenceNeed(node=node.key, operation=OP, params=(), resolves=IDS,
                            reruns=(str(STEP.id),), after_s=None, unprintable=()),)
    context = declaration + tuple(_ref(capture, k.WholeCapture()) for capture in captures)

    def unknown(reason: k.UnknownReason, detail: str) -> k.Unknown:
        return k.Unknown(reason=reason, detail=detail, evidence=context, candidates=(), next_evidence=needs)

    def field[T](value: resolver.ConfigValue[T] | resolver.ConfigGap, capture: Capture) -> k.Known[T] | k.Unknown:
        evidence = declaration + tuple(_ref(capture, span) for span in value.spans)
        if isinstance(value, resolver.ConfigGap):
            return k.Unknown(reason=value.reason, detail=value.detail,
                             evidence=evidence + (_ref(capture, k.WholeCapture()),),
                             candidates=(), next_evidence=needs)
        return k.Known(value=value.value, basis=k.Basis.CONFIGURED, evidence=evidence, raw=value.raw)

    rows: list[ConfigFields] = []
    by_port = {row.port: row for row in resolved[0]} if len(resolved) == 1 else {}
    if len(resolved) == 1:
        k.require(len(by_port) == len(resolved[0]) == len(node.ports) and set(by_port) == set(node.ports),
                  "configured_population_mismatch")
    for port in sorted(node.ports):
        mode: k.Known[str] | k.Unknown
        native: k.Known[int] | k.Unknown
        allowed: k.Known[str] | k.Unknown
        if not captures:
            mode = native = allowed = unknown(k.UnknownReason.NOT_COLLECTED, "running_config_not_collected")
        elif len(captures) != 1:
            mode = native = allowed = unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "multiple_running_config_captures")
        else:
            point = by_port[port]
            mode, native, allowed = field(point.mode, captures[0]), field(point.native, captures[0]), field(point.allowed, captures[0])
        rows.append(ConfigFields(local_port=port, subject=endpoint(node, port), mode=mode, native=native, allowed=allowed))
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=MODE, subject=row.subject, value=row.mode)
        writer.write(fact=NATIVE, subject=row.subject, value=row.native)
        writer.write(fact=ALLOWED, subject=row.subject, value=row.allowed)
    quality: Literal["complete", "partial"] = "complete" if rows and all(
        isinstance(value, k.Known) for row in rows for value in (row.mode, row.native, row.allowed)) else "partial"
    return ConfigResult(rows=tuple(rows), parses=tuple((document.capture.id, document.parse) for document in documents),
                        quality=quality)
