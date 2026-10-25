"""Exact synthetic discovery claims; no identity inference or physical-link claim."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import (
    Captured,
    ParseResult,
    Rule,
    TokenMap,
    run_rules,
)
from atlas_brain.evidence.synthetic import Node, SyntheticGroup, endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer

VARIANT_SUPPORT = "allowlisted"
DEVICE_ID = k.FactId("l2.discovery.device_id")
REMOTE_PORT = k.FactId("l2.discovery.remote_port")
BRIDGE = k.FactId("l2.discovery.bridge_capable")
IDS = tuple(sorted((DEVICE_ID, REMOTE_PORT, BRIDGE)))
STEP = StepSpec(id=StepId("l2.discovery/parse"), pack=k.PackId("l2.discovery"),
                kind="parse_build", scope="device", reads=(), produces=IDS,
                evaluator="l2.discovery.build_node")
FACTS = tuple(FactSpec(id=fact, pack=STEP.pack, subject="interface",
                      value_type="boolean" if fact == BRIDGE else "text", step=STEP.id) for fact in IDS)
OPERATIONS = {"iosxe.show_cdp_neighbors_detail": "show cdp neighbors detail",
              "iosxe.show_lldp_neighbors_detail": "show lldp neighbors detail"}


class _Capability(StrEnum):
    BRIDGE = "bridge"
    OTHER = "other"


_CDP = TokenMap.closed({"Switch": _Capability.BRIDGE, "Switch IGMP": _Capability.BRIDGE,
                       "Router Switch IGMP": _Capability.BRIDGE, "Router": _Capability.OTHER,
                       "Host": _Capability.OTHER, "Phone": _Capability.OTHER})
_LLDP = TokenMap.closed({"B": _Capability.BRIDGE, "B,R": _Capability.BRIDGE, "B, R": _Capability.BRIDGE,
                        "R": _Capability.OTHER, "T": _Capability.OTHER, "W": _Capability.OTHER})
_PORT = r"[A-Za-z][A-Za-z0-9./:_-]*+"
_PEER = r"[A-Za-z0-9][A-Za-z0-9_.:-]*+"


@dataclass(frozen=True, slots=True, kw_only=True)
class DiscoveryFields:
    local_port: str
    subject: k.EntityKey
    device_id: k.Known[str] | k.Unknown
    remote_port: k.Known[str] | k.Unknown
    bridge_capable: k.Known[bool] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class DiscoveryResult:
    rows: tuple[DiscoveryFields, ...]
    parses: tuple[tuple[k.CaptureId, ParseResult], ...]
    quality: Literal["complete", "partial"]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Claim:
    capture: Capture
    local: Captured
    fields: tuple[Captured, Captured, Captured]


def _rules(command: str) -> tuple[Rule, ...]:
    cdp = command == "show cdp neighbors detail"
    transitions = ((
        ("peer", "start", r"Device ID: (?P<peer>" + _PEER + ")", "peer", ("peer",)),
        ("capability", "peer", r"Platform: (?P<platform>[^,]++),[ \t]++Capabilities: (?P<bridge>.*+)",
         "cap", ("platform", "bridge")),
        ("ports", "cap", r"Interface: (?P<local>" + _PORT + r"),[ \t]++Port ID \(outgoing port\): (?P<remote>"
         + _PORT + ")", "start", ("local", "remote")),
    ) if cdp else (
        ("local", "start", r"Local Intf: (?P<local>" + _PORT + ")", "local", ("local",)),
        ("remote", "local", r"Port id: (?P<remote>" + _PORT + ")", "port", ("remote",)),
        ("peer", "port", r"System Name: (?P<peer>" + _PEER + ")", "peer", ("peer",)),
        ("capability", "peer", r"Enabled Capabilities: (?P<bridge>.*+)", "start", ("bridge",)),
    ))
    rules = [Rule(name, state, pattern, "enter_state", target, "", fields)
             for name, state, pattern, target, fields in transitions]
    states = ("start", "peer", "cap") if cdp else ("start", "local", "port", "peer")
    for state in states:
        rules.extend((
            Rule("blank_" + state, state, r"(?P<separator>[ \t]*+)", "record", state, "", ("separator",)),
        ))
    rules.extend((
        Rule("divider_start", "start", "-------------------------", "record", "start", "", ()),
        Rule("command", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[#>])[ \t]*+" + command,
             "record", "start", "", ("prompt",)),
        Rule("prompt", "start", r"(?P<prompt>[A-Za-z0-9_.:-]++[#>])[ \t]*+",
             "record", "start", "", ("prompt",)),
    ))
    return tuple(rules)



def _diagnose_local(capture: Capture, node: Node, parsed: ParseResult, command: str) -> None:
    prefix = "Interface: " if command == "show cdp neighbors detail" else "Local Intf: "
    token = prefix + r"(?P<local>" + _PORT + ")"
    shapes = ((token, ("local",)), (token + r"[, \t]++(?P<tail>.*+)", ("local", "tail")))
    rules = tuple(Rule("diagnostic_" + str(index), "start", pattern, "record", "start", "", fields)
                  for index, (pattern, fields) in enumerate(shapes))
    for line in parsed.lines:
        if line.status == "unrecognised":
            trial = run_rules(capture.raw[line.span.start:line.span.end], capture.id, rules, ())
            for record in trial.records:
                endpoint(node, dict(record.fields)["local"].raw)


def _parse(capture: Capture, node: Node) -> tuple[ParseResult, tuple[_Claim, ...]]:
    operation = capture.operation
    if operation is None or operation not in OPERATIONS:
        raise ValueError("unsupported_discovery_operation")
    command = OPERATIONS[operation]
    if capture.rendered != command or capture.codec not in ("utf-8", "ascii"):
        raise ValueError("unsupported_discovery_capture")
    parsed = run_rules(capture.raw, capture.id, _rules(command),
                       (("bridge", _CDP if command == "show cdp neighbors detail" else _LLDP),))
    _diagnose_local(capture, node, parsed, command)
    pending: dict[str, Captured] = {}
    claims: list[_Claim] = []
    for record in parsed.records:
        fields = dict(record.fields)
        if "local" in fields:
            endpoint(node, fields["local"].raw)  # Population cannot silently discard an observed port.
        for name in ("local", "peer", "remote", "bridge"):
            if name in fields:
                pending[name] = fields[name]
        if (record.rule_id == "ports" or command == "show lldp neighbors detail"
                and record.rule_id == "capability"):
            if set(pending) == {"local", "peer", "remote", "bridge"}:
                claims.append(_Claim(capture=capture, local=pending["local"],
                                     fields=(pending["peer"], pending["remote"], pending["bridge"])))
            pending = {}
    quality: Literal["complete", "partial"] = "partial" if pending or parsed.quality == "partial" else "complete"
    return ParseResult(parsed.records, parsed.lines, parsed.tokens, quality), tuple(claims)


def _ref(capture: Capture, span: k.ByteSpan | k.WholeCapture) -> k.EvidenceRef:
    raw = capture.raw[span.start:span.end] if isinstance(span, k.ByteSpan) else capture.raw
    return k.EvidenceRef(capture=capture.id, locator=span, role=k.EvidenceRole.SUBJECT,
                         excerpt_sha256=sha256(raw).hexdigest())


def _field_evidence(claims: tuple[_Claim, ...], index: int,
                    declaration: tuple[k.Evidence, ...]) -> tuple[k.Evidence, ...]:
    refs: list[k.Evidence] = list(declaration)
    for claim in claims:
        refs.extend((_ref(claim.capture, claim.fields[index].span), _ref(claim.capture, claim.local.span)))
    return tuple(refs)


def build_node(group: SyntheticGroup, node: Node, store: FactStore) -> DiscoveryResult:
    """Parse every collected protocol before writing each declared endpoint once."""
    if node.group != group.id or node not in group.nodes:
        raise ValueError("discovery_group_membership")
    captures = tuple(sorted((c for c in group.captures if c.source == node.key
                             and c.operation in OPERATIONS), key=lambda c: c.id))
    declaration = group.declaration.evidence + node.declaration.evidence
    needs = tuple(k.EvidenceNeed(node=node.key, operation=command, params=(), resolves=IDS,
                                reruns=(str(STEP.id),), after_s=None, unprintable=())
                  for command in sorted(OPERATIONS.values()))
    context = declaration + tuple(_ref(capture, k.WholeCapture()) for capture in captures)
    parsed: list[tuple[Capture, ParseResult, tuple[_Claim, ...]]] = []
    for capture in captures:
        result, claims = _parse(capture, node)
        parsed.append((capture, result, claims))
    reason = (k.UnknownReason.NOT_COLLECTED if not captures else
              k.UnknownReason.CAPTURE_ERROR if any(c.error is not None or c.integrity not in (
                  k.IntegrityState.COMPLETE, k.IntegrityState.EMPTY, k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS)
                  for c in captures) else
              k.UnknownReason.CAPTURE_TRUNCATED if any(c.integrity in (k.IntegrityState.TRUNCATED,
                  k.IntegrityState.PAGING_ARTIFACTS) for c in captures) else
              k.UnknownReason.EMPTY_UNREGISTERED if any(c.integrity is k.IntegrityState.EMPTY for c in captures) else
              k.UnknownReason.PARSE_PARTIAL if any(p.quality == "partial" for _, p, _ in parsed) else None)

    def unknown(why: k.UnknownReason, detail: str, evidence: tuple[k.Evidence, ...]) -> k.Unknown:
        return k.Unknown(reason=why, detail=detail, evidence=evidence, candidates=(), next_evidence=needs)

    rows: list[DiscoveryFields] = []
    writer = bind_writer(store, step=STEP)
    for port in node.ports:
        claims = tuple(claim for _, _, records in parsed for claim in records if claim.local.raw == port)
        peer: k.Known[str] | k.Unknown
        remote: k.Known[str] | k.Unknown
        bridge: k.Known[bool] | k.Unknown
        if reason is not None:
            peer = remote = unknown(reason, "discovery_not_complete", context)
            bridge = peer
        elif not claims:
            peer = remote = unknown(k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE, "discovery_port_not_observed", context)
            bridge = peer
        elif (len({claim.capture.operation for claim in claims}) != len(claims)
              or any((claim.fields[0].raw, claim.fields[1].raw, claim.fields[2].value)
                     != (claims[0].fields[0].raw, claims[0].fields[1].raw, claims[0].fields[2].value)
                     for claim in claims)):
            evidence = tuple(ref for index in range(3) for ref in _field_evidence(claims, index, ()))
            peer = remote = unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "duplicate_or_disagreeing_peer", declaration + evidence)
            bridge = peer
        else:
            peer = k.Known(value=claims[0].fields[0].raw, basis=k.Basis.OBSERVED,
                           evidence=_field_evidence(claims, 0, declaration), raw=claims[0].fields[0].raw)
            remote = k.Known(value=claims[0].fields[1].raw, basis=k.Basis.OBSERVED,
                             evidence=_field_evidence(claims, 1, declaration), raw=claims[0].fields[1].raw)
            bridge = k.Known(value=claims[0].fields[2].value == _Capability.BRIDGE, basis=k.Basis.OBSERVED,
                             evidence=_field_evidence(claims, 2, declaration), raw=claims[0].fields[2].raw)
        subject = endpoint(node, port)
        writer.write(fact=DEVICE_ID, subject=subject, value=peer)
        writer.write(fact=REMOTE_PORT, subject=subject, value=remote)
        writer.write(fact=BRIDGE, subject=subject, value=bridge)
        rows.append(DiscoveryFields(local_port=port, subject=subject, device_id=peer,
                                    remote_port=remote, bridge_capable=bridge))
    return DiscoveryResult(rows=tuple(rows), parses=tuple((c.id, p) for c, p, _ in parsed),
                           quality="partial" if reason is not None else "complete")
