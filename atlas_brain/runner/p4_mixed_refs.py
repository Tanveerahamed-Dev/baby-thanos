"""Current seven-fact leaf snapshots; no recursive facts, caller grants or origin seal."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.p4_admission import CaptureMember, Envelope
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build, version_profile, vrrp_profile
from atlas_brain.packs.l3.fhrp import mixed_component as owning
from atlas_brain.runner.pack_receipts import ParseReceipt


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryLeaf:
    reference: k.RegistryRef
    registry_raw: bytes
    canonical_value: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class CaptureLeaf:
    member: CaptureMember
    capture: Capture
    receipt: ParseReceipt
    reference: k.EvidenceRef
    raw: bytes
    capture_sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class MixedFactProof:
    reference: k.FactRef
    state: owning.Cell
    registry_leaves: tuple[RegistryLeaf, ...]
    capture_leaves: tuple[CaptureLeaf, ...]
    next_evidence: tuple[k.EvidenceNeed, ...]


def _need(condition: bool, code: str) -> None:
    k.require(condition, "p4_mixed_proofs_" + code)


def _cell(result: owning.MixedComponent, reference: k.FactRef) -> tuple[owning.Cell, Node, str]:
    cells: dict[k.FactRef, tuple[owning.Cell, Node, str]] = {}
    for tree_row in result.tree.rows:
        cells[k.FactRef(fact=stp.REPORTED_ROLE, subject=tree_row.subject)] = tree_row.role, tree_row.target.node, stp.stp.OP
        cells[k.FactRef(fact=stp.ROOT_GUARD, subject=tree_row.subject)] = tree_row.value, tree_row.target.node, stp.stp.OP
    for channel_row in result.channel.rows:
        cells[k.FactRef(fact=ec.REPORTED_PROTOCOL, subject=channel_row.subject)] = channel_row.value, channel_row.target.node, ec.parse_summary.OP
        cells[k.FactRef(fact=ec.REPORTED_MEMBER_TOKENS, subject=channel_row.subject)] = channel_row.member_tokens, channel_row.target.node, ec.parse_summary.OP
    for state_row in result.state.rows:
        cells[k.FactRef(fact=build.REPORTED_STATE, subject=state_row.subject)] = state_row.value, state_row.target.node, build.hsrp.OP
    for version_row in result.version.rows:
        cells[k.FactRef(fact=version_profile.REPORTED_PROTOCOL_VERSION, subject=version_row.subject)] = version_row.value, version_row.target.node, version_profile.parser.OP
    for vrrp_row in result.vrrp.rows:
        cells[k.FactRef(fact=vrrp_profile.REPORTED_VRRP_STATE, subject=vrrp_row.subject)] = vrrp_row.value, vrrp_row.target.node, vrrp_profile.parser.OP
    _need(reference in cells, "reference")
    return cells[reference]


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError("p4_mixed_proofs_registry")
    return value


def _registries(envelope: Envelope, budgets: Budgets) -> dict[k.RegistryRef, tuple[bytes, bytes]]:
    base = record(strict_json(envelope.base.raw, budgets.nesting_depth, budgets.numeric_digits),
        ("schema", "semantic_group", "group", "nodes", "captures"))
    side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
        ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    result: dict[k.RegistryRef, tuple[bytes, bytes]] = {}
    for name, table, raw, values, fields in (
        ("nodes", "synthetic_p2.nodes", envelope.base.raw, base["nodes"], ("id", "discovery_id", "ports")),
        ("targets", "synthetic_p4.targets", envelope.raw, side["targets"], ("id", "node", "operation", "params")),
    ):
        for index, value in enumerate(_list(values)):
            row = record(value, fields)
            ref = k.RegistryRef(table=table, row_id=string(row, "id"), table_digest=sha256(raw).hexdigest(), citation=f"/{name}/{index}")
            _need(ref not in result, "registry")
            result[ref] = raw, canonical(row)
    ref = k.RegistryRef(table="synthetic_p4.context", row_id=envelope.context,
        table_digest=sha256(envelope.raw).hexdigest(), citation="/context")
    result[ref] = envelope.raw, canonical(side["context"])
    return result


class MixedProofIndex:
    """One fresh owning source; every lookup revalidates current values and source data."""

    def __init__(self, source: owning.MixedComponentRun) -> None:
        _need(type(self) is MixedProofIndex and type(source) is owning.MixedComponentRun, "source")
        self.source = source
        owning.MixedComponentRun.current_component(source)

    def resolve(self, reference: k.FactRef) -> MixedFactProof:
        _need(type(self) is MixedProofIndex and type(self.source) is owning.MixedComponentRun, "source")
        result = owning.MixedComponentRun.current_component(self.source)
        _need(type(reference) is k.FactRef and all(type(value) is str and bool(value)
            for value in (reference.fact, reference.subject)), "reference")
        state, node, operation = _cell(result, reference)
        envelope, budgets = result.source.execution.envelope, self.source.budgets
        records = _registries(envelope, budgets)
        _need(type(state.evidence) is tuple and all(type(ref) in (k.RegistryRef, k.EvidenceRef) for ref in state.evidence), "evidence")
        registry: list[RegistryLeaf] = []
        captures: list[CaptureLeaf] = []
        targets: set[str] = set()
        registry_refs = tuple(ref for ref in state.evidence if isinstance(ref, k.RegistryRef))
        for ref in registry_refs:
            _need(all(type(value) is str for value in (ref.table, ref.row_id, ref.table_digest, ref.citation)), "registry")
            _need(ref in records, "registry")
            registry.append(RegistryLeaf(reference=ref, registry_raw=records[ref][0], canonical_value=records[ref][1]))
            if ref.table == "synthetic_p4.targets":
                targets.add(ref.row_id)
        _need(tuple(ref for ref in registry_refs if ref.table == "synthetic_p2.nodes") == node.declaration.evidence
            and tuple(ref for ref in registry_refs if ref.table == "synthetic_p4.context") == envelope.declaration.evidence and bool(targets), "registry")
        members = {member.id: member for member in envelope.captures}
        outputs = {output.receipt.capture.id: output for output in result.source.execution.executed}
        positive = type(state) is k.Known
        for ref in state.evidence:
            if not isinstance(ref, k.EvidenceRef):
                continue
            _need(type(ref.capture) is str and type(ref.excerpt_sha256) is str and type(ref.role) is k.EvidenceRole
                and ref.capture in members and ref.capture in outputs, "capture")
            member, receipt = members[ref.capture], outputs[ref.capture].receipt
            capture = receipt.capture
            _need(member.target.node is node and member.target.id in targets and member.target.operation == operation
                and capture.source == node.key and capture.operation == operation and capture.raw is member.raw
                and receipt.owner == member.target.owner and receipt.context == envelope.context
                and receipt.registration_sha256 == envelope.registration_sha256, "scope")
            _need(capture.scope == Scope(node=node.key, plane="exec", vrf=None, context=None, instance=None,
                vdc=None, tenant=None, afi=None), "scope")
            _need(not positive or capture.integrity is k.IntegrityState.COMPLETE and capture.error is None
                and receipt.parse.quality == "complete", "capture")
            _need(ref.role is (k.EvidenceRole.SUBJECT if positive else k.EvidenceRole.WITNESS), "role")
            point = ref.locator
            if type(point) is k.ByteSpan:
                _need(type(point.start) is int and type(point.end) is int and 0 <= point.start < point.end <= len(capture.raw), "span")
                raw = capture.raw[point.start:point.end]
            elif type(point) is k.WholeCapture:
                _need(not positive, "role")
                raw = capture.raw
            else:
                raise ValueError("p4_mixed_proofs_locator")
            whole = sha256(capture.raw).hexdigest()
            _need(whole == member.sha256 and sha256(raw).hexdigest() == ref.excerpt_sha256, "hash")
            captures.append(CaptureLeaf(member=member, capture=capture, receipt=receipt, reference=ref, raw=raw, capture_sha256=whole))
        _need(not positive or bool(captures), "evidence")
        needs = state.next_evidence if isinstance(state, k.Unknown) else ()
        return MixedFactProof(reference=reference, state=state, registry_leaves=tuple(registry),
            capture_leaves=tuple(captures), next_evidence=needs)
