"""Local VRRP byte-proof snapshots; registry references stay unexpanded, never root admission."""
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l3.fhrp import parse_vrrp as parser
from atlas_brain.packs.l3.fhrp import vrrp_owner as owning
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile


def _need(condition: bool, code: str) -> None:
    k.require(condition, "vrrp_proofs_" + code)


@dataclass(frozen=True, slots=True, kw_only=True)
class LocalCaptureLeaf:
    capture: Capture
    reference: k.EvidenceRef
    raw: bytes
    capture_sha256: str


@dataclass(frozen=True, slots=True, kw_only=True)
class LocalVRRPProof:
    reference: k.FactRef
    state: k.Known[str] | k.Unknown
    unexpanded_registry_refs: tuple[k.RegistryRef, ...]
    capture_leaves: tuple[LocalCaptureLeaf, ...]
    next_evidence: tuple[k.EvidenceNeed, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class LocalVRRPProofIndex:
    """Bind one actual local owner and Reader; outputs are snapshots, not post-return seals."""

    owner: owning.VRRPOwner
    result: owning.VRRPResult
    reader: FactReader

    def __post_init__(self) -> None:
        _need(type(self) is LocalVRRPProofIndex, "owner")
        self.validate()

    def validate(self) -> None:
        _need(type(self) is LocalVRRPProofIndex and type(self.owner) is owning.VRRPOwner, "owner")
        self.owner.validate_values(self.result, self.reader)

    def resolve(self, reference: k.FactRef) -> LocalVRRPProof:
        _need(type(self) is LocalVRRPProofIndex, "owner")
        self.validate()
        _need(type(reference) is k.FactRef and all(type(value) is str and bool(value)
              for value in (reference.fact, reference.subject)) and reference.fact == profile.REPORTED_VRRP_STATE,
              "reference")
        _need(reference in self.result.store.values, "reference")
        row = next(row for row in self.result.rows if row.subject == reference.subject)
        state = row.value
        _need(type(state) in (k.Known, k.Unknown)
              and self.reader.read(fact=reference.fact, subject=reference.subject) is state
              and state is self.result.store.values[reference], "reference")
        request = next((item for item in self.owner.inputs.requests
                        if item.context == row.target.context and item.capture.source == row.target.node.key), None)
        positive = type(state) is k.Known
        capture = None if request is None else request.capture
        allowed: set[k.ByteSpan] = set()
        if capture is not None:
            output = next((item for item in self.result.executed if item.receipt.capture is capture), None)
            _need(output is not None and capture.source == row.target.node.key and capture.operation == parser.OP, "scope")
            if output is None:
                raise ValueError("vrrp_proofs_capture")
            claims = parser.validate_claims(capture, output.value)
            allowed = {point for claim, points in claims
                       if claim.interface.raw == row.interface and claim.group.raw == row.group for point in points}
            _need(not positive or capture.integrity is k.IntegrityState.COMPLETE and capture.error is None
                  and output.value.parse.quality == "complete", "capture")
        whole_sha = "" if capture is None else sha256(capture.raw).hexdigest()
        registry: list[k.RegistryRef] = []
        leaves: list[LocalCaptureLeaf] = []
        for ref in state.evidence:
            if type(ref) is k.RegistryRef:
                registry.append(ref)
                continue
            if not isinstance(ref, k.EvidenceRef):
                raise TypeError("vrrp_proofs_evidence")
            _need(type(ref) is k.EvidenceRef and type(ref.capture) is str
                  and type(ref.role) is k.EvidenceRole and capture is not None, "evidence")
            if capture is None:
                raise ValueError("vrrp_proofs_scope")
            _need(ref.capture == capture.id, "scope")
            _need(ref.role is (k.EvidenceRole.SUBJECT if positive else k.EvidenceRole.WITNESS), "role")
            point = ref.locator
            if isinstance(point, k.ByteSpan):
                _need(type(point) is k.ByteSpan and type(point.start) is int and type(point.end) is int
                      and 0 <= point.start < point.end <= len(capture.raw), "span")
                _need(point in allowed, "scope")
                raw = capture.raw[point.start:point.end]
            elif type(point) is k.WholeCapture:
                _need(not positive and ref.role is k.EvidenceRole.WITNESS, "role")
                raw = capture.raw
            else:
                raise ValueError("vrrp_proofs_span")
            _need(type(ref.excerpt_sha256) is str and sha256(raw).hexdigest() == ref.excerpt_sha256, "span")
            leaves.append(LocalCaptureLeaf(capture=capture, reference=ref, raw=raw,
                capture_sha256=whole_sha))
        _need(tuple(registry) == row.target.node.declaration.evidence
              and bool(leaves) == (request is not None), "evidence")
        return LocalVRRPProof(reference=reference, state=state, unexpanded_registry_refs=tuple(registry),
            capture_leaves=tuple(leaves), next_evidence=state.next_evidence if isinstance(state, k.Unknown) else ())
