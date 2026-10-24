"""CLI captures with explicit metadata and an evidence-bound legacy bridge."""
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Literal

from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval

from .text import TextLine


class Channel(StrEnum):
    CLI = "cli"
    REST = "rest"
    MDM = "mdm"
    FILE = "file"


class ErrorKind(StrEnum):
    INVALID_INPUT = "invalid_input"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"
    UNAUTHORIZED = "unauthorized"
    UNSUPPORTED = "unsupported"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True, kw_only=True)
class Scope:
    node: k.EntityKey
    vrf: str | None
    context: str | None
    vdc: str | None
    tenant: str | None
    afi: str | None
    instance: str | None
    plane: Literal["exec", "admin", "controller"]

    def __post_init__(self) -> None:
        k.text_fields(self.node)
        k.require(self.plane in ("exec", "admin", "controller"), "invalid_plane")
        for value in (self.vrf, self.context, self.vdc, self.tenant, self.afi, self.instance):
            if value is not None:
                k.text_fields(value)


@dataclass(frozen=True, slots=True, kw_only=True)
class CaptureMetadata:
    channel: Channel
    scope: Scope
    collected_utc: TimeInterval | k.Unknown
    error: ErrorKind | None
    integrity_evidence: tuple[k.EvidenceRef, ...]
    read_scope_evidence: tuple[k.Evidence, ...]
    envelope: None

    def __post_init__(self) -> None:
        k.require(type(self.scope) is Scope, "invalid_capture_scope")
        k.require(type(self.channel) is Channel and self.channel is Channel.CLI and self.envelope is None,
                  "cli_transport_required")
        k.require(self.error is None or type(self.error) is ErrorKind, "invalid_error_kind")
        k.evidence_tuple(self.integrity_evidence, nonempty=True)
        k.evidence_tuple(self.read_scope_evidence, nonempty=False)
        k.require(type(self.collected_utc) in (TimeInterval, k.Unknown), "invalid_collector_time")
        if isinstance(self.collected_utc, TimeInterval):
            k.require(self.collected_utc.bound in (BoundSource.COLLECTOR_RECORDED, BoundSource.UNBOUNDED)
                      and self.collected_utc.clock.startswith("collector:"), "recorded_collector_time_required")


def classify_cli(raw: bytes, succeeded: str, prompt_verified: bool) -> k.IntegrityState:
    if not prompt_verified or succeeded != "yes":
        return k.IntegrityState.UNVERIFIED_PROMPT
    return k.IntegrityState.EMPTY if not raw else k.IntegrityState.UNKNOWN_FORMAT


def unrecorded_time(witness: k.EvidenceRef) -> k.Unknown:
    return k.Unknown(reason=k.UnknownReason.AS_OF_MISSING, detail="no_collector_time",
                     evidence=(witness,), candidates=(), next_evidence=())


@dataclass(frozen=True, slots=True)
class Capture:
    id: k.CaptureId
    source: k.EntityKey
    operation: str | None
    rendered: str
    codec: str
    raw: bytes
    integrity: k.IntegrityState
    lines: tuple[TextLine, ...]
    read_scope: k.ReadScope
    view: k.ViewConsistency
    metadata: CaptureMetadata | None = None

    def __post_init__(self) -> None:
        k.text_fields(self.id, self.source, self.rendered, self.codec)
        k.require(type(self.raw) is bytes, "immutable_capture_bytes_required")
        k.require(self.operation is None or (type(self.operation) is str and bool(self.operation)), "invalid_operation")
        k.require(type(self.integrity) is k.IntegrityState and type(self.read_scope) is k.ReadScope
                  and type(self.view) is k.ViewConsistency, "invalid_capture_classification")
        k.require(self.metadata is None or type(self.metadata) is CaptureMetadata, "invalid_capture_metadata")
        metadata = self.resolved_metadata
        k.require(metadata.scope.node == self.source, "scope_source_mismatch")
        for ref in metadata.integrity_evidence:
            k.require(type(ref) is k.EvidenceRef and ref.capture == self.id, "capture_witness_mismatch")
            if type(ref.locator) is k.ByteSpan:
                k.require(ref.locator.end <= len(self.raw), "capture_witness_out_of_bounds")
                excerpt = self.raw[ref.locator.start:ref.locator.end]
            elif type(ref.locator) is k.WholeCapture:
                excerpt = self.raw
            else:
                raise ValueError("cli_witness_locator_required")
            k.require(ref.excerpt_sha256 == sha256(excerpt).hexdigest(), "capture_witness_mismatch")
        k.evidence_tuple(metadata.read_scope_evidence, nonempty=self.read_scope is not k.ReadScope.UNKNOWN)

    @property
    def resolved_metadata(self) -> CaptureMetadata:
        if self.metadata is not None:
            return self.metadata
        # Legacy manifest-v1 callers record neither collector time nor richer scope.
        witness = k.EvidenceRef(capture=self.id, locator=k.WholeCapture(), role=k.EvidenceRole.SUBJECT,
                                excerpt_sha256=self.bytes_sha256)
        return CaptureMetadata(channel=Channel.CLI, scope=Scope(node=self.source, vrf=None, context=None,
                               vdc=None, tenant=None, afi=None, instance=None, plane="exec"),
                               collected_utc=unrecorded_time(witness), error=None, integrity_evidence=(witness,),
                               read_scope_evidence=(), envelope=None)

    @property
    def channel(self) -> Channel:
        return self.resolved_metadata.channel

    @property
    def scope(self) -> Scope:
        return self.resolved_metadata.scope

    @property
    def collected_utc(self) -> TimeInterval | k.Unknown:
        return self.resolved_metadata.collected_utc

    @property
    def error(self) -> ErrorKind | None:
        return self.resolved_metadata.error

    @property
    def integrity_evidence(self) -> tuple[k.EvidenceRef, ...]:
        return self.resolved_metadata.integrity_evidence

    @property
    def read_scope_evidence(self) -> tuple[k.Evidence, ...]:
        return self.resolved_metadata.read_scope_evidence

    @property
    def envelope(self) -> None:
        return self.resolved_metadata.envelope

    @property
    def bytes_sha256(self) -> str:
        return sha256(self.raw).hexdigest()

    @property
    def byte_len(self) -> int:
        return len(self.raw)
