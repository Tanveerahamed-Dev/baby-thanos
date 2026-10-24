"""Structural result-header projection; all analysis decisions are supplied by the runner."""
from dataclasses import asdict, dataclass
from typing import Literal

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel.states import CaptureId


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisAsOf:
    utc: str | None
    source: Literal["declared", "evidence_latest", "unknown"]
    evidence: tuple[CaptureId, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class EffectiveSemantics:
    packs: dict[str, str]
    checks: dict[str, str]


@dataclass(frozen=True, slots=True, kw_only=True)
class ResultHeader:
    schema: Literal["atlas-brain.result"]
    schema_version: Literal["0.1.0"]
    semantics: dict[str, int]
    effective_semantics: EffectiveSemantics
    catalogue_digest: str
    pack_build_fingerprints: dict[str, str]
    input_manifest_sha256: str
    options_sha256: str
    analysis_as_of: AnalysisAsOf
    status: Literal["complete", "incomplete"]


def encode_header(header: ResultHeader) -> bytes:
    return canonical(asdict(header))
