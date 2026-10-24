"""Closed fact states and raw-evidence locators (architecture section 1.3).

Constructors enforce structural invariants. Capture admissibility and evidence
resolution are enforced by the kernel admission and fact-writer boundaries.
"""
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, NewType, final

CaptureId = NewType('CaptureId', str)
EntityKey = NewType('EntityKey', str)
PackId = NewType('PackId', str)
FactId = NewType('FactId', str)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def text_fields(*values: str) -> None:
    require(all(type(v) is str and bool(v) for v in values), 'invalid_text_fields')


def digest(value: str) -> None:
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value, re.ASCII) is not None, 'invalid_digest')


@dataclass(frozen=True, slots=True, kw_only=True)
class ByteSpan:
    start: int
    end: int

    def __post_init__(self) -> None:
        require(type(self.start) is int and type(self.end) is int and 0 <= self.start <= self.end, 'invalid_span')


@dataclass(frozen=True, slots=True, kw_only=True)
class FieldPointer:
    pointer: str

    def __post_init__(self) -> None:
        require(type(self.pointer) is str and (self.pointer == '' or self.pointer.startswith('/'))
                and re.search('~(?![01])', self.pointer, re.ASCII) is None, 'invalid_pointer')


@dataclass(frozen=True, slots=True, kw_only=True)
class XmlPath:
    path: str

    def __post_init__(self) -> None:
        require(type(self.path) is str and self.path.startswith('/'), 'invalid_xml_path')


@dataclass(frozen=True, slots=True, kw_only=True)
class WholeCapture:
    pass


class EvidenceRole(StrEnum):
    SUBJECT = 'subject'
    DERIVED_FROM = 'derived_from'
    WITNESS = 'witness'
    ABSENCE_WITNESS = 'absence_witness'
    COUNTER_EVIDENCE = 'counter_evidence'


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceRef:
    capture: CaptureId
    locator: ByteSpan | FieldPointer | XmlPath | WholeCapture
    role: EvidenceRole
    excerpt_sha256: str

    def __post_init__(self) -> None:
        require(type(self.capture) is str and bool(self.capture), 'missing_capture')
        require(type(self.locator) in (ByteSpan, FieldPointer, XmlPath, WholeCapture), 'invalid_locator')
        require(type(self.role) is EvidenceRole, 'invalid_role')
        digest(self.excerpt_sha256)


@dataclass(frozen=True, slots=True, kw_only=True)
class FactRef:
    fact: FactId
    subject: EntityKey

    def __post_init__(self) -> None:
        text_fields(self.fact, self.subject)


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryRef:
    table: str
    row_id: str
    table_digest: str
    citation: str

    def __post_init__(self) -> None:
        text_fields(self.table, self.row_id, self.citation)
        digest(self.table_digest)


type Evidence = EvidenceRef | FactRef | RegistryRef


def evidence_tuple(evidence: tuple[Evidence, ...], *, nonempty: bool) -> None:
    require(type(evidence) is tuple and (bool(evidence) or not nonempty), 'invalid_evidence_tuple')
    require(all(type(e) in (EvidenceRef, FactRef, RegistryRef) for e in evidence), 'invalid_evidence')


def absence_witness(evidence: tuple[Evidence, ...]) -> None:
    evidence_tuple(evidence, nonempty=True)
    require(any(type(e) is EvidenceRef and e.role is EvidenceRole.ABSENCE_WITNESS for e in evidence), 'absence_witness_required')


class Basis(StrEnum):
    OBSERVED = 'observed'
    CONFIGURED = 'configured'
    DERIVED = 'derived'
    DECLARED = 'declared'
    CONTROLLER = 'controller'
    INFERRED = 'inferred'
    REGISTRY = 'registry'


class IntegrityState(StrEnum):
    COMPLETE = 'complete'
    EMPTY = 'empty'
    ABSENCE_BANNER = 'absence_banner'
    ERROR = 'error'
    TRUNCATED = 'truncated'
    PAGING_ARTIFACTS = 'paging_artifacts'
    UNVERIFIED_PROMPT = 'unverified_prompt'
    UNKNOWN_FORMAT = 'unknown_format'


class ReadScope(StrEnum):
    FULL_EVIDENCED = 'full_evidenced'
    NOT_SCOPE_SENSITIVE = 'not_scope_sensitive'
    LIMITED = 'limited'
    UNKNOWN = 'unknown'


class ViewConsistency(StrEnum):
    ATOMIC = 'atomic'
    SINGLE_RESPONSE = 'single_response'
    NON_ATOMIC = 'non_atomic'
    CACHED = 'cached'
    UNKNOWN = 'unknown'


class UnknownReason(StrEnum):
    NOT_COLLECTED = 'not_collected'
    PEER_NOT_COLLECTED = 'peer_not_collected'
    OUT_OF_SCOPE = 'out_of_scope'
    CAPTURE_ERROR = 'capture_error'
    CAPTURE_TRUNCATED = 'capture_truncated'
    EMPTY_UNREGISTERED = 'empty_unregistered'
    SCOPE_LIMITED = 'scope_limited'
    NON_ATOMIC_VIEW = 'non_atomic_view'
    BUDGET_EXCEEDED = 'budget_exceeded'
    PLATFORM_UNKNOWN = 'platform_unknown'
    PARSE_UNSUPPORTED_VARIANT = 'parse_unsupported_variant'
    PARSE_PARTIAL = 'parse_partial'
    FIELD_NOT_PRINTED = 'field_not_printed'
    DEFAULT_UNKNOWN = 'default_unknown'
    INHERITANCE_UNRESOLVED = 'inheritance_unresolved'
    UNMODELLED_PRESENT = 'unmodelled_present'
    IDENTITY_UNRESOLVED = 'identity_unresolved'
    IDENTITY_AMBIGUOUS = 'identity_ambiguous'
    SUBJECT_ABSENT_FROM_CAPTURE = 'subject_absent_from_capture'
    CONFLICTING_EVIDENCE = 'conflicting_evidence'
    STALE_EVIDENCE = 'stale_evidence'
    SINGLE_SAMPLE = 'single_sample'
    NOT_OBSERVABLE = 'not_observable'
    VIRTUAL_PLATFORM = 'virtual_platform'
    NO_BASELINE = 'no_baseline'
    AS_OF_MISSING = 'as_of_missing'
    JOIN_UNPROVEN = 'join_unproven'
    DENOMINATOR_OPEN = 'denominator_open'
    ANALYSIS_FAILED = 'analysis_failed'
    ANALYSIS_GAP = 'analysis_gap'


class NAReason(StrEnum):
    FEATURE_NOT_CONFIGURED = 'feature_not_configured'
    FEATURE_NOT_ENABLED = 'feature_not_enabled'
    ROLE_EXCLUDES = 'role_excludes'
    PLATFORM_LACKS_FEATURE = 'platform_lacks_feature'
    DECLARED_EXCLUSION = 'declared_exclusion'


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceNeed:
    node: EntityKey
    operation: str
    params: tuple[tuple[str, str], ...]
    resolves: tuple[str, ...]
    reruns: tuple[str, ...]
    after_s: int | None
    unprintable: tuple[str, ...]

    def __post_init__(self) -> None:
        text_fields(self.node, self.operation)
        require(type(self.params) is tuple and all(type(p) is tuple and len(p) == 2 and all(type(v) is str for v in p) for p in self.params), 'invalid_param_types')
        require(self.params == tuple(sorted(self.params)) and len(dict(self.params)) == len(self.params), 'invalid_params')
        for values in (self.resolves, self.reruns, self.unprintable):
            require(type(values) is tuple and values == tuple(sorted(set(values))), 'invalid_operation_refs')
            text_fields(*values)
        require(self.after_s is None or (type(self.after_s) is int and self.after_s >= 0), 'invalid_delay')


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class Known[T]:
    value: T
    basis: Basis
    evidence: tuple[Evidence, ...]
    raw: str | None

    def __post_init__(self) -> None:
        require(type(self.basis) is Basis, 'invalid_basis')
        evidence_tuple(self.evidence, nonempty=True)
        require(type(self.value) not in (list, dict, set, frozenset), 'mutable_or_unordered_value')
        if self.value == ():
            absence_witness(self.evidence)
        require(self.raw is None or type(self.raw) is str, 'invalid_raw')

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError('closed_fact_state')


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class Absent:
    kind: Literal['configured_line', 'closed_population_member']
    basis: Basis
    evidence: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        allowed = {'configured_line': (Basis.CONFIGURED,), 'closed_population_member': (Basis.OBSERVED, Basis.CONTROLLER)}
        require(type(self.basis) is Basis and self.kind in allowed and self.basis in allowed[self.kind], 'invalid_absence_basis')
        absence_witness(self.evidence)
        require(all(type(e) is EvidenceRef for e in self.evidence), 'capture_witness_required')

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError('closed_fact_state')


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class Unknown:
    reason: UnknownReason
    detail: str | None
    evidence: tuple[Evidence, ...]
    candidates: tuple[EntityKey, ...]
    next_evidence: tuple[EvidenceNeed, ...]

    def __post_init__(self) -> None:
        require(type(self.reason) is UnknownReason, 'invalid_unknown_reason')
        evidence_tuple(self.evidence, nonempty=self.reason not in (UnknownReason.NOT_COLLECTED, UnknownReason.OUT_OF_SCOPE))
        require(type(self.candidates) is tuple and self.candidates == tuple(sorted(set(self.candidates))), 'invalid_candidates')
        text_fields(*self.candidates)
        require(type(self.next_evidence) is tuple and all(type(n) is EvidenceNeed for n in self.next_evidence), 'invalid_next_evidence')
        require(self.detail is None or (type(self.detail) is str and re.fullmatch('[a-z][a-z0-9_]*', self.detail, re.ASCII) is not None), 'invalid_detail')

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError('closed_fact_state')


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class NotApplicable:
    reason: NAReason
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        require(type(self.reason) is NAReason, 'invalid_na_reason')
        evidence_tuple(self.evidence, nonempty=True)
        if self.reason is NAReason.FEATURE_NOT_CONFIGURED:
            absence_witness(self.evidence)

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError('closed_fact_state')


type Fact[T] = Known[T] | Absent | Unknown | NotApplicable
