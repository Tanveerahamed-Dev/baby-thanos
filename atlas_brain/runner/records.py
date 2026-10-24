"""Runner records and stable refusal codes; integers only, no floats."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.kernel.states import digest, require

EXIT_OK = 0
EXIT_REFUSED = 2
DEFAULT_WORKERS = 4


class RunnerRefused(ValueError):
    """The run is refused; the argument is a stable machine-readable code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True, kw_only=True)
class RunResult:
    """Public API result: the manifest facts a caller needs, never the run bytes."""

    out: Path
    evidence_files: int
    evidence_digest: str
    steps: int
    egress_denied: int

    def __post_init__(self) -> None:
        require(type(self.evidence_files) is int and self.evidence_files >= 0, "invalid_evidence_files")
        digest(self.evidence_digest)
        require(type(self.steps) is int and self.steps >= 0, "invalid_step_count")
        require(type(self.egress_denied) is int and self.egress_denied >= 0, "invalid_denied_count")
