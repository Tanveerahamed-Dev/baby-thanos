"""Canonical interval records from S1 1.11.4 / S5 5.4.1; no clock reads."""
import re
from dataclasses import dataclass
from enum import StrEnum

from .states import require


class BoundSource(StrEnum):
    COLLECTOR_RECORDED = 'collector_recorded'
    PER_EVENT_QUALITY = 'per_event_quality'
    CAPTURE_CONCURRENT = 'capture_concurrent'
    SAME_ANCHOR_RELATIVE = 'same_anchor_relative'
    UNBOUNDED = 'unbounded'


@dataclass(frozen=True, slots=True, kw_only=True)
class TimeInterval:
    earliest: int | None
    latest: int | None
    clock: str
    bound: BoundSource

    def __post_init__(self) -> None:
        require(type(self.bound) is BoundSource, 'invalid_bound_source')
        for endpoint in (self.earliest, self.latest):
            require(endpoint is None or type(endpoint) is int, 'invalid_time_endpoint')
        require(type(self.clock) is str and re.fullmatch(
            r'(?:collector:[A-Za-z0-9_.:/-]+|node:[A-Za-z0-9_.:/-]+/epoch:[A-Za-z0-9_.:-]+)',
            self.clock, re.ASCII) is not None, 'invalid_clock_identity')
        unbounded = self.earliest is None or self.latest is None
        require(unbounded == (self.bound is BoundSource.UNBOUNDED), 'inconsistent_bound_source')
        if self.earliest is not None and self.latest is not None:
            require(self.earliest <= self.latest, 'reversed_time_interval')
