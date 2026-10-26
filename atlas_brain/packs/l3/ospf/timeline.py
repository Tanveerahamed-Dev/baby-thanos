"""Conservative collector intervals; no sample selection, votes or clock reads."""
import re
from typing import cast

from atlas_brain.kernel import states as k
from atlas_brain.model.store import StoredState

type TimeFacts = tuple[StoredState, StoredState, StoredState]
type RoundTimes = tuple[TimeFacts, TimeFacts]


def unknown(reason: k.UnknownReason, detail: str | None, evidence: tuple[k.Evidence, ...],
            needs: tuple[k.EvidenceNeed, ...], origin: k.Unknown | None = None) -> k.Unknown:
    requests = set(needs + (origin.next_evidence if origin is not None else ()))
    ordered = tuple(sorted(requests, key=lambda item: (
        item.node, item.operation, item.params, item.resolves, item.reruns,
        item.after_s if item.after_s is not None else -1, item.unprintable)))
    return k.Unknown(reason=reason, detail=detail, evidence=evidence,
                     candidates=origin.candidates if origin is not None else (), next_evidence=ordered)


def measure(rounds: tuple[RoundTimes, ...], *, evidence: tuple[k.Evidence, ...],
            needs: tuple[k.EvidenceNeed, ...]) -> k.Known[int] | k.Unknown:
    """Return the guaranteed first-to-last separation, independent of OSPF state."""
    gaps: list[k.Unknown] = []
    for pair in rounds:
        k.require(type(pair) is tuple and len(pair) == 2, "ospf_time_round")
        for fields in pair:
            k.require(type(fields) is tuple and len(fields) == 3, "ospf_time_fields")
            for index, state in enumerate(fields):
                k.require(type(state) in (k.Known, k.Unknown), "ospf_time_state")
                if isinstance(state, k.Unknown):
                    gaps.append(state)
                elif isinstance(state, k.Known):
                    k.require(state.basis is k.Basis.DECLARED, "ospf_time_basis")
                    expected = str if index == 0 else int
                    k.require(type(state.value) is expected, "ospf_time_value")
                    if index == 0:
                        k.require(re.fullmatch(r"collector:[A-Za-z0-9_.:/-]{1,64}",
                                              cast(str, state.value), re.ASCII) is not None, "ospf_time_clock")
                    else:
                        k.require(0 <= cast(int, state.value) <= 9007199254740991, "ospf_time_value")
            if isinstance(fields[1], k.Known) and isinstance(fields[2], k.Known):
                k.require(cast(int, fields[1].value) <= cast(int, fields[2].value), "ospf_time_order")
    if not rounds:
        return unknown(k.UnknownReason.NOT_COLLECTED, "no_collection_rounds", evidence, needs)
    if gaps:
        gap = gaps[0]
        missing = gap.reason in (k.UnknownReason.NOT_COLLECTED, k.UnknownReason.AS_OF_MISSING)
        return unknown(k.UnknownReason.AS_OF_MISSING if missing else gap.reason,
                       "collector_time_required" if missing else gap.detail, evidence, needs, gap)
    intervals: list[tuple[str, int, int]] = []
    for pair in rounds:
        values = tuple((cast(k.Known[str], fields[0]).value, cast(k.Known[int], fields[1]).value,
                        cast(k.Known[int], fields[2]).value) for fields in pair)
        if values[0][0] != values[1][0]:
            return unknown(k.UnknownReason.AS_OF_MISSING, "collector_clock_mismatch", evidence, needs)
        if values[0] != values[1]:
            return unknown(k.UnknownReason.CONFLICTING_EVIDENCE, "round_collector_bounds_disagree", evidence, needs)
        intervals.append(values[0])
    if len({clock for clock, _, _ in intervals}) != 1:
        return unknown(k.UnknownReason.AS_OF_MISSING, "collector_clock_mismatch", evidence, needs)
    if len(intervals) == 1:
        return unknown(k.UnknownReason.SINGLE_SAMPLE, "second_collection_round_required", evidence, needs)
    intervals.sort(key=lambda item: (item[1], item[2]))
    if any(intervals[index + 1][1] <= intervals[index][2] for index in range(len(intervals) - 1)):
        return unknown(k.UnknownReason.NON_ATOMIC_VIEW, "collector_intervals_overlap", evidence, needs)
    return k.Known(value=intervals[-1][1] - intervals[0][2], basis=k.Basis.DERIVED,
                   raw=None, evidence=evidence)
