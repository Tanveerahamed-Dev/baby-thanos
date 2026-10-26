"""Pure interval tests cover uncertainty bounds rather than timestamp midpoints."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.ospf import specs as s
from atlas_brain.packs.l3.ospf import timeline

REF = k.RegistryRef(table="synthetic_p3.samples", row_id="first",
                    table_digest=sha256(b"generated-collector-record").hexdigest(), citation="/samples/0")
PROOF = (REF,)
NEED = k.EvidenceNeed(node="node:demo:a", operation="iosxe.show_ip_ospf_neighbor", params=(),
    resolves=(str(s.SPAN),), reruns=(str(s.SETTLE.id),), after_s=120,
    unprintable=("collector_time_required",))


def known(value):
    return k.Known(value=value, basis=k.Basis.DECLARED, evidence=PROOF, raw=None)


def fields(start, end=None, clock="collector:test"):
    return known(clock), known(start), known(start if end is None else end)


def pair(start, end=None, clock="collector:test"):
    values = fields(start, end, clock)
    return values, values


def measure(*rounds):
    return timeline.measure(rounds, evidence=PROOF, needs=(NEED,))


def gap(reason=k.UnknownReason.AS_OF_MISSING):
    return k.Unknown(reason=reason, detail="original_time_gap", evidence=PROOF,
                     candidates=(), next_evidence=(NEED,))


@pytest.mark.parametrize("separation", [119999999, 120000000])
def test_guaranteed_lower_bound_uses_later_earliest_minus_earlier_latest(separation):
    result = measure(pair(0, 100), pair(separation + 100, separation + 900))
    assert isinstance(result, k.Known) and result.value == separation and result.basis is k.Basis.DERIVED
    assert result.evidence == PROOF and result.raw is None


def test_numeric_order_and_every_intermediate_interval_are_respected():
    assert measure(pair(240000000), pair(0), pair(120000000)).value == 240000000
    result = measure(pair(0), pair(100, 200000000), pair(120000000, 240000000))
    assert result.reason is k.UnknownReason.NON_ATOMIC_VIEW


@pytest.mark.parametrize("rounds", [(pair(0, 10), pair(10, 20)), (pair(0, 10), pair(0, 10)),
                                    (pair(0, 20), pair(10, 30))])
def test_closed_interval_overlap_and_duplicate_bounds_are_unknown(rounds):
    assert measure(*rounds).reason is k.UnknownReason.NON_ATOMIC_VIEW


def test_per_round_bounds_must_agree_on_both_ends_and_clock_is_global():
    assert measure((fields(0), fields(1))).reason is k.UnknownReason.CONFLICTING_EVIDENCE
    assert measure((fields(0), fields(0, clock="collector:other"))).reason is k.UnknownReason.AS_OF_MISSING
    assert measure(pair(0), pair(120000000, clock="collector:other")).reason is k.UnknownReason.AS_OF_MISSING


def test_missing_round_time_is_not_skipped_and_producer_error_is_retained():
    missing = (gap(), known(1), known(1))
    result = measure(pair(0), (missing, missing), pair(240000000))
    assert result.reason is k.UnknownReason.AS_OF_MISSING and result.next_evidence == (NEED,)
    failed = (gap(k.UnknownReason.CAPTURE_ERROR), known(1), known(1))
    result = measure((failed, failed))
    assert result.reason is k.UnknownReason.CAPTURE_ERROR and result.detail == "original_time_gap"


def test_zero_one_and_one_untimed_round_are_distinct():
    assert measure().reason is k.UnknownReason.NOT_COLLECTED
    assert measure(pair(0, 100)).reason is k.UnknownReason.SINGLE_SAMPLE
    missing = (gap(), known(0), known(1))
    assert measure((missing, missing)).reason is k.UnknownReason.AS_OF_MISSING


@pytest.mark.parametrize("index,value", [(0, "node:a/epoch:1"), (0, "collector:" + "a" * 65),
    (1, True), (1, -1), (2, 9007199254740992), (2, 1.5)])
def test_bad_clock_or_integer_contract_refuses(index, value):
    values = list(fields(0))
    values[index] = known(value)
    with pytest.raises(ValueError, match="ospf_time_"):
        measure((tuple(values), fields(0)))


def test_bad_basis_or_reversed_bounds_refuse_before_returning_an_earlier_gap():
    values = fields(0)
    wrong = (gap(), replace(values[1], basis=k.Basis.OBSERVED), values[2])
    with pytest.raises(ValueError, match="ospf_time_basis"):
        measure((wrong, values))
    with pytest.raises(ValueError, match="ospf_time_order"):
        measure(pair(10, 9))

    with pytest.raises(ValueError, match="ospf_time_order"):
        measure(((gap(), known(0), known(0)), fields(0)), pair(10, 9))
