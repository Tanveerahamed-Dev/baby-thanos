from dataclasses import FrozenInstanceError
from typing import get_args

import pytest

from atlas_brain.kernel import states as k


def ref(role=k.EvidenceRole.SUBJECT):
    return k.EvidenceRef(capture=k.CaptureId('cap:synthetic'),
                         locator=k.ByteSpan(start=0, end=1), role=role,
                         excerpt_sha256='a' * 64)


def test_closed_fact_union_and_vocabularies():
    assert {getattr(t, '__origin__', t) for t in get_args(k.Fact.__value__)} == {
        k.Known, k.Absent, k.Unknown, k.NotApplicable}
    assert len(k.UnknownReason) == 30
    assert len(k.Basis) == 7
    assert len(k.NAReason) == 5
    assert len(k.IntegrityState) == 8
    assert len(k.ReadScope) == 4
    assert len(k.ViewConsistency) == 5
    for state in (k.Known, k.Absent, k.Unknown, k.NotApplicable):
        with pytest.raises(TypeError):
            type('Forged', (state,), {})


@pytest.mark.parametrize('factory', [
    lambda: k.Known(value=1, basis=k.Basis.OBSERVED, evidence=(), raw=None),
    lambda: k.Known(value=(), basis=k.Basis.OBSERVED, evidence=(ref(),), raw=None),
    lambda: k.Known(value=1, basis='observed', evidence=(ref(),), raw=None),
    lambda: k.Known(value=1, basis=k.Basis.OBSERVED, evidence=(object(),), raw=None),
    lambda: k.NotApplicable(reason='role_excludes', evidence=(ref(),)),
    lambda: k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=()),
    lambda: k.Absent(kind='configured_line', basis=k.Basis.OBSERVED,
                     evidence=(ref(k.EvidenceRole.ABSENCE_WITNESS),)),
    lambda: k.Absent(kind='configured_line', basis=k.Basis.CONFIGURED, evidence=(ref(),)),
    lambda: k.Unknown(reason='not_collected', detail=None, evidence=(), candidates=(), next_evidence=()),
    lambda: k.Unknown(reason=k.UnknownReason.PARSE_PARTIAL, detail=None, evidence=(), candidates=(), next_evidence=()),
    lambda: k.Unknown(reason=k.UnknownReason.IDENTITY_AMBIGUOUS, detail=None,
                      evidence=(ref(),), candidates=('node:b', 'node:a'), next_evidence=()),
    lambda: k.Unknown(reason=k.UnknownReason.IDENTITY_AMBIGUOUS, detail=None,
                      evidence=(ref(),), candidates=(1, 2), next_evidence=()),
    lambda: k.ByteSpan(start=-1, end=1),
    lambda: k.ByteSpan(start=True, end=1),
    lambda: k.FieldPointer(pointer='bad'),
    lambda: k.FieldPointer(pointer='/bad~2escape'),
    lambda: k.FactRef(fact=1, subject=2),
    lambda: k.RegistryRef(table=1, row_id='r', table_digest='a' * 64, citation='source'),
    lambda: k.EvidenceNeed(node='node:a', operation='example.read', params=(), resolves=['fact'], reruns=(), after_s=None, unprintable=()),
    lambda: k.Known(value=[], basis=k.Basis.OBSERVED, evidence=(ref(),), raw=None),
    lambda: k.EvidenceRef(capture=k.CaptureId(''), locator=k.WholeCapture(),
                          role=k.EvidenceRole.SUBJECT, excerpt_sha256='bad'),
])
def test_planted_invalid_states_are_refused(factory):
    with pytest.raises((TypeError, ValueError)):
        factory()


def test_known_is_frozen_slotted_and_requires_explicit_fields():
    known = k.Known(value=1, basis=k.Basis.OBSERVED, evidence=(ref(),), raw=None)
    with pytest.raises(FrozenInstanceError):
        known.value = 2
    assert not hasattr(known, '__dict__')
    with pytest.raises(TypeError):
        k.Known(value=1, evidence=(ref(),), raw=None)
    with pytest.raises(TypeError):
        k.Known(1, k.Basis.OBSERVED, (ref(),), None)


def test_positive_state_and_absence_witness_controls():
    witness = ref(k.EvidenceRole.ABSENCE_WITNESS)
    assert k.Known(value=(), basis=k.Basis.OBSERVED, evidence=(witness,), raw=None).value == ()
    assert k.Absent(kind='configured_line', basis=k.Basis.CONFIGURED, evidence=(witness,)).kind == 'configured_line'
    assert k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=(ref(),)).evidence
    assert k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail='never_attempted',
                     evidence=(), candidates=(), next_evidence=()).reason == k.UnknownReason.NOT_COLLECTED
    assert k.FieldPointer(pointer='/a~1b/~0').pointer
    assert k.RegistryRef(table='example', row_id='one', table_digest='a' * 64, citation='synthetic').row_id == 'one'
    assert k.FactRef(fact=k.FactId('example.fact'), subject=k.EntityKey('node:a')).fact
