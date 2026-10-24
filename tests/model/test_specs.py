"""Structural invariants of the closed model declaration records."""
from dataclasses import FrozenInstanceError
from typing import get_args

import pytest

from atlas_brain.kernel.states import FactId, PackId
from atlas_brain.model.specs import (
    Cardinality,
    EntityKindSpec,
    FactSpec,
    RelationSpec,
    StepId,
    StepKind,
    StepScope,
    StepSpec,
    ValueType,
)

PACK = PackId('l1.interface')


def fact(**overrides):
    fields = {'id': FactId('l1.interface.admin_state'), 'pack': PACK, 'subject': 'interface',
              'value_type': 'text', 'step': StepId('l1.interface/parse')}
    fields.update(overrides)
    return FactSpec(**fields)


def relation(**overrides):
    fields = {'id': 'l1.interface.adjacency', 'pack': PACK, 'source': 'interface',
              'target': 'interface', 'cardinality': 'one_to_one'}
    fields.update(overrides)
    return RelationSpec(**fields)


def kind(**overrides):
    fields = {'id': 'interface', 'pack': PACK, 'root': False}
    fields.update(overrides)
    return EntityKindSpec(**fields)


def step(**overrides):
    fields = {'id': StepId('l1.interface/parse'), 'pack': PACK, 'kind': 'parse_build',
              'scope': 'device', 'reads': (),
              'produces': (FactId('l1.interface.admin_state'),),
              'evaluator': 'l1.interface.build.parse'}
    fields.update(overrides)
    return StepSpec(**fields)


def test_closed_vocabularies_are_literal_unions():
    assert set(get_args(StepKind.__value__)) == {'check', 'derive', 'parse_build', 'population'}
    assert set(get_args(StepScope.__value__)) == {'device', 'estate'}
    assert set(get_args(ValueType.__value__)) == {'boolean', 'entity_ref', 'integer', 'text'}
    assert set(get_args(Cardinality.__value__)) == {'many_to_many', 'one_to_many', 'one_to_one'}


def test_valid_records_project_their_declaration_rows():
    assert kind().row() == {'entity_kind': 'interface', 'pack': PACK, 'root': False}
    assert fact().row() == {'fact': FactId('l1.interface.admin_state'), 'pack': PACK,
                            'step': StepId('l1.interface/parse'), 'subject': 'interface',
                            'value_type': 'text'}
    assert relation().row() == {'relation': 'l1.interface.adjacency', 'pack': PACK,
                                'source': 'interface', 'target': 'interface',
                                'cardinality': 'one_to_one'}
    assert step().row()['produces'] == (FactId('l1.interface.admin_state'),)


def test_specs_are_frozen_slotted_and_keyword_only():
    spec = fact()
    with pytest.raises(FrozenInstanceError):
        spec.subject = 'device'
    assert not hasattr(spec, '__dict__')
    with pytest.raises(TypeError):
        FactSpec(FactId('l1.interface.admin_state'), PACK, 'interface', 'text', StepId('l1.interface/parse'))
    with pytest.raises(TypeError):
        FactSpec(id=FactId('l1.interface.admin_state'), pack=PACK, subject='interface', value_type='text')


@pytest.mark.parametrize('build', [
    lambda: fact(id=FactId('l2.other.admin_state')),
    lambda: fact(id=FactId('orphan')),
    lambda: fact(pack=PackId('L1.Interface')),
    lambda: fact(subject='Interface'),
    lambda: fact(value_type='float'),
    lambda: fact(step=StepId('l1.interface/Parse')),
    lambda: fact(step=StepId('l2.other/parse')),
    lambda: kind(id='interface-1'),
    lambda: kind(pack=PackId('interface')),
    lambda: kind(root=1),
    lambda: relation(id='other.adjacency'),
    lambda: relation(cardinality='one_to_few'),
    lambda: relation(source=''),
    lambda: step(id=StepId('l1.interface')), lambda: step(pack=PackId('l2.other')),
    lambda: step(kind='render'), lambda: step(scope='site'),
    lambda: step(evaluator='l2.other.build.parse'),
    lambda: step(reads=(FactId('l1.interface.z'), FactId('l1.interface.a'))),
    lambda: step(produces=(FactId('l1.interface.a'), FactId('l1.interface.a'))),
    lambda: step(produces=[FactId('l1.interface.a')]),
    lambda: step(produces=(FactId('l2.other.a'),)),
])
def test_planted_invalid_specs_are_refused(build):
    with pytest.raises((TypeError, ValueError)):
        build()
