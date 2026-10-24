"""Deterministic catalogue bytes, digest stability and tamper refusal."""
import hashlib
import json

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel.states import FactId, PackId
from atlas_brain.model.catalogue import (
    CATALOGUE_SCHEMA,
    build_catalogue,
    catalogue_digest,
    verify_catalogue,
)
from atlas_brain.model.specs import (
    EntityKindSpec,
    FactSpec,
    RelationSpec,
    StepId,
    StepSpec,
)

PACK = PackId('l1.interface')
PINNED_DIGEST = '11e7541afb7e2cc48aa4d23ce01457ed4aadd2d4675ede885bb6524d0c9ae898'


def parse_step():
    return StepSpec(id=StepId('l1.interface/parse'), pack=PACK, kind='parse_build', scope='device',
                    reads=(), produces=(FactId('l1.interface.admin_state'), FactId('l1.interface.admin_up')),
                    evaluator='l1.interface.build.parse')


def check_step():
    return StepSpec(id=StepId('l1.interface/check'), pack=PACK, kind='check', scope='device',
                    reads=(FactId('l1.interface.admin_state'),), produces=(FactId('l1.interface.verdict'),),
                    evaluator='l1.interface.build.check')


def fact(name, value_type='text'):
    return FactSpec(id=FactId('l1.interface.' + name), pack=PACK, subject='interface',
                    value_type=value_type, step=StepId('l1.interface/parse'))


def kind():
    return EntityKindSpec(id='interface', pack=PACK, root=False)


def relation():
    return RelationSpec(id='l1.interface.adjacency', pack=PACK, source='interface',
                        target='interface', cardinality='one_to_many')


def catalogue(**overrides):
    parts = {'entity_kinds': (kind(),), 'facts': (fact('admin_state'), fact('admin_up', 'boolean')),
             'relations': (relation(),), 'steps': (parse_step(), check_step())}
    parts.update(overrides)
    return build_catalogue(**parts)


def test_catalogue_bytes_are_canonical_and_independent_of_input_order():
    first = catalogue()
    shuffled = catalogue(entity_kinds=(kind(),), facts=(fact('admin_up', 'boolean'), fact('admin_state')),
                         relations=(relation(),), steps=(check_step(), parse_step()))
    assert shuffled == first
    decoded = json.loads(first)
    assert decoded['schema'] == CATALOGUE_SCHEMA == 1
    assert [row['fact'] for row in decoded['facts']] == ['l1.interface.admin_state', 'l1.interface.admin_up']
    assert [row['step'] for row in decoded['steps']] == ['l1.interface/check', 'l1.interface/parse']
    assert canonical(decoded) == first


def test_catalogue_digest_is_stable_and_pinned():
    assert catalogue_digest(catalogue()) == PINNED_DIGEST
    assert PINNED_DIGEST == hashlib.sha256(catalogue()).hexdigest()


def test_verify_accepts_the_accepted_digest_and_refuses_a_modified_catalogue():
    accepted = catalogue()
    digest = catalogue_digest(accepted)
    verify_catalogue(accepted, digest=digest)
    tampered = accepted.replace(b'"text"', b'"integer"')
    assert tampered != accepted
    with pytest.raises(ValueError, match='catalogue_digest_mismatch'):
        verify_catalogue(tampered, digest=digest)
    with pytest.raises(ValueError, match='catalogue_digest_mismatch'):
        verify_catalogue(accepted, digest='0' * 64)
    with pytest.raises(ValueError, match='invalid_catalogue_bytes'):
        verify_catalogue('{}', digest=digest)


def test_duplicate_and_mistyped_collections_are_refused():
    with pytest.raises(ValueError, match='duplicate_catalogue_fact'):
        catalogue(facts=(fact('admin_state'), fact('admin_state')))
    with pytest.raises(ValueError, match='invalid_catalogue_steps'):
        catalogue(steps=(parse_step(), 'l1.interface/check'))
    with pytest.raises(ValueError, match='invalid_catalogue_entity_kinds'):
        build_catalogue(entity_kinds=[], facts=(), relations=(), steps=())


def test_empty_catalogue_is_deterministic():
    empty = build_catalogue(entity_kinds=(), facts=(), relations=(), steps=())
    assert json.loads(empty) == {'schema': 1, 'entity_kinds': [], 'facts': [], 'relations': [], 'steps': []}
    assert catalogue_digest(empty) == hashlib.sha256(empty).hexdigest()
