"""Closed pack joins and reproducible registration, without executing evaluators."""
import json
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel.states import FactId, PackId
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import (
    EntityKindSpec,
    FactSpec,
    RelationSpec,
    StepId,
    StepSpec,
)

SOURCE, CONSUMER = PackId('test.source'), PackId('test.consumer')


def step(pack, name, *, kind='parse_build', reads=(), scope='device'):
    return StepSpec(id=StepId(pack + '/' + name), pack=pack, kind=kind, scope=scope,
                    reads=reads, produces=(FactId(pack + '.' + name),),
                    evaluator=pack + '.uninstalled.' + name)


def fact(producer):
    return FactSpec(id=producer.produces[0], pack=producer.pack, subject='node',
                    value_type='text', step=producer.id)


def declarations():
    alpha, beta = step(SOURCE, 'alpha'), step(SOURCE, 'beta')
    derive = step(CONSUMER, 'derive', kind='derive', reads=alpha.produces)
    source = PackDeclaration(pack=SOURCE,
                            entity_kinds=(EntityKindSpec(id='node', pack=SOURCE, root=True),
                                          EntityKindSpec(id='peer', pack=SOURCE, root=False)),
                            facts=(fact(alpha), fact(beta)),
                            relations=(RelationSpec(id=SOURCE + '.link', pack=SOURCE,
                                                    source='node', target='peer', cardinality='one_to_one'),
                                       RelationSpec(id=SOURCE + '.reverse', pack=SOURCE,
                                                    source='peer', target='node', cardinality='one_to_many')),
                            steps=(beta, alpha),
                            operations=(OperationBinding(operation='show.beta', step=beta.id),
                                        OperationBinding(operation='show.alpha', step=alpha.id)))
    consumer = PackDeclaration(pack=CONSUMER, entity_kinds=(), facts=(fact(derive),),
                               relations=(), steps=(derive,), operations=())
    return source, consumer


def test_foreign_subject_kind_and_read_compile_to_canonical_registration():
    source, consumer = declarations()
    actual = compile_packs((source, consumer))
    assert actual.steps == (source.steps[1], consumer.steps[0], source.steps[0])
    assert actual.operations == tuple(reversed(source.operations))
    assert actual.catalogue_bytes == build_catalogue(
        entity_kinds=source.entity_kinds, facts=source.facts + consumer.facts,
        relations=source.relations, steps=source.steps + consumer.steps)
    expected = {'schema': 'atlas-brain.pack-registration/1',
                'catalogue_sha256': sha256(actual.catalogue_bytes).hexdigest(),
                'packs': ['test.consumer', 'test.source'],
                'operations': [{'operation': 'show.alpha', 'step': 'test.source/alpha'},
                               {'operation': 'show.beta', 'step': 'test.source/beta'}]}
    assert json.loads(actual.registration_bytes) == expected
    assert actual.registration_bytes == canonical(expected)
    assert actual.registration_sha256 == sha256(actual.registration_bytes).hexdigest()


def test_input_permutations_preserve_every_compiled_field():
    source, consumer = declarations()
    shuffled = replace(source, entity_kinds=tuple(reversed(source.entity_kinds)),
                       facts=tuple(reversed(source.facts)), relations=tuple(reversed(source.relations)),
                       steps=tuple(reversed(source.steps)), operations=tuple(reversed(source.operations)))
    assert compile_packs((source, consumer)) == compile_packs((consumer, shuffled))


def test_swapping_operations_between_valid_parse_steps_changes_registration_only():
    source, consumer = declarations()
    first = compile_packs((source, consumer))
    swapped = replace(source, operations=(
        replace(source.operations[0], step=source.operations[1].step),
        replace(source.operations[1], step=source.operations[0].step)))
    second = compile_packs((swapped, consumer))
    assert first.catalogue_bytes == second.catalogue_bytes
    assert catalogue_digest(first.catalogue_bytes) == catalogue_digest(second.catalogue_bytes)
    assert first.steps == second.steps
    assert first.operations != second.operations
    assert first.registration_bytes != second.registration_bytes
    assert first.registration_sha256 != second.registration_sha256


def test_distinct_operations_may_share_one_parse_step():
    source = declarations()[0]
    aliased = replace(source, operations=tuple(
        replace(binding, step=source.steps[1].id) for binding in source.operations))
    actual = compile_packs((aliased,))
    assert len(actual.operations) == 2
    assert {binding.step for binding in actual.operations} == {source.steps[1].id}
    assert len(actual.steps) == 2


def test_unbound_parse_steps_remain_in_compiled_metadata():
    source = replace(declarations()[0], operations=())
    actual = compile_packs((source,))
    assert actual.operations == ()
    assert actual.steps == tuple(reversed(source.steps))
    assert {row['step'] for row in json.loads(actual.catalogue_bytes)['steps']} == {
        step.id for step in source.steps}


def test_empty_pack_membership_is_bound_even_without_catalogue_rows():
    empty = PackDeclaration(pack=PackId('test.empty'), entity_kinds=(), facts=(),
                            relations=(), steps=(), operations=())
    first, second = compile_packs(()), compile_packs((empty,))
    assert first.catalogue_bytes == second.catalogue_bytes
    assert first.steps == second.steps == first.operations == second.operations == ()
    assert json.loads(first.registration_bytes)['packs'] == []
    assert json.loads(second.registration_bytes)['packs'] == ['test.empty']
    assert first.registration_sha256 != second.registration_sha256


@pytest.mark.parametrize('field,code', [
    ('entity_kinds', 'entity_kind'), ('facts', 'fact'), ('relations', 'relation'), ('steps', 'step'),
])
def test_duplicate_catalogue_members_are_refused(field, code):
    source = declarations()[0]
    with pytest.raises(ValueError, match='duplicate_catalogue_' + code):
        compile_packs((replace(source, **{field: getattr(source, field) * 2}),))


@pytest.mark.parametrize('field', ['entity_kinds', 'facts', 'relations', 'steps', 'operations'])
@pytest.mark.parametrize('value', [[], ('mistyped',)])
def test_declarations_require_exact_typed_tuples(field, value):
    with pytest.raises(ValueError, match='invalid_pack_' + field):
        replace(declarations()[0], **{field: value})


@pytest.mark.parametrize('mutate,code', [
    (lambda p: replace(p, pack=PackId('test.other')), 'declared_member_outside_pack'),
    (lambda p: replace(p, facts=(replace(p.facts[0], subject='missing'), p.facts[1])),
     'missing_subject_kind'),
    (lambda p: replace(p, relations=(replace(p.relations[0], source='missing'),)), 'missing_relation_kind'),
    (lambda p: replace(p, relations=(replace(p.relations[0], target='missing'),)), 'missing_relation_kind'),
    (lambda p: replace(p, facts=(replace(p.facts[0], step=StepId('test.source/missing')), p.facts[1])),
     'missing_fact_step'),
    (lambda p: replace(p, facts=(replace(p.facts[0], step=p.facts[1].step), p.facts[1])),
     'fact_step_mismatch'),
    (lambda p: replace(p, steps=(p.steps[0], replace(p.steps[1], produces=()))), 'fact_step_mismatch'),
    (lambda p: replace(p, facts=p.facts[1:]), 'missing_fact_spec'),
    (lambda p: replace(p, steps=(p.steps[0], replace(p.steps[1], produces=(
        FactId('test.source.alpha'), FactId('test.source.extra'))))), 'missing_fact_spec'),
    (lambda p: replace(p, operations=(replace(p.operations[0], step=StepId('test.source/missing')),)),
     'invalid_operation_step'),
    (lambda p: replace(p, operations=(replace(p.operations[0], step=StepId('test.consumer/derive')),)),
     'declared_member_outside_pack'),
])
def test_broken_declaration_joins_are_refused(mutate, code):
    source = declarations()[0]
    assert compile_packs((source,)).operations
    with pytest.raises(ValueError, match=code):
        compile_packs((mutate(source),))


@pytest.mark.parametrize('kind', ['derive', 'check', 'population'])
def test_operation_binding_requires_a_parse_build_step(kind):
    source = declarations()[0]
    with pytest.raises(ValueError, match='invalid_operation_step'):
        compile_packs((replace(source, steps=(replace(source.steps[0], kind=kind), source.steps[1])),))


@pytest.mark.parametrize('case', ['pack', 'operation_within_pack', 'operation_across_packs'])
def test_duplicate_pack_and_operation_owners_are_refused(case):
    source, consumer = declarations()
    consumer = replace(consumer, steps=(replace(consumer.steps[0], kind='parse_build'),),
                       operations=(OperationBinding(operation='show.gamma', step=consumer.steps[0].id),))
    assert len(compile_packs((source, consumer)).operations) == 3
    if case == 'pack':
        invalid, code = (source, source), 'duplicate_pack'
    elif case == 'operation_within_pack':
        invalid, code = (replace(source, operations=source.operations * 2),), 'duplicate_operation'
    else:
        consumer = replace(consumer, operations=(replace(consumer.operations[0], operation='show.alpha'),))
        invalid, code = (source, consumer), 'duplicate_operation'
    with pytest.raises(ValueError, match=code):
        compile_packs(invalid)


@pytest.mark.parametrize('mutate,code', [
    (lambda s, c: replace(s, steps=(s.steps[0], replace(
        s.steps[1], reads=(FactId('test.source.missing'),)))), 'missing_producer:test.source.missing'),
    (lambda s, c: replace(s, steps=(replace(
        s.steps[0], produces=s.steps[1].produces), s.steps[1])), 'duplicate_producer:test.source.alpha'),
    (lambda s, c: replace(s, steps=(s.steps[0], replace(
        s.steps[1], scope='estate'))), 'device_reads_estate:test.consumer/derive'),
    (lambda s, c: replace(s, steps=(s.steps[0], replace(s.steps[1], reads=c.steps[0].produces))),
     'cyclic_steps:test.consumer/derive,test.source/alpha'),
])
def test_graph_failures_propagate_without_partial_compilation(mutate, code):
    source, consumer = declarations()
    assert len(compile_packs((source, consumer)).steps) == 3
    with pytest.raises(ValueError, match=code):
        compile_packs((mutate(source, consumer), consumer))


@pytest.mark.parametrize('operation', ['', 'show Alpha', 'Show.alpha', 'show..alpha', 'show.é', 'show.alpha\n', 3])
def test_invalid_operation_identifiers_are_refused(operation):
    with pytest.raises(ValueError, match='invalid_operation'):
        OperationBinding(operation=operation, step=StepId('test.source/alpha'))


def test_registration_inputs_and_records_are_closed_and_frozen():
    source, consumer = declarations()
    with pytest.raises(ValueError, match='invalid_pack_declarations'):
        compile_packs([source, consumer])
    with pytest.raises(ValueError, match='invalid_pack_declarations'):
        compile_packs(('mistyped',))
    with pytest.raises(ValueError, match='invalid_pack_id'):
        replace(source, pack=PackId('invalid'))
    with pytest.raises(ValueError, match='invalid_step_id'):
        replace(source.operations[0], step=StepId('invalid'))
    for record, field in ((source, 'pack'), (source.operations[0], 'operation'),
                          (compile_packs((source, consumer)), 'registration_sha256')):
        with pytest.raises(FrozenInstanceError):
            setattr(record, field, 'changed')
