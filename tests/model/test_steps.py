"""Deterministic producer-graph ordering and every graph refusal."""
import pytest

from atlas_brain.kernel.states import FactId, PackId
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps

PACK = PackId('l1.interface')


def fact(name):
    return FactId('l1.interface.' + name)


def step(name, *, reads=(), produces=(), scope='device'):
    return StepSpec(id=StepId('l1.interface/' + name), pack=PACK, kind='derive', scope=scope,
                    reads=tuple(fact(item) for item in reads),
                    produces=tuple(fact(item) for item in produces),
                    evaluator='l1.interface.build.' + name)


def ids(steps):
    return tuple(item.id for item in order_steps(steps))


def test_happy_path_orders_every_producer_before_its_reader():
    steps = (step('parse', produces=('raw',)), step('derive', reads=('raw',), produces=('admin',)),
             step('check', reads=('admin',), produces=('verdict',)))
    assert ids(steps) == ('l1.interface/parse', 'l1.interface/derive', 'l1.interface/check')


def test_input_order_is_irrelevant_and_ready_ties_are_lexicographic():
    steps = (step('z', produces=('z',)), step('a', produces=('a',)),
             step('join', reads=('a', 'z'), produces=('join',)))
    assert ids(steps) == ids(tuple(reversed(steps))) == ('l1.interface/a', 'l1.interface/z', 'l1.interface/join')
    newly_ready = (step('a', produces=('a',)), step('b', reads=('a',)), step('z'))
    assert ids(newly_ready) == ('l1.interface/a', 'l1.interface/b', 'l1.interface/z')


def test_duplicate_step_is_refused():
    with pytest.raises(ValueError, match='duplicate_step'):
        order_steps((step('a'), step('a')))


def test_duplicate_fact_producer_is_refused():
    with pytest.raises(ValueError, match='duplicate_producer:l1.interface.shared'):
        order_steps((step('a', produces=('shared',)), step('b', produces=('shared',))))


def test_missing_producer_is_refused():
    with pytest.raises(ValueError, match='missing_producer:l1.interface.missing'):
        order_steps((step('a', reads=('missing',)),))


def test_device_step_cannot_read_estate_facts():
    estate = step('estate', produces=('estate_fact',), scope='estate')
    with pytest.raises(ValueError, match='device_reads_estate:l1.interface/device'):
        order_steps((estate, step('device', reads=('estate_fact',))))
    assert len(order_steps((estate, step('summary', reads=('estate_fact',), scope='estate')))) == 2


@pytest.mark.parametrize('members', [
    ('a', 'b'),
    ('a', 'b', 'c'),
    ('a', 'c', 'b'),
])
def test_cyclic_registration_names_every_cycle_member(members):
    def cycle_step(index):
        return step(members[index], reads=(members[index - 1] + '_fact',),
                    produces=(members[index] + '_fact',))
    steps = tuple(cycle_step(index) for index in range(len(members)))
    with pytest.raises(ValueError) as refused:
        order_steps(steps)
    names = refused.value.args[0].removeprefix('cyclic_steps:').split(',')
    assert names == ['l1.interface/' + name for name in sorted(members)]


def test_cycle_error_does_not_name_a_downstream_non_cycle_step():
    cyclic = (step('a', reads=('b_fact',), produces=('a_fact',)),
              step('b', reads=('a_fact',), produces=('b_fact',)))
    with pytest.raises(ValueError) as refused:
        order_steps((*cyclic, step('tail', reads=('a_fact',))))
    assert refused.value.args[0] == 'cyclic_steps:l1.interface/a,l1.interface/b'


def test_only_step_spec_tuples_are_accepted():
    with pytest.raises(ValueError, match='invalid_steps'):
        order_steps([step('a')])
