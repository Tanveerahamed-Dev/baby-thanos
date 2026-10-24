"""Step-bound writer, declared-read reader and single-owner registry refusals."""
import pytest

from atlas_brain.kernel import states as k
from atlas_brain.kernel.states import (
    Absent,
    CaptureId,
    EntityKey,
    FactId,
    Known,
    NAReason,
    NotApplicable,
    PackId,
    Unknown,
    UnknownReason,
)
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import (
    FactReader,
    FactStore,
    FactWriter,
    bind_reader,
    bind_writer,
)

PACK = PackId('l1.interface')
ADMIN = FactId('l1.interface.admin_state')
VERDICT = FactId('l1.interface.verdict')
SUBJECT = EntityKey('node:a')


def witness(role=k.EvidenceRole.SUBJECT):
    return k.EvidenceRef(capture=CaptureId('cap:synthetic'), locator=k.ByteSpan(start=0, end=1),
                         role=role, excerpt_sha256='a' * 64)


def known(value='up'):
    return Known(value=value, basis=k.Basis.OBSERVED, evidence=(witness(),), raw=None)


def step(name, *, reads=(), produces=()):
    return StepSpec(id=StepId('l1.interface/' + name), pack=PACK, kind='derive', scope='device',
                    reads=tuple(FactId('l1.interface.' + item) for item in reads),
                    produces=tuple(FactId('l1.interface.' + item) for item in produces),
                    evaluator='l1.interface.build.' + name)


def producer():
    return step('parse', produces=('admin_state', 'verdict'))


def consumer():
    return step('check', reads=('admin_state',), produces=('verdict',))


def test_writer_and_reader_roundtrip_a_kernel_state():
    store = FactStore()
    bind_writer(store, step=producer()).write(fact=ADMIN, subject=SUBJECT, value=known())
    state = bind_reader(store, step=consumer()).read(fact=ADMIN, subject=SUBJECT)
    assert isinstance(state, Known) and state.value == 'up'
    assert state.evidence[0].role is k.EvidenceRole.SUBJECT


def test_every_closed_state_is_storable():
    states = (known(), Absent(kind='configured_line', basis=k.Basis.CONFIGURED,
                              evidence=(witness(k.EvidenceRole.ABSENCE_WITNESS),)),
              Unknown(reason=UnknownReason.NOT_COLLECTED, detail=None, evidence=(),
                      candidates=(), next_evidence=()),
              NotApplicable(reason=NAReason.ROLE_EXCLUDES, evidence=(witness(),)))
    store = FactStore()
    writer = bind_writer(store, step=producer())
    for index, state in enumerate(states):
        writer.write(fact=ADMIN, subject=EntityKey('node:' + str(index)), value=state)
    reader = bind_reader(store, step=consumer())
    assert type(reader.read(fact=ADMIN, subject=EntityKey('node:2'))) is Unknown


def test_write_outside_the_steps_declared_productions_is_refused():
    store = FactStore()
    writer = bind_writer(store, step=step('a', produces=('admin_state',)))
    bind_writer(store, step=step('b', produces=('verdict',)))
    with pytest.raises(ValueError, match='write_outside_produces:l1.interface.verdict'):
        writer.write(fact=VERDICT, subject=SUBJECT, value=known())


def test_second_owner_of_a_fact_is_refused():
    store = FactStore()
    bind_writer(store, step=step('a', produces=('admin_state',)))
    with pytest.raises(ValueError, match='duplicate_owner:l1.interface.admin_state'):
        bind_writer(store, step=step('b', produces=('admin_state',)))


def test_second_write_of_one_fact_subject_is_refused():
    store = FactStore()
    writer = bind_writer(store, step=producer())
    writer.write(fact=ADMIN, subject=SUBJECT, value=known())
    with pytest.raises(ValueError, match='duplicate_write:l1.interface.admin_state:node:a'):
        writer.write(fact=ADMIN, subject=SUBJECT, value=known('down'))
    writer.write(fact=ADMIN, subject=EntityKey('node:b'), value=known('down'))


def test_undeclared_read_is_refused():
    store = FactStore()
    bind_writer(store, step=producer()).write(fact=ADMIN, subject=SUBJECT, value=known())
    with pytest.raises(ValueError, match='undeclared_read:l1.interface.admin_state'):
        bind_reader(store, step=producer()).read(fact=ADMIN, subject=SUBJECT)


def test_declared_read_before_its_producer_writes_is_refused():
    store = FactStore()
    bind_writer(store, step=producer())
    reader = bind_reader(store, step=consumer())
    with pytest.raises(ValueError, match='missing_fact:l1.interface.admin_state:node:a'):
        reader.read(fact=ADMIN, subject=SUBJECT)


def test_writer_must_be_bound_by_the_registry_and_values_must_be_kernel_states():
    store = FactStore()
    unregistered = FactWriter(store=store, step=producer())
    with pytest.raises(ValueError, match='unregistered_writer'):
        unregistered.write(fact=ADMIN, subject=SUBJECT, value=known())
    with pytest.raises(ValueError, match='invalid_fact_state'):
        bind_writer(store, step=producer()).write(fact=ADMIN, subject=SUBJECT, value='up')
    with pytest.raises(ValueError, match='invalid_evidence_tuple'):
        Known(value='up', basis=k.Basis.OBSERVED, evidence=(), raw=None)


def test_reader_is_bound_to_one_steps_declared_inputs():
    store = FactStore()
    bind_writer(store, step=producer()).write(fact=ADMIN, subject=SUBJECT, value=known())
    reader = bind_reader(store, step=consumer())
    other = step('other', reads=('verdict',))
    assert isinstance(reader, FactReader) and isinstance(bind_reader(store, step=other), FactReader)
    with pytest.raises(ValueError, match='undeclared_read:l1.interface.admin_state'):
        bind_reader(store, step=other).read(fact=ADMIN, subject=SUBJECT)
