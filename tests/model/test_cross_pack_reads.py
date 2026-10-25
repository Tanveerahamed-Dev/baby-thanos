"""Declared foreign reads preserve ownership, kernel states and graph refusals."""
import pytest

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.steps import order_steps
from atlas_brain.model.store import FactStore, bind_reader, bind_writer

FACT = k.FactId("l2.source.value")
RESULT = k.FactId("l1.consumer.result")
SUBJECT = k.EntityKey("node:synthetic")


def owner(*, scope="device", reads=()):
    return StepSpec(id=StepId("l2.source/parse"), pack=k.PackId("l2.source"),
                    kind="parse_build", scope=scope, reads=reads, produces=(FACT,),
                    evaluator="l2.source.parse")


def consumer(*, scope="device", reads=(FACT,), produces=(RESULT,)):
    return StepSpec(id=StepId("l1.consumer/derive"), pack=k.PackId("l1.consumer"),
                    kind="derive", scope=scope, reads=reads, produces=produces,
                    evaluator="l1.consumer.derive")


def witness(role=k.EvidenceRole.SUBJECT):
    return k.EvidenceRef(capture=k.CaptureId("cap:synthetic"),
                         locator=k.ByteSpan(start=0, end=1), role=role,
                         excerpt_sha256="a" * 64)


def states():
    return (
        k.Known(value="up", basis=k.Basis.OBSERVED, evidence=(witness(),), raw=None),
        k.Absent(kind="configured_line", basis=k.Basis.CONFIGURED,
                 evidence=(witness(k.EvidenceRole.ABSENCE_WITNESS),)),
        k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail=None, evidence=(),
                  candidates=(), next_evidence=()),
        k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=(witness(),)),
    )


@pytest.mark.parametrize("value", states(), ids=("known", "absent", "unknown", "not_applicable"))
@pytest.mark.parametrize("scope", ("device", "estate"))
def test_declared_foreign_read_preserves_the_exact_kernel_state(value, scope):
    producer, reader_step = owner(), consumer(scope=scope)
    # The consumer sorts first lexically: this order must come from the read edge.
    for steps in ((reader_step, producer), (producer, reader_step)):
        assert order_steps(steps) == (producer, reader_step)
    store = FactStore()
    bind_writer(store, step=producer).write(fact=FACT, subject=SUBJECT, value=value)
    actual = bind_reader(store, step=reader_step).read(fact=FACT, subject=SUBJECT)
    assert actual is value
    assert actual.evidence == value.evidence


def test_existing_foreign_fact_does_not_allow_an_undeclared_read():
    store, value = FactStore(), states()[0]
    bind_writer(store, step=owner()).write(fact=FACT, subject=SUBJECT, value=value)
    with pytest.raises(ValueError, match="undeclared_read:l2.source.value"):
        bind_reader(store, step=consumer(reads=())).read(fact=FACT, subject=SUBJECT)


def test_declared_foreign_read_does_not_grant_a_foreign_write():
    store, value = FactStore(), states()[0]
    bind_writer(store, step=owner()).write(fact=FACT, subject=SUBJECT, value=value)
    writer = bind_writer(store, step=consumer())
    with pytest.raises(ValueError, match="write_outside_produces:l2.source.value"):
        writer.write(fact=FACT, subject=SUBJECT, value=states()[1])
    assert bind_reader(store, step=consumer()).read(fact=FACT, subject=SUBJECT) is value


def test_consumer_cannot_declare_ownership_of_the_foreign_fact():
    with pytest.raises(ValueError, match="produce_outside_pack"):
        consumer(produces=(FACT,))


def test_declared_foreign_read_requires_the_subject_to_have_been_written():
    store = FactStore()
    bind_writer(store, step=owner())
    reader = bind_reader(store, step=consumer())
    with pytest.raises(ValueError, match="missing_fact:l2.source.value:node:synthetic"):
        reader.read(fact=FACT, subject=SUBJECT)
    value = states()[0]
    bind_writer(store, step=owner()).write(fact=FACT, subject=SUBJECT, value=value)
    assert reader.read(fact=FACT, subject=SUBJECT) is value


def test_foreign_read_edges_do_not_bypass_scope_or_cycle_checks():
    with pytest.raises(ValueError, match="device_reads_estate:l1.consumer/derive"):
        order_steps((owner(scope="estate"), consumer()))
    with pytest.raises(ValueError, match="cyclic_steps:l1.consumer/derive,l2.source/parse"):
        order_steps((consumer(), owner(reads=(RESULT,))))
