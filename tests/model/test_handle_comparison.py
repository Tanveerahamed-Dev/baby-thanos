"""Pure handle comparisons and actual first-operation callback attacks."""
from dataclasses import replace

import pytest

from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison as comparison
from atlas_brain.model import store
from atlas_brain.model.specs import StepId, StepSpec

FACTS = (k.FactId("test.handle.first"), k.FactId("test.handle.second"))
SUBJECT = k.EntityKey("node:fixture")


def fixture():
    write = StepSpec(id=StepId("test.handle/write"), pack=k.PackId("test.handle"), kind="parse_build",
        scope="device", reads=(), produces=FACTS, evaluator="test.handle.write")
    read = StepSpec(id=StepId("test.handle/read"), pack=write.pack, kind="derive",
        scope="device", reads=FACTS, produces=(), evaluator="test.handle.read")
    source = store.FactStore()
    seed = store.bind_writer(source, step=write)
    ref = k.RegistryRef(table="fixture", row_id="one", table_digest="0" * 64, citation="/one")
    values = tuple(k.Known(value=word, basis=k.Basis.DECLARED, raw=word, evidence=(ref,)) for word in ("first", "second"))
    unselected = k.FactRef(fact=FACTS[0], subject=k.EntityKey("node:unselected"))
    store.FactWriter.write(seed, fact=unselected.fact, subject=unselected.subject, value=values[0])
    writer, reader = store.bind_writer(source, step=write), store.bind_reader(source, step=read)
    return source, writer, reader, values, unselected


def test_real_registered_growth_and_original_immutable_step_expectations():
    source, writer, reader, values, _ = fixture()
    original_writer, original_reader = comparison.retain_handle(writer), comparison.retain_handle(reader)
    cells = tuple((fact, SUBJECT, value) for fact, value in zip(FACTS, values, strict=True))
    for fact, subject, value in cells:
        comparison.compare_writer(original_writer, writer, fact=fact, subject=subject, value=value)
        store.FactWriter.write(writer, fact=fact, subject=subject, value=value)
    for fact, subject, value in cells:
        comparison.compare_reader(original_reader, reader, fact=fact, subject=subject)
        assert store.FactReader.read(reader, fact=fact, subject=subject) is value
    assert len(source.values) == 3 and source.values is original_writer.values is original_reader.values
    assert original_writer.metadata == ("test.handle/write", (), FACTS)
    assert original_reader.metadata == ("test.handle/read", FACTS, ())


@pytest.mark.parametrize("role", ["reader", "writer"])
@pytest.mark.parametrize("fault", [
    "handle_clone", "handle_get", "handle_set", "store_foreign", "store_clone", "store_get",
    "owners_clone", "values_clone", "owners_dict", "values_dict", "step_foreign", "step_clone", "step_get",
    "id_opaque", "reads_tuple", "produces_tuple", "reads_leaf", "produces_leaf",
    "id_changed", "reads_changed", "produces_changed", "owner_key", "owner_value",
    "foreign_key", "reference_get", "reference_fact", "reference_subject",
])
def test_real_first_callback_prevents_second_operation_before_any_hook(monkeypatch, role, fault):
    source, writer, reader, values, unselected = fixture()
    if role == "reader":
        for fact, value in zip(FACTS, values, strict=True):
            store.FactWriter.write(writer, fact=fact, subject=SUBJECT, value=value)
    handle = reader if role == "reader" else writer
    original = comparison.retain_handle(handle)
    step, owners, entries = handle.step, source.owners, source.values
    current = [handle]
    calls, operations, hit = [], [], []
    def hook(*args, **kwargs):
        calls.append("hook")
        raise AssertionError("unsafe next-use hook")
    class Foreign:
        __getattribute__ = hook
    class ForeignDict(dict):
        __iter__ = __getitem__ = __contains__ = hook
    class ForeignTuple(tuple):
        __iter__ = hook
    class Equal(str):
        __eq__ = hook
        __hash__ = str.__hash__
    class ForeignKey:
        __eq__ = hook
        __hash__ = object.__hash__
    def mutate():
        hit.append(True)
        if fault == "handle_clone": current[0] = replace(handle)
        elif fault in ("handle_get", "handle_set"):
            changed = type("ChangedHandle", (type(handle),), {"__slots__": (),
                "__getattribute__" if fault == "handle_get" else "__setattr__": hook})
            object.__setattr__(handle, "__class__", changed)
        elif fault == "store_foreign": object.__setattr__(handle, "store", Foreign())
        elif fault == "store_clone":
            clone = store.FactStore()
            clone.owners, clone.values = owners, entries
            object.__setattr__(handle, "store", clone)
        elif fault == "store_get":
            changed = type("ChangedStore", (store.FactStore,), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(source, "__class__", changed)
        elif fault == "owners_clone": source.owners = dict(owners)
        elif fault == "values_clone": source.values = dict(entries)
        elif fault == "owners_dict": source.owners = ForeignDict(owners)
        elif fault == "values_dict": source.values = ForeignDict(entries)
        elif fault == "step_foreign": object.__setattr__(handle, "step", Foreign())
        elif fault == "step_clone": object.__setattr__(handle, "step", replace(step))
        elif fault == "step_get":
            changed = type("ChangedStep", (StepSpec,), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(step, "__class__", changed)
        elif fault == "id_opaque": object.__setattr__(step, "id", Equal(step.id))
        elif fault == "reads_tuple": object.__setattr__(step, "reads", ForeignTuple(step.reads))
        elif fault == "produces_tuple": object.__setattr__(step, "produces", ForeignTuple(step.produces))
        elif fault == "reads_leaf": object.__setattr__(step, "reads", (Equal(FACTS[0]),))
        elif fault == "produces_leaf": object.__setattr__(step, "produces", (Equal(FACTS[0]),))
        elif fault == "id_changed": object.__setattr__(step, "id", "test.handle/changed")
        elif fault == "reads_changed": object.__setattr__(step, "reads", () if role == "reader" else FACTS)
        elif fault == "produces_changed": object.__setattr__(step, "produces", FACTS if role == "reader" else ())
        elif fault == "owner_key": owners[Equal("test.handle.unselected")] = step.id
        elif fault == "owner_value": owners[FACTS[0]] = Equal(step.id)
        elif fault == "foreign_key":
            entries.clear()
            entries[ForeignKey()] = values[0]
        elif fault == "reference_get":
            changed = type("ChangedRef", (k.FactRef,), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(unselected, "__class__", changed)
        elif fault == "reference_fact": object.__setattr__(unselected, "fact", Equal(unselected.fact))
        else: object.__setattr__(unselected, "subject", Equal(unselected.subject))
    real = store.FactReader.read if role == "reader" else store.FactWriter.write
    def operation(self, **kwargs):
        result = real(self, **kwargs)
        operations.append((kwargs["fact"], kwargs["subject"]))
        if len(operations) == 1:
            mutate()
        return result
    cells = tuple((fact, SUBJECT, value) for fact, value in zip(FACTS, values, strict=True))
    monkeypatch.setattr(store.FactReader if role == "reader" else store.FactWriter,
        "read" if role == "reader" else "write", operation)
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        for fact, subject, value in cells:
            local_handle = current[0]
            if role == "reader":
                comparison.compare_reader(original, local_handle, fact=fact, subject=subject)
                store.FactReader.read(local_handle, fact=fact, subject=subject)
            else:
                comparison.compare_writer(original, local_handle, fact=fact, subject=subject, value=value)
                store.FactWriter.write(local_handle, fact=fact, subject=subject, value=value)
    assert hit == [True] and calls == [] and operations == [(FACTS[0], SUBJECT)]


@pytest.mark.parametrize("role", ["reader", "writer"])
def test_capture_and_compare_are_pure_even_when_all_store_operations_are_forbidden(monkeypatch, role):
    _source, writer, reader, values, _ = fixture()
    handle = reader if role == "reader" else writer
    def forbidden(*args, **kwargs):
        pytest.fail("comparison performed a store operation")
    monkeypatch.setattr(store.FactReader, "read", forbidden)
    monkeypatch.setattr(store.FactWriter, "write", forbidden)
    monkeypatch.setattr(store.FactStore, "register", forbidden)
    monkeypatch.setattr(store, "bind_reader", forbidden)
    monkeypatch.setattr(store, "bind_writer", forbidden)
    original = comparison.retain_handle(handle)
    if role == "reader":
        assert comparison.compare_reader(original, handle, fact=FACTS[0], subject=SUBJECT) is None
    else:
        assert comparison.compare_writer(original, handle, fact=FACTS[0], subject=SUBJECT, value=values[0]) is None


@pytest.mark.parametrize("state", ["known", "absent", "unknown", "not_applicable"])
def test_exact_kernel_state_classes_keep_existing_registered_writer_semantics(state):
    source, writer, _reader, values, _ = fixture()
    witness = k.EvidenceRef(capture=k.CaptureId("cap:fixture"), locator=k.WholeCapture(),
        role=k.EvidenceRole.ABSENCE_WITNESS, excerpt_sha256="0" * 64)
    value = {"known": values[0],
        "absent": k.Absent(kind="configured_line", basis=k.Basis.CONFIGURED, evidence=(witness,)),
        "unknown": k.Unknown(reason=k.UnknownReason.NO_BASELINE, detail=None, evidence=values[0].evidence, candidates=(), next_evidence=()),
        "not_applicable": k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=values[0].evidence)}[state]
    original = comparison.retain_handle(writer)
    comparison.compare_writer(original, writer, fact=FACTS[0], subject=SUBJECT, value=value)
    store.FactWriter.write(writer, fact=FACTS[0], subject=SUBJECT, value=value)
    assert source.values[k.FactRef(fact=FACTS[0], subject=SUBJECT)] is value


@pytest.mark.parametrize("target", ["capture", "value", "carrier"])
def test_custom_metaclass_equality_never_participates_in_class_admission(target):
    _source, writer, _reader, _values, _ = fixture()
    original = comparison.retain_handle(writer)
    calls = []
    class Meta(type):
        def __eq__(cls, other):
            calls.append("equality")
            raise AssertionError("class equality")
        def __hash__(cls):
            calls.append("hash")
            raise AssertionError("class hash")
    class Foreign(metaclass=Meta):
        def __getattribute__(self, name):
            calls.append("attribute")
            raise AssertionError("foreign carrier read")
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        if target == "capture": comparison.retain_handle(Foreign())
        elif target == "carrier": comparison.compare_writer(Foreign(), writer, fact=FACTS[0], subject=SUBJECT, value=Foreign())
        else: comparison.compare_writer(original, writer, fact=FACTS[0], subject=SUBJECT, value=Foreign())
    assert calls == []


@pytest.mark.parametrize("role", ["reader", "writer"])
@pytest.mark.parametrize("field", ["fact", "subject"])
def test_access_arguments_must_be_plain_strings_before_membership_or_hash(role, field):
    _source, writer, reader, values, _ = fixture()
    handle = reader if role == "reader" else writer
    original = comparison.retain_handle(handle)
    calls = []
    class Equal(str):
        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError
        def __hash__(self):
            calls.append("hash")
            raise AssertionError
    fact, subject = (Equal(FACTS[0]), SUBJECT) if field == "fact" else (FACTS[0], Equal(SUBJECT))
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        if role == "reader": comparison.compare_reader(original, handle, fact=fact, subject=subject)
        else: comparison.compare_writer(original, handle, fact=fact, subject=subject, value=values[0])
    assert calls == []


@pytest.mark.parametrize("fault", ["step_tuple", "step_id", "owners", "values", "reference"])
def test_retain_refuses_already_hostile_graph_without_snapshot_hooks(fault):
    source, writer, _reader, _values, reference = fixture()
    calls = []
    def hook(*args, **kwargs):
        calls.append("hook")
        raise AssertionError
    class Tuple(tuple):
        __iter__ = hook
    class Dict(dict):
        __iter__ = hook
    class Equal(str):
        __eq__ = __hash__ = hook
    if fault == "step_tuple": object.__setattr__(writer.step, "produces", Tuple(FACTS))
    elif fault == "step_id": object.__setattr__(writer.step, "id", Equal(writer.step.id))
    elif fault == "owners": source.owners = Dict(source.owners)
    elif fault == "values": source.values = Dict(source.values)
    else: object.__setattr__(reference, "subject", Equal(reference.subject))
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        comparison.retain_handle(writer)
    assert calls == []


def test_reader_payloads_and_unused_step_fields_are_not_semantic_authority():
    source, _writer, reader, _values, reference = fixture()
    original = comparison.retain_handle(reader)
    payload = object()
    source.values[reference] = payload
    object.__setattr__(reader.step, "evaluator", payload)
    object.__setattr__(reader.step, "kind", payload)
    object.__setattr__(reader.step, "scope", payload)
    comparison.compare_reader(original, reader, fact=reference.fact, subject=reference.subject)
    assert store.FactReader.read(reader, fact=reference.fact, subject=reference.subject) is payload


def test_helper_does_not_replace_legacy_declared_read_write_and_duplicate_checks():
    _source, writer, reader, values, _ = fixture()
    original_writer, original_reader = comparison.retain_handle(writer), comparison.retain_handle(reader)
    foreign = k.FactId("test.handle.foreign")
    comparison.compare_reader(original_reader, reader, fact=foreign, subject=SUBJECT)
    with pytest.raises(ValueError, match="^undeclared_read:"):
        store.FactReader.read(reader, fact=foreign, subject=SUBJECT)
    comparison.compare_writer(original_writer, writer, fact=foreign, subject=SUBJECT, value=values[0])
    with pytest.raises(ValueError, match="^write_outside_produces:"):
        store.FactWriter.write(writer, fact=foreign, subject=SUBJECT, value=values[0])
    store.FactWriter.write(writer, fact=FACTS[0], subject=SUBJECT, value=values[0])
    comparison.compare_writer(original_writer, writer, fact=FACTS[0], subject=SUBJECT, value=values[0])
    with pytest.raises(ValueError, match="^duplicate_write:"):
        store.FactWriter.write(writer, fact=FACTS[0], subject=SUBJECT, value=values[0])


def test_cross_reader_writer_modes_refuse_with_real_handles():
    _source, writer, reader, values, _ = fixture()
    original_writer, original_reader = comparison.retain_handle(writer), comparison.retain_handle(reader)
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        comparison.compare_reader(original_writer, writer, fact=FACTS[0], subject=SUBJECT)
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        comparison.compare_writer(original_reader, reader, fact=FACTS[0], subject=SUBJECT, value=values[0])
