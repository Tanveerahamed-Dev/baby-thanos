"""Shared plants exercise actual qualified model handles; unit rows carry no runtime/admission claim."""
from dataclasses import dataclass

import pytest
from first_use_support import (
    DATA_FAULTS,
    HANDLE_FAULTS,
    poison_data,
    poison_handle,
    poison_value_class,
)

from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison as handles
from atlas_brain.model import store
from atlas_brain.model.specs import StepId, StepSpec

FACT=k.FactId("l3.fhrp.unit")
def steps():
    write=StepSpec(id=StepId("l3.fhrp/unit_write"),pack=k.PackId("l3.fhrp"),kind="derive",scope="device",
        reads=(),produces=(FACT,),evaluator="l3.fhrp.unit_write")
    read=StepSpec(id=StepId("l3.fhrp/unit_read"),pack=k.PackId("l3.fhrp"),kind="derive",scope="device",
        reads=(FACT,),produces=(),evaluator="l3.fhrp.unit_read")
    return write,read


def cells():
    return tuple((FACT,k.EntityKey("unit:"+str(index)),k.Known(value=True,raw=None,basis=k.Basis.DERIVED,
        evidence=(k.FactRef(fact=k.FactId("l3.fhrp.source"),subject=k.EntityKey("source")),))) for index in range(2))


@pytest.mark.parametrize("mode",["reader","writer"])
@pytest.mark.parametrize("fault",HANDLE_FAULTS)
def test_every_shared_handle_plant_stops_real_next_model_operation_without_foreign_hooks(mode,fault):
    values=cells()
    WRITE,READ=steps()
    storage=store.FactStore()
    if mode=="reader":
        writer=store.bind_writer(storage,step=WRITE)
        for fact,subject,value in values:store.FactWriter.write(writer,fact=fact,subject=subject,value=value)
        handle=store.bind_reader(storage,step=READ)
    else:handle=store.bind_writer(storage,step=WRITE)
    anchor=handles.retain_handle(handle)
    calls,ops=[],[]
    step,original_reads=handle.step,handle.step.reads
    try:
        with pytest.raises(ValueError):
            for fact,subject,value in values:
                if mode=="reader":
                    handles.compare_reader(anchor,handle,fact=fact,subject=subject)
                    store.FactReader.read(handle,fact=fact,subject=subject)
                else:
                    handles.compare_writer(anchor,handle,fact=fact,subject=subject,value=value)
                    store.FactWriter.write(handle,fact=fact,subject=subject,value=value)
                ops.append(subject)
                if len(ops)==1:poison_handle(handle,fault,calls)
    finally:
        object.__setattr__(step,"reads",original_reads)
    assert len(ops)==1 and calls==[]


def test_shared_metaclass_value_plant_is_closed_before_legacy_state_tuple_membership():
    values=cells()
    WRITE,_READ=steps()
    storage=store.FactStore()
    writer=store.bind_writer(storage,step=WRITE)
    anchor=handles.retain_handle(writer)
    calls=[]
    poison_value_class(values[1][2],calls)
    fact,subject,value=values[1]
    with pytest.raises(ValueError):handles.compare_writer(anchor,writer,fact=fact,subject=subject,value=value)
    assert calls==[] and storage.values=={}


@dataclass(frozen=True,slots=True,kw_only=True)
class Source:
    subject: k.EntityKey


@dataclass(frozen=True,slots=True,kw_only=True)
class Row:
    subject: k.EntityKey
    source: Source
    value: k.Known[bool]


@pytest.mark.parametrize("fault",DATA_FAULTS)
def test_data_plants_leave_captured_flat_model_operations_safe_until_whole_phase_check(fault):
    WRITE,_READ=steps()
    rows=tuple(Row(subject=subject,source=Source(subject=subject),value=value) for _fact,subject,value in cells())
    flat=tuple((FACT,row.subject,row.value) for row in rows)
    storage=store.FactStore()
    writer=store.bind_writer(storage,step=WRITE)
    anchor=handles.retain_handle(writer)
    calls,ops=[],[]
    for fact,subject,value in flat:
        handles.compare_writer(anchor,writer,fact=fact,subject=subject,value=value)
        store.FactWriter.write(writer,fact=fact,subject=subject,value=value)
        ops.append(subject)
        if len(ops)==1:poison_data(rows,fault,calls)
    assert len(ops)==2 and calls==[]
    assert not all(type(row) is Row and type(row.source) is Source and type(row.subject) is str
        and type(row.source.subject) is str and type(row.value) is k.Known and row.value.value is True for row in rows)
