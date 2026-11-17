"""Test-only first-callback plants; actual handle comparisons are qualified model APIs."""
from copy import copy
from dataclasses import replace

from atlas_brain.kernel import states as k

HANDLE_FAULTS=("class","foreign_store","cloned_store","step_clone","foreign_step","owners","values","owner_key","fact_key","step_reads")
DATA_FAULTS=("row_class","source_class","subject","value")


def poison_handle(handle,fault,calls):
    class Foreign:
        def __getattribute__(self,name):calls.append(name);raise AssertionError
    class Text(str):
        __hash__=str.__hash__
        def __eq__(self,_other):calls.append("equality");raise AssertionError
        def encode(self,*_args,**_kw):calls.append("encode");raise AssertionError
    if fault=="class":
        class Hook(type(handle)):
            __slots__=()
            __getattribute__=Foreign.__getattribute__
        object.__setattr__(handle,"__class__",Hook)
    elif fault=="foreign_store":object.__setattr__(handle,"store",Foreign())
    elif fault=="cloned_store":object.__setattr__(handle,"store",copy(handle.store))
    elif fault=="step_clone":object.__setattr__(handle,"step",replace(handle.step))
    elif fault=="foreign_step":object.__setattr__(handle,"step",Foreign())
    elif fault=="owners":handle.store.owners=dict(handle.store.owners)
    elif fault=="values":handle.store.values=dict(handle.store.values)
    elif fault=="owner_key":
        owner=next(iter(handle.store.owners.values()))
        handle.store.owners.clear()
        handle.store.owners[Text("foreign_owner")]=owner
    elif fault=="fact_key":object.__setattr__(next(iter(handle.store.values)),"fact",Text("l3.fhrp.reported_state"))
    elif fault=="step_reads":
        class Tuple(tuple):
            def __iter__(self):calls.append("iteration");raise AssertionError
        object.__setattr__(handle.step,"reads",Tuple(handle.step.reads))
    else:raise ValueError("first_use_fault")


def poison_data(rows,fault,calls):
    row=rows[1]
    if fault in ("row_class","source_class"):
        target=row if fault=="row_class" or "source" not in type(row).__dataclass_fields__ else row.source
        class Hook(type(target)):
            __slots__=()
            def __getattribute__(self,name):calls.append(name);raise AssertionError
        object.__setattr__(target,"__class__",Hook)
    elif fault=="subject":
        target=row.source if "source" in type(row).__dataclass_fields__ else row
        class Text(str):
            __hash__=str.__hash__
            def __eq__(self,_other):calls.append("equality");raise AssertionError
            def encode(self,*_args,**_kw):calls.append("encode");raise AssertionError
        object.__setattr__(target,"subject",Text(target.subject))
    elif fault=="value":
        target=next(row.value for row in rows[1:] if type(row.value) is k.Known)
        object.__setattr__(target,"value",not target.value if type(target.value) is bool else "forged")
    else:raise ValueError("first_use_fault")


def poison_value_class(value,calls):
    assert type(value) is k.Known and calls==[]
    class Equal(type):
        def __eq__(self,_other):calls.append("metaclass_equality");raise AssertionError
    class Hook[T](metaclass=Equal):
        __slots__=k.Known.__slots__
    assert Hook.__slots__==k.Known.__slots__ and calls==[]
    object.__setattr__(value,"__class__",Hook)
    assert type(value) is Hook and calls==[]
