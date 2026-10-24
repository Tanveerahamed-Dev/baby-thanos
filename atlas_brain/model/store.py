"""Single-owner fact store: step-bound writer, declared-read reader, kernel states.

The store is the only place facts exist at rest. A writer is bound to one
registered step and may write only that step's declared outputs; a reader is
bound to one step's declared inputs. Ownership is registered once per fact id
and each (fact, subject) pair is written at most once.
"""
from dataclasses import dataclass
from typing import cast

from atlas_brain.kernel.states import (
    Absent,
    EntityKey,
    FactId,
    FactRef,
    Known,
    NotApplicable,
    Unknown,
    require,
)
from atlas_brain.model.specs import StepId, StepSpec

type StoredState = Known[object] | Absent | Unknown | NotApplicable


class FactStore:
    """Single-owner registry over step-declared facts."""

    owners: dict[FactId, StepId]
    values: dict[FactRef, StoredState]

    def __init__(self) -> None:
        self.owners = {}
        self.values = {}

    def register(self, *, step: StepSpec) -> None:
        """Record step ownership of its declared outputs, refusing a second owner."""
        for fact in step.produces:
            owner = self.owners.get(fact)
            require(owner is None or owner == step.id, 'duplicate_owner:' + fact)
            self.owners[fact] = step.id


@dataclass(frozen=True, slots=True, kw_only=True)
class FactWriter:
    """A write handle bound to one step's declared productions."""

    store: FactStore
    step: StepSpec

    def write[T](self, *, fact: FactId, subject: EntityKey,
                 value: Known[T] | Absent | Unknown | NotApplicable) -> None:
        store = self.store
        require(fact in self.step.produces, 'write_outside_produces:' + fact)
        require(store.owners.get(fact) == self.step.id, 'unregistered_writer:' + fact)
        require(type(value) in (Known, Absent, Unknown, NotApplicable), 'invalid_fact_state')
        reference = FactRef(fact=fact, subject=subject)
        require(reference not in store.values, 'duplicate_write:' + fact + ':' + subject)
        store.values[reference] = cast('StoredState', value)


@dataclass(frozen=True, slots=True, kw_only=True)
class FactReader:
    """A read handle bound to one step's declared consumptions."""

    store: FactStore
    step: StepSpec

    def read(self, *, fact: FactId, subject: EntityKey) -> StoredState:
        require(fact in self.step.reads, 'undeclared_read:' + fact)
        reference = FactRef(fact=fact, subject=subject)
        require(reference in self.store.values, 'missing_fact:' + fact + ':' + subject)
        return self.store.values[reference]


def bind_writer(store: FactStore, *, step: StepSpec) -> FactWriter:
    """Register the step as owner of its outputs and return its write handle."""
    store.register(step=step)
    return FactWriter(store=store, step=step)


def bind_reader(store: FactStore, *, step: StepSpec) -> FactReader:
    """Return a read handle restricted to the step's declared inputs."""
    return FactReader(store=store, step=step)
