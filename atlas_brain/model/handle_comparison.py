"""Pure next-use handle comparisons; retained anchors are caller-owned, not origin seals.

Capture actual handles and flat (fact, subject, value) locals before exposure.
Compare immediately before EACH class-qualified operation, including two writes
in one Row. Never rebuild arguments from mutable Row/Run fields after callbacks.
This checks handle/access shape, not payload meaning or whole-phase semantics.
Map content may grow. Callers protect anchors and perform final semantic closure.
"""
from dataclasses import dataclass

from atlas_brain.kernel import states as k
from atlas_brain.model import store as storage
from atlas_brain.model.specs import StepId, StepSpec

type Metadata = tuple[str, tuple[str, ...], tuple[str, ...]]
type Parts = tuple[storage.FactStore, StepSpec, dict[k.FactId, StepId],
    dict[k.FactRef, storage.StoredState], Metadata]


@dataclass(frozen=True, slots=True, kw_only=True)
class HandleComparison:
    handle: storage.FactReader | storage.FactWriter
    store: storage.FactStore
    step: StepSpec
    owners: dict[k.FactId, StepId]
    values: dict[k.FactRef, storage.StoredState]
    metadata: Metadata


def _need(condition: bool) -> None:
    k.require(condition, "store_handle_comparison")


def _metadata(value: Metadata) -> None:
    _need(type(value) is tuple and len(value) == 3 and type(value[0]) is str
        and type(value[1]) is tuple and type(value[2]) is tuple)
    _need(all(type(item) is str for item in value[1]) and all(type(item) is str for item in value[2]))


def _parts(handle: storage.FactReader | storage.FactWriter) -> Parts:
    kind = type(handle)
    _need(kind is storage.FactReader or kind is storage.FactWriter)
    current_store, step = handle.store, handle.step
    _need(type(current_store) is storage.FactStore and type(step) is StepSpec)
    metadata = (step.id, step.reads, step.produces)
    _metadata(metadata)
    owners, values = current_store.owners, current_store.values
    _need(type(owners) is dict and type(values) is dict)
    return current_store, step, owners, values, metadata


def _maps(owners: dict[k.FactId, StepId], values: dict[k.FactRef, storage.StoredState]) -> None:
    # Exact dict iteration does not hash/compare keys; close EVERY key first.
    _need(all(type(fact) is str and type(owner) is str for fact, owner in owners.items()))
    for reference in values:
        _need(type(reference) is k.FactRef)
        _need(type(reference.fact) is str and type(reference.subject) is str)


def retain_handle(handle: storage.FactReader | storage.FactWriter) -> HandleComparison:
    """Call only on the actual original handle before its first exposure."""
    current_store, step, owners, values, metadata = _parts(handle)
    _maps(owners, values)
    return HandleComparison(handle=handle, store=current_store, step=step,
        owners=owners, values=values, metadata=metadata)


def _compare(original: HandleComparison, handle: storage.FactReader | storage.FactWriter,
             kind: type[storage.FactReader] | type[storage.FactWriter], fact: k.FactId, subject: k.EntityKey) -> None:
    _need(type(handle) is kind and type(original) is HandleComparison)
    current_store, step, owners, values, metadata = _parts(handle)
    _need(handle is original.handle and current_store is original.store and step is original.step
        and owners is original.owners and values is original.values)
    _metadata(original.metadata)
    _maps(owners, values)
    _need(type(fact) is str and type(subject) is str)
    _need(metadata == original.metadata)


def compare_reader(original: HandleComparison, reader: storage.FactReader,
                   *, fact: k.FactId, subject: k.EntityKey) -> None:
    """Pass only pre-exposure locals; then call FactReader.read(reader, ...)."""
    _compare(original, reader, storage.FactReader, fact, subject)


def compare_writer(original: HandleComparison, writer: storage.FactWriter,
                   *, fact: k.FactId, subject: k.EntityKey, value: object) -> None:
    """Class-close only the write value; nested state meaning remains caller-owned."""
    _compare(original, writer, storage.FactWriter, fact, subject)
    kind = type(value)
    _need(kind is k.Known or kind is k.Absent or kind is k.Unknown or kind is k.NotApplicable)
