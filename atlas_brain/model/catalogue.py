"""Deterministic catalogue bytes and SHA-256 digest over declared model specs.

The catalogue is a pure sorted projection: declaration order never reaches the
bytes, and the digest is taken over RFC 8785 canonical bytes so a modified
catalogue cannot keep its accepted digest.
"""
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel.states import require
from atlas_brain.model.specs import EntityKindSpec, FactSpec, RelationSpec, StepSpec

CATALOGUE_SCHEMA = 1


def build_catalogue(
    *,
    entity_kinds: tuple[EntityKindSpec, ...],
    facts: tuple[FactSpec, ...],
    relations: tuple[RelationSpec, ...],
    steps: tuple[StepSpec, ...],
) -> bytes:
    """Return canonical catalogue bytes; unordered or duplicated input is refused."""
    require(type(entity_kinds) is tuple and all(type(spec) is EntityKindSpec for spec in entity_kinds),
            'invalid_catalogue_entity_kinds')
    require(type(facts) is tuple and all(type(spec) is FactSpec for spec in facts),
            'invalid_catalogue_facts')
    require(type(relations) is tuple and all(type(spec) is RelationSpec for spec in relations),
            'invalid_catalogue_relations')
    require(type(steps) is tuple and all(type(spec) is StepSpec for spec in steps),
            'invalid_catalogue_steps')
    ordered_kinds = sorted(entity_kinds, key=lambda spec: spec.id)
    ordered_facts = sorted(facts, key=lambda spec: spec.id)
    ordered_relations = sorted(relations, key=lambda spec: spec.id)
    ordered_steps = sorted(steps, key=lambda spec: spec.id)
    require(len({spec.id for spec in ordered_kinds}) == len(ordered_kinds), 'duplicate_catalogue_entity_kind')
    require(len({spec.id for spec in ordered_facts}) == len(ordered_facts), 'duplicate_catalogue_fact')
    require(len({spec.id for spec in ordered_relations}) == len(ordered_relations), 'duplicate_catalogue_relation')
    require(len({spec.id for spec in ordered_steps}) == len(ordered_steps), 'duplicate_catalogue_step')
    body: dict[str, object] = {
        'schema': CATALOGUE_SCHEMA,
        'entity_kinds': [spec.row() for spec in ordered_kinds],
        'facts': [spec.row() for spec in ordered_facts],
        'relations': [spec.row() for spec in ordered_relations],
        'steps': [spec.row() for spec in ordered_steps],
    }
    return canonical(body)


def catalogue_digest(catalogue: bytes) -> str:
    """SHA-256 hex digest over already-canonical catalogue bytes."""
    require(type(catalogue) is bytes and bool(catalogue), 'invalid_catalogue_bytes')
    return sha256(catalogue).hexdigest()


def verify_catalogue(catalogue: bytes, *, digest: str) -> None:
    """Refuse bytes whose digest does not match the accepted catalogue digest."""
    require(type(digest) is str and catalogue_digest(catalogue) == digest, 'catalogue_digest_mismatch')
