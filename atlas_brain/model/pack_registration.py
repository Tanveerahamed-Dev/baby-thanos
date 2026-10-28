"""Compile closed, static pack metadata; never load or execute evaluators.

Catalogue bytes retain schema 1. A separate registration digest binds pack
membership and operation ownership. Neither record proves capture admission,
population closure, network health, or the admission-to-output EX-02 witness.
"""
import re
from dataclasses import dataclass
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel.states import PackId, require
from atlas_brain.model.catalogue import build_catalogue, catalogue_digest
from atlas_brain.model.specs import (
    PACK,
    STEP,
    EntityKindSpec,
    FactSpec,
    RelationSpec,
    StepId,
    StepSpec,
)
from atlas_brain.model.steps import order_steps

REGISTRATION_SCHEMA = 'atlas-brain.pack-registration/1'
OPERATION = r'[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+'


@dataclass(frozen=True, slots=True, kw_only=True)
class OperationBinding:
    """An opaque operation identity and its statically declared producer."""

    operation: str
    step: StepId

    def __post_init__(self) -> None:
        require(type(self.operation) is str
                and re.fullmatch(OPERATION, self.operation, re.ASCII) is not None, 'invalid_operation')
        require(type(self.step) is str
                and re.fullmatch(STEP, self.step, re.ASCII) is not None, 'invalid_step_id')


@dataclass(frozen=True, slots=True, kw_only=True)
class PackDeclaration:
    """One pack's immutable declarations; cross-pack subjects remain legal."""

    pack: PackId
    entity_kinds: tuple[EntityKindSpec, ...]
    facts: tuple[FactSpec, ...]
    relations: tuple[RelationSpec, ...]
    steps: tuple[StepSpec, ...]
    operations: tuple[OperationBinding, ...]

    def __post_init__(self) -> None:
        require(type(self.pack) is str and re.fullmatch(PACK, self.pack, re.ASCII) is not None,
                'invalid_pack_id')
        require(type(self.entity_kinds) is tuple
                and all(type(spec) is EntityKindSpec for spec in self.entity_kinds), 'invalid_pack_entity_kinds')
        require(type(self.facts) is tuple
                and all(type(spec) is FactSpec for spec in self.facts), 'invalid_pack_facts')
        require(type(self.relations) is tuple
                and all(type(spec) is RelationSpec for spec in self.relations), 'invalid_pack_relations')
        require(type(self.steps) is tuple
                and all(type(spec) is StepSpec for spec in self.steps), 'invalid_pack_steps')
        require(type(self.operations) is tuple
                and all(type(binding) is OperationBinding for binding in self.operations), 'invalid_pack_operations')
        for member in (*self.entity_kinds, *self.facts, *self.relations, *self.steps):
            require(member.pack == self.pack, 'declared_member_outside_pack')
        for binding in self.operations:
            require(binding.step.partition('/')[0] == self.pack, 'declared_member_outside_pack')


@dataclass(frozen=True, slots=True, kw_only=True)
class CompiledPackSet:
    """Immutable compile result, not an execution or evidence-admission receipt."""

    catalogue_bytes: bytes
    registration_bytes: bytes
    registration_sha256: str
    steps: tuple[StepSpec, ...]
    operations: tuple[OperationBinding, ...]


def compile_packs(declarations: tuple[PackDeclaration, ...]) -> CompiledPackSet:
    """Validate composition and return deterministic metadata without side effects."""
    require(type(declarations) is tuple
            and all(type(pack) is PackDeclaration for pack in declarations), 'invalid_pack_declarations')
    require(len({pack.pack for pack in declarations}) == len(declarations), 'duplicate_pack')
    entity_kinds = tuple(spec for pack in declarations for spec in pack.entity_kinds)
    facts = tuple(spec for pack in declarations for spec in pack.facts)
    relations = tuple(spec for pack in declarations for spec in pack.relations)
    steps = tuple(spec for pack in declarations for spec in pack.steps)
    operations = tuple(sorted((binding for pack in declarations for binding in pack.operations),
                              key=lambda binding: binding.operation))
    require(len({binding.operation for binding in operations}) == len(operations), 'duplicate_operation')
    # Preserve the legacy pure projection and its duplicate-identity checks.
    catalogue = build_catalogue(entity_kinds=entity_kinds, facts=facts, relations=relations, steps=steps)
    ordered = order_steps(steps)
    kinds = {spec.id for spec in entity_kinds}
    by_step = {spec.id: spec for spec in steps}
    by_fact = {spec.id: spec for spec in facts}
    for fact in sorted(facts, key=lambda spec: spec.id):
        require(fact.subject in kinds, 'missing_subject_kind:' + fact.subject)
        require(fact.step in by_step, 'missing_fact_step:' + fact.id)
        require(fact.id in by_step[fact.step].produces, 'fact_step_mismatch:' + fact.id)
    for step in ordered:
        for fact_id in step.produces:
            require(fact_id in by_fact, 'missing_fact_spec:' + fact_id)
            require(by_fact[fact_id].step == step.id, 'fact_step_mismatch:' + fact_id)
    for relation in sorted(relations, key=lambda spec: spec.id):
        require(relation.source in kinds, 'missing_relation_kind:' + relation.source)
        require(relation.target in kinds, 'missing_relation_kind:' + relation.target)
    for binding in operations:
        require(binding.step in by_step and by_step[binding.step].kind == 'parse_build',
                'invalid_operation_step:' + binding.operation)
    body: dict[str, object] = {
        'schema': REGISTRATION_SCHEMA,
        'catalogue_sha256': catalogue_digest(catalogue),
        'packs': sorted(pack.pack for pack in declarations),
        'operations': [{'operation': binding.operation, 'step': binding.step} for binding in operations],
    }
    registration = canonical(body)
    return CompiledPackSet(catalogue_bytes=catalogue, registration_bytes=registration,
                           registration_sha256=sha256(registration).hexdigest(),
                           steps=ordered, operations=operations)
