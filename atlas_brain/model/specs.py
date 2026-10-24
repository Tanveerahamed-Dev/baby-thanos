"""Frozen declarations for model facts, relations, entity kinds and producer steps.

Every record is closed: all fields are required, identifiers are pack-prefixed
where they name pack-owned material, and vocabularies are Literal unions with
the same closed values enforced again at construction.
"""
import re
from dataclasses import dataclass
from typing import Literal, NewType

from atlas_brain.kernel.states import FactId, PackId, require, text_fields

StepId = NewType('StepId', str)

type Cardinality = Literal['many_to_many', 'one_to_many', 'one_to_one']
type StepKind = Literal['check', 'derive', 'parse_build', 'population']
type StepScope = Literal['device', 'estate']
type ValueType = Literal['boolean', 'entity_ref', 'integer', 'text']

PACK = r'[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*'
NAME = r'[a-z][a-z0-9_]*'
STEP = r'[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*/[a-z][a-z0-9_]*'


def _pack_id(value: str) -> None:
    require(type(value) is str and re.fullmatch(PACK, value, re.ASCII) is not None, 'invalid_pack_id')


def _name(value: str, code: str) -> None:
    require(type(value) is str and re.fullmatch(NAME, value, re.ASCII) is not None, code)


def _prefixed(value: str, code: str) -> None:
    prefix, _, name = value.rpartition('.')
    require(re.fullmatch(PACK, prefix, re.ASCII) is not None
            and re.fullmatch(NAME, name, re.ASCII) is not None, code)


def _pack_owner(identifier: str, pack: str, code: str) -> None:
    require(identifier.rpartition('.')[0] == pack, code)


@dataclass(frozen=True, slots=True, kw_only=True)
class EntityKindSpec:
    """A network-model entity kind with exactly one owning pack."""

    id: str
    pack: PackId
    root: bool

    def __post_init__(self) -> None:
        text_fields(self.id, self.pack)
        _name(self.id, 'invalid_entity_kind_id')
        _pack_id(self.pack)
        require(type(self.root) is bool, 'invalid_entity_root')

    def row(self) -> dict[str, object]:
        return {'entity_kind': self.id, 'pack': self.pack, 'root': self.root}


@dataclass(frozen=True, slots=True, kw_only=True)
class FactSpec:
    """One typed fact owned by one pack step; no field is optional."""

    id: FactId
    pack: PackId
    subject: str
    value_type: ValueType
    step: StepId

    def __post_init__(self) -> None:
        text_fields(self.id, self.pack, self.subject, self.step)
        _pack_id(self.pack)
        _prefixed(self.id, 'invalid_fact_id')
        _pack_owner(self.id, self.pack, 'fact_id_outside_pack')
        _name(self.subject, 'invalid_subject_kind')
        require(re.fullmatch(STEP, self.step, re.ASCII) is not None, 'invalid_step_id')
        require(self.step.partition('/')[0] == self.pack, 'fact_step_outside_pack')
        require(self.value_type in ('boolean', 'entity_ref', 'integer', 'text'), 'invalid_value_type')

    def row(self) -> dict[str, object]:
        return {'fact': self.id, 'pack': self.pack, 'step': self.step,
                'subject': self.subject, 'value_type': self.value_type}


@dataclass(frozen=True, slots=True, kw_only=True)
class RelationSpec:
    """A declared correlation edge between two entity kinds, owned by one pack."""

    id: str
    pack: PackId
    source: str
    target: str
    cardinality: Cardinality

    def __post_init__(self) -> None:
        text_fields(self.id, self.pack, self.source, self.target)
        _pack_id(self.pack)
        _prefixed(self.id, 'invalid_relation_id')
        _pack_owner(self.id, self.pack, 'relation_id_outside_pack')
        _name(self.source, 'invalid_source_kind')
        _name(self.target, 'invalid_target_kind')
        require(self.cardinality in ('many_to_many', 'one_to_many', 'one_to_one'), 'invalid_cardinality')

    def row(self) -> dict[str, object]:
        return {'relation': self.id, 'pack': self.pack, 'source': self.source,
                'target': self.target, 'cardinality': self.cardinality}


@dataclass(frozen=True, slots=True, kw_only=True)
class StepSpec:
    """A producer step declaring exactly what it reads and what it produces."""

    id: StepId
    pack: PackId
    kind: StepKind
    scope: StepScope
    reads: tuple[FactId, ...]
    produces: tuple[FactId, ...]
    evaluator: str

    def __post_init__(self) -> None:
        text_fields(self.id, self.pack, self.evaluator)
        _pack_id(self.pack)
        require(re.fullmatch(STEP, self.id, re.ASCII) is not None, 'invalid_step_id')
        require(self.id.partition('/')[0] == self.pack, 'step_outside_pack')
        require(self.kind in ('check', 'derive', 'parse_build', 'population'), 'invalid_step_kind')
        require(self.scope in ('device', 'estate'), 'invalid_step_scope')
        require(self.evaluator.startswith(self.pack + '.'), 'evaluator_outside_owner')
        for facts, code in ((self.reads, 'invalid_read_declarations'),
                            (self.produces, 'invalid_produce_declarations')):
            require(type(facts) is tuple and facts == tuple(sorted(set(facts))), code)
            text_fields(*facts)
            for fact in facts:
                _prefixed(fact, 'invalid_fact_id')
        for fact in self.produces:
            _pack_owner(fact, self.pack, 'produce_outside_pack')

    def row(self) -> dict[str, object]:
        return {'step': self.id, 'pack': self.pack, 'kind': self.kind, 'scope': self.scope,
                'reads': self.reads, 'produces': self.produces, 'evaluator': self.evaluator}
