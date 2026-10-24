# ADR-0014: Model fact-store admission — new fact owner, no new source capability

Status: accepted

Date: 2026-10-24

## Context

M0 PR 3 adds `atlas_brain/model/`: the layer between `kernel/` and the packs
that declares fact ownership and holds facts at rest. It introduces a new fact
owner (pack-prefixed `FactSpec` ids, one producer step per fact id), so
`PLAN.md` §10 requires an ADR for the new fact owner. ADR-0002 keeps the source
fence default-closed: engine source may use only exact admitted standard-library
endpoints, otherwise `tools/fence.py` refuses it.

## Decision

1. `atlas_brain/model/` is admitted as engine source under the existing
   `atlas_brain/` tree. It imports only `atlas_brain.*` engine modules and the
   standard-library endpoints already admitted by ADR-0002. **This ADR admits
   no new standard-library API**: `STDLIB_API`, `SCOPED_API` and `RUNTIME_API`
   in `tools/fence.py` are unchanged and no existing rule is weakened.
2. The model layer owns the fact-store contract: one owner per fact id, one
   write per `(fact, subject)`, writers bound to a step's `produces`, readers
   bound to a step's declared reads, deterministic producer-graph order with
   cycles refused, and a deterministic catalogue digest over RFC 8785 bytes.
3. Facts at rest are the closed kernel states `Known/Absent/Unknown/
   NotApplicable`; evidence requirements (including `EvidenceRef` where
   applicable) stay enforced by the kernel constructors, never re-implemented.
4. The catalogue is a pure sorted projection; the accepted digest is held
   outside it, so modified catalogue bytes fail verification.

## Reused admissions (ADR-0002, unchanged)

| API | Reason | Using module |
|---|---|---|
| dataclasses.dataclass | Frozen/slotted keyword-only spec records, writer/reader handles | model/specs.py, model/store.py |
| typing.Literal | Closed step-kind, step-scope, value-type and cardinality vocabularies | model/specs.py |
| typing.NewType | Typed step identifier beside kernel `FactId`/`PackId` | model/specs.py |
| typing.cast | Erase the payload type only after the closed kernel-state check | model/store.py |
| re.fullmatch | Exact pack, name and step identifier syntax | model/specs.py |
| re.ASCII | ASCII-only identifier patterns | model/specs.py |
| hashlib.sha256 | SHA-256 catalogue digest | model/catalogue.py |

`atlas_brain.contract.canonical` supplies RFC 8785 canonical bytes; engine
imports need no fence entry.

## Consequences

- No fence edit or new capability grant is required by this PR; existing fence
  refusal and positive-control tests stay green.
- `tools/fence.py` reports `0 refused paths, imports, dependencies or
  machine-data files`; `tests/model/` proves every refusal this layer owns: a
  write outside `produces`, an undeclared read, a second owner of a fact id, a
  second write of one `(fact, subject)`, a missing or duplicate producer, a
  device step reading estate facts, and a cycle that names every member.
- Future model modules that need a new endpoint must amend ADR-0002 through a
  later ADR before the fence will pass; this ADR does not pre-approve any.
