# ADR-0002: Default-closed source capability admission

Status: superseded

Approved by the supervisor under owner delegation on 2026-10-20:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/59#issuecomment-6294921926

Only these named standard-library APIs are admitted by `tools/fence.py`.
Paths below are relative to `atlas_brain/`; tests retain existing positive controls.

| API | Reason | Using module |
|---|---|---|
| collections.abc.Mapping | Immutable mapping interface | evidence/parsekit/rules.py |
| dataclasses.asdict | Receipt projection | evidence/admission.py |
| dataclasses.dataclass | Frozen records | kernel/states.py, evidence/ |
| enum.StrEnum | Closed state vocabulary | kernel/states.py, evidence/parsekit/rules.py |
| hashlib.sha256 | Evidence digests | evidence/capture.py, evidence/admission.py, evidence/parsekit/rules.py |
| json.dumps | Canonical intake receipts | evidence/admission.py; fence positive control |
| json.loads | Manifest admission | evidence/admission.py |
| math.isfinite | Refuse non-finite intake values | evidence/admission.py |
| stat.S_ISDIR | Directory admission | evidence/admission.py |
| stat.S_ISREG | Regular-file admission | evidence/admission.py |
| pathlib.Path | Evidence path traversal | evidence/admission.py |
| pathlib.PurePosixPath | Manifest member paths | evidence/admission.py |
| re.ASCII | ASCII-only patterns | kernel/states.py, evidence/parsekit/patterns.py |
| re.Pattern | Compiled pattern typing | evidence/parsekit/patterns.py |
| re.compile | Bounded parser patterns | evidence/parsekit/patterns.py; fence positive control |
| re.error | Invalid pattern refusal | evidence/parsekit/patterns.py |
| re.fullmatch | Exact state token validation | kernel/states.py |
| re.search | Pointer syntax validation | kernel/states.py |
| typing.Literal | Closed field vocabularies | kernel/states.py, evidence/parsekit/rules.py |
| typing.NewType | Typed identifiers | kernel/states.py |
| typing.final | Sealed state records | kernel/states.py |
| typing.cast | Typed admitted JSON | evidence/admission.py |

Unregistered modules and exports, wildcard imports, namespace reflection and
private attribute reads are refused except existing constructor protocols.
No pack-loader exception exists. Preserve all dynamic-import plants and derive
unregistered-module cases from the interpreter's full `sys.stdlib_module_names`.

Any later addition or removal requires an ADR-0002 amendment, a REV MERGE-READY
verdict and an explicit supervisor approval comment. Acceptance requires green
published exact-head Linux and Windows jobs. Legitimate new APIs can block until
their admission is approved. This is source policy, not hostile Python containment;
runtime import auditing, the output witness and OS isolation remain distinct gates.
