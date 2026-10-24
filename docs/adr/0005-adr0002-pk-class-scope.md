# ADR-0005: ADR-0002 amendment for PK class scope

Status: superseded

Supersedes ADR-0004. All previous global and per-file grants remain unchanged.
Standing supervisor approval:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
Exact request and actual-source heads:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/62#issuecomment-6299279399

| API | Using path | Reason |
|---|---|---|
| ast.ClassDef | atlas_brain/evidence/parsekit/token_lint.py | Identify class scopes and skip class frames when resolving lexical owners. |

The pinned actual source uses 34 AST APIs in token_lint.py; token_audit.py
retains its 10. Hosted inventory checks parse source without executing it.
No global AST grant is added. Unlisted, outside-file and runtime re-export
refusals remain mandatory alongside the positive actual-source probe.
Future changes require a C1 amendment, independent MERGE-READY, supervisor
approval explicitly or within standing bounds, and green Linux/Windows CI.
This policy does not certify PK behavior, truth or runtime qualification.
