# ADR-0006: ADR-0002 amendment for K token scope

Status: superseded

Supersedes ADR-0005; all previous global and per-file grants remain unchanged.
Standing supervisor approval:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
Exact using-path request:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/66#issuecomment-6298784558
T = atlas_brain/kernel/token_lints.py, actual source
0228a01445558bed3a503b73db17d5b297620784 (24 AST endpoints).

| Additional API | Using path | Reason |
|---|---|---|
| ast.AnnAssign | T | Detect annotated value branches. |
| ast.Assign | T | Detect assignment value branches. |
| ast.Compare | T | Recognize literal enum comparisons. |
| ast.Constant | T | Identify literal keys and enum values. |
| ast.Expr | T | Recognize a sole assertion expression. |
| ast.MatchAs | T | Identify captured/default match arms. |
| ast.MatchMapping | T | Account for mapping-rest pattern bindings. |
| ast.MatchStar | T | Account for sequence-star pattern bindings. |
| ast.Return | T | Detect return value branches. |
| ast.stmt | T | Type statement sequences. |
| ast.Subscript | T | Recognize explicit mapping reads. |

This adds only eleven bindings at T. No global AST or runtime grant is added.
The K full-lint grant and all PK grants remain unchanged. Hosted inventory
parses actual source without executing it; unlisted, outside-file, runtime
borrowing and re-export refusals remain mandatory. Admission does not certify
the K guard, audit repair, verdict logic or kernel freeze.
Future changes require a C1 amendment, independent MERGE-READY, supervisor
approval explicitly or within standing bounds, and green Linux/Windows CI.
