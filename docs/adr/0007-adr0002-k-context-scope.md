# ADR-0007: ADR-0002 amendment for K contextual token inspection

Status: superseded

Supersedes ADR-0006; its prior global and per-file grants remain unchanged.
Standing supervisor approval:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
Exact using-path request:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/94#issuecomment-6310729895
T = atlas_brain/kernel/token_lints.py, actual published source
a4f2beec65f23f66236a04ef7c1291b5c95d242f (27 AST endpoints).
Source SHA-256: b794cf3acfb8d339340681fc701e3bd2b5f94ee36bdcc7bcd77bb95595b77ea6.

| Additional API | Using path | Reason |
|---|---|---|
| ast.Eq | T | Identify a finite literal equality on the same token input. |
| ast.Raise | T | Identify an explicit refusal successor statement. |
| ast.iter_fields | T | Inspect actual statement-successor fields without executing source. |

Only these three bindings are added at T. The K full-lint grant stays at 32,
PK grants stay at 34/10 and the 22 global APIs remain unchanged. No runtime
AST, runtime data API or other file grant is added. Unlisted, outside-file
and runtime re-export refusals remain mandatory. The hosted inventory parses
the pinned source and exercises the actual tracked CLI without executing K.
Admission does not certify K behavior, audit72, verdict logic or kernel freeze.
Further admissions require a C1 amendment, independent MERGE-READY, supervisor
approval explicitly or within standing bounds, and green Linux/Windows CI.
