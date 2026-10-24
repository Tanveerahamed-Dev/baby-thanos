# ADR-0008: ADR-0002 amendment for K membership operators

Status: superseded

Supersedes ADR-0007; all prior per-file and global grants remain unchanged.
Standing public per-file AST approval:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
Bounded audit-remediation sequence and exact-use decision:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/76#issuecomment-6315489307
Using source request:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/76#issuecomment-6315436338
T = atlas_brain/kernel/token_lints.py at published source
df6016ef31d086ef836d5666d629aad132a66890 (29 used AST endpoints).
LF SHA-256: 8e1ec42e8cdc2900acadb49fe8ce9f309cccbfaff80e8c268c15cf2ce0d788a8.

| Additional API | Using path | Reason |
|---|---|---|
| ast.In | T | Identify positive membership before the matching direct lookup. |
| ast.NotIn | T | Identify inverse membership requiring the refusal branch. |

Only these two operator bindings are added at T, preserving its prior 27.
K full-lint32, PK34/10 and all22 global APIs stay unchanged. No runtime AST,
ZIP/data grant, reflection workaround or other using-file admission is added.
Hosted source inventory parses the pin as data and runs the real tracked CLI;
unlisted, wrong-file, direct and bridge re-export refusals remain mandatory.
Admission does not certify K behavior, audit72 closure, public lint activation
or kernel freeze. Independent REV, Linux/Windows checks and merged-main custody
remain required; K must then refresh and obtain its own new behavior evidence.
