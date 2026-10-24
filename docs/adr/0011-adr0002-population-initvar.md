# ADR-0011: ADR-0002 amendment for a population constructor witness

Status: accepted

Extends ADR-0010; all prior global, AST, path and ZIP grants remain unchanged.
Authority: owner standing safe per-file stdlib delegation, 2026-10-20 22:15.
Existing request, revised from global names to exact per-file bindings:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/62#issuecomment-6299426861
Plan: S1 section 1.9.4 requires ExpectedSet's candidate partition invariant;
K's queued PR3 admissibility work supplies the constructor witness.

| Additional API | Only using path | Reason |
|---|---|---|
| dataclasses.InitVar | atlas_brain/kernel/population.py | Constructor-only candidate witness, absent from the stored ExpectedSet fields. |

Actual using source: 0d1664c58e99dc42894323d182f05419b6597288.
Git blob: 2e207c167c9bc1b6190b7c2f8e9cadd0db1ffe85.
SHA-256: 1036383e0fa74d988be50f073d080a2c2cfa694e338c00c119e979c323d8fd1d.
The 75-line byte-pinned fixture is data, never imported or executed by C1.
Its sole InitVar annotation is ExpectedSet.candidates with no default.

Use RUNTIME_API, preserving this normal runtime module's public record imports.
Do not classify it as AST tooling or add a global dataclasses grant.
Unlisted dataclasses names, other-file InitVar and direct/module/bridge API
re-exports refuse; public ExpectedSet, CoverageSummary and coverage stay importable.
All other requested verdict and scheduler bindings remain outside this amendment.
This name/path admission is not a semantic proof of future uses at that path.
It does not accept population behavior, K integration, R3 confinement or release.
No workflow, command, permission, budget, timeout or other gate changes.
Independent REV, full hosted Linux/Windows proof and native merge custody are
required; K then owns its refreshed exact-source functional acceptance.
