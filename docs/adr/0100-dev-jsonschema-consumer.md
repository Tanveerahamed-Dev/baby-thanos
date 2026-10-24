# ADR-0100: development-only JSON Schema consumer

Status: accepted

## Accepted development-only decision
Pin jsonschema==4.26.0 in the hashed dev lock only, with no optional format extras.
Use Draft202012Validator to check generated schemas and actual contract wire bytes.
S3 section3.5 requires a development-only result validator; S2 DA-4/DA-7 govern admission.
The runtime dependency list stays empty; atlas_brain cannot import this test library.
The consumer refuses external schema references/IDs, noncanonical bytes, floats and
unsafe integers; empty JSONL does not bypass schema validation or imply health.

## DA-7 evidence and boundaries (checked 2026-10-21)
(a) Not a parser, fact producer or runtime engine component; parser admission is N/A.
(b) Runtime admission is N/A; native Linux/Windows consumer tests are required anyway.
(c) Licence: MIT; redistribution is permitted with copyright/permission notice kept.
Nothing from this dev closure is shipped; preserve the MIT notice if that ever changes.
Pinned licence: https://github.com/python-jsonschema/jsonschema/blob/a7277432b0f7bcd0551f6e589d30457017125df4/COPYING
PyPI metadata: https://pypi.org/pypi/jsonschema/4.26.0/json
Hosted uv.lock pins attrs26.1.0, jsonschema-specifications2025.9.1,
referencing0.37.0 and rpds-py2026.9.1; their checked PyPI metadata reports MIT.
The exact lock bytes/hashes come from hosted C1 run39573657895, not local resolution.
(d) CT proposed; independent REV2 approved DA-7 development-only admission:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/99#issuecomment-6312428267
(e) PyPI JSON reports4.26.0 first uploaded2026-01-07T13:41:05Z, one release in the
2025-10-21 through2026-10-21 window, and Python>=3.10 including the3.14 classifier.
PyPI maintenance source: https://pypi.org/pypi/jsonschema/json
GitHub's release page agrees on v4.26.0 and displays179 commits to main since it:
https://github.com/python-jsonschema/jsonschema/releases/tag/v4.26.0
REST metadata, initially rate-limited, was successfully checked2026-10-21: archived=false;
latest GitHub release v4.26.0 was published2026-01-07T13:41:11Z. Latest default commit
c497561ea0a95f5aac09cd63d15eb1420eb7bbec is dated2026-10-07T10:49:35Z.
This records maintenance activity from both primary API sources. The independent
approval is limited to this exact dev-only package/closure and no optional extras.
REST sources: https://api.github.com/repos/python-jsonschema/jsonschema
https://api.github.com/repos/python-jsonschema/jsonschema/releases/latest
https://api.github.com/repos/python-jsonschema/jsonschema/commits?per_page=1

## Validation and disposition
Metaschema, actual header/evidence instances, malformed data, offline references,
JSONL framing and real CLI success/refusal must pass on both hosted OS jobs.
No local installation/runtime acceptance. The independent approval above admits only
the dev/test consumer; green tests do not complete result schemas, contract v0 or runner.
