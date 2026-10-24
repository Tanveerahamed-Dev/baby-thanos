# ADR-0009: Exact existing path reads before constructor enforcement

Status: superseded

Supersedes ADR-0008; all its grants remain unchanged.
Standing exact safe per-file stdlib approval: 2026-10-20 22:15.
This is a proposed preservation prerequisite for audit115 constructor checks.
Using source is existing evidence admission, not new consumer behavior:
atlas_brain/evidence/admission.py at
ca64e4d0912e2ad7dbacff8ef2394fc8c5a4a307.
SHA-256: 9ab117baf6efe2908ea3aca450852421bdebf268b2f87ee70611cd4a52343870.

| Additional API | Exact using path | Existing reason |
|---|---|---|
| pathlib.PurePosixPath.is_absolute | atlas_brain/evidence/admission.py | Refuse absolute archive member paths. |
| pathlib.PurePosixPath.parts | atlas_brain/evidence/admission.py | Verify devices/source/captures member layout. |

Both operations are read-only public Path APIs already used by merged code.
They are exact per-file entries in a separate RUNTIME_API map; normal public
declarations remain importable. Wrong-file/unlisted/reexport controls remain.
The existing globally admitted constructor stays callable when its explicitly
admitted members also form a namespace; this adds no global permission.
All22 globals and K29/32/PK34/10 remain unchanged. No writes, risky class,
product source edit or runtime/ZIP acceptance is granted. The checker successor
must enforce direct constructor members and preserve every output refusal.
Independent REV and Linux/Windows exact-head proof remain required.
