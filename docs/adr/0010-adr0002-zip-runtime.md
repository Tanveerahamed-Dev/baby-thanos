# ADR-0010: ADR-0002 amendment for bounded ZIP source admission

Status: accepted

Supersedes ADR-0009; its two path reads, AST and global grants remain unchanged.
Standing safe per-file stdlib approval: owner prompt 2026-10-20 22:15.
Bounded sequencing decision:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/issues/89#issuecomment-6314092860
Using source:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/100
T = atlas_brain/evidence/archives.py at published source
a5a2959dd27bd6326e6e907f9866984aa41d7449.
SHA-256: 2c882be101d184cdfde60fdcfbff866ff8c0a49e5bdb17c8e0e369d8ee77f897.

| Additional API | Using path | Reason |
|---|---|---|
| zipfile.ZipFile | T | Read the ZIP index and member streams for admission. |
| zipfile.BadZipFile | T | Translate index, member and CRC refusal. |
| zipfile.ZIP_STORED | T | Recognize stored members and require equal sizes. |
| zipfile.ZIP_DEFLATED | T | Recognize the supported DEFLATE profile. |
| zlib.error | T | Translate decoder refusal via DecompressionError. |
| zlib.decompressobj | T | Bound decoded bytes and verify real EOF/no unused data. |
| stat.S_IFMT | T | Refuse archived special-member file types. |
| zipfile.ZipFile.infolist | T | Inspect member metadata for bounded admission checks. |
| zipfile.ZipFile.open | T | Read a member stream under the consumer's byte budgets. |
| pathlib.Path.suffix | T | Identify nested archive names without filesystem access. |

These ten APIs bind only to T in a separate RUNTIME_API map; T remains a
normal runtime module whose public declarations may be imported. Direct,
module and bridge API re-exports and wrong-file/unlisted uses must refuse.
All 22 globals and K29/32/PK34/10 AST grants remain unchanged.
Hosted inventory parses pinned source and runs the real tracked source fence
without executing the consumer. No process/network/dynamic/unsafe-deserialiser
or runtime-thread grant is added. This admission does not certify ZIP runtime,
stream limits, hostile-code containment or historical CI recovery.
Independent REV and Linux/Windows proof, then E's separate full functional
proof and recorded ZIP-merge disposition, remain mandatory.
The three member names preserve this same pinned source under the accepted
constructor gate; REV classified their publication scope under standing22:15:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/116#issuecomment-6322054786
That scope decision is not implementation, merge or ZIP behavior acceptance.
