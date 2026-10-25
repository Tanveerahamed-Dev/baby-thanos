# ADR-0015: Runner raw evidence path

Status: accepted

Date: 2026-10-25

P0 admits a directory of raw CLI files and calls the existing system pack. The
manifest-v1 importer requires a manifest/devices hierarchy, so this path reuses
its `folder_members` and `Budgets` instead. It rejects missing/empty/unreadable
input, links (including hard links/junctions), special files, unsafe names, invalid
UTF-8, unsupported content and explicit CLI error/pager/truncation markers. Limits
are 128 files, 4 MiB per file, 16 MiB total and the inherited depth limit of 64;
the actual total read is checked as well. No member is silently skipped.

Input/output trees must remain stable during the run: this is not an adversarial
filesystem snapshot. Files need a recognizable IOS-XE banner or a headerless
three-record fragment (optional prompts); other headers refuse. A prompt alone
does not identify IOS-XE. Recognition is not platform/train qualification.
`COMPLETE` means supplied file bytes, not a verified collector session. Scope and
view remain unknown. The existing Capture metadata bridge supplies the whole-file
SHA-256 witness and `unrecorded_time`; file-derived identity is not device identity.
Capture IDs hash relative UTF-8 name, NUL and raw bytes, never a host path or mtime.

The coordinator parses once from those admitted bytes. Witness workers and their
deny counts remain unchanged. Each pack fact retains its state and raw-byte
references; the summary includes parse quality and uptime retains literal units.
Untimed admitted captures always have `boot_epoch=unknown(as_of_missing)`, detail
`no_collector_time`, even
when uptime is unknown. This prerequisite is enforced by the owning system pack;
its existing error/empty-capture precedence remains intact.

The manifest adds `facts` keyed by capture ID; sorted JSON and ASCII summary use
LF output and only integer/string scalar values. The evidence digest binds sorted
capture IDs and whole-file hashes. Facts do not depend on worker count or hash seed.
Resolved overlapping evidence/output directories refuse before any output write.
Existing output members must be regular files with one link; both are checked
before writing so a linked second output cannot overwrite evidence or other files.

New admissions are exact and path-scoped in `RUNNER_EVIDENCE_API`, separate from
the immutable ADR-0013 `RUNNER_API` inventory. No existing map/rule is weakened.

| API | Reason | Using module |
|---|---|---|
| pathlib.Path.resolve | Resolve evidence/output aliases before writing | atlas_brain/runner/coordinator.py |
| pathlib.Path.is_relative_to | Refuse overlapping resolved input/output trees | atlas_brain/runner/coordinator.py |
| pathlib.Path.lstat | Refuse linked/special output members before writing either | atlas_brain/runner/coordinator.py |

All other used stdlib APIs were already admitted; intake reuses the existing
admission module's capabilities. No runtime dependency or `tools` import is added.
P0 tests cover whole-folder refusal, bounded input, byte-span hashes, missing-clock
honesty, unchanged input, repeat/worker/hash-seed identity and exact API confinement.
This is observed-field extraction, not a complete IOS-XE adapter or device merge.
Independent Lead review and approval remain required before merge.
