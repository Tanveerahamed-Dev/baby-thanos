# Evidence-loss candidates (I1 / I3 mechanics)

`tools/evidence_mutations.py` implements the reusable missing-command and
partial-output mechanics assigned to MU by the TR gap handoff. It reuses V's
schema, parser and whole-fixture validator. It adds no schema and writes no files.

Both APIs take a repository root, a relative `fixtures/.../provenance.yaml` path
and the caller's expected raw SHA-256. Source bytes and sidecar bytes are bound
in the receipt; linked paths, unrecorded siblings, invalid records, hash drift and
changes observed after validation are refused. This is a validated local snapshot,
not upstream authenticity, atomic filesystem isolation or device attestation.

- `truncate(root, provenance, expected_sha256, cut)` retains exactly `[0,cut)`.
  The cut must remove bytes; negative, oversized, boolean and no-op cuts refuse.
  Byte zero yields a present empty artifact. UTF-8 and CRLF are never rewritten.
- `drop_form(root, provenance, expected_sha256, retained)` returns `None` for an
  absent artifact, plus a requested derived attempt of unknown/unknown. Retained
  context is a nonempty tuple of `(provenance, expected_sha256)` references.
  Duplicate IDs, raw hashes and upstream references, including aliases of the
  removed source, refuse. Context ordering and repository root do not affect IDs.

Every receipt has `qualification: unqualified`, no output tier and no truth label.
It records the exact removed half-open byte span, its hash, empty inserted bytes,
parent/source metadata, metadata/raw hashes, retained references, output presence
and hash, and a deterministic derivation ID. Replaying the span against the pinned
parent reconstructs the cut; the original suffix supplies an inverse byte control.

The declared inserted-token vocabulary is empty: these operators only remove
bytes or an artifact. Unknown train/capture fields remain unknown. The original
capture metadata and the requested derived attempt are separate. No real failed
collection, common device, peer, clock or independently verified population is
invented; `capture_relationship: not_verified` remains explicit even for Q inputs.

These are candidate descriptions, not rewritten/admitted engine Bundles. They do
not classify surviving records as unknown or problem_permitted. The eventual
truth harness needs the eligible parent, independent subject population and
predeclared labels before making those decisions. No PR 11 source/grammar gap,
H/L holdout quota, Tier-M issuance or accuracy status is closed by this library.
Tests use synthetic controls and existing Q text without editing their fixtures.
