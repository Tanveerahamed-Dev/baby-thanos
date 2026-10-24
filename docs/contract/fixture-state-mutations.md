# Fixture-bound state-edit candidates

`tools.evidence_mutations.mutate_fixture` extends the snapshot loader used by
I1/I3 candidates to the declared operators in `tools/mutations.py`. It reads
fixtures, returns bytes and a receipt, and never writes or admits a bundle.

`mutate_fixture(root, parent, operator, start, end, after, witness, witness_start,
witness_end)` takes parent/witness pairs of `(relative_provenance_path,
expected_raw_sha256)`. V's unchanged public-M0 schema and fixture gate validate
both snapshots. Source IDs, raw/sidecar hashes, repository references, platform
and capture declarations are retained. No caller-built Capture object is used.

Both P/S declarations must name the same stated IOS-XE or NX-OS family/train.
Unknown or mismatched declarations refuse. Conflicting IDs/upstream aliases
refuse; using one unchanged fixture explicitly as its own witness is permitted.
One path cannot designate different sidecar snapshots within the same request.
The replacement must match the complete witness byte span. The existing closed
operator/token/transition registry and span guards enforce the parent edit.

The deterministic receipt records both snapshots, the complete witness span and
token bytes, exact before/after edit bytes, output hash and derivation ID. Only
the selected parent span changes; all other bytes and both fixtures survive.

Every result remains `qualification: unqualified`, `witness_status: lexical_only`
and `capture_relationship: not_verified`, with no output tier or truth label.
Matching declared cohort fields do not resolve held version conflicts, supported
cohorts, source authenticity, real state-field manifestation or legal Tier-M
donor eligibility. A legend occurrence is only lexical evidence. Synthetic S
fixtures exercise mechanics and never become H/L/P witnesses or M truth.

Current Q samples still lack the required same-train fault donors. No source,
release, peer, population, timing or label is invented. Snapshot checks retain
#92's documented hostile-filesystem/atomic-isolation limit. Admission-bound M
issuance, shared M-schema support and independently accepted truth cases remain
separate closing work. Tests preserve old cases and exercise every declared
transition plus numeric controls, inverses, stale/aliased/cohort/token refusals,
changing same-path snapshots, deterministic roots and Q's honest negative case.
