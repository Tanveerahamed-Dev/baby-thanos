# ADR-0020: Explicit synthetic P2 grouping and owned peer facts

Status: accepted

Date: 2026-10-26

P2 needs cross-capture subjects; filenames, prompts and hostname resemblance
cannot establish them. Existing owned facts, declared relations, estate steps
and restricted readers support this contract without model API redesign.

The optional `p2.json` uses `atlas-brain.synthetic-p2/1` and requires
`semantic_group: declared_synthetic`: one safe group ID, 1–32 nodes, 1–128
exact interface names per node, and 1–64 CLI references. Nodes explicitly
declare unique IDs and exact discovery IDs. References bind path, node, supported
CDP/LLDP-detail or trunk operation and SHA-256. Duplicate identities, paths or
source-operation pairs, unsafe names, missing/unlisted members and hash failures
refuse the group. Logical rows sort; registry pointers retain original indexes.
Group/node values are `Known(basis=declared)` with `/group` or `/nodes/i` registry
pointers and digests of exact envelope bytes, retained for resolution. JSON is never a CLI Capture.

Whole-folder safety and budgets precede pure admission. Raw CLI bytes remain
unchanged. Preliminary header/control/context recognition does not authorize
pairing: every capture must pass its owning parser's whole-response accounting
before any estate checks. COMPLETE describes supplied file bytes only; failed,
empty and truncated input cannot be COMPLETE. Unsupported headers and mixed
contexts refuse. Scope/view remain unknown and collector time is unrecorded.

`l1.link` owns the new declared node/interface entity kinds and one-to-one
interface peer relation. Node keys include group and node ID; endpoint keys
hash canonical (node key, exact interface) bytes. Keys change across groups and
remain stable when filenames or capture bytes change. Exact discovery IDs are
explicit declarations; no alias shortening is permitted. P1 capture-row
interface facts retain their subjects and are never joined through this contract.

Next slices admit `l2.discovery` as owner of remote device/port facts and
`l2.vlan_trunk` as owner of native/allowed VLAN facts and checks. Their FactSpec
subjects are interface. Foreign reads use StepSpec.reads and FactReader, never
backing maps or foreign writes. Kernel/store/step semantics, fence grants and
runtime dependencies remain unchanged.

Only reciprocal exact claims prove a declared synthetic pair. Missing reverse
discovery is unknown(peer_not_collected); explicit contradictory reverse claims
produce a stable refusal. Duplicate/ambiguous claims are unknown or refuse.
Comparisons cite both ends and the declaration chain; blank native never
becomes 1. Positive mismatches are conditional declared-synthetic counterexamples;
equal untimed inputs remain unknown(as_of_missing), and estate coverage remains
unknown. No real-device identity, time consistency, physical-cabling, train or
qualification claim follows. P0/P1 retain existing paths and projections.
