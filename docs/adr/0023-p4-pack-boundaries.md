# ADR-0023: P4 evidence and pack boundaries

Status: proposed

Date: 2026-10-28

P4 implements issue #7: STP root/guards, EtherChannel membership and HSRP/VRRP
groups on a bounded synthetic demo estate. The owner authorized this phase
after P3 completion. All P4 PRs remain unmerged. P5/release work is excluded.
This decision does not amend accepted P0-P3 semantics or output bytes.

## Admission and ownership

A separate declared-synthetic P4 envelope will pin the exact P2 schema1
discovery-only registry bytes for node/link context, not SVI peer proof.
Exact local FHRP interfaces are declared separately. It owns each additional
capture. Initial packs use disjoint show forms; config/inheritance remain Unknown.
Shared configuration parsing requires a later disjoint line-ownership decision.
Whole-folder budgets, unique paths, hashes and exhaustive accounting precede semantic work.
Declarations supply expected subjects independently of captured observations;
removing a capture never removes its subject from a denominator. Declarations
are labelled DECLARED and never presented as observed network truth.

Each pack owns its parsers, primitive facts, checks and pack-specific entity kinds;
shared entity kinds retain their existing owner. Existing
FactSpec/StepSpec declarations, FactStore read/write restrictions, ordered graph
and fail-closed evidence references remain controlling. Capture/source/operation/
owner receipts must close for every input before estate consumers run. Facts and
productions, expected writes, source/subject relevance and recursive proof custody
are validated; a resolvable unrelated span is not evidence for another subject. Unknown
and refused capture states cannot become positive absence or healthy findings.

Use a typed, static pack interface and a closed trusted composition supplied by
the application. No dynamic imports, reflection, entry points, file-provided code
or new runtime dependency. Generic admission, receipt validation and projection
must not contain protocol-specific verdict logic. A held-out synthetic pack must
exercise the ordinary admission-to-output path with zero core edits before
claiming EX-02; relocating a dispatch switch alone is not that proof.

## Pack semantics

STP initially admits explicit VLAN PVST/RPVST forms. Root/bridge identity and
priority are observations, never intended-root proof. Root guard, loop guard,
BPDU guard/filter and PortFast remain distinct. Missing, inherited, failed or
unmodelled guard evidence stays Unknown. An observed enabled side versus missing
other side is not proven enabled/disabled asymmetry. MST comparison remains
Unknown until region and instance applicability are modelled.

EtherChannel keeps local group identity, protocol, explicit mode and membership
separate. Port-channel numbers do not join devices. Wrapped and nonactive members
remain in the population; legends create none. LACP passive and PAgP are not
static. A summary "-" is not evidence of mode On. Expected membership and
minimum-links require their own evidence; omission supplies no default.

FHRP local identity includes node, exact interface, address family, protocol
and group. The logical comparison key is envelope-scoped declared L2 domain,
VLAN, address family,
protocol and group; node/interface identify local participants, not peer groups.
Repeated VLANs across domains or protocols/groups never coalesce. Protocol version
and virtual IPs are compared operands, not key components: conflicting VIPs
within one group must remain visible. Expected participants are independent of
observed rows. Missing domain prevents joining; domain names never join bundles.
A missing-FHRP finding requires an explicit redundancy baseline, closed expected
population and admissible complete/read-scope evidence. Empty or uncollected
output alone remains Unknown. Positive anycast evidence is a countercondition;
declared anycast, if admitted, remains visibly synthetic.

## Proof and delivery

Regression twins cover missing/failed/partial inputs, conflicting duplicates,
scope and ownership errors, exact byte spans, removed expected participants,
root-guard omission, negotiation modes, version/VIP conflicts and repeated VLANs.
Hosted full suites and Linux/Windows worker/order/hash-seed determinism retain
all existing P0-P3 output pins and gates. Parser forms without admitted format
floors publish allowlisted/synthetic limits, never platform/train qualification.

Deliver separate pack/core slices, at most 400 total changed lines per PR and
at most 3 hand-edited files outside the owning pack/fixtures. Preserve the current
two-stream WIP limits and independent-review requirement. Do not weaken gates to
fit an implementation. Addressing/reduced VRF remain unallocated M1/v1 obligations
outside issue #7; P4 completion alone cannot establish full M1 acceptance.
