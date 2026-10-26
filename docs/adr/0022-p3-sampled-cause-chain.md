# ADR-0022: P3 sampled MTU/OSPF candidate chain

Status: accepted

Date: 2026-10-26

The owner authorized P3/issue6 after the P2 hold. This adds a bounded synthetic
cause-candidate path; P4 is out of scope. Kernel/store semantics and P2 schemas,
facts, checks and accepted output bytes stay unchanged.

A new `p3.json`, schema `atlas-brain.synthetic-p3/1`, declares only
`semantic_group=declared_synthetic`, `base_sha256`, `adjacencies`, `samples`.
It pins exact `p2.json` bytes. Whole-folder budgets/names/hashes/accounting run
first; the exact unchanged P2 schema1 discovery-only subset is admitted by P2.
P3 owns every remaining listed capture; paths are disjoint, globally unique and
their union exhausts the folder. Existing bridge-capable peer rules are retained.

There are 1..16 declared adjacencies and 0..16 rounds, at most64 P3 captures.
Each adjacency has `id,domain,area,left,right`; endpoints have
`node,port,process,router_id,address,vrf`. Ports match exactly, endpoints are
unique/cross-node, and per-node process/router-id/VRF agree. Process is1..65535,
area uint32, addresses/RIDs canonical IPv4, VRF explicitly `default`.
Address/RID are local on their endpoint and remote in the opposite neighbor row;
process IDs are local and need not equal across ends. Domain is a group-scoped
declared namespace, never routing-domain proof or a VRF-name inference.
Printed context must agree; omitted printed VRF is not filled as an observation.

A round has `id,time,captures`; time is null or
`{unit:unix_us,clock,earliest,latest,bound:collector_recorded}`.
Bounds are strict integers0..9007199254740991, earliest<=latest; clock matches
`collector:[A-Za-z0-9_.:/-]{1,64}`. Captures have path/node/operation/sha256,
unique per(round,node,operation). Identity hashes both registry digests, schema,
round/source/path/operation/raw hash. Time is supplied synthetic collector
metadata, not authenticated clock truth; no clock/file/device-time inference.
A whole-round interval bounds collection, never simultaneity/atomicity.

P3 operations are exact `show interfaces`, `show ip interface`,
`show ip ospf neighbor`, `show ip ospf interface`, `show running-config all`.
Generated parsers are thin allowlists, not vendor/train/format-floor qualification.
The config form requires an explicit `ip ospf mtu-ignore` or
`no ip ospf mtu-ignore`; omission, inheritance and unsupported syntax stay unknown.
[Cisco command references](https://github.com/CiscoTestAutomation/genielibs/blob/9fd4846825c99ad8a954c89d245aff90a686a9f0/pkgs/sdk-pkg/src/genie/libs/sdk/apis/iosxe/ospf/configure.py)
support these controls; config-all availability remains platform-sensitive.

`l2.mtu` owns printed interface-byte MTU; `l3.mtu` owns printed IP-byte MTU.
No substitution, header subtraction or default1500. `l3.ospf` owns
`ospf_sample`/`ospf_adjacency` kinds, protocol context/state/control/time facts,
sample settlement and the no-output R1 check. Sample subjects bind full declared
adjacency/endpoint context plus round ID, independent of capture removal/order.
All stored Known values are primitives; TimeInterval remains capture metadata.
Every capture/owner/node/round receipt closes before settlement/correlation.

Every declared adjacency × round × end is expected: no unusable round is dropped.
Both directed neighbors must match opposite RID/address and local exact context;
only point-to-point scope is supported. Positive sampled persistence requires
one identical EXSTART or EXCHANGE token at both ends in every round, at least2
complete rounds, one clock, strictly nonoverlapping intervals, and
`last.earliest-first.latest >=120000000`. All records contribute evidence.
Zero rounds is NOT_COLLECTED; one complete round SINGLE_SAMPLE(after_s120);
missing/failed/partial required operands preserve their Unknown and named stop.
Disagreeing states, including EXSTART-FULL-EXSTART, are CONFLICTING_EVIDENCE
before missing-time handling. Missing/incomparable time is AS_OF_MISSING;
overlap is NON_ATOMIC_VIEW; insufficient separation is SINGLE_SAMPLE.
Repeated FULL/2WAY is a non-candidate, never health or continuous-state proof.

R1 consumes only L3 IP MTU; L2 MTU remains independently visible. Every round
must have unequal IP MTUs with the same smaller receiving endpoint. Reversal,
mixed equality/mismatch or conflicting series stop as CONFLICTING_EVIDENCE;
all-equal MTUs or uniformly non-stuck state make this candidate
NotApplicable(ROLE_EXCLUDES). Receiving-side ignore=true at any round makes it
NotApplicable(FEATURE_NOT_ENABLED) at the countercondition hop, citing
COUNTER_EVIDENCE; larger-side true
alone does not block. Missing control stays Unknown; omission is never false.

Hops are peer/context, IP-MTU mismatch, sampled persistence, receiving control,
then candidate; the first unresolved premise stops the chain visibly.
Output `atlas-brain.p3-demo/1` under runner-manifest/3 projects owned facts,
ordered named hops and their next evidence. The arrow means a conditional
candidate matched the supplied observations, not unique cause, unobserved
continuous state, current/physical truth or qualification. P3 proofs validate
both registries, sample/time/capture binding, source/operation/span/hash,
read permissions and cycles; unchanged P2 leaves delegate to P2 resolution.
Hosted negative twins, 119/120-second boundary, all-sample interruption,
directional blockers, complete proof custody,1/4/4 determinism and legacy pins
require independent review and all hosted checks. No P4 work follows.
