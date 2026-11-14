# ADR-0046: New project-owned P4 synthetic case contracts

Status: accepted (new project design only); implementation and qualification remain open.

Date: 2026-11-14
Decision: [Named Lead design adoption](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/7#issuecomment-6882855367).

The historical authoritative EI regression definitions remain UNVERIFIED.
The owner asked the delegated Lead to choose a best next design after that gap was identified.
This decision creates explicit NEW project contracts; it does not recover or rename historical truth.
The catalogue is `baby-thanos.p4.synthetic/1`, with local aliases EI-R04, EI-R10 and EI-R11.
Every case/result must retain both catalogue version and short ID; IDs are not inferred from PLAN order.

[Issue #7](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/7) and accepted
[ADR-0023](0023-p4-pack-boundaries.md) supply the product boundaries.
The accepted design [case contract](../contract/p4-synthetic-case-contracts-v1.md) assigns:
- EI-R04: root-guard omission/default honesty and declared-edge reported mismatch.
- EI-R10: EtherChannel protocol/member observation and prohibited static-mode inference.
- EI-R11: baseline-closed missing FHRP, read-scope and positive-anycast counterconditions.

These are explicit new design assignments, not claims about historical EI-R10/EI-R11 meanings.
Each contract requires original synthetic inputs, fault/countercondition/insufficient twins,
positive evidence and declared assumptions, exact state/reason/needs/proofs and retained denominators.
Unknown, empty or uncollected evidence never establishes disabled defaults, absence or health.
Complete operand/gap records retain their evidence and needs; primary finding needs follow explicit case priority.
R04 resolves scope and positive role exclusion before role/guard gaps; R10 resolves operand gaps before a dash.
Capture-scoped positive FHRP presence refutes a missing-report predicate, not an untimed health predicate.
A baseline-permitted but unproven alternative blocks a missing-FHRP fault; anycast is linked through the
baseline requirement and envelope/domain/VLAN/AF scope, without invented FHRP group or VIP/MAC joins.
Declared synthetic intent and anycast exclusions remain visibly DECLARED.

This design decision authorizes these normative project expectations only; it proves no implementation or pass.
Existing semantic twins may satisfy a case only after exact-source evidence is recorded.
R11 remains genuine new owning coverage/presence, policy and checker engineering.
No Unknown subject-absent value or caller-labelled complete carrier becomes an absence fact.

Keep HSRP/VRRP coexistence and the visible mixed evidence/report/demo as required P4 work.
Preserve all existing profile/output pins, ownership and scope-fence rules.
Actual changes require bounded slices, regressions, all hosted gates and independent exact-head review.
No donor imports, local testing, cleanup, new product phase or P5/release work is authorized here.
This decision establishes neither historical provenance, platform/train truth, field qualification,
full M1/EX-02 nor P4 acceptance. Historical mappings stay UNVERIFIED after adoption.
