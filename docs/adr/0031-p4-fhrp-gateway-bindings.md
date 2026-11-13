# ADR-0031: Declared logical FHRP gateway bindings

Status: proposed.

A named factory accepts root, budgets and typed grouped gateway policies, then calls
the original-source factory afresh. It cannot admit provided sources/plans/targets.
Each DECLARED policy names domain/VLAN/IPv4/HSRP/group and exact local participants.
Keys include original schema/profile/registry/base/context scope, never local node,
interface, VIP or version. Local identities remain participants, not gateway keys.
Missing domain preserves unbound Unknown rows; repeated VLANs across domains do not join.
Expected participants survive missing captures. Complete duplicate keys and conflicting
local assignments refuse. One local participant is valid; no redundancy minimum is inferred.
Canonical policy references stay separate from capture evidence; budgets charge once.
Known binding is DECLARED, not observed L2-domain/VLAN/peer or deployment proof.
No VIP/version/raw semantic reads, redundancy/anycast/health finding, new registered fact,
profile/report/CLI, R-ID/P4/M1/EX-02/field or P5 acceptance is added. ADR-0030 source guarantees stay fixed.
