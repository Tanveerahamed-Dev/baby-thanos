# ADR-0024: Local displayed-root fact profile

Status: proposed.

Default guard/role and five-fact reports remain unchanged. The named local
`build_root_observations(targets, requests)` selects fixed Root4 before parsing:
existing facts plus `reported_root_priority` (integer 0..65535, not bool)
and `reported_root_mac` (case-preserved text), with the same pack, OP and StepId.
Profiles cannot compile together; caller profiles and callbacks are excluded.

Original registration/request/capture/parse/value identities close before writes.
Each declared subject has four facts in one FactStore; known root facts cite six
original spans. Consumers use declared FactReader reads; gaps stay Unknown, without defaults.
Claims, digests and typed results do not admit evidence; callers enforce budgets.

A fixed literal deferred import resolves the build/root_identity cycle;
module names never come from data. No loader, grant or fence change is made.

There is no root folder/global projection, CLI format or report schema.
Legacy profile digests and report bytes stay fixed. Priority keeps printed
extension bits, not configured base priority. No intended root, synchronized
topology, health, platform/train qualification or P4 completion is claimed.
