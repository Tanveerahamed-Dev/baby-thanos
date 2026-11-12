# ADR-0026: Fixed displayed-root folder observations

Status: proposed.

The named `analyse_root_observations_folder(root, budgets)` API selects
STP Root4, EtherChannel and HSRP before one shared parser execution.
It emits `atlas-brain.p4-root-observations/1`: five canonical bundle files
with seven declared facts. Legacy APIs, profiles, bytes and CLI stay fixed.

A separate RootProofIndex accepts only this fixed composition. Legacy
ProofIndex retains its two existing profiles. Permission scopes require all six
root spans, with distinct priority/MAC anchors and no neighbor borrowing.
Known priority uses exact int, including zero and excluding bool; MAC keeps case.

Every peer finishes before projection. Row, Store, Reader, declared population
and source permissions close before the bundle is built. The STP owner compares
all four states with the same retained execution, including Unknown needs.
Neither claims, digests nor result objects substitute for source admission.

Budgets count both registries, captures and all five outputs, including manifest.
Priority retains printed extension bits. This is synthetic observations only:
no intended root, topology, health, platform qualification, Root CLI, P4
completion, EX-02, M1 or P5 claim.
