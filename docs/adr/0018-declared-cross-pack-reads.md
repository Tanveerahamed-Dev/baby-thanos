# ADR-0018: Declared cross-pack reads

Status: accepted

Date: 2026-10-25

## Context

PLAN section 3 requires each consumer to read facts from their single owner,
while section 5.1 prohibits every cross-pack read. Accepted ADR-0014 binds the
reader API to declared inputs, and the generic model permits foreign reads.
That capability alone did not choose between pack code and a separate correlation
layer. On 2026-10-25 the delegated project lead selected declaration-bound pack
reads under the user's explicit current-task decision authority. This records
lead acceptance, not a claim that the repository owner personally selected this
option. Independent technical review supplied evidence, not decision authority.
No runtime code or API grant changes.

## Decision

1. A step may consume another pack's fact only through a reader bound to its
   explicit StepSpec.reads declaration. Producer-graph dependencies still
   require an available producer and refuse cycles and forbidden scopes.
2. Consumption does not confer ownership. A producer remains bound to its own
   pack-prefixed outputs; foreign writes and second owners remain refused.
   Consumers must not rederive, rewrite or bypass the reader via backing maps.
3. Kernel states and evidence pass through unchanged. Declaring a read does
   not establish subject identity, capture membership, provenance or an estate
   population; those require their own admitted contracts.

## Alternative considered

Retain pack isolation and allow foreign consumption only in separate correlation
steps. That interpretation would need explicit enforcement and new refusal
proofs; the current generic reader API does not establish it. The proposed
choice reuses the accepted single-owner/declaration model without re-parsing.

## Proof and limits

Synthetic cross-pack tests cover all four kernel states, evidence identity,
a dependency that reverses lexical order, undeclared reads, foreign writes,
foreign ownership, missing values, scope violations and cycles. They exercise
existing handles and graph checks, not a Python capability sandbox: this
proposal does not claim backing dictionaries are mechanically inaccessible.

No engine source, fence inventory, dependency or production fact registration
changes. No new node/link entity, capture grouping or discovery/VLAN parser is
admitted. CF-01's consumption-policy decision is accepted; integration closeout
requires the merged decision, exact-head hosted checks and independent review.
Tests support the decision but did not confer authority. P1 public-format
evidence and P2 identity/grouping remain open. This decision neither establishes
P1 exit nor starts or authorizes P2.
