# ADR 0043: Fixed ordinary-protocol STATE/VERSION peer composition

Status: proposed design. Context/PeerOwner and ordinary Pack execution are scoped units; Store, Source/Proof and comparison acceptance remain later.

The new named application selects only legacy STP, EC and the closed FHRP
STATE/VERSION declaration. It does not amend default, Root-observation, VIP or
the separately named FHRP-only profiles. Version remains an operand, never a key.
The four-operation registration remains unchanged in the trusted context tests.

The ordinary product packs prepare against the original admitted envelope before
one actual batch. A fixed public STP Pack permits p4_pipeline staging without
a private call or the immediate-writing convenience builder. The pipeline closes
the complete original ledger; later owning producers must close their own
candidates and readiness before their Writers, without all-peer preflight or rollback.
The FHRP Pack claims both BRIEF and ALL; trusted correspondence rejects
unknown peer operations and matches ALL only to the original BRIEF domain.

Returned context data supplies no Source, proof-index or checker authority.
A fresh six-fact proof/Reader source and logical version comparison remain later
owning units. No platform/train floor, healthy network, full P4/M1 or P5 is claimed.
