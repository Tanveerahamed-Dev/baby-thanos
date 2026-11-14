# ADR 0043: Fixed ordinary-protocol STATE/VERSION peer composition

Status: proposed design. First unit is trusted full-context/PeerOwner only; ordinary Pack, Source/Proof and comparison acceptance remain later.

The new named application selects only legacy STP, EC and the closed FHRP
STATE/VERSION declaration. It does not amend default, Root-observation, VIP or
the separately named FHRP-only profiles. Version remains an operand, never a key.
The four-operation registration remains unchanged in the trusted context tests.

Later product packs will prepare against the original admitted envelope before
one actual batch. A future public STP Pack will permit p4_pipeline staging without
a private call or the immediate-writing convenience builder. That design closes
the complete original ledger before finishes; each producer must close its own
candidates and readiness before its Writers, without all-peer preflight or rollback.
The current test adapter claims both BRIEF and ALL; trusted correspondence rejects
unknown peer operations and matches ALL only to the original BRIEF domain.

Returned context data supplies no Source, proof-index or checker authority.
A fresh six-fact proof/Reader source and logical version comparison remain later
owning units. No platform/train floor, healthy network, full P4/M1 or P5 is claimed.
