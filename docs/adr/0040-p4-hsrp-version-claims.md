# ADR-0040: Owning HSRP version raw-claim verification

Status: proposed.

validate_claims authenticates supplied HSRP-all observations against the owning static rule grammar.
Each claimed rule must match its physical line, legal claimed phase, exact fields and plaintext token spans.
Every consumed or unrecognised physical line and every Record is accounted once, in order, without overlap.
Literal command lines are authenticated even when they produce no Record.
All block censuses, same-block IPv4 witnesses, original Row pointers and canonical reasons close, including Unknown rows.
The verifier matches only the claimed trusted rule; it never calls the parser or redispatches alternatives.
For otherwise complete, error-free inputs, unrecognised claims force PARSE_PARTIAL; stronger capture reasons stay primary and all rows stay Unknown.
Returned sorted owning spans preserve header/identity/version/VIP and footer-closure witnesses; footer names supply no identity.
This is raw-proof verification, not source admission, parser-execution proof or a cached-producer value seal.
A fresh registered VERSION producer must consume this verifier and separately close inputs, caches, receipts and Stores.
Legacy parser outcomes, STATE/VIP/default profiles and report bytes remain unchanged.
GLOBAL source/proof/Reader closure and fresh conditional logical version comparison remain required.
No field/platform/train qualification, full P4/M1/P5 acceptance or numbered correlation claim is added.
