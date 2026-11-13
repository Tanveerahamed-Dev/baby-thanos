# ADR-0034: GLOBAL registered reported virtual IP producer

Status: proposed.

VirtualIpPack joins ordinary trusted P4 composition: STATE+VIP precedes execution; each HSRP capture is parsed once by its owner.
Original prepared Request/Capture custody and fixed catalogue/evaluator/row/column validation precede STATE writes.
VIP uses the actual STATE Reader; owning canonical validation covers every declared VIP without parser/Writer replay.
Prepared construction precedes run publication; failure keeps attempted=True and refuses retry.

The typed producer, adapter and inspectable carriers are not whole-profile admission or value seals.
Exact peer/Store/Reader/proof closure and a fresh fixed source factory remain required, then the logical-gateway VIP check.
Legacy/default/Root profiles and reports stay fixed. No health, version, anycast, read-scope, absence-baseline,
P4/M1/field qualification or P5 acceptance is claimed.
