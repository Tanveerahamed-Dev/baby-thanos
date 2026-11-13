# ADR-0034: GLOBAL registered reported virtual IP producer

Status: proposed.

VirtualIpPack joins ordinary trusted P4 composition: STATE+VIP precedes execution; each HSRP capture is parsed once by its owner.
Original prepared Request/Capture custody and fixed catalogue/evaluator/row/column validation precede STATE writes.
VIP uses the actual STATE Reader; owning canonical validation covers every declared VIP without parser/Writer replay.
Prepared construction precedes run publication; failure keeps attempted=True and refuses retry.

Producer, adapter and carriers are not whole-profile admission/value seals; peer/Store/Reader/proof closure, a fresh factory and logical VIP check remain required.
Legacy/default/Root output stays fixed; no health, version, anycast, read-scope, absence-baseline, P4/M1/field or P5 acceptance.
