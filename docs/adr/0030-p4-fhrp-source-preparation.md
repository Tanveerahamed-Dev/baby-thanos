# ADR-0030: Original FHRP source preparation

Status: accepted by owner in PR #142.

`prepare_fhrp_source(root, budgets)` owns one fresh fixed STP/EC/HSRP run.
Callers cannot submit Stores, executions, targets or prepared carriers.
All owners finish and whole-profile Store/Reader/proof/census checks close.
The FHRP-only source step reads every declared local state, including unselected
or uncollected subjects. Owning validation reconstructs canonical rows from the
original plan, cached parser values and receipts without parser or Writer replay.
Production shares that row constructor. Returned targets are original metadata,
not origin/admission tokens. Existing facts/profiles/report/CLI bytes stay fixed.

This is an integrated source-qualification dependency, not logical gateway binding.
Envelope/domain/VLAN/AF/protocol/group policy, expected gateway population and
VIP/version/anycast/read-scope semantics remain required later units. Those units
must call this factory afresh, never admit its inspectable carriers. No bindings,
findings, inferred defaults/intent, R-ID/P4/M1/EX-02/field or P5 acceptance is added.
