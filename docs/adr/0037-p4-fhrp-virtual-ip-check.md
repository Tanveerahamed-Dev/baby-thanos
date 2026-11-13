# ADR-0037: Conditional reported virtual IP comparison

Status: proposed.

The trusted owning checker reads only registered VIP facts through its declared Reader, validates every original source subject and policy selector before any finding, and never reads raw parser rows or writes facts.
Declared logical keys retain envelope/registration/domain/VLAN/AF/protocol/group scope; VIP values are operands, never join keys. Missing domain prevents comparison.
Each result preserves every participant's original state and gap. Two distinct Known literal VIPs give a conditional reported disagreement even with additional Unknown participants; all gap needs remain visible.
Without a Known disagreement, the canonical primary Unknown remains exact; equal untimed reports and singleton comparisons remain Unknown, never health or redundancy-baseline evidence.

This lower checker assumes owning source and plan closure; typed Stores/plans/results are not admission or canonical value seals. A separate fresh public wrapper must own the whole source factory and binder.
Existing 1..128 participant cardinality and default/Root profiles/reports stay fixed. Version, anycast, read-scope, absence-baseline and full P4/M1/field/P5 acceptance remain separate.
