# ADR 0042: Fixed FHRP STATE and VERSION input preparation

Status: accepted (design boundaries only); runtime and GLOBAL readiness remain unverified.

The existing STATE, VIP and default profiles remain closed and unchanged.
A new named FHRP-only profile owns STATE and reported protocol VERSION with one
fhrp_local entity declaration and the exact BRIEF and ALL operation bindings.
Its registration differs from both the local VERSION and future peer compositions.

prepare_state_version_inputs(root, budgets) admits the entire declared-synthetic
folder under that fixed profile before preparing any invocation inputs. The
original BRIEF declarations supply every subject, including missing ALL captures
or absent ALL declarations. ALL declarations must match the same original node
and exact interface/group census. Frame/model checks do not judge body semantics.
Returned registries, compiled metadata and input graphs are inspectable comparison
data. A future fresh component must compile/admit internally, close the complete
ledger and both owning raw-claim graphs before either Writer, and use one batch.
No prepared carrier, local hash, subject-key change or caller profile flag supplies
admission. STP/EC composition, recursive proof/source closure and conflict checks remain later work.
