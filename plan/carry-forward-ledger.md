# EI carry-forward ledger: retained intelligence for P2-P5

Status: proposed documentation-only carry-forward, audited 2026-10-25. The owner authorized this sanitized ledger, preservation of local work, and no cleanup or code imports. This records lessons and gaps; it does not accept architecture changes, start a product phase, qualify truth, replace the original evidence, or authorize deletion. PR #14 stays unmerged.

## Baseline and interpretation

- **B0 (merged foundation):** baby-thanos main `0eb744fed4f90ba16ccc26bfb9c1d834464f8a42`.
- **B1 (reviewed but unmerged):** [PR #14](https://github.com/Tanveerahamed-Dev/baby-thanos/pull/14), head `2ba7443d654019e5e3dece1a539c8470929fbfcb`, base B0. References to its interface work are conditional on that branch, not claims about main.
- **U0 (inherited source):** atlas-brain-staging main `4f476b8c2cc38db081397dc8588377741b40499a`. This is the seed comparison point, not a shared Git history.
- Phase anchors: [P2 / issue #5](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/5), [P3 / #6](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/6), [P4 / #7](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/7), [P5 / #8](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/8), and [pinned PLAN](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/PLAN.md). Historical illustrative PR numbers in PLAN are not live PR identities.

Phase placement below is a proposed closure checkpoint, not an assignment or permission to defer a prerequisite. Roles are **roles to assign**, not assertions of current ownership. P5 hardening/report rows do not authorize new scope: route any needed implementation to an explicitly bounded earlier change. Resolve DECISION_REQUIRED items before dependent implementation; keep current PLAN/ADRs controlling until changed through their review process.

Public real-output format floors, mutation truth, synthetic regression and device/train qualification are different evidence. The current no-lab/no-holdout route remains `measured_*` with actual n, cells and shortfall; this ledger adds no lab or holdout gate. Every source-derived lesson below is a candidate requirement or regression shape, not an accepted truth label.

| Disposition | Meaning |
|---|---|
| CARRIED | Present in the pinned Baby baseline within the stated scope. |
| RETAIN | Preserve a semantic lesson; implementation and new closure proof remain open. |
| GAP | Referenced capability or proof is absent or incomplete at the pinned baseline. |
| DECISION_REQUIRED | Conflicting or missing scope/ownership semantics need an explicit decision. |
| PARKED | Preserve as evidence only; do not resume or import. |
| REJECTED | Do not carry the old assumption or conditional label forward as truth. |

All RETAIN, GAP and DECISION_REQUIRED rows remain open. A future closure needs a Baby commit, exact-head hosted evidence and independent review; an old passing result cannot close it.

## What is already carried

Against U0's 187 blobs, B0 retains 174 byte-identical blobs, modifies four retained files, and deliberately omits nine upstream-specific files. The inherited evidence admission, parse kit, fact algebra, contracts, licences and provenance are present; this is content continuity, not wholesale migration of every stream.

- **CARRIED at B0:** the Q public-corpus path/provenance material is inherited. All 76 tracked Q paths are present (62 identical, 14 changed); this does not make every form a supported floor or establish accuracy.
- **CARRIED at B1 only:** the capture-scoped interface pack and diagnostic regressions reviewed in PR #14. Its bounded allowlisted engineering approval does not close the public full-command format-floor gap, device/train support or full P1 phase acceptance. Retain that prerequisite when preparing P2.
- **Not automatically carried:** unpublished planning/truth drafts, local stream refinements, full K admission/lint/verdict semantics, the disposable S0 pipeline, and old CI/qualification claims. Their dispositions follow.

## P2 - Two ends

| ID / disposition | Retained lesson and source | Closure evidence required | Role to assign |
|---|---|---|---|
| CF-01 DECISION_REQUIRED | PLAN doctrine says consumers read the owning pack, but its pack contract prohibits reading another pack's facts. Retained strict declared-consumer semantics [LPLAN S1:1538,1568-1570] need reconciliation with [PLAN sections 3 and 5.1](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/PLAN.md#L132). | Explicit ADR/contract decision before dependent packs; prove allowed declared consumption, undeclared-read refusal and second-writer refusal. | Architecture/model |
| CF-02 RETAIN | A collected peer/port is positive link evidence. One collected end is unknown; mispatch requires an evidenced intended map, not neighbour inference. [LTR L1-10:22-33,52] | Reciprocal and asymmetric pairs, missing peer, conflicting identities, interface aliases and intended-map/no-intent twins. | Discovery/link |
| CF-03 RETAIN | Preserve LLDP-only discovery when CDP/platform data is absent. Phone/AP neighbours and incomplete capabilities must not create phantom redundancy or switch links. [LTR L2-06:31-38; LAUDIT refuteYes:19] | LLDP-only, dual-protocol disagreement, missing capability and phone/AP producer-to-consumer cases. | Discovery |
| CF-04 RETAIN | Keep allowed, active, forwarding/not-pruned and native VLAN sets distinct. Blank native VLAN is not VLAN 1; routed/nontrunk state and config inheritance affect applicability. [LTR L2-01:21-40] | Separate-set mismatches, blank-native twin, routed/nontrunk and inherited-config cases, one-sided evidence unknown. | VLAN/trunk |
| CF-05 GAP | Admission, semantic relevance and verdict/population proof are separate. Included/excluded/unresolved partitions and closed-empty versus open populations must remain explicit; failed-command empty is not registered empty. [UKERNEL] | Closed-empty/open/failed-empty controls; N/A versus unknown, missing scope, incompatible views and deterministic population partitions through the actual pipeline. | Kernel/model |
| CF-06 GAP | Completion needs an entity-mention barrier across relevant producers, not just an acyclic declared fact graph. Historical graph semantics are reference material, not installed scheduler proof. [UGRAPH] | Late producer/mention, permutation, cycle and scope tests; show no complete consumer runs before all relevant producers finish. | Model/scheduler |

## P3 - Cause chain

| ID / disposition | Retained lesson and source | Closure evidence required | Role to assign |
|---|---|---|---|
| CF-07 DECISION_REQUIRED | Retained planning used unified MTU ownership; current PLAN commits separate `l2.mtu` and `l3.mtu`. Preserve one writer per operand instead of copying either design silently. [LPLAN S1:194-199,2824; PLAN section 8.2] | Explicit MTU ownership/consumer ADR before R1, including typed link/IP operands and refusal of duplicate ownership. | Architecture/MTU |
| CF-08 RETAIN | Distinguish frame/interface/IP MTU and interface kind. Printed IP MTU must not be reduced by an assumed header offset; unrelated local interfaces are not paired endpoints. [LPLAN S4:615; S5:473-487; LTR L3-28:21-25] | Typed kind/unit/path cases, printed-IP-MTU preservation, absent-IP-MTU unknown, mismatched/equal paired twins; retain donor/train/paired-bundle gaps. | MTU |
| CF-09 RETAIN | R1 requires two collector-timed captures at least 120 s apart on one clock with usable intervals and evidence of continuous stuck state. EXSTART-FULL-EXSTART is not continuous; untimed rival samples do not vote. [Issue #6; LPLAN S1:843-868; S5:463; LTR L3-05:38-54] | 119/120-s boundary, overlap, different clocks, intermediate FULL, conflicting untimed samples and missing-time controls with honest unknown reasons. | Timeline/OSPF |
| CF-10 GAP | Rich evidence references need integrity, semantic relevance and resolvable provenance. The current omitted-metadata bridge correctly produces an evidence-bound collector-time Unknown; that bridge is not a defect. [UCAPTURE; LE] | Wrong capture/digest/span, FactRef/RegistryRef mismatch and temporal/reference cases. Do not impose a blanket same-capture rule on legitimate conflict evidence. | Evidence/model |
| CF-11 RETAIN | R1 needs reciprocal peers, settled adjacency state, receiving-side `mtu-ignore` counterconditions, visible unknown hops and causal-candidate discipline. A 2WAY state alone is not a fault. [LPLAN S5:462-465; S6:697; US0] | Remove each operand independently; healthy and wrong-reason twins, unknown middle hop, direction-sensitive mtu-ignore and non-fault 2WAY. | OSPF/correlation |

## P4 - EI breadth

| ID / disposition | Retained lesson and source | Closure evidence required | Role to assign |
|---|---|---|---|
| CF-12 DECISION_REQUIRED | Addressing and reduced VRF are committed v1 scope but absent from the current P2-P4 issue cards. Equal/different VRF names alone neither join nor isolate routing domains. [PLAN sections 8.2-8.3; LPLAN S1:1280-1350; LTR L3-01:40; L3-04:36] | Explicit phase allocation without silently expanding P4/P5; positive domain proof, same-name separate-domain and different-name shared-domain twins, missing topology unknown. | Scope/addressing/VRF |
| CF-13 RETAIN | PortFast and guard semantics must survive producer projection and regional applicability. Root priority is not evidence of intended root. [LAUDIT rows:156; US0] | Actual producer-to-consumer PortFast, loop guard, BPDU filter/guard, MST region/root and intended-root/no-intent cases. | STP |
| CF-14 RETAIN | EtherChannel wrapped and nonactive members matter. A legend is not a donor member; passive LACP/PAgP is not static; expected membership/min-links needs evidence. [LTR L2-04:21,28-29,45] | Wrapped/nonactive/legend-only, protocol/mode and expected-member/min-links controls; unknown when intended membership is absent. | EtherChannel |
| CF-15 DECISION_REQUIRED | Issue #7 says a single gateway keyed by VLAN id. Retained FHRP identity also needs the evidenced L2 domain and protocol/group/VIP semantics; VLAN ids recur across sites and anycast is a countercondition. [Issue #7; LPLAN S1:1233,1357-1359] | Explicit group/domain key decision; repeated-VLAN separate-site, protocol/group separation, anycast and missing-domain twins. | FHRP/scope |
| CF-16 RETAIN | Test actual producer representations: protocol and role are separate fields, not a combined synthetic stub. Preserve secondary/non-SVI addresses and routed/subinterface populations. [LAUDIT refuteYes:25; rows:360,504] | End-to-end projection tests with real field shapes, protocol/role combinations and secondary/routed/subinterface population controls. | FHRP/addressing |

## P5 - Hardening and report closure

These are closure/review checkpoints for existing commitments, not new P5 product scope. Safety and correctness prerequisites must close before dependent behavior is exposed, even when the final report is P5.

| ID / disposition | Retained lesson and source | Closure evidence required | Role to assign |
|---|---|---|---|
| CF-17 RETAIN | `next_evidence` is a closed typed command/parameter grammar. Hostile or unprintable captured names must not become executable command text. [LPLAN S1:737-755,778-795] | Parameter grammar, quoting/control-byte refusal and scope-specific suggestion cases; no live collection feature. | Contract/evidence |
| CF-18 RETAIN | Wrong reason with the right state is still wrong. Healthy and insufficient populations need separate metrics; zero denominators are not measured success. [LPLAN S6:272-305] | Reason mismatch twins; distinct false-healthy-on-fault/insufficient and incorrect-N/A rates, actual n/cells/shortfall, explicit unmeasured cells. | Truth/report |
| CF-19 RETAIN | Evidence removal must not erase the subject from the denominator. Hold expected population independently for insufficient-evidence cases I1-I10. [LPLAN S6:331-344,725-727] | Independently derived population plus every declared removal case, unchanged subject identity, no disappearance-as-success. | Truth/model |
| CF-20 GAP | A retained local lint refinement catches implicit builtins through shadowing/class/comprehension contexts. The present helper does not prove an active complete 15-lint public gate. [LK; ULINT] | Pin the accepted lint subject, planted lexical/context violations and actual gate invocation; do not claim full K freeze or copy a helper as gate evidence. | Kernel/CI |
| CF-21 GAP | Eight runner witness steps are executed sequentially; their count is not proof of pack parser parallelism. [URUNNER] | Actual bounded pack-worker scheduling, cancellation/retry/determinism and same-runner scale evidence on the new Baby head, if required by existing exits. | Runner |
| CF-22 GAP | Probe receipts count probe-local deltas; the lifetime violations accessor is separate. Startup origin checks/audit hooks do not alone prove OS containment. [UTRIPWIRE; URUNNER; US0] | Plant a swallowed denial outside probes and prove lifetime refusal; retain role baselines and Linux/Windows containment limits. This records missing proof, not an observed escape. | Runtime/security |
| CF-23 GAP | Whole-output assembly and two direct output writes do not demonstrate streaming or atomic publication. [URUNNER; US0] | Fault during second write, disk-full/interruption and previous-complete-output preservation; bounded memory/stream evidence. No current corruption is asserted without a counterexample. | Runner/contract |
| CF-24 RETAIN | Preserve Windows venv executable identity, exact spawn/audit shapes and PID birth-time custody. Separate `-I` acceptance from labelled fixed-seed `-P -s -B` probes; cross-job timing is not same-runner scaling. [US0] | Exact-head Linux/Windows role/startup/venv and PID-reuse cases; all sizes on one runner; independent workload arithmetic; labelled acceptance/probe profiles. | Runtime/CI |
| CF-25 RETAIN | Native event, exact source/head, complete job pages and terminal steps bind a hosted result. Job success is not budget or qualification proof; retain earlier failures/skips. [UC1; US0] | New-head complete hosted receipts and decisive logs, intended gates terminal, explicit skipped/cancelled/expired evidence and separately measured budgets. | CI/reviewer |
| CF-26 RETAIN | Corpus provenance/licence, supported format floor, authentic Tier-M donor admission and independent semantic truth are different gates. Prepared seeds are not applied/scored mutations. [UQ; LSB; LTR] | Per-variant provenance/floor or explicit allowlist, admitted donors, independent application/scoring and per-cell shortfall; no transferred legacy accuracy claim. | Corpus/truth |

## Parked, rejected and unresolved carry-forward

| ID / disposition | Record and boundary | Next action |
|---|---|---|
| CF-27 PARKED | S0 is a disposable runtime experiment. Its pipeline code never merges. Old holds, partial metrics and green jobs do not authorize resumption, PR opening, K freeze or qualification transfer. [US0] | Retain lessons and negative evidence; use a fresh bounded Baby implementation/validation only when separately in scope. |
| CF-28 PARKED | CT, E manifest/admission refinements and NX stream work are not drop-in implementations. Their branches/contracts differ; NX stays outside the EI product fence. [LCT; LE; U0] | Preserve source custody; use only applicable sanitized semantics after ownership/contract review. No imports in this task. |
| CF-29 REJECTED | An old conditional truth draft inferred administrative enablement from down/down. B1 correctly keeps unproven admin state unknown. [LTR interface-truth:26,42-46; B1 [ADR-0017](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/docs/adr/0017-interface-answer.md)] | Retain as a rejected label with a counterexample; never restore that inference. |
| CF-30 REJECTED | No lab-first/mandatory holdout gate, name-only isolation proof, cross-head score aggregation, or conversion of observations/prepared seeds into proven defects/scored mutations. [LPLAN; LSB; LAUDIT] | Keep actual denominators, source head and evidence tier; publish unknown/unmeasured rather than inherited success. |
| CF-31 DECISION_REQUIRED | PLAN hardware promises versus deferrals, and overlapping row/wave counts, need owner-level reconciliation. Current scope text is not a simple set subtraction. | Record a bounded scope decision before related work; this ledger does not alter committed rows, add hardware work or rewrite counts. |

## Source register and provenance limits

Public sources are pinned links. Owner-held sources below are relative references to existing material, not uploaded files, remote backup claims or accepted truth. The original content remains controlling for reinspection. Source line references refer to the audited snapshot.

| Alias | Audited source |
|---|---|
| UFOUND / U0 | [Seed source tree](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/tree/4f476b8c2cc38db081397dc8588377741b40499a) and [Baby NOTICE at B0](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/0eb744fed4f90ba16ccc26bfb9c1d834464f8a42/NOTICE). |
| UQ | [Tier-P corpus notes at U0](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/blob/4f476b8c2cc38db081397dc8588377741b40499a/docs/contract/tier-p/README.md); Q source `eeacdcb036aa1a137484734b03affdec25d1b923` is an ancestor of U0. False format-floor flags are not silently upgraded. |
| UC1 | [C1 source tree](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/tree/f583c770e084e8c2821cadc43db0d13501370097), ancestor of U0; custody/correction evidence was selectively inspected, not every archive replayed. |
| US0 | [S0 ADR at b64d04856cad546eddf20a950d0501606c585507](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/blob/b64d04856cad546eddf20a950d0501606c585507/docs/adr/0001-language-runtime.md#L70), plus [run 39447420195](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/actions/runs/39447420195) at source `2773cfd4fdde0b800662c23dc8f72f947f2107b5`. ADR, experiment head and run source are distinct subjects. |
| UKERNEL | Historical [admissibility](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/blob/574b7854528eab0bf6a71fc3db47f0e93a32f70d/atlas_brain/kernel/admissibility.py#L24), [population](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/blob/574b7854528eab0bf6a71fc3db47f0e93a32f70d/atlas_brain/kernel/population.py#L21), [verdict](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/blob/574b7854528eab0bf6a71fc3db47f0e93a32f70d/atlas_brain/kernel/verdict.py#L151). Historical verdict still returned unknown for some time/cross-device proofs; this is not a complete ready implementation. |
| UGRAPH | Historical [entity-mention steps](https://github.com/Tanveerahamed-Dev/atlas-brain-staging/blob/4f0a86817c99d085761b602a8a20e1380a3bf782/atlas_brain/model/steps.py#L32). Verify against the current Baby graph before any design change. |
| UCAPTURE | B1 [capture admission and omitted-metadata bridge](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/atlas_brain/evidence/capture.py#L58), especially lines 118-127. |
| URUNNER | B1 [coordinator](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/atlas_brain/runner/coordinator.py#L18): witness steps 18, whole-output assembly 53-99, direct writes 98-99, sequential subprocess calls 110-114. |
| UTRIPWIRE | B1 [tripwire](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/atlas_brain/runner/tripwire.py#L46): all-events accessor 46-48 and probe delta 51-76. |
| ULINT | B1 [lint helper](https://github.com/Tanveerahamed-Dev/baby-thanos/blob/2ba7443d654019e5e3dece1a539c8470929fbfcb/atlas_brain/kernel/lints.py#L61). Helper presence is not full-gate evidence. |
| LPLAN | Owner-held tracked planning snapshot `4bacaac47811c459d526d87b1bdde1a844a0e4bc`. S1=`plans/synthesis/1-architecture.md`; S4=`4-coverage-and-platforms.md`; S5=`5-correlation-and-time.md`; S6=`6-accuracy-and-ci.md` in the same directory. These documents were verified unchanged against their tracked snapshot. |
| LAUDIT | Owner-held historical audit at the LPLAN snapshot: `rows.json` and `refuteYes.json`. Only sanitized defect shapes are retained here; original rows are not published or reclassified as proven current defects. |
| LTR | Owner-held untracked `work/research/truth/` research drafts. L1-10, L2-01, L2-04, L2-06, L3-01, L3-04, L3-05, L3-28 use their `.md` basenames; interface-truth means `l1.interface.admin_up_oper_down.md`. Hashes below bind research documents, not raw captures. Draft labels remain conditional and donor gaps remain open. |
| LK | Owner-held K head `10b05aaf5b58103794c0711d073c6aa0993f3bfb`, lint refinement (`lints.py`:76-132,165-175). Exact head not found through the audited GitHub lookup; no qualification is implied. |
| LE | Owner-held E metadata/admission revision `20a6b2925cbe61fb90da1cf309db0ba5d00221c2`, `admission.py`:223-269,281-306. Exact revision not GitHub-retrievable in the audit; branch publication does not prove this ignored refinement was published. |
| LCT | Owner-held CT head `334db2391e6f9dd973c5e3f7ade26f6bc27b47ba`, `contract/results.py`:1-32, dependent on older K types. Exact head not found in the audited GitHub lookup. |
| LSB | Owner-held SB head `8cc47311c462853151bf7e33e023ce36449a2c13`, README/seeds record: 24 prepared, zero independently applied/scored; inactive. Exact head not found in the audited GitHub lookup. |

| LTR document | SHA-256 of audited research document |
|---|---|
| L1-10.md | `9bfe6fb5f1be3ab6ed314e67c1ba96d8ea6c08c14e40faa74318bd6cda383310` |
| L2-01.md | `345c850ec7ccea126cafff4e53b766db7213a3d94a9d033d03c1fad55ddf9bdd` |
| L2-04.md | `4128a22104a916d9f227117e92db9dcf099deeaf40d6aaecc58387e05cf1e637` |
| L2-06.md | `ddaf641687f1c2b2d9ec84fa56316aa949ecf2dbe54cbf971e5aed66e045807b` |
| L3-01.md | `ef5c4e2716b240d115915fea402f5327e77601eeda1867d6942834b027489399` |
| L3-04.md | `079190ad9a0218340cc86c12026ee7274602bf97da1ec2ca9ba5e26d560fb740` |
| L3-05.md | `e8b2534851d183f7f982ce99b11d5ef25c411bc221c4cd8342697482e87f0832` |
| L3-28.md | `f9c0ffa034a5c173a172dc58eb83fdcae620915a371bf8352dddf18b057ef3bb` |
| l1.interface.admin_up_oper_down.md | `2ee8796daba4bb7a30be1928a51e5f9c5910ebb5f75b70ac77c7a67281952ec0` |

## Audit coverage and limits

- Planning: 66 tracked and 41 untracked files were accounted for. The 107-file disposition comprises 18 full reads, 36 section reads, eight metadata checks, one duplicate and 44 indexed dispositions. Superseded/out-of-EI/workflow material was classified; broad matrices were not read cell by cell. Research/truth sources were accounted for; no known unread current P2-P5 requirement remained in that indexed set.
- Historical duplicates were compared selectively. The canonical redacted material controls; private configuration and an older less-redacted verification copy are excluded from publication. No text or identifying map from those excluded sources belongs in this ledger.
- The 11 stream trees yielded 199 unique paths / 251 path-blob variants; 191 first-party variants comprised 128 baseline, 15 contribution and 48 superseded/bootstrap variants. All 15 active contribution files and seven substantive ignored implementation variants were read/diffed. The 1,442 ignored evidence files were inventoried selectively, not all logs line-read or executed. Counts are audit coverage, not proof of backup completeness.
- Q's tracked paths are present as stated above. C1's 187 paths compare to B0 as 174 identical, four changed and nine deliberately absent. S0's 52 tracked files were inventoried with key code/tests/ADR/handoffs/receipts reviewed; large old archives and C1 evidence were selective custody reads, not replay validation.
- The cited S0 push run has 22 successful jobs and one skipped Windows locked-install job on its own source head. Earlier failures, supplemental probes and unresolved Windows OS-containment/qualification limits remain negative or bounded evidence. Neither this run nor a historical review upgrades the Baby product.
- Git HEAD/status/index custody across the 15 existing checkouts and the canonical/historical planning content manifests was unchanged by the audit. This proof does not cover every ignored cache/archive byte. This task performs no local repository writes, cleanup, source imports, project execution or tests.
- Exact unpublished heads failing the audited GitHub lookups establishes only that reachability gap. It does not prove no equivalent squashed content or no other remote backup exists.

## Preservation and closure protocol

1. Preserve every original local folder, linked-worktree metadata, ignored evidence and unpublished refinement. This selective sanitized ledger is not a backup and grants no deletion or cleanup permission.
2. Before a dependent phase, assign the relevant role, re-read the pinned/current sources and resolve its DECISION_REQUIRED items. Revalidate B0/B1 drift rather than treating this snapshot as perpetual authority.
3. Implement only through a separately scoped change authorized for that work. Do not copy old code, captures, fixtures or configuration under this ledger's documentation authority.
4. Close a row only with its actual new Baby source/head, counterexample and healthy/insufficient twins where relevant, complete exact-head hosted checks and the required independent review. Record residual gaps and prior failures; do not substitute an old spike score.
5. Keep PR #14 unchanged and unmerged in this task. Do not close phase issues, alter the controlling PLAN, or claim full P1/P2-P5 acceptance from publishing this record.
