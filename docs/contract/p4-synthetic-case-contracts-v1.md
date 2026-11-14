# P4 synthetic regression contracts, version 1

Status: accepted (new project design only); implementation and qualification remain open.
Decision: [Named Lead design adoption](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/7#issuecomment-6882855367).

Catalogue: `baby-thanos.p4.synthetic/1`.
Aliases: EI-R04, EI-R10, EI-R11. Always retain the catalogue version with an alias or case ID.
Historical authoritative mappings remain UNVERIFIED; these are explicit NEW project definitions.
The owner requested a delegated best decision; this contract is not evidence of missing historical facts.
Authority anchors: [issue #7](https://github.com/Tanveerahamed-Dev/baby-thanos/issues/7) and
[accepted ADR-0023](../adr/0023-p4-pack-boundaries.md); design adoption is recorded by
[accepted ADR-0046](../adr/0046-p4-synthetic-case-contracts.md).

## Common evidence and outcome contract

- Use original generated synthetic bytes, labelled synthetic; retain generator revision and input SHA-256.
- Retain the exact envelope, declarations, policies, capture IDs/command identities and original inputs.
- Distinguish observed capture facts from `Basis.DECLARED` intent; declarations never become network truth.
- Declare expected subjects before reading observations. Removed captures never shrink the denominator.
- Validate the whole original population, including unselected subjects, before any finding.
- Bind facts to actual owner/registration/Store/Reader and subject-local authenticated evidence.
- Require exact byte spans/hashes, original participant references and scoped next-evidence requests.
- Policy/baseline needs have empty resolves when no fact is requested; do not relabel them as capture proof.
- A malformed/foreign ownership, selector or evidence graph refuses before publication, rather than voting.
- Authentic insufficient evidence keeps its canonical reason, evidence and needs in complete retained operand/gap records; never coerce it to False.
- Emit no healthy/current/redundancy claim from equal untimed reports, absence of rows or open coverage.
- Result records must include catalogue version, alias, case suffix, expected state/reason and denominators.
- Capture-scope conditional problems are not contemporaneous faults or field qualification.

Case suffixes F, C and U mean fault, countercondition/control and insufficient evidence.
Each case must have a complete expected result, including every operand/gap, not just a problem count.
Combined faults require a predeclared deterministic priority; no test may infer priority from output order.
Canonical policy/participant order chooses the finding's primary gap and its owning next-evidence tuple.
The complete retained result/oracle must still include every operand's state, evidence and needs.
This does not require concatenating all needs into an existing finding field or changing existing output pins.

## EI-R04: Root-guard reporting and default honesty

Scope: explicit reported root guard on an independently declared edge.
It does not determine intended root, inherited configuration, implicit defaults or synchronized topology.
The policy names exact original node/port/VLAN participants and supported declared PVST applicability.
Known guard/role operands require eligible complete own-subject captures and authenticated field spans.
Priority is declared-scope gaps, positive observed role exclusion, canonical first role gap, canonical first
guard gap, then explicit guard mismatch/equality. Scope gaps retain `unknown / analysis_gap`; a positive
role exclusion wins over a missing/partial other operand once declared scope is applicable.

| Case | Positive evidence or missing premise | Required outcome |
|---|---|---|
| F01 reported mismatch | Both designated roles are observed; explicit enabled versus disabled guard fields; same-reported-guard policy is DECLARED. | Conditional problem `l2.stp.reported_root_guard_mismatch`; cite both actual facts and spans. |
| C01 role exclusion | Applicable declared scope and a positive observed role make the comparison inapplicable under its explicit policy. | `not_applicable / role_excludes`; cite role evidence, not missing guard data. |
| C02 equal reports | Both eligible captures explicitly print the same guard value, with no admitted timing proof. | `unknown / as_of_missing`; never healthy. |
| U01 omitted field | Applicable declared scope, both roles positively designated, and otherwise complete record omits root guard. | `unknown / field_not_printed`; never default-disabled or enabled/disabled asymmetry. |
| U02 missing capture | Applicable declared scope, no positive role exclusion, and a declared participant has no capture. | Retain both participants; `unknown / not_collected` with its collection need. |
| U03 unusable premise | Partial/error/truncated/unmodelled input, unsupported applicability or unresolved inheritance; evaluate at its active priority stage. | Preserve its actual Unknown reason; no guessed guard/default/intent. |

Negative controls: foreign VLAN/header/port, swapped endpoint, role donor, altered digest/span,
coherent Row/Store false guard, missing declaration and removed capture must not qualify a mismatch.
Root priority/MAC never supplies intended-root or root-guard configuration evidence.

Existing semantic coverage:
- [Guard API](../../atlas_brain/runner/p4_guard_policy.py), [checker](../../atlas_brain/packs/l2/stp/guard_check.py).
- [Retained-evidence twins](../../tools/p4_guard_cases.py), [semantic/oracle tests](../../tests/packs/l2/stp/test_guard_cases.py).
- Existing mismatch/omitted/equal/role-excluded cases are coverage candidates, not newly certified passes.

## EI-R10: EtherChannel negotiation and member honesty

Scope: reported protocol/member observations and prohibited inference of static mode.
A declared comparison selects exact local subjects on different nodes; equal channel numbers do not join.
Protocol, explicit mode, member flags, intended membership and minimum-links remain separate quantities.
This contract does not assert that explicit mode-On or expected-member analysis is already implemented.
Priority is the canonical first actual Unknown operand, then a known `none_reported` operand, then
explicit eligible protocol discrepancy/equality. Retain all other operand gaps and needs in their records.

| Case | Positive evidence or missing premise | Required outcome |
|---|---|---|
| F01 protocol discrepancy | Original declared peer pair has eligible explicit LACP versus PAgP observations. | Conditional problem `l2.etherchannel.reported_protocol_mismatch`; retain both operands/refs. |
| C01 equal protocol | Eligible explicit protocols agree, without admitted temporal proof. | `unknown / as_of_missing`; no protocol-health claim. |
| C02 member preservation | Wrapped/nonactive/suspended members are printed in their own bundle records. | Preserve every observed member/flag/span; legends create no members. This is not membership intent. |
| U01 dash | Both operands are eligible Known observations, at least one reports protocol `-`, and no actual Unknown operand takes priority. | Keep `none_reported`; negotiation check remains `unknown / not_observable`, never mode On. |
| U02 passive or mode prose | Passive/on text is outside the admitted summary form, or explicit mode evidence is absent. | Partial/Unknown with its owning reason; never synthesize static On or a missing mode fact. |
| U03 missing baseline/data | Expected-member/min-links intent or a required capture is absent. | Unknown for that predicate; no member-loss/default/static inference. |

LACP, including positively evidenced passive negotiation in any later supported form, and PAgP
must never be classified as static On. Any future Known On value requires its own exact positive
mode evidence, owner and scope; a summary dash, legend or protocol token cannot donate it.
Expected membership/min-links findings require an independent explicit baseline and full population.
No raw group number, member flag, empty bundle or legend is a substitute.

Negative controls: repeated local IDs on different nodes, foreign group/member spans, missing wrapped
members, duplicates/conflicts, arbitrary port donors and uncollected endpoints retain scope and gaps.

Existing semantic coverage:
- [Protocol API](../../atlas_brain/runner/p4_etherchannel_policy.py), [checker](../../atlas_brain/packs/l2/etherchannel/protocol_check.py).
- [Summary tests](../../tests/packs/l2/etherchannel/test_parse_summary.py), [protocol twins](../../tests/packs/l2/etherchannel/test_protocol_check.py).
- These cover reported protocol, dash/passive honesty and member preservation; they do not certify mode/intent features.

## EI-R11: Baseline-closed missing FHRP and anycast

Scope: a conditional discrepancy against an explicit redundancy baseline, never a universal VLAN rule.
The baseline declares the original gateway scope, required protocol/group, exact expected participants
and any permitted alternative mechanism independently of observed HSRP/VRRP rows.
Local identities include node/interface/AF/protocol/group. Logical keys retain envelope/domain/VLAN/AF/
protocol/group; VIP/version are operands. Repeated VLANs, protocols or groups never coalesce.
An anycast alternative links to an explicit baseline requirement ID and the same envelope/domain/VLAN/AF
scope. FHRP protocol/group stay on the exact requirement being excluded; do not invent an anycast FHRP
protocol/group or join mechanisms by VIP/MAC equality. Another gateway/domain/requirement cannot donate it.

A missing-required-group problem requires ALL of:
1. Explicit applicable baseline and proven declared binding, not an inferred requirement for every VLAN.
2. Closed independently declared expected population, retaining every missing participant.
3. Actual owner-authenticated complete successful supported response and complete scoped census.
4. Positive `full_evidenced` read-scope proof and a view admissible for that supported capture-scope predicate.
5. An owning positive presence/coverage result proving the required subject is absent from that census.
6. Every baseline-permitted alternative is resolved: no eligible positive exclusion, unproven permitted
   alternative or unresolved baseline/mechanism conflict remains. Lack of positive anycast alone is not
   proof that a permitted alternative is absent.

Metadata flags or caller-labelled complete carriers do not establish conditions 3-5.
Do NOT promote `Unknown(SUBJECT_ABSENT_FROM_CAPTURE)` alone into positive absence or a problem.
Bare empty bytes, failed-command-looking-empty, missing captures and unknown/limited scope never qualify.
Any supported valid-empty control needs its own authenticated grammar/footer/census/read-scope proof.
No simultaneous/current-health claim follows from a conditional node-local capture discrepancy.

| Case | Positive evidence or missing premise | Required outcome |
|---|---|---|
| F01 required report missing | All six conditions close; an exact expected HSRP or VRRP group is positively absent for a required participant. | Conditional missing-required-FHRP-report problem, with baseline, coverage/presence and scoped capture proofs. |
| C01 required reports present | Applicable baseline/binding and closed expected set; every exact required subject has positive capture-scoped presence evidence. | The future owning missing-report predicate is `Known(False, Basis.DERIVED)` with baseline/binding and original positive presence references; no missing problem. Any separate untimed health predicate remains `unknown / as_of_missing`. |
| C02 permitted anycast | Explicit permitted-anycast alternative and positive DECLARED synthetic anycast exclusion match the gateway scope. | `not_applicable / declared_exclusion` for this missing-FHRP predicate; remain visibly DECLARED/synthetic. |
| U01 contradictory mechanism | Baseline specifically requires FHRP but positive anycast evidence conflicts with that intent. | `unknown / conflicting_evidence`; collect/review policy, never silently override it or emit missing-FHRP. |
| U02 no baseline | Binding exists but no applicable explicit redundancy baseline. | `unknown / no_baseline` and a declaration-policy need, not a fabricated capture need. |
| U03 open population | Expected participants are not independently closed. | `unknown / denominator_open`; never shrink the set to observed rows. |
| U04 unproven join | Domain or original participant binding is missing/ambiguous. | `unknown / join_unproven`; no cross-domain/protocol/group merge. |
| U05 insufficient capture/scope | Missing/partial/error/truncated/cached/unqualified-view or limited/unknown read scope. | Preserve the actual collection/scope/view Unknown and next evidence; no absence. |
| U06 permitted alternative unproven | Baseline permits anycast, but neither an eligible scoped DECLARED synthetic exclusion nor a supported owning positive evidence path closes that alternative. | `unknown` with that alternative's actual reason/needs (`not_collected` when uncollected); no missing-FHRP problem from lack of positive anycast. |

Rows assume their named applicable scope/premises and no higher-priority outcome; combined cases must
record their complete operand states and declared precedence before execution. C01 is a capture-scope
countercondition to missing reports, not a healthy/redundancy verdict or a new generic finding enum.
Positive DECLARED synthetic anycast is not observed deployment proof. Shared MAC/VIP, one gateway,
an absent HSRP row or a user description alone cannot manufacture observed anycast.
A permitted synthetic exclusion needs its admitted declaration and exact scope references.
Observed anycast support, if later added, requires a separately owned positive evidence path.
HSRP and VRRP cannot substitute for one another unless the explicit baseline permits that alternative.

Negative controls: remove one capture; forge completion/read-scope; omit an expected subject; donate
neighbor header/footer or another gateway's anycast; reuse a VLAN across domains; swap protocols/groups;
conflict baseline declarations; inject a failed/empty reply. Every control must retain denominators and gaps.

Current coverage and engineering:
- [Gateway policy](../../atlas_brain/packs/l3/fhrp/gateway_policy.py) supplies declared HSRP keys and open coverage only.
- It does not yet provide this baseline/closed-population/read-scope/anycast predicate.
- Add owning presence/coverage and its Reader/proof/value closure before the checker.
- Add baseline/alternative policy, conditional checker, HSRP/VRRP coexistence and visible mixed report/demo.
- R11 executable twins belong in those owning product slices; documentation adoption closes none of them.

## Implementation and qualification records

Record each implemented case's exact source head, original input hashes, expected outputs, predicate
state/reason/needs, complete operands, denominator/coverage, evidence spans/hashes and negative controls.
Require all hosted checks, exact-head independent review and native post-merge validation per project rules.
Existing semantic tests may be linked only with their real recorded scope; no prose-mirroring tests are needed.
Never claim historical catalogue provenance, platform/train truth, field qualification or full M1/EX-02
from these documents or a green suite. Full P4 acceptance remains a separate requirement-by-requirement audit.
Keep existing profile/output pins. No donor imports, local testing, cleanup, new product phase, P5 or release.
