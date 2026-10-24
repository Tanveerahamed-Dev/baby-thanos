# Foundation seed — what was inherited and what happens to it

**Source:** [`Tanveerahamed-Dev/atlas-brain-staging`](https://github.com/Tanveerahamed-Dev/atlas-brain-staging)
at `main` `4f476b8c` (2026-10-23), Apache-2.0, 187 tracked files / 630 commits. Baby Thanos starts
from a **fresh root commit** in this repository: no upstream branch refs, no upstream history, no
private staging data. Upstream remains a reference; sync is by deliberate cherry-pick, never by pull.

**What the seed is:** a tested *foundation library* for a read-only, offline, deterministic Cisco
evidence engine — not a runnable product. It supplies the honesty kernel, evidence custody, parse
kit, output contract and one IOS-XE pack; the product (runner, fact store, network model, EI packs)
is the build described in [`PLAN.md`](../PLAN.md).

---

## 1. What the seed contains

| Area | Files / LOC | State | Role in Baby Thanos |
|---|---|---|---|
| `kernel/states.py` | 288 LOC | real | Closed fact algebra: `Known/Absent/Unknown/NotApplicable`, evidence refs and byte spans, ~30 unknown reasons, structural invariants. **Central asset — unchanged.** |
| `kernel/time.py` | 34 LOC | real | `TimeInterval` with clock-bound sources (the `settle` rule's substrate). |
| `kernel/lints.py`, `kernel/token_lints.py` | 101 + 316 LOC | real | Static AST guards over engine source (silent defaults, unordered iteration, import binding). Dev/CI only. |
| `evidence/text.py`, `capture.py` | 38 + 163 LOC | real | LF line/byte views; capture classification and metadata bridge. |
| `evidence/admission.py` | 272 LOC | real | Fail-closed folder/manifest intake: path and anchor safety, JSON limits, budgets, SHA-256 custody. |
| `evidence/parsekit/patterns.py`, `rules.py` | 84 + 199 LOC | real | Conservative regex admission; ordered stateful byte-rule engine with exhaustive line accounting and closed token maps — no TextFSM silent drops. |
| `contract/canonical.py`, `header.py`, `bundle.py`, `manifest.py` | 135 LOC | real | RFC 8785 canonical JSON, result header, JSONL+manifest bundle bytes. |
| `packs/platform/system/` | 32 + 158 LOC | real, narrow | The only device pack: IOS-XE `show version` fields (uptime, image, reload reason; boot epoch always Unknown). Proves the pack path. |
| `tests/` | 55 files, 440 tests | green upstream | Kernel/evidence/contract/parsekit/fence/privacy/provenance suites, Hypothesis property tests. |
| `fixtures/` | 23 raw samples + `provenance.yaml` | green upstream | 11 IOS-XE tier-P, 7 NX-OS tier-P, 4 mutation, 1 synthetic. |
| `tools/` | 18 tools | green upstream | Contract schema/lint, privacy, provenance, fence, governance/receipt tooling. |
| `docs/contract/`, `docs/adr/` | schema + ADR-0000..0012/0100 | green upstream | Output-contract schema and the upstream source-policy decision chain. |
| `.github/workflows/` | 7 → 6 workflows | green upstream | Lock, static, privacy, contract, provenance, system fields, governance, mutation. |

**What the seed does not contain:** a runner/CLI, a fact store, a network model, correlation, an
IOS-XE interface/L2/L3 parser, any EI pack, a truth corpus beyond tier-P floors, or a scale harness.
There is no product-level end-to-end path today.

---

## 2. What was changed at seed time (first commit)

1. **New project identity and plan** — `README.md` rewritten for Baby Thanos; `PLAN.md`,
   `plan/scope-ccie-ei.md`, `plan/foundation-seed.md`, `NOTICE`, `reference/` added.
2. **Fence allowlist extended** — `tools/fence.py` `ROOTS` gains `NOTICE`, `PLAN.md`; `TREES` gains
   `plan/`, `reference/`. Rationale: the owner asked for the plan to live in this repository; the
   old "no process documents in tree" rule is relaxed for the plan while it is being executed
   (revisit at `ei-v1`).
3. **`privacy-status.yml` dropped** — it fetched pinned upstream commits
   (`a5a2959`, `ca64e4d`, `df6016e`, …) that do not exist in this repository's history; keeping it
   would have made CI red by construction. The privacy gate it contained is retained through
   `ci.yml` (changed-blob scan) plus the stub `privacy`/provenance jobs.
4. **Derivation recorded** — `NOTICE` states the copied material, its origin commit and the
   Apache-2.0 derivation; `LICENSE` unchanged. Third-party notices under
   `docs/contract/tier-p/_licences/` and `docs/contract/mutation-sources/` are preserved.
5. **Upstream governance/receipt chain pruned at seed time** — removed `governance.yml`,
   `tools/main_receipts.py`, `tools/base_native_receipts.py`, `tools/governance.py`,
   `tests/test_main_receipts.py`, `tests/test_governance.py`. Those gates are bound to the upstream
   repository's CI-run receipts and PR/board model; Baby Thanos replaces them with PR-linked review
   records and its own governance checks (PLAN.md §10, PR 10). Their removal also removes the two
   slowest tests from the local suite.

Nothing in `atlas_brain/` was modified at seed time except the fence allowlist (a `tools/` change).

---

## 3. M0 prune list (scheduled, not urgent)

The seed intentionally carries some upstream full-scope material. It is out of EI scope and should
be removed or archived in M0, in a single `chore: prune upstream full-scope material` PR:

| Item | Why prune | Keep as |
|---|---|---|
| NX-OS tier-P fixtures (`fixtures/tier-p/nxos/`) + NX-OS sample bytes | NX-OS is out of EI scope (zero blueprint mentions) | reference only, or delete |
| Mutation corpora (`fixtures/mutations/`, `tools/mutations.py`, `tools/evidence_mutations.py`, 3 contract docs, 3 test files) | upstream full-scope coverage programme; EI v1 uses its own regression catalogue | re-add a slim mutation set when the EI truth program needs it |
| Governance receipts / fence-inventory tools (`tools/main_receipts.py`, `base_native_receipts.py`, `check_*_inventory.py`, `output_witness.py`, `governance.yml`) | tied to the upstream CI-run/receipt model; Baby Thanos uses PR-linked review records | **pruned at seed time** (receipt chain); `check_*_inventory.py`/`output_witness.py` remain for the M0 prune |
| Upstream ADR-0002 source-policy chain (`docs/adr/0002`–`0012`) | records upstream source-admission negotiations | archive under `docs/adr/upstream/` or delete; new ADRs start at 0001 in this repo |
| 8 fence/receipt-linked test files (~65 tests) | exercise the pruned tooling | prune with the tools |

**Not pruned:** the kernel lints, admission hardening, parse kit, contract tooling, privacy and
provenance tools — they are the quality system of the product.

---

## 4. EI relevance of the seed

- **Keep, unchanged:** kernel fact algebra and time; evidence capture/text/admission; parse kit;
  contract modules; `platform.system` pack; contract schema and provenance tooling; the privacy and
  provenance gates (reduced to the EI product's needs).
- **Adapt:** fence path allowlist (done); CI workflows (6 remain, all self-contained); truth corpus
  (IOS-XE tier-P floors and synthetic validator are the useful parts).
- **Build (not in the seed):** runner, fact store, network model, correlation engine, IOS-XE adapter,
  the 12 EI v1 packs, the truth/regression programme, scale harness.
- **The seed is a foundation, not an accelerator for scope:** it removes the kernel/evidence/contract
  risk (the parts that are expensive to get right) but it does not shorten the EI pack work.

---

## 5. Branch and PR landscape of the source repository (for context only)

Upstream `atlas-brain-staging` carries ~150 remote branches (K 58, C1 50, PK 12, CT 10, E 8, V 5,
NX/MU/Q/S0 one each), 73 merged into `main`, 75 unmerged, 3 open drafts, ~100 merged/closed PRs over
2026-10-20..23 — a fast, review-gated AI sprint on kernel/parsekit/contract qualification, not on EI
fact packs. Consequences for Baby Thanos:

- Do **not** carry upstream refs or branch history into this repository; it starts fresh.
- Upstream improvements to kernel/parsekit/contract may be cherry-picked later, deliberately, one at
  a time — never merged wholesale (they carry full-scope policy).
- The 8 `k/diagnostic-147-*` probe branches are debris; they are never referenced here.

---

## 6. Licence and attribution

- `LICENSE` — Apache License 2.0, retained unchanged.
- `NOTICE` — derivation statement for all copied material; new files listed as original; Cisco
  public exam-topic reference text excluded from the project licence.
- Third-party notices for copied sample bytes are preserved in place: `docs/contract/tier-p/_licences/`
  (ntc-templates MIT LICENSE + NOTICE, genieparser/napalm/suzieq NOTICEs) and
  `docs/contract/mutation-sources/`.

---

## 7. Validation status of the seed in this repository

| Check | Result |
|---|---|
| `uv lock`/`uv sync --locked` reproducibility | verified locally (uv 0.13.5, CPython 3.14.8) |
| `ruff check .` | pass |
| `pyright` strict | pass (0 errors) |
| `tools/fence.py` path/import gate | pass after the allowlist extension (0 refused paths) |
| `pytest -q` | see CI; the seed carried 440 tests green upstream, 2 receipt-chain test files were pruned at seed time, and the first CI run on this repository is the binding check |
| Contract schema regeneration | no diff expected; verified in CI (`contract.yml`) |
| Privacy / provenance gates | CI (`ci.yml`, `provenance.yml`) |
