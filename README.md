# Baby Thanos

**Atlas Brain — CCIE Enterprise Infrastructure edition.** A read-only, offline, deterministic Cisco
network analysis engine.

Status: **v0.1 — plan proposed (2026-10-24), foundation seeded.** Not yet a runnable product.

## What this is

Baby Thanos is the product codename for an EI-only edition of the Atlas Brain engine: evidence in
(read-only CLI and configuration captures) → versioned findings out. The engine computes; nothing here
is a UI, an installer, a collector or a live device write, and no LLM sits in any path that produces a
fact.

The full Atlas Brain plan was correctly ambitious but too broad to ship first: it committed 13 Cisco
families, ~106 protocol packs and a multi-year wave plan. This repository keeps the same doctrine and
the same proven foundation, and targets exactly one credential — **CCIE Enterprise Infrastructure
(EI) v1.1** — starting with **EI Network Infrastructure on IOS-XE**.

## Read the plan

- [PLAN.md](PLAN.md) — the final CCIE EI-only plan: scope, architecture, milestones, quality bar,
  governance and the first ten PRs.
- [plan/scope-ccie-ei.md](plan/scope-ccie-ei.md) — EI blueprint → protocol-row → pack mapping, the
  v1 slice, and what is deliberately deferred.
- [plan/foundation-seed.md](plan/foundation-seed.md) — what was inherited from
  `atlas-brain-staging`, what is kept, adapted or dropped, and why.

## Repository layout

| Path | Purpose |
|---|---|
| `atlas_brain/` | Engine code: kernel fact algebra, evidence intake, parse kit, output contract, platform packs |
| `tests/`, `fixtures/` | Inherited test suite and evidence fixtures with provenance |
| `tools/` | Contract, privacy, provenance and fence tooling used by CI |
| `docs/contract/`, `docs/adr/` | Output-contract schema, custody records, inherited architecture decisions |
| `plan/`, `reference/` | The EI plan, scope map and public Cisco EI reference material |
| `.github/workflows/` | CI gates (lock, static, privacy, contract, provenance, system fields) |

## Quick start

Requires Python 3.14.7+ and [uv](https://docs.astral.sh/uv/):

```powershell
uv sync --locked
uv run pytest -q
```

The inherited code is a tested **foundation library**, not a runner: there is no CLI yet, and only one
parser (IOS-XE `show version`). The first end-to-end vertical — L1 interface state — is Milestone 0 in
[PLAN.md](PLAN.md).

## Provenance and licence

Engine foundation, tests, fixtures, tools, contract docs and CI workflow files are derived from
[`Tanveerahamed-Dev/atlas-brain-staging`](https://github.com/Tanveerahamed-Dev/atlas-brain-staging)
at commit `4f476b8c` (2026-10-23), Apache-2.0. See [NOTICE](NOTICE) for the derivation statement and
[LICENSE](LICENSE).

`reference/` contains the public Cisco CCIE EI v1.1 exam-topic text and a protocol-row list derived
from public Cisco blueprints, included for scope reference only.
