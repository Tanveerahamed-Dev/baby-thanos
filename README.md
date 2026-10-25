# Baby Thanos

**Atlas Brain — CCIE Enterprise Infrastructure edition.** A read-only, offline, deterministic Cisco
network analysis engine.

Status: **P0 — offline system-field analysis.** The wider EI engine remains planned.

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
$env:ATLAS_TEST_MARKER = "codex-local"
uv run pytest -q
uv run python -m atlas_brain.runner --evidence captures --out out
```

Put raw UTF-8 IOS-XE `show version` files in `captures/`; keep `out/` separate.
Each file must contain one response beginning with its IOS-XE header, or the
supported headerless three-field fragment. An exact `show version` prompt may
wrap it; conflicting commands and configuration sections refuse. See
[ADR-0016](docs/adr/0016-runner-response-recognition.md) for recognition limits.
The runner writes `SUMMARY.txt` and `MANIFEST.json` with uptime, image, reload reason
and boot epoch states, capture IDs and byte-span evidence. Missing collector time
leaves boot epoch `unknown(as_of_missing)`; unsupported or unsafe inputs refuse
with exit code 2. Output is identical across reruns and `--workers 1` / `--workers 4`.
P0 extracts observed fields only; it does not identify/merge devices or qualify
platform/train support. Keep input/output trees stable during each run. Limits and
admissions are documented in [ADR-0015](docs/adr/0015-runner-evidence-path.md).
The L1 interface-state vertical remains planned in [PLAN.md](PLAN.md).

## Provenance and licence

Engine foundation, tests, fixtures, tools, contract docs and CI workflow files are derived from
[`Tanveerahamed-Dev/atlas-brain-staging`](https://github.com/Tanveerahamed-Dev/atlas-brain-staging)
at commit `4f476b8c` (2026-10-23), Apache-2.0. See [NOTICE](NOTICE) for the derivation statement and
[LICENSE](LICENSE).

`reference/` contains the public Cisco CCIE EI v1.1 exam-topic text and a protocol-row list derived
from public Cisco blueprints, included for scope reference only.
