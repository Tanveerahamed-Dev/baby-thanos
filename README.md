# Baby Thanos

**Atlas Brain — CCIE Enterprise Infrastructure edition.** A read-only, offline, deterministic Cisco
network analysis engine.

Analysis modes: **P1 capture-scoped answers; P2 declared two-end comparisons; P3 conditional MTU/OSPF candidates.**
P2/P3 are bounded generated CLI allowlists, with explicit synthetic scope and evidence gaps.

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
wrap it; recognized conflicting command/configuration markers refuse. See
[ADR-0016](docs/adr/0016-runner-response-recognition.md) for recognition limits.
The runner writes `SUMMARY.txt` and `MANIFEST.json` with uptime, image, reload reason
and boot epoch states, capture IDs and byte-span evidence. Missing collector time
leaves boot epoch `unknown(as_of_missing)`; unsupported or unsafe inputs refuse
with exit code 2. Output is identical across reruns and `--workers 1` / `--workers 4`.
P0 extracts observed fields only; it does not identify/merge devices or qualify
platform/train support. Keep input/output trees stable during each run. Limits and
admissions are documented in [ADR-0015](docs/adr/0015-runner-evidence-path.md).
P1 also accepts `show interfaces` and `show ip interface brief` captures, reporting
admin/line-protocol mismatches as `l1.interface.admin_up_oper_down` findings.
Unknowns include the next command to collect; missing interface evidence is explicit.
Counts cover observed names per capture, with no cross-file device or alias joining.
Support is measured on synthetic regressions, not qualified across devices/trains;
unmodelled detail lines keep healthy captures partial/unknown. See
[ADR-0017](docs/adr/0017-interface-answer.md).

## Declared P2 and P3 analysis

A P2 `p2.json` registry declares nodes, exact ports and capture hashes. Schema 1
accepts discovery/trunk observations; schema 2 adds bounded static configuration
inheritance. Configured intent remains separate from observed state.

P3 adds `p3.json`, bound to the exact `p2.json` hash. Its baseline contains only
CDP/LLDP captures. The sidecar declares adjacency endpoints and collection rounds;
MTU, OSPF state and control values come from the supplied CLI bytes. Initial scope
is explicitly declared default-VRF, point-to-point OSPFv2. It is not inferred from
omitted VRF output. Supported thin forms are:

- `show interfaces` for interface MTU, and `show ip interface` for IP MTU.
- `show ip ospf neighbor` and `show ip ospf interface` for observed adjacency context.
- `show running-config all` for explicit `ip ospf mtu-ignore` or
  `no ip ospf mtu-ignore` statements. Omission stays unknown.

```powershell
uv run python -m atlas_brain.runner --evidence p3-captures --out p3-output --workers 4
```

The runner writes outer `atlas-brain.runner-manifest/3` with inner
`atlas-brain.p3-demo/1`, plus a summary of the chain and its stopping hop.
A supported candidate requires reciprocal/context-consistent observations, an
IP MTU mismatch with a stable receiving endpoint, matching EXSTART or EXCHANGE
samples, and explicit disabled `mtu-ignore` on that receiver. Every declared round
is checked. Collector windows use integer Unix microseconds on one supplied clock;
the guaranteed first-to-last separation must be at least 120 seconds.

One complete round yields `unknown(single_sample)`. Disagreeing untimed states conflict;
missing MTU stops at the `ip_mtu` hop. Enabled receiver `mtu-ignore` is positive
counter-evidence. The result is a conditional candidate, not proof of continuous
adjacency state, an authenticated clock or a unique cause. No missing MTU becomes
1500, and interface MTU never replaces IP MTU.

The existing Linux/Windows runner workflow runs the hosted-only
`uv run python -m tools.p3_demo`. Its `P3_RECEIPT` log line and
`p3/DIGESTS.json` artifact bind the reviewed commit and five generated cases to
manifest, summary, result and catalogue digests. These receipts report synthetic
regression scope; they do not qualify device platforms or software trains.

## Provenance and licence

Engine foundation, tests, fixtures, tools, contract docs and CI workflow files are derived from
[`Tanveerahamed-Dev/atlas-brain-staging`](https://github.com/Tanveerahamed-Dev/atlas-brain-staging)
at commit `4f476b8c` (2026-10-23), Apache-2.0. See [NOTICE](NOTICE) for the derivation statement and
[LICENSE](LICENSE).

`reference/` contains the public Cisco CCIE EI v1.1 exam-topic text and a protocol-row list derived
from public Cisco blueprints, included for scope reference only.
