# Baby Thanos

**Atlas Brain — CCIE Enterprise Infrastructure edition.** A read-only, offline, deterministic Cisco
network analysis engine.

Analysis modes: **P1 capture-scoped answers; P2 declared two-end comparisons; P3 conditional MTU/OSPF candidates;
P4 declared STP/EtherChannel/HSRP observations.**
P2–P4 use bounded CLI allowlists, with explicit synthetic scope and evidence gaps. P4 also provides a
separate Python API for caller-declared STP guard comparisons.

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

## Declared P4 observations

P4 is in progress. Its current observation profile admits bounded IOS-XE forms:
`show spanning-tree interface <port> detail`, `show etherchannel summary` and
`show standby brief`. These are allowlisted forms, not platform/train qualification.

The input folder needs a discovery-only schema-1 `p2.json`, a
`atlas-brain.synthetic-p4/1` `p4.json` bound to its exact hash, and every declared
capture. Targets declare expected subjects independently of observations; capture
paths and hashes are checked before semantic work. Extra unlisted files refuse.
P2 schema-2 configuration/inheritance is not admitted by this P4 profile.

For an admitted folder, the existing observation command is:

```powershell
uv run python -m atlas_brain.runner --format p4-observations --evidence p4-captures --out p4-output --workers 4
```

Keep input and output separate. The output directory must be new, with an existing
parent. The command writes five files: `result.json`, `MANIFEST.sha256`,
`facts/stp_port_vlan.jsonl`, `facts/etherchannel_group.jsonl` and
`facts/fhrp_local.jsonl`. The result declares `observations_only` and
`checks: not_implemented`; this command emits no conditional guard findings.

| Pack | Current facts | Meaning |
|---|---|---|
| STP | `root_guard`, `reported_role` | Explicit reported guard state and port/VLAN role |
| EtherChannel | `reported_protocol`, `reported_member_tokens` | Local protocol observation and derived member-token text |
| FHRP | `reported_state` | Local IPv4 HSRP state, keyed by context/node/exact interface/IPv4/HSRP/group |

Facts retain their basis, raw token where applicable, exact evidence spans and
unknowns with next evidence to collect. The denominator counts declared subjects,
not fact cells. Declared targets without a capture entry stay `not_collected`;
every listed capture must be present and hash-match. A declared subject absent
from an otherwise complete capture stays `subject_absent_from_capture`; a guard field
omitted within an otherwise complete port/VLAN record stays `field_not_printed`.
None of these unknowns means disabled or healthy. EtherChannel `-` is
`none_reported`, not mode On; member flags are reported tokens, not membership intent.

The separate [guard comparison API](atlas_brain/runner/p4_guard_policy.py)
accepts typed caller-declared policies and emits conditional reported-guard results.
Its [report](atlas_brain/packs/l2/stp/guard_report.py) includes the declared policy
and cited operands. An omitted guard stays unknown; equal untimed observations do
not prove health. This API is not a CLI policy-file input path, and its exported
policy is not an admission seal. Reports still require the original pinned inputs.

### Hosted P4 evidence

The existing [P0 runner workflow](.github/workflows/p0-runner.yml) runs both hosted-only
[guard](tools/p4_guard_demo.py) and [three-pack estate](tools/p4_estate_demo.py) demos
on Linux and Windows. In an exact-commit successful run, inspect
`P4_GUARD_RECEIPT` and `P4_ESTATE_RECEIPT` in the logs and the corresponding
`p0-demo-<OS>-<commit>` artifact. Under `p4-guards/` and `p4-estate/`, each case
retains `inputs/`, `out0/`, `out1/`; each demo also retains `DIGESTS.json` and
batch stdout/stderr. Keep the original input folders with their reports.

The estate demo covers baseline, PAgP and missing-capture twins: three cases,
19 cells each, subject denominators STP=3/EtherChannel=4/FHRP=5, six API analyses in
two fresh processes seeded 1/83. It checks complete output bytes, source/report
hashes and zero additional tripwire denials. These receipts measure the API
processes on synthetic fixtures; they do not qualify CLI workers or the whole host.
Compare bytes across seeds/OS only for the same pinned inputs.

Root identity, other guards/defaults/inheritance, explicit EtherChannel mode or
expected membership, VRRP/VIP/version, FHRP peer/redundancy/anycast checks and the held-out
pack admission proof remain open. This evidence does not complete P4, EX-02 or M1, or
qualify field behavior. See [ADR-0023](docs/adr/0023-p4-pack-boundaries.md).

## Provenance and licence

Engine foundation, tests, fixtures, tools, contract docs and CI workflow files are derived from
[`Tanveerahamed-Dev/atlas-brain-staging`](https://github.com/Tanveerahamed-Dev/atlas-brain-staging)
at commit `4f476b8c` (2026-10-23), Apache-2.0. See [NOTICE](NOTICE) for the derivation statement and
[LICENSE](LICENSE).

`reference/` contains the public Cisco CCIE EI v1.1 exam-topic text and a protocol-row list derived
from public Cisco blueprints, included for scope reference only.
