# Baby Thanos — the plan

**Atlas Brain, CCIE Enterprise Infrastructure edition.**
Read-only, offline, deterministic Cisco network analysis engine — the brain only.

- **Plan version:** 0.1 (proposed) — 2026-10-24
- **Owner:** Tanveerahamed-Dev
- **Status:** awaiting G0 approval (owner sign-off). The repository is seeded with the foundation
  and the plan so building can start the moment G0 is given.
- **Companion documents:** [`plan/scope-ccie-ei.md`](plan/scope-ccie-ei.md) (EI blueprint → engine
  mapping, v1 slice) and [`plan/foundation-seed.md`](plan/foundation-seed.md) (what was inherited
  from Atlas Brain, kept/adapted/dropped and why).

---

## 0. The verdict in one page

**What is built:** one read-only, offline, deterministic analysis engine scoped to **CCIE Enterprise
Infrastructure (EI) v1.1**, starting with **EI Network Infrastructure on IOS-XE**.

**Can it be achieved? Yes — and this time the scope is small enough to finish.** The full Atlas Brain
plan was right in doctrine and wrong in first scope: 13 Cisco families, ~106 protocol packs and a
multi-year wave plan is not a first product. This edition keeps the doctrine and the proven
foundation and cuts the first product down to:

| Dimension | Full Atlas Brain v1 | Baby Thanos v1 |
|---|---|---|
| Credentials targeted | 4 CCIE tracks | **1: CCIE EI v1.1** |
| Platform families | 13 families, 21 adapters | **1: IOS-XE** (classic IOS as backfill) |
| Protocol rows | 122 rows across L1–L7/SP/OOS | **60 EI-relevant rows**, 12 committed in v1 |
| Committed packs | ~106 planned | **12 packs**, EI domain 1 plus FHRP |
| Evidence channels | CLI + controller REST | **offline CLI/config captures only** |
| Language | Python 3.14 typed | same (already in the foundation) |
| Team | 2 construction + qualification streams | **2 author streams + 1 independent reviewer** |

**What already exists (so the estimate is not from zero):** the seeded foundation already contains
the hard, boring parts — a closed tri-state fact algebra (~288 LOC), fail-closed evidence admission
with custody and budgets, an ordered parse kit with byte spans and no silent drops, an RFC 8785
canonical output contract, an IOS-XE `show version` pack, and **440 passing tests** with provenance
records and CI gates. What is missing is the product: a runner, a fact store, an IOS-XE interface
adapter, and the EI packs. That is the build.

**Target:** `ei-v1` tag in **9–12 weeks** (2 author streams + reviewer, 4–6 hours/day each), with the
fit test at PR 10 replacing that estimate with a measured one — the rule is written in §11, so a
bad estimate fails loudly instead of quietly.

**What you must decide:** approve this plan (G0), name the reviewer, and confirm the EI
evidence-channel boundary (§4.4). The truth route is **decided**: the owner has **no lab** today, so v1
truth is tier-P public real output + mutation/regression truth, published as `measured_*` only (§9).

---

## 1. Product definition

Baby Thanos tells a consultant what is true about a Cisco enterprise estate **in the EI blueprint's
scope**, with the cited evidence behind every answer, by analysing captures they already have — no
network access, no device writes, no LLM in fact-making.

**What v1 answers, each with the `show` lines behind it:**

1. Which interfaces are administratively up but operationally down, and which counters show physical
   or data-link trouble (L1-01).
2. Which links run half-duplex, mismatched duplex, or mis-negotiated speed (L1-02).
3. Which chassis have empty or failed PSU bays or out-of-threshold temperatures, on the models whose
   bay/baseline tables the engine holds (L1-05).
4. Which physical links exist end-to-end from both neighbours, and which have only one collected
   end (L1-10, L2-06).
5. Which 802.1Q trunks disagree on the native VLAN at the two ends, and which have a VLAN allowed on
   one side only (L2-01).
6. Where the STP root and guards (root guard, BPDU guard/filter, PortFast, loop guard) sit, and
   where a guard is observed on one side and not the other (L2-03).
7. Which EtherChannel bundles have mismatched modes/protocols or lost members against their expected
   membership (L2-04).
8. Which L2 links differ in MTU/jumbo configuration (L2-08).
9. Which IPv4 addresses are duplicated inside one evidenced routing domain, and which interfaces sit
   in which VRF (L3-01; VRF depth grows in W1).
10. Which OSPFv2 adjacencies are stuck, and — when the bundle holds two collector-timed captures at
    least 120 s apart — whether an MTU mismatch explains it (L3-05, L3-28, correlation R1).
11. What the engine could **not** decide, why (a closed reason code), and which `show` to collect
    next (`next_evidence`).

**Never:** a user interface, a web app, an installer, a collector, a live device write, or an LLM
anywhere a fact is made. The engine never touches the network while analysing; identical evidence
always produces byte-identical output.

---

## 2. Scope fences

**In scope for this repository**

- The analysis engine: evidence intake, parsing, normalization, the network model, checks,
  cross-layer correlation, findings and answers, one versioned output contract.
- A command-line runner and a Python API for tests and future front ends.
- The EI v1.1 blueprint's technology scope, *to the depth an offline read-only engine can honestly
  reach with the evidence it is given*, on IOS-XE.
- Public, licence-clean evidence fixtures with provenance records.

**Out of scope, permanently for this repository**

- Every CCIE track except EI (Data Center, Security, Service Provider); every non-EI Cisco family:
  IOS-XR, NX-OS, ASA/FTD, ACI, ISE, wireless, UCS/compute, collaboration, SD-WAN controllers.
- Any user interface, web app, desktop shell, 3-D view, design system or visual work.
- Installers, USB packaging, auto-update, signing, release machinery beyond a plain tagged package.
- Live device access of any kind — collection, collection orchestration, device writes, packet
  captures started by this repository.
- Controller REST evidence channels in v1 (SD-Access/DNAC, SD-WAN vManage, Catalyst Center). These
  are deferred to EI wave W4/W5 with an explicit separate decision (§4.4); until then those topics
  read `unknown`, never "healthy".
- Non-Cisco vendors. The design must not block them later; no work is spent on them now.
- An LLM or any model inference in any path that produces a fact or a finding.

A change that crosses a fence is refused in review however useful it looks. Scope drift is the
failure this project exists to avoid, and the fence is machine-checked from the first commit
(`tools/fence.py` path allowlist + CI).

---

## 3. Doctrine (non-negotiable)

1. **Read-only.** The engine never writes to a device. Evidence is read-only `show` output,
   configuration reads and read-only API GETs captured *before* analysis.
2. **Evidence-grounded.** Every fact cites the evidence it came from: device, command or endpoint,
   capture identity, line and byte span. No fact comes from memory, defaults or vendor folklore.
3. **Coverage-honest.** Missing evidence is `unknown`, never `ok`. Every check has a denominator;
   "not observed" never becomes "healthy". This was the old toolkit's most frequent defect and the
   single most important rule in the code (`kernel/states.py`).
4. **Deterministic and offline.** The same evidence gives byte-identical output. No network egress at
   analysis time; no LLM in the fact path. A tripwire proves it in CI.
5. **One source of truth.** Each fact has exactly one owning pack; every consumer reads it there and
   no consumer re-derives it. Fact ids are pack-prefixed and mechanically checked.
6. **Privacy by construction.** No client data in the repository, ever: no names, hostnames,
   addresses, MACs, serials or configurations from real engagements. Tests use public vendor
   examples, synthetic/mutation data, or lab captures when available, each with a provenance
   record. A privacy gate runs from the first commit; the owner holds the marker list.
7. **Proposer is not verifier.** Every consequential change gets an independent review from a
   different model or person than its author before it merges. This repository is public; review
   records are attached to PRs.

---

## 4. The EI-only scope

Full mapping: [`plan/scope-ccie-ei.md`](plan/scope-ccie-ei.md). This section is the executive cut.

### 4.1 EI blueprint domains → engine phase

| EI domain (weight) | What the engine can honestly do offline | Phase |
|---|---|---|
| **1. Network Infrastructure (30%)** — switched campus, routing concepts, EIGRP, OSPF, BGP, multicast | Full read-only analysis of L1/L2/L3 state on IOS-XE: interfaces, VLAN/trunk, STP, EtherChannel, discovery, MTU, addressing, OSPF, then EIGRP/BGP/multicast/VRF/PBR/BFD | **v1** (STP, EtherChannel, discovery included) → W1 for routing/multicast |
| **2. Software-Defined Infrastructure (25%)** — SD-Access, SD-WAN | Device-side underlay evidence is analysable with domain-1 packs; fabric/OMP control-plane truth needs controller REST, which is a new evidence channel | Underlay in v1/W1; **fabric/controller topics W4/W5** after the evidence-channel decision (4.4) |
| **3. Transport Technologies (15%)** — GRE, MPLS L3VPN, DMVPN, IPsec | Offline CLI/config analysis of tunnel and VPN state (GRE, DMVPN/NHRP, IPsec/IKEv2, MPLS/L3VPN depth) | **W3** |
| **4. Infrastructure Security & Services (15%)** — device security, ACLs, switch/router security, IPv6 security, system management, QoS, FHRP/NTP/DHCP/NAT, IP SLA, NetFlow, SPAN | Mostly offline CLI/config analysis; IPv6 parts need the IPv6 fact model. FHRP is the one domain-4 row with cited IOS-XE truth at v1 depth, so it ships in v1 | **FHRP in v1; rest W2/E2** (ACL, CoPP, security features, services) |
| **5. Infrastructure Automation & Programmability (15%)** — data formats, automation/scripting, APIs, telemetry | Only config-presence analysis (EEM, Guest Shell, NETCONF/RESTCONF, telemetry subscriptions configured); API *interaction* is out of an engine that never touches the network | **W4/W5**, after evidence-channel decision |

**v1 commit = EI domain 1 core on IOS-XE, plus FHRP**: 12 rows and 12 packs (one cell per row,
single family). Rows and packs are fixed in [`plan/scope-ccie-ei.md`](plan/scope-ccie-ei.md) §4 and
repeated in §8.3 here. The 62 rows EI never names and the 21 SP rows are out of the repository
entirely.

### 4.2 Platform adapters

- **v1: IOS-XE only** — Catalyst 9000, Catalyst 8000/8000V, ISR/ASR 1000, CSR1000V; 17.x train
  primary, 16.x where a fixture proves it. One adapter, one family, one `detect()`.
- **Backfill: classic IOS** only if legacy estates need it (E1 back-fill; no lab dependency); it is
  a cheap addition and adds one fixture family, not a re-plan.
- **Excluded from this repository:** IOS-XR, NX-OS, ASA/FTD, ACI, ISE, wireless, UCS, collaboration,
  SD-WAN/ SD-Access controller channels. The inherited NX-OS fixtures stay as reference bytes only
  (they belong to upstream) and are not part of the EI product.
- **Lab images / fixture sources (owner has no lab — decision recorded 2026-10-24):** v1 uses
  **tier-P public real-output fixtures** (vendor documentation examples, version-stated public
  samples, licence-clean upstream fixture bytes) plus **mutation and synthetic truth**. No CML/lab
  images are assumed and no acceptance criterion depends on them. Every supported (train, platform
  class) still needs at least one format-floor fixture with a provenance record; a form without one
  publishes `unknown(parse_unsupported_variant)`. `verified` truth is deferred until the owner has a
  lab or hardware; v1 publishes `measured_*` with n, cells and the shortfall stated.

### 4.3 Evidence channels

| Channel | v1 | Later |
|---|---|---|
| Folder of one-file-per-command captures | **yes** | — |
| Terminal session logs (prompt, pager, truncated capture handling) | **yes** | — |
| Lab-harness export (only if a capture ever exists; owner has no lab) | optional (M1) | — |
| Controller REST snapshot (vManage, DNAC/Catalyst Center) | no | W4/W5, separate decision + new envelope |
| Flow/telemetry/pcap evidence | no | out of engine (W5+ decision) |

Evidence prerequisites are enforced by the kernel (§5.3): absence claims need a read-scope form in the
same session (`show privilege` on IOS-XE); two-sample checks need collector-recorded capture times;
disagreeing untimed samples are a conflict, never a vote.

### 4.4 Deliberate EI exclusions in v1 (each mapped, never silently "healthy")

- **SD-Access / SD-WAN control planes** — need controller REST; the device-side underlay is still
  analysed by domain-1 packs. Fabric state reads `unknown(evidence_channel_unavailable)` with
  `next_evidence` naming the controller snapshot to collect (decision D-6, §13).
- **Automation/API interactions (5.3)** — the engine does not call vManage or DNAC; it can check what
  is *configured* on the device (EEM applet presence, Guest Shell, model-driven management
  configuration), clearly labelled as config-presence depth, not operational truth.
- **IPv6** — read `unknown(unmodelled_present)` with detail `not_in_ei_v1` where configured; EI is
  explicitly dual-stack and OSPFv3 is a topic, so IPv6/OSPFv3 is the first E1 decision (priced then,
  not smuggled into v1).
- **MPLS/DMVPN/IPsec depth** — W3, after the routing-core packs prove the model.

---

## 5. Architecture

Seven layers, imports downward only, mechanically checked on every PR. This is the approved Atlas
Brain architecture with adapters reduced to one family and packs to EI domain 1; **nothing about the
layering, evidence model or contract changes.**

### 5.1 Layers

```
kernel        honesty rules: fact algebra, reasons, settle, verdict, admissibility
  ↓
evidence      bytes: bundle/capture records, admission, spans, parse kit (rules → values + spans)
  ↓
platform      adapters (iosxe): detect, error/pager/prompt tables, interface grammar, config dialect
  ↓
model         one-owner fact store, catalogue, step graph, network model (estate→site→device→
  ↓           components→interfaces→L2/L3 domains→protocol instances→adjacencies)
packs         12 EI packs: parsers, facts, denominators, checks, correlation edges
  ↓
correlation   R1 (MTU→OSPF stuck) and later rules; timeline; answers
  ↓
contract      versioned pure projection: result directory, JSON Schema, RFC 8785 bytes, no floats
  ↓
runner        CLI/API, scheduler, worker pool, egress tripwire, ASCII summary
```

**Contracts (the plugin surface):**

- **Platform adapter** — `detect(capture) -> Family`, error/pager/prompt tables, interface-name
  grammar, configuration dialect (inheritance resolved before any absence), read-scope form. No
  facts, no checks.
- **Protocol pack** — one `domain.pack` id: the command forms it parses, the facts and subjects it
  owns, its expected-set partitions (denominators), its checks over `problem | ok | unknown |
  not_applicable`, and the correlation edges it declares. No pack reads another pack's facts; no
  pack writes outside its declared ids.
- **Fact spec / step** — typed, frozen, slotted; one writer, strict readers; declared read/write
  edges in a deterministic step graph (cycles refused).
- **Check** — a single verdict constructor; `ok` needs positive proof on every input; an empty or
  open set is never `ok`; a reason is bound to exactly one state.
- **Correlation rule** — declared by the downstream pack, single-edge, emits a chain (never a fact);
  an unknown hop stops the chain and prints the next evidence.
- **Finding / contract** — pure projection over facts; no arithmetic outside the owning pack; output
  validates against the versioned JSON Schema.

### 5.2 The fact algebra (inherited, unchanged)

`Known | Absent | Unknown | NotApplicable`, plus `EvidenceRef` (capture id, command, span, field
pointer) on every Known; `Unknown` always carries a closed reason code (30 inherited reasons) and the
next `show`; `Absent` is proven non-configuration, never an effective default; `NotApplicable` needs
positive evidence. `settle` orders samples only on one collector clock with non-overlapping
intervals; disagreement is `unknown(conflicting_evidence)`, never a vote. Admissibility is
integrity × read scope × view consistency.

### 5.3 Network model

Estate → site → device → platform/component → interfaces (physical/logical) → L2 domains → L3
domains/VRFs → protocol instances → adjacencies → findings. One owner per fact; every configuration
line, route source and log mnemonic is claimed by at most one pack; unclaimed lines feed a census so
an unmodelled protocol reads `unknown(unmodelled_present)`, never "conforms".

### 5.4 Output contract

One versioned result directory: `HEADER.json` + per-pack `RESULTS.jsonl` + `MANIFEST.sha256` + a
plain-text ASCII summary; schema `1.0.0` with generated JSON Schema 2020-12; RFC 8785 canonical
bytes; integers only (no floats); per-pack semantics integers, per-item effective semantics and a
catalogue digest; keyed-pseudonym redaction projection; every unknown/problem carries
`next_evidence`.

---

## 6. Language and runtime (carried over unchanged)

Typed Python on CPython **3.14.8** (floor 3.14.7), one language, **stdlib-only runtime, zero runtime
dependencies**, `pyright` strict as the single type gate, `ruff`, hashed `uv` lock, frozen/slotted
keyword-only dataclasses with runtime invariants. No entry points, no dynamic import, no network.
`msgspec` only by ADR after a measured ≥30% gain. Rust only through pre-agreed measured triggers; a
kernel move to Rust stays an owner decision.

Why this survives the down-scope: the foundation already proves the runtime works (440 tests, pyright
strict, green CI), and a field app that must run offline on a laptop with a single binary later is
served better by one language and a locked environment than by early performance work the EI datasets
do not need.

---

## 7. What was inherited from Atlas Brain, and what happens to it

Full inventory and prune list: [`plan/foundation-seed.md`](plan/foundation-seed.md).

| Inherited piece | State | Decision |
|---|---|---|
| `kernel/states.py`, `kernel/time.py` | real, 322 LOC | **keep** — the central honesty asset |
| `kernel/lints.py`, `kernel/token_lints.py` | real, dev/CI guards | **keep** (optional quality guard) |
| `evidence/capture.py`, `text.py`, `admission.py` | real, 473 LOC | **keep** — fail-closed intake with custody |
| `evidence/parsekit/` | real, ordered rules + spans | **keep** — every pack parser is built on it |
| `contract/canonical.py`, `header.py`, `bundle.py`, `manifest.py` | real, 135 LOC | **keep** |
| `packs/platform/system/` (`show version`) | real, narrow | **keep** — first adapter pack, proves the path |
| `tests/` (55 files, 440 tests), `fixtures/` (23 samples + provenance) | green CI | **keep**, prune ~8 out-of-EI files in M0 |
| `tools/fence.py` + path allowlist | real | **keep and adapt** — the allowlist gains `plan/`, `reference/`, `PLAN.md`, `NOTICE` |
| Full-scope mutation corpora, NX-OS fixtures, fence-receipt/inventory governance, ADR-0002 source-policy chain | upstream scope | **prune in M0** (list in foundation doc); keep as reference when useful |
| No runner, no fact store, no network model, no EI packs | missing | **this is the build** |

**Seed provenance:** copied from `Tanveerahamed-Dev/atlas-brain-staging` at `4f476b8c` (2026-10-23),
Apache-2.0; this repository starts from a fresh root commit and carries no upstream branch refs.
The privacy-status workflow (which fetched pinned upstream commits that do not exist here) was
dropped at seed time; the remaining workflows are self-contained and run here.

---

## 8. Milestones, first PRs, exit criteria

### 8.1 Milestones and owner gates

| Milestone | Definition | Target | Owner gate |
|---|---|---|---|
| **G0** | Owner approves this plan (scope, doctrine, v1 rows, schedule rule) | now | **approve** |
| **M0 — walking skeleton** | Runner + fact store + IOS-XE adapter + `l1.interface` pack end-to-end: evidence bundle in → canonical result directory out; determinism double run; CI green; inherited tests still green; 10 PRs merged | weeks 1–3 | **G0+2 scope check** |
| **M1 — architecture proof** | 12 EI packs (`l1.interface`, `l1.link`, `l2.discovery`, `l2.vlan_trunk`, `l2.stp`, `l2.etherchannel`, `l2.mtu`, `l3.addressing`, `l3.vrf`, `l3.ospf`, `l3.fhrp`, `l3.mtu`) + correlation R1 + exit criteria EX-01..EX-15 pass; frozen kernel; architecture report | weeks 3–7 | **G1** (proceed to v1) |
| **v1 — EI Network Infrastructure** | The 12 committed rows deliver a real analysis of an EI campus on IOS-XE; tagged `ei-v1`; measured throughput and accuracy published | weeks 7–11 | **G2** release |
| **E1 — campus depth / IGPs** | L1-02, L1-05, L1-08, L1-09, L2-05, L2-07, L3-03, L3-06, L3-07, L3-10, L3-11, L3-12, L3-14, L3-27, L7-03; classic-IOS back-fill and the IPv6/OSPFv3 decision | after v1 | G3 |
| **E2 — transport + managed services** | L3-18, L3-19, L3-20, L4-01, L4-02, L7-02, L7-04, L7-06, L7-07 | after E1 | G4 |
| **E3 — campus security & services** | L2-10..L2-15, L2-17, L2-18, L2-19, L3-15, L3-25, L4-05, L4-06, L7-08..L7-11, L7-16, L7-17 | after E2 | G5 |
| **E4 — software-defined infrastructure** | L3-21, L3-22, L3-23, OOS-08; first REST adapters after the page-set consistency contract + evidence-channel ADR | after E3 | G6 |
| **E5 — remainder** | L3-16, OOS-05, OOS-16 | after E4 | G7 |

Gate rule: at each gate the owner may stop, re-scope or continue. M1 is never cut: it is the proof
that the architecture holds.

### 8.2 Milestone M0/M1 detail (what changes in the repository)

- **Runner:** CLI + Python API; coordinator runs in a spawned child; explicit-spawn worker pool;
  egress tripwire installed first in `__main__` and each worker; ASCII summary; per-PR determinism
  double run (1 vs 4 workers, two hash seeds, Windows + Linux).
- **Fact store:** `FactSpec`/`RelationSpec`/`EntityKindSpec`, writer bound to a step's outputs, strict
  reader, single-owner registry, digest-bound `CATALOGUE.json`, deterministic step graph, per-item
  effective semantics.
- **IOS-XE adapter:** `detect()` for 16.x/17.x banners; error, pager and prompt tables; interface
  grammar; config dialect; read-scope form; format floors for every supported form.
- **EI packs (M0 thin):** `l1.interface` (`show interfaces`, `show ip interface brief`) producing
  admin/oper facts and `admin_up_oper_down`.
- **EI packs (M1):** `l1.interface` (`show interfaces`, `show ip interface brief`), `l1.link`
  (speed/duplex stretch, two-end pairing), `l2.discovery` (CDP/LLDP), `l2.vlan_trunk`,
  `l2.stp`, `l2.etherchannel`, `l2.mtu`, `l3.addressing`, `l3.vrf` (instances/membership, reduced
  depth), `l3.ospf` (adjacency state), `l3.fhrp` (HSRP/VRRP groups), `l3.mtu`, plus
  `platform.system` (inherited) and minimal `platform.inventory`. Stretch rows for the M1 exit:
  L1-02 speed/duplex, L1-08 UDLD, L1-09 errdisable, L2-07 MAC table.
- **Correlation R1:** MTU mismatch on a segment → OSPF adjacency stuck in EXSTART/EXCHANGE, two
  collector-timed neighbour captures ≥120 s apart, `ip ospf mtu-ignore` as blocking
  countercondition; unknown hop stays visible and names the next `show`.
- **Contract v0 → 1.0.0:** schema, RFC 8785 writer, no floats, JSON Schema 2020-12, manifest hashes,
  validation on every run.

### 8.3 The 12 committed rows (EI Network Infrastructure v1)

| # | Row | Pack | Primary evidence (IOS-XE) | Depth target |
|---|---|---|---|---|
| 1 | L1-01 Interface state and counters | `l1.interface` | `show interfaces`, `show ip interface brief`, error counters | expected-vs-observed |
| 2 | L1-10 Physical links / cabling (both ends) | `l1.link` | CDP/LLDP + interface outputs | cross-device-correlated |
| 3 | L2-01 VLANs (access/trunk/native/allowed/voice) | `l2.vlan_trunk` | `show interfaces trunk`, `show vlan brief`, `show running-config` | cross-device-correlated |
| 4 | L2-03 STP (root, guards, PortFast) | `l2.stp` | `show spanning-tree`, `show spanning-tree interface`, config | cross-device-correlated |
| 5 | L2-04 EtherChannel (membership, mode) | `l2.etherchannel` | `show etherchannel summary`, `show etherchannel detail` | cross-device-correlated |
| 6 | L2-06 CDP / LLDP discovery | `l2.discovery` | `show cdp neighbors detail`, `show lldp neighbors detail` | cross-device-correlated |
| 7 | L2-08 L2 MTU / jumbo | `l2.mtu` | `show interfaces`, config `mtu`/`system mtu` | cross-device-correlated |
| 8 | L3-01 IPv4 addressing / duplicates | `l3.addressing` | `show ip interface`, `show running-config` | cross-device-correlated |
| 9 | L3-04 VRF / route domains (reduced depth) | `l3.vrf` | `show ip vrf` / `show vrf`, config | cross-device-correlated |
| 10 | L3-05 OSPFv2 adjacencies | `l3.ospf` | `show ip ospf neighbor`, `show ip ospf interface` | cross-device-correlated |
| 11 | L3-13 FHRP groups (HSRP/VRRP) | `l3.fhrp` | `show standby`, `show vrrp`, config | cross-device-correlated |
| 12 | L3-28 L3 MTU / IP MTU | `l3.mtu` | `show ip interface`, config `ip mtu` | cross-device-correlated |

**Fallback** if stretch discipline must be kept: defer L2-03 STP and L3-13 FHRP to E1 (10 rows, the
approved-plan shape). Do not shrink further — without L2-01/L2-06/L3-05 the product has no EI answer
that matters. **Stretch for v1** (only if the fit test allows): L1-02 speed/duplex, L1-08 UDLD,
L1-09 errdisable, L2-07 MAC table, L3-03 static routing/admin distance, L2-17 IGMP snooping,
EtherChannel mode/protocol checks, VRF route leaking.

### 8.4 The first ten PRs (order matters; each PR touches one path class, ≤400 lines)

| # | PR | Contains | Must-pass negative case |
|---|---|---|---|
| 1 | **Seed + project identity** (this commit) | foundation mirror, `README.md`, `PLAN.md`, `plan/`, `NOTICE`, `reference/`, fence allowlist update, drop upstream-pinned workflow | fence refuses a path outside the allowlist; CI green on the seed |
| 2 | **Runner skeleton** | CLI/API, coordinator child, worker pool, egress tripwire, ASCII summary | socket/DNS/subprocess probes denied and counted; two runs byte-identical |
| 3 | **Fact store minimum** | specs, strict writer/reader, single-owner registry, catalogue digest, step graph | second owner of a fact, second write of a (fact, subject), cyclic step, undeclared read all refused |
| 4 | **IOS-XE adapter subset** | detect, error/pager/prompt tables, interface grammar, read-scope form, 2 tier-P fixtures with provenance | a classic-IOS banner detected as IOS; an error string never parsed as data |
| 5 | **`l1.interface` pack v0** | parsers for `show interfaces` / `show ip interface brief`, admin/oper facts, `admin_up_oper_down`, first real answer in the contract | truncated output → `partial` parse; absent command → `unknown`, never `ok` |
| 6 | **Contract v0** | result types, RFC 8785 writer, no floats, JSON Schema 2020-12, `MANIFEST.sha256`, validation | a float reaches the writer → refused; schema change without version change → refused |
| 7 | **Discovery + link packs** | `l2.discovery` (CDP/LLDP), `l1.link` (two-end pairing; L1-02 speed/duplex is stretch) | one collected end → `unknown`, never `ok` |
| 8 | **VLAN/trunk pack** | `l2.vlan_trunk`: native VLAN, allowed/pruned VLANs, voice VLAN | blank native VLAN never read as VLAN 1; one-sided allowed VLAN flagged |
| 9 | **MTU + OSPF packs and correlation R1** | `l2.mtu`, `l3.mtu`, `l3.ospf` adjacency facts, R1 rule | MTU mismatch → EXSTART supported; one capture → `unknown(single_sample)`; unknown hop visible |
| 10 | **Governance + truth** | PR size/fence checks, fixture provenance, regression catalogue EI-R01..EI-R12, M0/M1 exit report, measured throughput | planted oversized PR refused; planted home path refused; every EI-R case passes with its twin |

PR 5 is the first end-to-end evidence; PR 10 is the first measured-throughput point — the fit test in
§11 is computed there and weekly after. After PR 10, M1 opens the remaining packs in order:
PR 11 STP, PR 12 EtherChannel, PR 13 VRF, PR 14 FHRP, then the M1 exit run (EX-01..EX-15) and the
G1 review.

### 8.5 Exit criteria for v1 (each measurable, each able to fail)

| ID | Criterion |
|---|---|
| EX-01 | Every guard fires on its planted violation; output byte-identical across 1 vs 4 workers and Windows vs Linux on the thin slice |
| EX-02 | Adding a new EI pack changes zero core files; a synthetic new pack runs with zero core edits |
| EX-03 | `l1.link`/`l2.mtu` pair both ends from discovery; an uncollected end is `unknown`, never `ok` |
| EX-04 | R1: supported on two-timed-capture bundles; one capture → `unknown(single_sample)`; a removed MTU fact stops the chain at a named unknown hop |
| EX-05 | An unmodelled protocol on the box (EIGRP/BGP/IS-IS, or OSPFv3) makes its routing summary `unknown(unmodelled_present)`, never "conforms" |
| EX-06 | Absence guards: valid-empty control passes; failed-command-looks-empty case is `unknown`; no check can be `ok` from `not_collected` inputs |
| EX-07 | Offline witness: tripwire denies and counts every probe; Linux `--network none` bytes equal host bytes |
| EX-08 | Every supported parser variant has a format-floor fixture with a provenance record, or publishes `variant_support: allowlisted` |
| EX-09 | Truth (no lab — owner decision 2026-10-24): zero false-healthy on faults, zero false-healthy on insufficient evidence, zero incorrect N/A on every replay; every result publishes `measured_*` with n, cells and shortfall stated; precision ≥0.95 / recall ≥0.90 apply only if a sealed holdout exists |
| EX-10 | Determinism: four-digest comparison green on every merged PR; 5 consecutive green nightly matrices on the tagged SHA |
| EX-11 | CI: per-PR active time ≤15 min p90, nightly ≤60 min; scale: 500-device EI estate ≤120 s median, ≤2 GiB peak on the 2-vCPU reference runner |
| EX-12 | Contract: schema 1.0.0 validates every result; RFC 8785 bytes; no floats; every unknown/problem has `next_evidence` |
| EX-13 | Privacy: zero gate hits on the nightly full-tree scan; no tier-L/tier-H bytes in this public repository; fixture provenance complete |
| EX-14 | Fix locality: no fix PR >3 hand-edited files outside its pack without a written override; overrides per milestone ≤3 |
| EX-15 | Adapter definition of done: detection claims every IOS-XE fixture and refuses other banners; every interface name canonicalizes; config inheritance resolved before any absence; read-scope parsed |

---

## 9. Quality and test strategy

- **Truth tiers.** P public real-output fixtures (format floors only), M mutation truth, S synthetic
  and the EI-R regression catalogue. **L (lab captures) and H (owner hardware) are unavailable today
  — the owner has no lab (decision 2026-10-24)** — so they are optional inputs if such captures ever
  arrive, never a gate. Client captures never enter a repository. Each fixture carries a provenance
  record (source, platform, version, licence, SHA-256).
- **Accuracy targets, adapted to a no-lab reality.** On every measured replay: **zero observed
  false-healthy** on faults, zero false-healthy on insufficient evidence, zero incorrect N/A, and
  unknown-rate/N-A-rate/assessability reported with denominators. Precision/recall targets
  (≥0.95/≥0.90) apply only where a sealed holdout exists — with no lab the v1 deliverable publishes
  **`measured_*`** results with n, cells and the shortfall printed; `verified` is not claimed.
- **Regression catalogue.** EI-R01..EI-R18 seeded from the old toolkit's named defects and re-pointed
  at IOS-XE, each with a must-flag case and twins: PSU absence-as-installed, half-duplex as Auto,
  blank native VLAN as VLAN 1, root guard default, telnet-with-no-transport-input, OSPF 2WAY
  accepted, IS-IS-only routing "conforms", VRF/duplicate-address honesty, MTU "unset = 1500",
  LACP-passive/PagP read as static, one-sided STP guard, empty-table-as-healthy, failed-command as
  empty.
- **Mutation and property tests.** Seeded absence-as-health mutants per PR; nightly mutation run
  (80% floor); Hypothesis property tests over the parse kit; every lint has a planted-violation
  self-test.
- **Determinism.** Four digests (schema bytes, result bytes, catalogue, summary) compared across
  1 vs 4 workers, two hash seeds, reversed listing order, Linux `--network none` and Windows.
- **CI budgets.** PR ≤15 min active (p90), nightly ≤60 min, every required check on
  `pull_request` and `push`, no cancelled-as-green, timeouts at twice budget.

---

## 10. Governance and anti-drift

- **One board, one writer.** Work items are GitHub issues with a `scope:` and `phase:` label; the
  owner is the sole writer of the plan/scope files. PRs link an issue.
- **Streams.** Two author streams (A: core/runner/contract; B: adapter/packs) and one independent
  reviewer. WIP limit: ≤1 non-draft PR per stream + 1 draft. Shared-schema paths (kernel, contract,
  model) are held by one PR at a time.
- **PR discipline.** ≤400 changed lines, one path class, one pack or core module; >3 files outside the
  pack fails CI unless labelled with a written reason (max 3 per milestone).
- **ADRs.** ≤1 page, immutable once accepted, superseded by a new ADR. Architecture changes, new
  evidence channels, a new fact owner and scope-fence changes need an ADR.
- **Scope fence.** `tools/fence.py` path allowlist and import/dependency rules run in CI; the plan
  and scope files are the only allowed process documents while the plan is being executed (owner
  decision; the old "no process documents in tree" rule is relaxed for `PLAN.md`/`plan/` until v1,
  then historical plan material moves to `docs/plan/` or is removed).
- **Independent review.** Every non-trivial PR gets a review record (reviewer, model, diff digest,
  verdict) before merge; the reviewer is a different model family or person than the author. The
  owner spot-audits 20% of merges.
- **Pre-committed estimate rule.** At PR 10 and weekly, measured throughput replaces the plan's
  assumed rate: `F = t + R(1+ρ)/(sλ) + w`; stretch items are admitted in order only while
  `F×1.15 ≤ cap`, and dropped last-admitted-first. If the committed scope misses, the owner chooses:
  third stream, later cap, or a named cut. M1 is never cut.
- **Privacy gate.** Structural detectors (home paths, private addresses, serial shapes) run on every
  changed blob in public CI; the owner-held marker list stays with the owner and runs at release
  promotion. No truth bundle, no lab capture and no client data in this repository.

---

## 11. Sizing and schedule (assumptions stated so they can fail)

The approved full Engine v1 was priced at 76.4–129.65 base units (~124 expected PRs) for 2 families /
12 rows, with a T0+38-week cap and 2 construction + 1 qualification streams. Baby Thanos removes:
NX-OS (one family, and the second adapter's qualification), ~106 packs, controller families,
qualification machinery for a multi-family holdout, and the old-toolkit strangler path. It adds:
STP, EtherChannel and FHRP committed rather than stretch, and L2 depth the EI domain-1 topics need;
it defers the hardware-truth L1 rows (L1-02, L1-05) to E1. Net estimate:

| Block | Units (est.) | Why |
|---|---|---|
| M0 (PRs 2–10 + inherited fixes) | 12–20 | foundation absorbs the kernel/evidence/contract cost |
| M1 (EI domain-1 packs, R1, exits) | 25–40 | 12 packs × parser/fact/check/fixture cost, minus the 2 already-seeded (`platform.system`, `l1.interface` thin) |
| v1 release (tag, reports, accuracy run) | 6–12 | measured run, contract 1.0.0, documentation, v1 report |
| **Total** | **43–72 units** | ≈ 4–6 units per EI pack; 0.75–1.5 units per PR |

**Calendar (2 author streams + 1 reviewer, ~4–6 hours/day per stream):** M0 ~2–3 weeks, M1 ~4 weeks,
v1 release ~2–3 weeks → **tag `ei-v1` in 9–12 weeks**, range 8–16 weeks once PR 10 measures the
actual rate. Single-stream (owner only) would roughly double: 18–24 weeks. All figures are planning
assumptions, not promises: the fit test at PR 10 (§10) is the mechanism that replaces them with
measured numbers.

---

## 12. Risks and early signals

| Risk | Early signal | Mitigation |
|---|---|---|
| Second-system effect / never shipping | no end-to-end result by PR 5; PR 10 late | thin slice first (PR 5), PR-size cap, fit test, M1 gate |
| Scope drift back to all-CIEI/all-families | PRs touching non-EI rows; fence edits | machine-checked fence, scope file, owner gates |
| Fixture/truth scarcity (no lab — decided) | parsers shipping without floors; `measured_*` everywhere | tier-P format floors first; honest `measured_*` with n; no `verified` claim; lab optional later |
| Evidence model mis-fit for EI (show output drift) | rising `unknown(parse_unsupported_variant)` | per-train fixtures, variant allowlist, adapter DoD (EX-15) |
| SD-Access/SD-WAN truth unreachable offline | EI domain 2/5 rows stalling | explicit E4 decision; honest `unknown(evidence_channel_unavailable)` meanwhile |
| Privacy leak in a public repo | any hit in fixture scan | provenance gate from PR 1; owner marker list; no client data ever |
| Single-person bus factor (review) | review latency >1 day; unreviewed merges | independent reviewer (other model) required; records in repo; owner spot-audits |
| Upstream divergence from atlas-brain-staging | duplicated fixes | this repo starts fresh; upstream is reference only, no refs carried, sync only by deliberate cherry-pick |

---

## 13. Decisions needed from the owner (G0 checklist)

| ID | Decision | Recommendation | Owner action |
|---|---|---|---|
| D-1 | Approve this plan and the 12 committed v1 rows | approve | sign G0 |
| D-2 | **DECIDED 2026-10-24 — no lab available.** Truth route: tier-P public floors + mutation/synthetic truth, `measured_*` only; lab stays optional forever | keep tier-P floors and honest `measured_*`; no delivery gate on a lab | recorded |
| D-3 | **DECIDED 2026-10-24 — no holdout operator.** No sealed holdout; precision/recall are reported only where data exists, never claimed | publish `measured_*` with n, cells, shortfall | recorded |
| D-4 | Independent reviewer: other-model agent + review record format | required from PR 2 | confirm |
| D-5 | Keep the plan in-tree until `ei-v1`? | yes (owner asked for plan in GitHub) | confirm |
| D-6 | Controller evidence channel (SD-Access/SD-WAN): decide at E4 | defer, keep it a separate ADR | note |
| D-7 | Public vs private truth/lab repositories | public engine; truth/lab private | confirm |
| D-8 | Repo name/identity: `baby-thanos`; engine package stays `atlas_brain` until an ADR renames it | keep (rename later if wanted) | note |
| D-9 | SD-WAN/SD-Access in v1? (EI domain 2 is 25% but needs REST) | CLI-only v1; REST adapters in E4 | note |
| D-10 | ISE adapter | exclude now; device-side TrustSec/802.1X only; schedule with E4 only if wanted | note |
| D-11 | L1 hardware rows (L1-02 speed/duplex, L1-05 environment) | defer to E1 (truth is hardware-only); L1-01/L1-10 stay in v1 | note |
| D-12 | Classic IOS back-fill | E1 only; adds no EI coverage | note |
| D-13 | IPv6 / OSPFv3 timing (EI is explicitly dual-stack, OSPFv3 is topic 1.4) | first E1 decision: add IPv6 fact model + OSPFv3 packs, or keep IPv4/OSPFv2 with honest `unknown` | decide at E1 |

**Owner decisions recorded 2026-10-24:** the owner has **no lab and no holdout operator**. D-2 and
D-3 are therefore decided as described above: v1 ships on tier-P public real output plus mutation and
regression truth, every result publishes `measured_*` with n/cells/shortfall, and no acceptance
criterion, milestone or CI gate depends on a lab, CML images or a sealed holdout. If a lab or
hardware ever becomes available, `verified` truth is a later-wave upgrade, not a re-plan of v1.

---

## 14. Definition of done for `ei-v1`

1. The 12 committed rows produce real answers on an EI IOS-XE estate, each with evidence spans and
   `next_evidence` for every unknown.
2. EX-01..EX-15 pass, with the evidence report attached to the G2 review.
3. `ei-v1` tag on a commit whose CI was green; contract schema 1.0.0 validates every result.
4. The v1 report (accuracy, unknown rate, performics, known limits) is delivered to the owner, not
   buried in the tree.
5. A stranger can run `uv sync --locked && uv run python -m atlas_brain ...` on a folder of captures
   and read the ASCII summary without reading this plan.
