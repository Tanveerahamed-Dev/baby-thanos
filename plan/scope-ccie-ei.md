# CCIE Enterprise Infrastructure v1.1 → engine scope

**Purpose.** This file is the traceability contract of Baby Thanos: every CCIE EI v1.1 blueprint
topic is mapped either to a protocol row and a phase, or to an explicit out-of-engine reason. The
acceptance rule for any plan or PR is: **no EI topic is left unmapped, and nothing outside EI is
built.**

Sources:

- [`reference/ccie-ei-v1.1-blueprint.txt`](../reference/ccie-ei-v1.1-blueprint.txt) — the official
  Cisco CCIE EI v1.1 exam topics (public Cisco document, 2023).
- [`reference/protocol-rows.md`](../reference/protocol-rows.md) — the 122-row protocol reference
  derived from the public Cisco blueprints (L1-01..L7-17, SP-01..SP-21, OOS-01..OOS-20).

---

## 1. EI-relevant protocol rows: 60 of 122

A row is EI-relevant when its subject is named by an EI v1.1 topic/sub-topic, or is an unstated
prerequisite of one (for example L3-01 addressing, from the exam's dual-stack statement). Rows
counted once even when cross-listed.

| EI domain | Rows |
|---|---|
| **1 Network Infrastructure** (30%) | L1-08 UDLD · L1-09 errdisable · L2-01 VLAN/trunk · L2-03 STP · L2-04 EtherChannel · L2-05 MC-LAG · L2-06 CDP/LLDP · L2-07 MAC table · L2-08 L2 MTU · L2-17 IGMP/MLD snooping · L3-01 addressing · L3-03 static/AD · L3-04 VRF · L3-05 OSPF · L3-06 EIGRP · L3-07 BGP · L3-10 redistribution/filtering · L3-11 PBR · L3-12 BFD · L3-15 multicast/PIM · L3-27 auth/GTSM · L3-28 L3 MTU → **22** |
| **2 Software-Defined Infrastructure** (25%) | L2-15 802.1X/MAB · L3-21 VXLAN · L3-22 LISP/SD-Access · L3-23 SD-WAN · L3-25 TrustSec · L7-16 ISE* · OOS-08 Catalyst Center* → **7** |
| **3 Transport Technologies** (15%) | L3-16 MPLS/L3VPN · L3-18 GRE · L3-19 DMVPN/NHRP · L3-20 IPsec/IKEv2 → **4** |
| **4 Infrastructure Security & Services** (15%) | L2-10 storm control · L2-11 port security · L2-12 DHCP snooping · L2-13 DAI · L2-14 IPSG · L2-18 IPv6 first-hop · L2-19 SPAN · L3-13 FHRP · L3-14 tracking · L3-26 uRPF · L4-01 ACL/VACL/PACL · L4-02 NAT · L4-05 QoS · L4-06 CoPP · L7-02 DHCP · L7-03 NTP/PTP · L7-04 SNMP · L7-05 logging · L7-06 AAA · L7-07 mgmt access · L7-08 NETCONF/RESTCONF/gNMI · L7-09 FNF · L7-10 IP SLA · L7-11 NBAR · OOS-05 packet evidence → **25** |
| **5 Automation & Programmability** (15%) | L7-17 EEM · OOS-16 Guest Shell/IOx → **2** |

\* ISE and Catalyst Center are controller rows implied by the blueprint (TrustSec policy plane, SD-Access
LAN automation/provisioning, 5.3 API topics) even though the words never appear; they are counted once.

**Not mapped — 62 rows.** Technologies EI never names: L2-02 VTP, L2-09 PVLAN, L2-16 MACsec, L3-02
ARP/ND, L3-08 IS-IS, L3-09 RIP, L3-17 Segment Routing, L3-24 ACI, L4-03/04 firewalls, L4-07 TCP/UDP,
L7-01 DNS, L7-12/13 inspection, L7-14 voice, L7-15 service insertion, the remaining OOS rows, and all
21 SP rows. They stay out of this repository (EI scope fence).

**Blueprint topics with no matching row** (disposition required, not silently dropped):

| EI topic | Gap | Disposition |
|---|---|---|
| 5.1 JSON/XML/YAML/Jinja | no protocol row | Not device evidence; declare **not-assessable** by an engine that never runs automation, or add an automation-inventory row in E4 |
| 4.7.b data-path packet trace / conditional debug | partly L7-05 + OOS-05 | **E2/E4** (logging config presence); packet evidence itself is out of engine |
| 2.1.a/d fabric deployment specifics (LAN automation, border priority, fabric-in-a-box) | only OOS-08 controller projection | **E4** with the controller evidence channel |
| 2.2.d templates | only L3-23 | **E4** (SD-WAN controller snapshot) |
| 5.2.b Guest Shell depth | OOS-16 is an OOS row | **E4** as config-presence only |
| 3.2.a(iii) MPLS ping/traceroute | folded into L3-16 | **E5** as part of MPLS depth |

---

## 2. Platform adapters

| Adapter | v1? | Justification |
|---|---|---|
| **IOS-XE CLI** | **yes** | The only OS family named by the blueprint ("4.1 Device security on Cisco IOS XE"); owns 57 of the 60 EI rows; read-only `show`/config evidence |
| Classic IOS | E1 back-fill (optional) | Zero blueprint mentions; EI labs are IOS-XE; cheap to add later, adds no EI coverage |
| vManage REST (SD-WAN Manager) | **E4** | EI 2.2 + 5.3.a; owns L3-23; REST is only safe after a page-set-consistency evidence contract exists |
| Catalyst Center (DNAC) REST | **E4** | EI 2.1.a LAN automation/PnP + 5.3.b; owns OOS-08; same prerequisite |
| ISE REST | excluded unless the owner schedules it | never named; implied only by TrustSec/SGACL. Without it, L7-16 is unassessable and L2-15/L3-25 stay device-side |
| IOS-XR, NX-OS, ASA/FTD, ACI, wireless, UCS, collaboration, all SP depth | **excluded** | zero EI mentions; those are Data Center / Security / Service Provider scopes |

---

## 3. Evidence channels

| Channel | v1 | Later |
|---|---|---|
| Folder of one-file-per-command captures | yes | — |
| Terminal session logs (prompt/pager/truncation aware) | yes | — |
| Lab harness export | M1 | — |
| Controller REST snapshot (vManage, Catalyst Center) | no | E4, new envelope + page-set consistency contract |
| Flow / telemetry / pcap | no | E4+ decision; today out of engine |

Offline CLI evidence per EI device in the v1 slice: `show running-config`, `show vlan`,
`show interfaces trunk`, `show spanning-tree` (+ interface detail), `show etherchannel summary/detail`,
`show cdp neighbors detail`, `show lldp neighbors detail`, `show interfaces`, `show ip interface`,
`show ip ospf neighbor`, `show ip ospf interface`, `show ip vrf` / `show vrf`, `show standby`,
`show privilege` (read scope). Cross-device rows need at least two device captures in one bundle;
the R1 two-sample check needs two collector-timed captures ≥120 s apart.

---

## 4. v1 slice — EI Network Infrastructure, IOS-XE first

**12 committed rows / 12 product packs, one family, zero REST.** The slice is the EI subset of the
already-approved Engine v1 scope (its 12 committed rows contain 8 EI rows) plus the two EI rows that
were stretch in the old plan (STP, FHRP) and the pairing row (L1-10) required by every cross-device
check. Rows kept out: L1-02 speed/duplex, L1-05 environment (truth is hardware-only/virtual-image
weak), and the domain-4 breadth.

| # | Row | Pack | Primary evidence (IOS-XE) | Depth target | Truth path |
|---|---|---|---|---|---|
| 1 | L1-01 Interface state and counters | `l1.interface` | `show interfaces`, `show ip interface brief`, error counters | expected-vs-observed | `measured_*` on mutation truth (virtual images), `verified` only on owner hardware |
| 2 | L1-10 Physical links / cabling from both ends | `l1.link` | CDP/LLDP + interface outputs | cross-device-correlated | cited |
| 3 | L2-01 VLANs (access/trunk/native/allowed/voice) | `l2.vlan_trunk` | `show interfaces trunk`, `show vlan brief`, config | cross-device-correlated | cited (U4a) |
| 4 | L2-03 STP (root, guards, PortFast) | `l2.stp` | `show spanning-tree`, interface detail, config | cross-device-correlated | cited |
| 5 | L2-04 EtherChannel (membership, mode) | `l2.etherchannel` | `show etherchannel summary/detail` | cross-device-correlated | cited |
| 6 | L2-06 CDP / LLDP discovery | `l2.discovery` | `show cdp neighbors detail`, `show lldp neighbors detail` | cross-device-correlated | cited |
| 7 | L2-08 L2 MTU / jumbo | `l2.mtu` | `show interfaces`, config `mtu` / `system mtu` | cross-device-correlated | cited (U1a) |
| 8 | L3-01 IPv4 addressing / duplicate IPs | `l3.addressing` | `show ip interface`, config | cross-device-correlated | cited |
| 9 | L3-04 VRF / route domains (reduced depth) | `l3.vrf` | `show ip vrf` / `show vrf`, config | cross-device-correlated | cited; route leaking is E1 |
| 10 | L3-05 OSPFv2 adjacencies | `l3.ospf` | `show ip ospf neighbor`, `show ip ospf interface` | cross-device-correlated | cited (U2a, U3) |
| 11 | L3-13 FHRP groups (HSRP/VRRP) | `l3.fhrp` | `show standby`, `show vrrp`, config | cross-device-correlated | cited |
| 12 | L3-28 L3 MTU / IP MTU | `l3.mtu` | `show ip interface`, config `ip mtu` | cross-device-correlated | cited |

Support packs (no EI row of their own, deliver the wiring the rows need): inherited
`platform.system`; new `platform.inventory` (minimal, M1) and the link-pairing producers inside
`l1.link`.

**Correlation in v1:** R1 — MTU mismatch on a segment → OSPF adjacency stuck in EXSTART/EXCHANGE,
proved only by two collector-timed neighbour captures ≥120 s apart, with `ip ospf mtu-ignore` as a
blocking countercondition. One capture → `unknown(single_sample)`; missing MTU fact → the chain stops
at a named unknown hop.

**Stretch for v1 (only if the fit test allows):** L1-02 speed/duplex, L1-08 UDLD, L1-09 errdisable,
L2-07 MAC table, L3-03 static routing / administrative distance, L2-17 IGMP snooping,
`l3.etherchannel` mode/protocol checks, VRF route leaking.

**Fallback:** if stretch discipline must be kept, v1 shrinks to 10 rows by deferring L2-03 STP and
L3-13 FHRP to E1 — the approved-plan shape. Do not shrink further: without L2-01/L2-06/L3-05 the
product has no EI answer that matters.

**Deliberately not in v1:** all other domain-2..5 rows, IPv6/OSPFv3 (dual-stack is real EI content
but Engine v1 semantics are IPv4/OSPFv2; IPv6 reads `unknown(unmodelled_present)` with detail
`not_in_ei_v1`), controller channels, and automation execution.

---

## 5. Later EI waves (50 rows after v1)

| Wave | Rows | Notes |
|---|---|---|
| **E1 — campus depth / IGPs** (15) | L1-02, L1-05, L1-08, L1-09, L2-05, L2-07, L3-03, L3-06, L3-07, L3-10, L3-11, L3-12, L3-14, L3-27, L7-03 | classic IOS back-fill and IPv6/OSPFv3 decision also land here |
| **E2 — transport + managed services** (9) | L3-18, L3-19, L3-20, L4-01, L4-02, L7-02, L7-04, L7-06, L7-07 | GRE/DMVPN/IPsec first, then ACL/NAT/AAA |
| **E3 — campus security & services** (19) | L2-10..L2-15, L2-17, L2-18, L2-19, L3-15, L3-25, L4-05, L4-06, L7-08..L7-11, L7-16, L7-17 | split into 3a device security / 3b QoS+telemetry if sizing requires |
| **E4 — software-defined infrastructure** (4) | L3-21, L3-22, L3-23, OOS-08 | first REST adapters; needs the page-set consistency contract + evidence-channel ADR |
| **E5 — remainder** (3) | L3-16, OOS-05, OOS-16 | MPLS depth, packet evidence, Guest Shell presence |

---

## 6. Counts (planning facts, re-derived from the matrix)

- **EI rows: 60 of 122 (49%)**; primary cells 57 IOS-XE + 1 SD-WAN + 1 Controllers + 1 ISE.
- **By target depth:** cross-device-correlated 39, expected-vs-observed 20, config-presence 1, none 0.
- **By phase:** M1 4, M2 6 (the 10-row v1 pool), W1/W2/W3 equivalents collapsed into E1–E5 above.
- **Truth/channel:** cited-candidate 49, uncited 9, not-capable 2; CLI 56, CLI+REST 2, REST 1,
  CLI+FILE 1; signable 59/60.
- **v1 = 12 rows / 12 cells ≈ 20% of EI rows** (one adapter, zero REST). Full EI coverage needs
  3–4 adapters, 5 waves, and 50 more rows — the reason this repository starts with the slice.

All counts and phase assignments are planning inputs, not truth claims: the matrix's applicability
states and the fixture/truth-class rules in `PLAN.md` §9 govern what each row may publish.

---

## 7. Acceptance checklist for this scope file

- [x] Every EI v1.1 blueprint section (1.0–5.3) maps to at least one row or an explicit gap
      disposition (§1, §4, §5).
- [x] Every mapped row has an owner pack, an evidence channel, a depth target and a phase.
- [x] v1 rows have an IOS-XE evidence list and a truth path.
- [x] Out-of-EI technologies are enumerated, not implied (§1 "not mapped", §2 adapters).
- [x] The known blueprint gaps are listed with a decision (§1).
- [ ] Owner decisions still open: SD-WAN/SD-Access timing (E4 confirmed?), ISE adapter, IPv6 timing,
      classic IOS back-fill, L1 hardware rows (see `PLAN.md` §13).
