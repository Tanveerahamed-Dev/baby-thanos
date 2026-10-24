# Reference list: main protocols L1-L7 for a brownfield Cisco assessment engine

Derived from the official Cisco blueprints (text extracted in this folder):
- CCIE Enterprise Infrastructure v1.1 (ccie_ei_v1.1.txt) — https://learningcontent.cisco.com/documents/marketing/exam-topics/CCIE_EI_v1.1_Blue_Print.pdf
- CCIE Data Center v3.1 (dc.txt) — https://learningcontent.cisco.com/documents/marketing/exam-topics/New_CCIE-DataCenter-v3.1-BluePrint_v2_reviewed.pdf
- CCIE Security v6.1 (sec.txt) — https://learningcontent.cisco.com/documents/marketing/exam-topics/CCIE_Security_v6.1_Blueprint.pdf
Plus physical-layer items an assessment needs that exams do not list (environment, optics, lifecycle).
Scope note: the engine is a READ-ONLY show-command/config/controller-REST analyser. "L5-L7" for it means
network services, management plane and application-aware policy configured on devices — not application
performance itself.

## L1 Physical
L1-01 Interface state and counters (CRC, input/output errors, drops, resets)
L1-02 Speed / duplex / autonegotiation (configured vs negotiated)
L1-03 Transceivers / optics (type, PID, serial, DOM light levels, thresholds)
L1-04 PoE (budget, per-port state, faults)
L1-05 Chassis environment (PSU per bay, fans, temperature)
L1-06 Stack / supervisor / StackWise Virtual redundancy
L1-07 Hardware inventory and lifecycle (EoL/EoS for chassis, modules, optics, PSUs)
L1-08 UDLD
L1-09 Errdisable state, causes and recovery
L1-10 Physical links / cabling derived from neighbours (both ends)

## L2 Data link
L2-01 VLANs (access, trunk 802.1Q, native, allowed/pruning, voice VLAN, extended range)
L2-02 VTP
L2-03 STP (PVST+, Rapid PVST+, MST; priority/root placement; PortFast, BPDU guard/filter, root guard, loop guard)
L2-04 EtherChannel (LACP, PAgP, static; L2/L3; load balancing; misconfiguration guard)
L2-05 Multichassis LAG (vPC, MLAG, StackWise Virtual)
L2-06 CDP / LLDP
L2-07 MAC address table (counts, flaps, aging)
L2-08 L2 MTU / jumbo
L2-09 Private VLANs
L2-10 Storm control
L2-11 Port security
L2-12 DHCP snooping / option 82
L2-13 Dynamic ARP Inspection
L2-14 IP Source Guard
L2-15 802.1X / MAB / IBNS 2.0
L2-16 MACsec (802.1AE / MKA)
L2-17 IGMP snooping / querier / MLD snooping (L2 multicast)
L2-18 IPv6 first-hop security (RA guard, DHCPv6 guard, ND inspection, device tracking, binding table)
L2-19 SPAN / RSPAN / ERSPAN

## L3 Network
L3-01 IPv4/IPv6 addressing, subnets, duplicate IPs
L3-02 ARP / IPv6 ND
L3-03 Static and default routing; administrative distance
L3-04 VRF / VRF-Lite / route leaking (route maps, VASI)
L3-05 OSPFv2 / OSPFv3 (adjacencies, areas, network types, LSA, authentication)
L3-06 EIGRP (adjacencies, stub, SIA, named mode)
L3-07 BGP (eBGP/iBGP, peering state, RR, path selection, policies, communities, address families VPNv4/EVPN)
L3-08 IS-IS
L3-09 RIP / RIPng (minor)
L3-10 Redistribution and route filtering (route-maps, prefix-lists, distribute-lists)
L3-11 Policy-based routing
L3-12 BFD
L3-13 FHRP (HSRP, VRRP, GLBP; IPv6 RS/RA redundancy)
L3-14 Object tracking
L3-15 Multicast PIM (SM, SSM, BIDIR; RP: static/BSR/Auto-RP/Anycast/MSDP; RPF) and IGMP/MLD
L3-16 MPLS (LDP, L3VPN, L2VPN)
L3-17 Segment Routing (SR-MPLS, SRv6, TI-LFA)
L3-18 GRE tunnels
L3-19 DMVPN / NHRP
L3-20 IPsec / IKEv2 / FlexVPN / site-to-site and remote-access VPN
L3-21 VXLAN EVPN
L3-22 LISP / SD-Access fabric
L3-23 SD-WAN (OMP, TLOC, control connections, policies) — controller channel
L3-24 Cisco ACI (tenants, EPG/ESG, BD, VRF, contracts, faults) — controller channel
L3-25 TrustSec / SGT / SXP
L3-26 uRPF
L3-27 Routing protocol authentication / GTSM
L3-28 L3 MTU / PMTU / IP MTU

## L4 Transport and policy
L4-01 ACLs (IPv4/IPv6, VACL, PACL, iACL) — content and application to interfaces
L4-02 NAT / PAT (static, dynamic, policy, VRF-aware) — IOS and ASA/FTD
L4-03 Stateful firewall (ASA/FTD routed/transparent, contexts, zones; IOS ZBFW)
L4-04 Firewall HA / clustering
L4-05 QoS (classification/trust, DSCP marking, policing, shaping, queuing, HQoS, MQC) and drops
L4-06 CoPP / control-plane protection
L4-07 TCP/UDP-level settings (TCP MSS adjust, keepalives) and synthetic five-tuple reachability (Traffic Assurance)

## L5-L7 Network services, management plane, application-aware policy
L7-01 DNS (name servers, domain lookup, DNS on devices)
L7-02 DHCP (server, relay / ip helper, options, DHCPv6, prefix delegation)
L7-03 NTP / PTP (sources, sync state, authentication)
L7-04 SNMP (v2c/v3, communities, views, ACLs, traps)
L7-05 Syslog / logging (hosts, levels, timestamps, buffer, config-change logging)
L7-06 AAA (TACACS+, RADIUS, LDAP; authentication/authorization/accounting for admin access)
L7-07 Management access (console/VTY, SSH version, SCP, Telnet, HTTP/HTTPS server, exec-timeout)
L7-08 Model-driven management (NETCONF, RESTCONF, gNMI, telemetry subscriptions)
L7-09 NetFlow / IPFIX / NSEL / Flexible NetFlow
L7-10 IP SLA probes (ICMP/UDP/TCP) and their tracking
L7-11 NBAR / AVC application recognition
L7-12 Application inspection / ALGs on firewalls (SIP, FTP, DNS inspection)
L7-13 SSL/TLS inspection and PKI / certificates (trustpoints, expiry)
L7-14 Voice readiness (voice VLAN, voice QoS, SIP/CUBE presence)
L7-15 Service insertion (WCCP, policy-based redirect)
L7-16 ISE / identity services (controller channel: posture, profiling, NAD config)
L7-17 EEM / on-box automation presence

## SP — Service Provider additions (CCIE Service Provider v5.1)
Source: https://learningcontent.cisco.com/documents/marketing/exam-topics/CCIE_Service_Provider_v5.1_Exam_Topics-mor.pdf
(text in sp_mor.txt; older variant sp_v4.txt). Rows below are SP depth NOT already covered by L1-L7 rows above;
where an L-row covers the base protocol (IS-IS L3-08, BGP L3-07, MPLS L3-16, SR L3-17, multicast L3-15), the SP
row covers the SP-specific depth only.
SP-01 IOS-XR platform channel (collection commands + parsers for XR show output; XR config syntax)
SP-02 IS-IS SP depth (levels, wide metrics, SR extensions, overload bit, multi-topology)
SP-03 MP-BGP SP address families (VPNv4/VPNv6, labeled unicast BGP-LU, BGP-LS, route reflection hierarchy, add-path)
SP-04 MPLS Traffic Engineering / RSVP-TE (tunnels, LSP attributes, auto-tunnel, DS-TE)
SP-05 SR-MPLS depth (SRGB/SRLB, prefix/adjacency SIDs, SR-TE policies, Flex-Algo, mapping server, LDP-SR interworking)
SP-06 PCE / PCEP / SR-PCE (stateful PCE, delegated LSPs, disjoint paths)
SP-07 SRv6 (locators, uSID, encapsulation functions, interworking gateway)
SP-08 L3VPN SP depth (RD/RT import-export, inter-AS options A/B/C, PE-CE OSPF/BGP, extranet/shared services, multihoming loop prevention)
SP-09 L2VPN legacy (VPWS/pseudowire xconnect, VPLS, H-VPLS)
SP-10 EVPN SP (EVPN-VPWS, EVPN-ELAN, EVPN-IRB, ESI multihoming, service steering into SR policy)
SP-11 Multicast SP depth (mLDP, NG-mVPN profiles, Tree-SID)
SP-12 Carrier Ethernet access (802.1ad Q-in-Q, ITU G.8032 ERPS, MST-AG / PVST-AG, MC-LAG with ICCP)
SP-13 High availability (SSO/NSF/NSR/graceful restart; redundancy state of RPs)
SP-14 Fast convergence (LFA, remote LFA, TI-LFA, BGP PIC, MPLS TE FRR, LDP-IGP sync, IGP/LDP convergence timers)
SP-15 Internet edge services (CGNAT/NAT44, NAT64/MAP-T, peering and transit policy enforcement)
SP-16 SP control/infrastructure security (LPTS, MPP, BGP RPKI/ROV, BGP Flowspec, RTBH, ACL object groups, gRPC/gNMI TLS certs)
SP-17 SP QoS (MPLS EXP/TC marking, pipe/short-pipe/uniform models, DS-TE MAM/RDM, PBTS)
SP-18 SP OAM and performance monitoring (CFM, Y.1731/Y.1564, TWAMP, SR-PM, MPLS ping/traceroute, RMON)
SP-19 Timing and synchronization (PTP/IEEE 1588 profiles, SyncE, clock state)
SP-20 BNG / subscriber management (PPPoE/IPoE sessions, control/user plane separation)
SP-21 Routed optical and 5G transport (coherent ZR/ZR+ optics PM, network slicing via Flex-Algo/QoS)

## OOS — Areas outside the current plan (owner asked 2026-10-19 to cover them too)
Sources: CCIE DC v3.1 (dc.txt), CCIE Security v6.1 (sec.txt), CCIE EI v1.1 (ccie_ei_v1.1.txt), CCIE SP v5.1, plus ADR 0009's explicit out-of-scope list (wireless, model-driven and flow/packet telemetry, QUIC, RoCE/DCB, OT protocols).
OOS-01 Wireless (WLC/AP join and CAPWAP, WLAN/SSID security WPA2/WPA3, 802.1X/MAB on WLAN, guest, roaming, RF health)
OOS-02 FC / FCoE storage networking (VSAN, zoning, NPV/NPIV, SAN port-channel and trunking, FCoE/DCBX) on Nexus/MDS
OOS-03 RoCEv2 / lossless Ethernet for AI/HPC (PFC 802.1Qbb, ECN, DCQCN, ETS/DCBX, buffer/no-drop classes)
OOS-04 Flow telemetry data analysis (NetFlow/IPFIX/NSEL records, top talkers, application flows) as an evidence channel
OOS-05 Packet evidence (pcap ingest, Embedded Packet Capture, SPAN-captured traces) as an evidence channel
OOS-06 Model-driven management and automation (NETCONF/RESTCONF/gNMI/YANG telemetry subscriptions, NSO, secure ZTP)
OOS-07 UCS compute fabric (fabric interconnects end-host vs switch mode, uplink pinning, port modes, UCS Manager, Intersight)
OOS-08 Catalyst Center (DNA Center) controller channel (inventory, assurance, LAN automation/PnP, SD-Access provisioning)
OOS-09 Nexus Dashboard / NDFC / Orchestrator / Insights and Cloud Network Controller channel
OOS-10 Virtual networking / VMM integration (vSphere VDS, ACI VMM domains)
OOS-11 DC interconnect and multi-fabric (VXLAN-EVPN Multi-Site border gateways, ACI Multi-Pod, Multi-Site, remote leaf)
OOS-12 Intrusion prevention (NGIPS/Snort policy, inline/passive/TAP modes, IOS ip ips) and FMC correlation rules
OOS-13 Control-plane and platform resource health (CPU, memory thresholding, TCAM/hardware table pressure)
OOS-14 Public cloud networking (AWS/Azure/GCP VPC/VNet routing, security groups/NSGs, transit gateways, cloud WAN edge)
OOS-15 SASE/SSE and remote access (Umbrella/DNS-layer security, AnyConnect/Secure Client VPN, posture, zero trust)
OOS-16 On-box automation and app hosting (Guest Shell, IOx, EEM Python)
OOS-17 Voice and collaboration platforms in depth (CUBE dial-peers, SIP trunks, CUCM integration)
OOS-18 OT/IoT and industrial Ethernet (REP, PRP/HSR, Modbus/PROFINET awareness, Cisco IE switches)
OOS-19 Kubernetes CNI / service mesh / container networking
OOS-20 QUIC / HTTP/3 visibility
