"""Original synthetic Root9 saved-estate bytes only; no parsing, admission or network authority."""
from hashlib import sha256

from atlas_brain.contract.canonical import canonical

CASES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial",
    "no_all_capture", "no_all_target", "zero_vrrp")
STP = "iosxe.show_spanning_tree_interface_detail"
EC = "iosxe.show_etherchannel_summary"
HSRP = "iosxe.show_standby_brief"
ALL = "iosxe.show_standby_all"
VRRP = "iosxe.show_vrrp"
GROUPS = (("Vl20", "0"), ("Vl10", "1"), ("BD3329", "129"), ("Vl99", "2"))
DISCOVERY = b"Device ID: fixture-b\n"
TREE = (b"Port 1 (Gi1/0/1) of VLAN0001 is designated forwarding\n"
    b"   Root guard is disabled on the port\n"
    b"   Designated root has priority 0, address aBcD.EF01.2345\n")
CHANNEL = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
    b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")
BRIEF = (b"                     P indicates configured to preempt.\n                     |\n"
    b"Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
    b"Vl20        0    100   Init    unknown         unknown         203.0.113.1\n"
    b"Vl10        1    110 P Active  local           192.0.2.2       192.0.2.1\n"
    b"BD3329      129  90 P Standby 198.51.100.2    local           198.51.100.1\n")
HSRP_DETAIL = (b"  State is Active\n"
    b"  Virtual IP address is 192.0.2.1\n"
    b"  Active virtual MAC address is 0000.0000.0000 (MAC In Use)\n"
    b"    Local virtual MAC address is 0000.0000.0000 (v2 default)\n"
    b"  Hello time 3 sec, hold time 10 sec\n"
    b"  Preemption enabled\n"
    b"  Active router is local\n"
    b"  Standby router is 192.0.2.2, priority 100 (expires in 1.000 sec)\n"
    b"  Priority 100 (default 100)\n"
    b'  Group name is "synthetic-other-interface-99" (default)\n')
VRRP_DETAIL = (b"  State is Backup\n"
    b"  Virtual IP address is 198.51.100.41\n"
    b"  Virtual MAC address is 0011.2233.4455\n"
    b"  Advertisement interval is 1.250 sec\n"
    b"  Preemption disabled\n"
    b"  Priority is 109\n"
    b'  Authentication text "synthetic-lab"\n'
    b"  Master Router is 192.0.2.17, priority is 113\n"
    b"  Master Advertisement interval is 2.375 sec\n"
    b"  Master Down interval is 9.125 sec\n")


def _need(condition: bool) -> None:
    if not condition:
        raise ValueError("p4_root_mixed_cases_case")


def members(case: str) -> dict[str, bytes]:
    _need(type(case) is str and case in CASES)
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": node, "discovery_id": "fixture-" + node, "ports": ["Gi1/0/1"]} for node in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
            "sha256": sha256(DISCOVERY).hexdigest()}]})
    detail = b"".join(f"{interface} - Group {group} (version {version})\n".encode("ascii") + HSRP_DETAIL
        for interface, group, version in (("Vl20", "0", "2"), ("Vl10", "1", "1"), ("BD3329", "129", "2")))
    files = {"p2.json": base, "discovery.txt": DISCOVERY, "brief.txt": BRIEF, "all.txt": detail,
        "tree.txt": TREE, "channel.txt": CHANNEL, "vrrp.txt": b"Vlan61 - Group 100\n" + VRRP_DETAIL}
    targets = [
        {"id": "brief-a", "node": "a", "operation": HSRP, "params": {"groups": [list(pair) for pair in GROUPS]}},
        {"id": "brief-b", "node": "b", "operation": HSRP, "params": {"groups": [["Vl30", "2"]]}},
        {"id": "all-a", "node": "a", "operation": ALL, "params": {"groups": [list(pair) for pair in GROUPS]}},
        {"id": "all-b", "node": "b", "operation": ALL, "params": {"groups": [["Vl30", "2"]]}},
        {"id": "tree", "node": "a", "operation": STP, "params": {"port": "Gi1/0/1", "vlans": [1]}},
        {"id": "channel", "node": "b", "operation": EC, "params": {"groups": ["1"], "ports": ["Gi1/0/1"]}},
        {"id": "vrrp", "node": "a", "operation": VRRP, "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]}}]
    selected = [("brief-a", "brief.txt"), ("all-a", "all.txt"), ("tree", "tree.txt"),
        ("channel", "channel.txt"), ("vrrp", "vrrp.txt")]
    if case == "only_vrrp":
        targets = [row for row in targets if row["operation"] == VRRP]
        selected = [row for row in selected if row[0] == "vrrp"]
    elif case == "zero_vrrp":
        targets = [row for row in targets if row["operation"] != VRRP]
        selected = [row for row in selected if row[0] != "vrrp"]
    elif case == "none":
        selected = []
    elif case == "cold_vrrp":
        selected = [row for row in selected if row[0] != "vrrp"]
    elif case in ("no_all_capture", "no_all_target"):
        selected = [row for row in selected if row[0] != "all-a"]
        if case == "no_all_target":
            targets = [row for row in targets if row["operation"] != ALL]
    elif case == "empty":
        files["vrrp.txt"] = b""
    elif case == "partial":
        files["vrrp.txt"] += b"unrecognized\n"
    claimed = {path for _, path in selected}
    for path in ("brief.txt", "all.txt", "tree.txt", "channel.txt", "vrrp.txt"):
        if path not in claimed:
            files.pop(path)
    captures = [{"target": target, "path": path, "sha256": sha256(files[path]).hexdigest()}
        for target, path in selected]
    files["p4.json"] = canonical({"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic",
        "context": "round", "base_sha256": sha256(base).hexdigest(), "targets": targets, "captures": captures})
    return files
