"""Generated P3 CLI extracts and declarations; no raw fixture or device imports."""
from hashlib import sha256

PORT = "GigabitEthernet1"
CDP = "iosxe.show_cdp_neighbors_detail"
INTERFACE_MTU, IP_MTU = "iosxe.show_interfaces", "iosxe.show_ip_interface"
NEIGHBOR, INTERFACE = "iosxe.show_ip_ospf_neighbor", "iosxe.show_ip_ospf_interface"
IGNORE = "iosxe.show_running_config_all"
CASES = ("supported", "single_sample", "untimed_conflict", "untimed", "missing_mtu", "mtu_ignore",
         "missing_ignore", "full", "two_way", "same_mtu", "short_interval", "unmodeled",
         "missing_neighbor", "no_rounds", "changed_peer", "different_clock", "missing_peer", "changed_receiver")


def members(canonical, case="supported"):
    if case not in CASES:
        raise ValueError("p3_demo_case")
    files, baseline = {}, []
    for node, peer in (("a", "b"), ("b", "a")):
        if case == "missing_peer" and node == "b":
            continue
        raw = (f"Device ID: sw-{peer}\nPlatform: synthetic-switch, Capabilities: Switch\n"
               f"Interface: {PORT}, Port ID (outgoing port): {PORT}\n").encode("ascii")
        path = node + "_cdp.txt"
        files[path] = raw
        baseline.append({"path": path, "node": node, "operation": CDP, "sha256": sha256(raw).hexdigest()})
    files["p2.json"] = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic",
        "group": "demo", "nodes": [{"id": node, "discovery_id": "sw-" + node, "ports": [PORT]} for node in ("a", "b")],
        "captures": baseline})
    def point(node, number):
        return {"node": node, "port": PORT, "process": number, "router_id": "192.0.2." + str(number),
                "address": "198.51.100." + str(number), "vrf": "default"}
    rounds = () if case == "no_rounds" else (("first", 1000000),) if case == "single_sample" else (
        ("first", 1000000), ("second", 50000000 if case == "short_interval" else 122000000))
    samples = []
    for round_id, start in rounds:
        captures = []
        for node, number, peer in (("a", 1, 7), ("b", 7, 1)):
            mtu = 1500 if case == "same_mtu" or node == "b" else 9000
            if case == "changed_receiver" and round_id == "second":
                mtu = 1500 if node == "a" else 9000
            state = "FULL" if case == "full" or case == "untimed_conflict" and round_id == "second" else (
                "2WAY" if case == "two_way" else "EXSTART")
            neighbor_id = 9 if case == "changed_peer" and round_id == "second" and node == "a" else peer
            control = "ip ospf mtu-ignore" if case == "mtu_ignore" and node == "b" else "no ip ospf mtu-ignore"
            outputs = {
                INTERFACE_MTU: f"{PORT} is up, line protocol is up\n  MTU {mtu} bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n",
                IP_MTU: f"{PORT} is up, line protocol is up\n  MTU is {mtu} bytes\n",
                NEIGHBOR: f"Neighbor ID Pri State Dead Time Address Interface\n192.0.2.{neighbor_id} 0 {state}/- 00:00:30 198.51.100.{peer} {PORT}\n",
                INTERFACE: f"{PORT} is up, line protocol is up\n  Internet Address 198.51.100.{number}/30, Area 0\n"
                    f"  Process ID {number}, VRF default Router ID 192.0.2.{number}, Network Type POINT_TO_POINT, Cost: 10\n",
                IGNORE: f"interface {PORT}\n {control}\nend\n",
            }
            for index, (operation, output) in enumerate(outputs.items()):
                if (case == "missing_mtu" and round_id == "first" and node == "a" and operation == IP_MTU
                        or case == "missing_ignore" and node == "b" and operation == IGNORE
                        or case == "missing_neighbor" and round_id == "second" and node == "a" and operation == NEIGHBOR):
                    continue
                if case == "unmodeled" and node == "a" and operation == INTERFACE:
                    output += "  unmodeled policy\n"
                raw, path = output.encode("ascii"), f"{round_id}_{node}_{index}.txt"
                files[path] = raw
                captures.append({"path": path, "node": node, "operation": operation, "sha256": sha256(raw).hexdigest()})
        clock = "collector:other" if case == "different_clock" and round_id == "second" else "collector:fixture"
        interval = None if case in ("untimed", "untimed_conflict") else {
            "unit": "unix_us", "clock": clock, "earliest": start, "latest": start + 1, "bound": "collector_recorded"}
        samples.append({"id": round_id, "time": interval, "captures": captures})
    files["p3.json"] = canonical({"schema": "atlas-brain.synthetic-p3/1", "semantic_group": "declared_synthetic",
        "base_sha256": sha256(files["p2.json"]).hexdigest(), "adjacencies": [{"id": "link", "domain": "lab", "area": 0,
            "left": point("a", 1), "right": point("b", 7)}], "samples": samples})
    return files
