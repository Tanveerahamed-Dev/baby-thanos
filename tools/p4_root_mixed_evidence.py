"""Independent original-fixture evidence tables only; no parser, owner, origin or semantic authority."""
import json
from hashlib import sha256

CASES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all_capture", "no_all_target", "zero_vrrp")
OPS = ("iosxe.show_standby_brief", "iosxe.show_standby_all", "iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary", "iosxe.show_vrrp")
OWNERS = ("l3.fhrp/parse_hsrp_brief", "l3.fhrp/parse_hsrp_all_version", "l2.stp/parse_root_guard", "l2.etherchannel/parse_protocol", "l3.fhrp/parse_vrrp")
COMMANDS = ("show standby brief", "show standby all", "show spanning-tree interface Gi1/0/1 detail", "show etherchannel summary", "show vrrp")
PINS = {
    "discovery.txt": (21, "c7ebce2d080affaba5445d91c7e0cc9eec38e794c4bbb8a29eb4bdd72464aa45"), "tree.txt": (150, "8ee9ac0d03eeb819bf06a12e7cacd899ee500c33b2bbe00dfcfca626220cd905"),
    "channel.txt": (132, "e3f7c100cae34017e2a002db7fb135b7da6cd6c3fb697077c41a9f9f29d67eed"), "brief.txt": (376, "255b6d5a21150ced6474e9ee86e62105c4be58810edabc3724e969ca836f7375"),
    "all.txt": (1312, "a363f5d7db39b7b68abac0d4091cc81eb8e3664d2cadc3ea22bba9ea9cd97197"), "vrrp.txt": (359, "880bc5dbe19a8f5e5b30b7e25b47391d22927d95cde787b70864d32b2d6e0333"),
}
EMPTY = (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
PARTIAL = (372, "0a8e643af31fbbfa9362f2f8b9a9e7c1a3c4981ec8f558b0596d0ac02b560e43")
ANCHORS = {
    "tree.txt": (
        ("header", 0, 53), ("port", 8, 15), ("vlan", 24, 28), ("role", 32, 42), ("state", 43, 53), ("guard", 54, 91), ("guard_token", 71, 79), ("root", 92, 149),
        ("priority", 124, 125), ("mac", 135, 149),
    ),
    "channel.txt": (
        ("row", 106, 131), ("group", 106, 107), ("channel", 108, 111), ("protocol", 116, 120), ("member", 121, 131), ("port", 121, 128), ("flag", 129, 130),
    ),
    "brief.txt": (
        ("0.row", 153, 227), ("0.interface", 153, 157), ("0.group", 165, 166), ("0.state", 176, 180), ("0.active", 184, 191), ("0.standby", 200, 207), ("0.vip", 216, 227), ("1.row", 228, 300),
        ("1.interface", 228, 232), ("1.group", 240, 241), ("1.state", 251, 257), ("1.active", 259, 264), ("1.standby", 275, 284), ("1.vip", 291, 300), ("2.row", 301, 375), ("2.interface", 301, 307),
        ("2.group", 313, 316), ("2.state", 323, 330), ("2.active", 331, 343), ("2.standby", 347, 352), ("2.vip", 363, 375),
    ),
    "all.txt": (
        ("0.heading", 0, 26), ("0.interface", 0, 4), ("0.group", 13, 14), ("0.version", 24, 25), ("0.vip_line", 45, 78), ("0.vip", 69, 78), ("0.group_name", 379, 435), ("1.heading", 436, 462),
        ("1.interface", 436, 440), ("1.group", 449, 450), ("1.version", 460, 461), ("1.vip_line", 481, 514), ("1.vip", 505, 514), ("1.group_name", 815, 871), ("2.heading", 872, 902), ("2.interface", 872, 878),
        ("2.group", 887, 890), ("2.version", 900, 901), ("2.vip_line", 921, 954), ("2.vip", 945, 954), ("2.group_name", 1255, 1311),
    ),
    "vrrp.txt": (
        ("heading", 0, 18), ("interface", 0, 6), ("group", 15, 18), ("state_line", 19, 36), ("state", 30, 36), ("vip_line", 37, 74), ("vip", 61, 74), ("master_down", 323, 358),
    ),
}


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError("p4_root_mixed_evidence_" + code)


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _capture(identifier: str, node: str, operation: str, command: str, raw: bytes, integrity: str) -> dict[str, object]:
    witness = {"type": "capture", "layer": "p2" if operation == "iosxe.show_cdp_neighbors_detail" else "p4",
        "capture": identifier, "role": "subject", "locator": {"kind": "whole_capture"}, "excerpt_sha256": _digest(raw)}
    return {"layer": witness["layer"], "id": identifier, "raw": _digest(raw), "node": node,
        "operation": operation, "rendered": command, "codec": "utf-8", "integrity": integrity,
        "read_scope": "unknown", "view": "unknown", "metadata_recorded": False,
        "metadata": {"channel": "cli", "scope": {"node": node, "vrf": None, "context": None, "vdc": None,
            "tenant": None, "afi": None, "instance": None, "plane": "exec"},
            "collected_utc": {"state": "unknown", "reason": "as_of_missing", "detail": "no_collector_time",
                "candidates": [], "next_evidence": [], "evidence": [witness]},
            "error": None, "integrity_evidence": [dict(witness)], "read_scope_evidence": [], "envelope": None}}


def evidence_tables(case: str, members: dict[str, bytes], registration_sha256: str) -> dict[str, object]:
    _need(type(case) is str and case in CASES, "case")
    _need(type(members) is dict and all(type(name) is str and type(raw) is bytes for name, raw in members.items()), "members")
    _need(type(registration_sha256) is str and len(registration_sha256) == 64
        and all(char in "0123456789abcdef" for char in registration_sha256), "registration")
    groups = [["Vl20", "0"], ["Vl10", "1"], ["BD3329", "129"], ["Vl99", "2"]]
    targets = [
        {"id": "brief-a", "node": "a", "operation": OPS[0], "params": {"groups": groups}},
        {"id": "brief-b", "node": "b", "operation": OPS[0], "params": {"groups": [["Vl30", "2"]]}},
        {"id": "all-a", "node": "a", "operation": OPS[1], "params": {"groups": groups}},
        {"id": "all-b", "node": "b", "operation": OPS[1], "params": {"groups": [["Vl30", "2"]]}},
        {"id": "tree", "node": "a", "operation": OPS[2], "params": {"port": "Gi1/0/1", "vlans": [1]}},
        {"id": "channel", "node": "b", "operation": OPS[3], "params": {"groups": ["1"], "ports": ["Gi1/0/1"]}},
        {"id": "vrrp", "node": "a", "operation": OPS[4], "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]}}]
    supplied = [("brief-a", "brief.txt"), ("all-a", "all.txt"), ("tree", "tree.txt"),
        ("channel", "channel.txt"), ("vrrp", "vrrp.txt")]
    if case == "only_vrrp":
        targets, supplied = targets[-1:], supplied[-1:]
    elif case == "zero_vrrp":
        targets, supplied = targets[:-1], supplied[:-1]
    elif case == "none":
        supplied = []
    elif case == "cold_vrrp":
        supplied = supplied[:-1]
    elif case in ("no_all_capture", "no_all_target"):
        supplied = [supplied[0], *supplied[2:]]
        if case == "no_all_target":
            targets = [row for row in targets if row["operation"] != OPS[1]]
    wanted = {"discovery.txt", *(path for _, path in supplied)}
    _need(set(members) == wanted | {"p2.json", "p4.json"}, "members")
    for path in wanted:
        pin = EMPTY if path == "vrrp.txt" and case == "empty" else PARTIAL if path == "vrrp.txt" and case == "partial" else PINS[path]
        _need((len(members[path]), _digest(members[path])) == pin, "raw")
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": node, "discovery_id": "fixture-" + node, "ports": ["Gi1/0/1"]} for node in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
            "sha256": PINS["discovery.txt"][1]}]}
    _need(members["p2.json"] == _json(base), "registry")
    base_hash = _digest(members["p2.json"])
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "round",
        "base_sha256": base_hash, "targets": targets,
        "captures": [{"target": target, "path": path, "sha256": _digest(members[path])} for target, path in supplied]}
    _need(members["p4.json"] == _json(side), "registry")
    side_hash = _digest(members["p4.json"])
    discovery = "cap:" + _digest(_json(("atlas-brain.synthetic-p2/1", "demo", base_hash,
        "discovery.txt", "a", "iosxe.show_cdp_neighbors_detail", PINS["discovery.txt"][1])))
    captures = [_capture(discovery, "node:demo:a", "iosxe.show_cdp_neighbors_detail",
        "show cdp neighbors detail", members["discovery.txt"], "complete")]
    extra = []
    for target_id, path in supplied:
        target = next(row for row in targets if row["id"] == target_id)
        operation = OPS.index(target["operation"])
        identifier = "cap:" + _digest(_json(("atlas-brain.synthetic-p4/1", side_hash, base_hash, "round",
            target_id, path, _digest(members[path]), registration_sha256)))
        row = _capture(identifier, "node:demo:" + target["node"], OPS[operation], COMMANDS[operation],
            members[path], "empty" if path == "vrrp.txt" and case == "empty" else "complete")
        row.update(path=path, target=target_id, owner=OWNERS[operation], context="round", registration_sha256=registration_sha256,
            parse_quality="partial" if path == "vrrp.txt" and case in ("empty", "partial") else "complete", params=target["params"])
        extra.append(row)
    captures.extend(sorted(extra, key=lambda row: row["id"]))
    catalogue = []
    for table, digest, rows, pointer in (("synthetic_p2.nodes", base_hash, base["nodes"], "nodes"),
        ("synthetic_p4.targets", side_hash, targets, "targets")):
        for index, row in enumerate(rows):
            catalogue.append({"table": table, "row_id": row["id"], "table_sha256": digest, "pointer": f"/{pointer}/{index}",
                "raw": digest, "encoding": "hex", "canonical": _json(row).hex()})
    catalogue.append({"table": "synthetic_p4.context", "row_id": "round", "table_sha256": side_hash,
        "pointer": "/context", "raw": side_hash, "encoding": "hex", "canonical": _json("round").hex()})
    blobs = {_digest(raw): raw for raw in members.values()}
    _need(all(blobs[_digest(raw)] == raw for raw in members.values()), "collision")
    anchors = {}
    for path in sorted(wanted):
        raw = members[path]
        points = () if not raw else ANCHORS.get(path, ())
        anchors[path] = {"whole": {"locator": {"kind": "whole_capture"}, "excerpt_sha256": _digest(raw)}}
        for name, start, end in points:
            _need(type(start) is int and type(end) is int and 0 <= start < end <= len(raw), "anchor")
            anchors[path][name] = {"locator": {"kind": "bytes", "start": start, "end": end},
                "excerpt_sha256": _digest(raw[start:end])}
    return {"raws": [{"sha256": digest, "bytes": len(raw), "encoding": "hex", "data": raw.hex()}
        for digest, raw in sorted(blobs.items())], "registries": [{"layer": "p2", "raw": base_hash}, {"layer": "p4", "raw": side_hash}],
        "captures": captures, "registry_catalogue": catalogue, "anchors": anchors,
        "physical_inputs": {"files": len(members), "bytes": sum(map(len, members.values()))}}
