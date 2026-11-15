"""Independent original-fixture ordered custody only; no scalar, Needs, origin or admission authority."""
import json
from hashlib import sha256

from tools.p4_root_mixed_evidence import evidence_tables

TREE = ("l2.stp.root_guard", "l2.stp.reported_role", "l2.stp.reported_root_priority", "l2.stp.reported_root_mac")
CHANNEL = ("l2.etherchannel.reported_protocol", "l2.etherchannel.reported_member_tokens")
HSRP = ("l3.fhrp.reported_state", "l3.fhrp.reported_protocol_version")
VRRP = "l3.fhrp.reported_vrrp_state"
VPOINTS = ("interface", "heading", "group", "state_line", "state", "vip_line", "vip", "master_down")
OWNERS = {"iosxe.show_standby_brief": "l3.fhrp/parse_hsrp_brief", "iosxe.show_standby_all": "l3.fhrp/parse_hsrp_all_version",
    "iosxe.show_spanning_tree_interface_detail": "l2.stp/parse_root_guard",
    "iosxe.show_etherchannel_summary": "l2.etherchannel/parse_protocol", "iosxe.show_vrrp": "l3.fhrp/parse_vrrp"}


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError("p4_root_mixed_leaves_" + code)


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _subject(family: str, prefix: str, *coordinates: object) -> str:
    return prefix + ":" + _digest(_json(("atlas-brain." + family + "/1", "round", *coordinates)))


def claim_leaves(case: str, members: dict[str, bytes], registration_sha256: str) -> dict[str, object]:
    tables = evidence_tables(case, members, registration_sha256)
    base, side = json.loads(members["p2.json"]), json.loads(members["p4.json"])
    p2, p4 = _digest(members["p2.json"]), _digest(members["p4.json"])
    records = {(row["table"], row["row_id"], row["table_sha256"], row["pointer"]): row for row in tables["registry_catalogue"]}
    _need(len(records) == len(tables["registry_catalogue"]), "registry")
    aliases = {"context": ("synthetic_p4.context", "round", p4, "/context")}
    for index, node in enumerate(base["nodes"]):
        aliases["node-" + node["id"]] = ("synthetic_p2.nodes", node["id"], p2, f"/nodes/{index}")
    targets = {}
    for index, target in enumerate(side["targets"]):
        aliases[target["id"]] = ("synthetic_p4.targets", target["id"], p4, f"/targets/{index}")
        targets[target["id"]] = target
    captures = {row["path"]: row for row in tables["captures"] if row["layer"] == "p4"}
    _need(set(captures) == set(members) - {"p2.json", "p4.json", "discovery.txt"}
        and len(captures) == len({row["id"] for row in captures.values()}), "capture")
    claims = []

    def leaves(node, target, path, role, names):
        if path is None or path not in members:
            return []
        _need(path in captures and target in targets and path in tables["anchors"], "capture")
        capture, declared, raw = captures[path], targets[target], members[path]
        scope = {"node": node, "vrf": None, "context": None, "vdc": None, "tenant": None,
            "afi": None, "instance": None, "plane": "exec"}
        _need(capture["node"] == node == "node:demo:" + declared["node"] and capture["target"] == target
            and capture["operation"] == declared["operation"] and capture["owner"] == OWNERS[declared["operation"]]
            and capture["context"] == "round" and capture["codec"] == "utf-8"
            and capture["registration_sha256"] == registration_sha256 and capture["raw"] == _digest(raw)
            and capture["metadata"]["scope"] == scope and capture["metadata_recorded"] is False
            and capture["read_scope"] == capture["view"] == "unknown", "scope")
        _need(role in ("subject", "witness"), "role")
        result = []
        for name in names:
            _need(name in tables["anchors"][path], "anchor")
            anchor = tables["anchors"][path][name]
            point = anchor["locator"]
            if point["kind"] == "whole_capture":
                _need(role == "witness", "role")
                excerpt = raw
            else:
                _need(point["kind"] == "bytes" and type(point["start"]) is int and type(point["end"]) is int
                    and 0 <= point["start"] < point["end"] <= len(raw), "anchor")
                excerpt = raw[point["start"]:point["end"]]
            _need(anchor["excerpt_sha256"] == _digest(excerpt), "hash")
            result.append({"type": "capture", "layer": "p4", "capture": capture["id"], "role": role,
                "locator": {**point}, "excerpt_sha256": anchor["excerpt_sha256"]})
        return result

    def append(kind, fact, subject, local, registry, target, path, role, names):
        claims.append({"kind": kind, "fact": fact, "subject": subject, "local": local, "registry": registry,
            "evidence": leaves(local["node"], target, path, role, names)})

    if case != "only_vrrp":
        tree = _subject("stp-port-vlan", "stp_port_vlan", "node:demo:a", "Gi1/0/1", 1)
        local = {"protocol": "stp", "node": "node:demo:a", "port": "Gi1/0/1", "vlan": 1}
        tree_points = (("guard_token", "guard", "port", "vlan", "header"), ("header", "port", "vlan", "role", "state"),
            ("header", "port", "vlan", "root", "priority", "mac"), ("header", "port", "vlan", "root", "priority", "mac"))
        for fact, names in zip(TREE, tree_points, strict=True):
            append("stp_port_vlan", fact, tree, {**local}, ["node-a", "context", "tree"], "tree", "tree.txt", "subject", names)
        channel = _subject("etherchannel-group", "etherchannel_group", "node:demo:b", "1")
        for fact, names in zip(CHANNEL, (("group", "protocol", "row"), ("group", "row", "channel", "port", "member", "flag")), strict=True):
            append("etherchannel_group", fact, channel, {"protocol": "etherchannel", "node": "node:demo:b", "group": "1"},
                ["node-b", "context", "channel"], "channel", "channel.txt", "subject", names)
        for node, interface, group, index in (("a", "Vl20", "0", 0), ("a", "Vl10", "1", 1),
            ("a", "BD3329", "129", 2), ("a", "Vl99", "2", None), ("b", "Vl30", "2", None)):
            subject = _subject("fhrp-local", "fhrp_local", "node:demo:" + node, interface, "ipv4", "hsrp", group)
            local = {"protocol": "hsrp", "node": "node:demo:" + node, "interface": interface, "group": group}
            registry = ["node-" + node, "context", "brief-" + node]
            state_names = ("whole",) if index is None else tuple(f"{index}." + name for name in
                ("interface", "row", "group", "state", *(("standby",) if index == 1 else ("active",) if index == 2 else ()), "vip"))
            append("fhrp_local", HSRP[0], subject, {**local}, registry, "brief-" + node,
                "brief.txt" if node == "a" else None, "witness" if index is None else "subject", state_names)
            version_names = ("whole",) if index is None else tuple(f"{index}." + name for name in
                ("interface", "heading", "group", "version", "vip_line", "vip", "group_name"))
            append("fhrp_local", HSRP[1], subject, {**local}, registry + ([] if case == "no_all_target" else ["all-" + node]),
                "all-" + node, "all.txt" if node == "a" else None, "witness" if index is None else "subject", version_names)
    if case != "zero_vrrp":
        for interface, group in (("Vlan61", "100"), ("Vl61", "101")):
            subject = _subject("vrrp-local", "fhrp_local", "node:demo:a", interface, "ipv4", "vrrp", group)
            names, role = (("whole",), "witness") if group == "101" or case == "empty" else (
                (("whole", *VPOINTS), "witness") if case == "partial" else (VPOINTS, "subject"))
            append("fhrp_local", VRRP, subject, {"protocol": "vrrp", "node": "node:demo:a", "interface": interface, "group": group},
                ["node-a", "context", "vrrp"], "vrrp", "vrrp.txt", role, names)
    claims.sort(key=lambda row: (row["fact"], row["subject"]))
    identifiers, used = {}, []
    for claim in claims:
        registry = []
        for alias in claim["registry"]:
            _need(alias in aliases and aliases[alias] in records, "registry")
            key = aliases[alias]
            if key not in identifiers:
                identifiers[key] = "registry-" + str(len(identifiers))
                used.append({"id": identifiers[key], **records[key]})
            registry.append(identifiers[key])
        claim["registry"] = registry
    _need(len({(row["fact"], row["subject"]) for row in claims}) == len(claims), "population")
    return {"claims": claims, "registry_records": used}
