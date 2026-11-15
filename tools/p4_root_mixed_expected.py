"""Exact expected bytes for nine original synthetic fixtures only; no admission, origin or general network truth authority."""
import json
from hashlib import sha256

from tools.p4_root_mixed_evidence import evidence_tables
from tools.p4_root_mixed_leaves import claim_leaves

KINDS = ("stp_port_vlan", "etherchannel_group", "fhrp_local")
SUBJECTS = {
    "tree": "stp_port_vlan:730a08c860ce02743eb02951a8c9a75370a039c5ae83b8ad9b0ee3553eb90243",
    "channel": "etherchannel_group:06853b77bf2a03be0230d37e33731556eaeebdf0e3e24eff3f54ecec73f016ae",
    "a0": "fhrp_local:6640e29d545e42f9ab809e36ecc78cd168f4149315233b14db0a1ff17b5f6586",
    "a1": "fhrp_local:9571375d26c1482c9949415d8798530966b1998149f21a257063b75f51b7a6bf",
    "a2": "fhrp_local:78d7dee64540e9430b1835f8f78fcc93947dab37a71a33c2844f3d7c9dc761cd",
    "a3": "fhrp_local:5a3afb12a2193b1ef572f1fadfcab3bcecfaa0673609a1ff62a0a9f43984f9b8",
    "b0": "fhrp_local:3fb6edd325995a73e3591eed61239967d8c672609c7c860288e2be364b967841",
    "v0": "fhrp_local:0c8773de1be6aa4a4bb56384c78eaacb9ca1cfc3c4f894a4ad8d5eaf9640e9b8",
    "v1": "fhrp_local:18802deae4f5a4e68b1e49ab5abc5ce4b4892adc3c35f506f60f2f165b4237e0",
}
HSRP = (("a0", "a", "Vl20", "0", "Init", "2"), ("a1", "a", "Vl10", "1", "Active", "1"),
    ("a2", "a", "BD3329", "129", "Standby", "2"), ("a3", "a", "Vl99", "2", None, None), ("b0", "b", "Vl30", "2", None, None))


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError("p4_root_mixed_expected_" + code)


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _known(value: bool | int | str, basis: str, raw: str | None) -> dict[str, object]:
    return {"state": "known", "basis": basis, "value": value, "raw": raw}


def _unknown(reason, detail, node, operation, params, resolves, reruns, unprintable=()):
    return {"state": "unknown", "reason": reason, "detail": detail, "candidates": (), "next_evidence": [
        {"node": node, "operation": operation, "params": params, "resolves": resolves, "reruns": reruns,
            "after_s": None, "unprintable": unprintable}]}


def _states(case):
    states = {}
    def add(alias, fact, value):
        key = (fact, SUBJECTS[alias])
        _need(key not in states, "population")
        states[key] = value
    if case != "only_vrrp":
        both_roots = ("l2.stp.reported_root_mac", "l2.stp.reported_root_priority")
        for suffix, value, raw, detail in (("root_guard", False, "disabled", "stp_root_guard_unresolved"),
            ("reported_role", "designated", "designated", "stp_reported_role_unresolved"),
            ("reported_root_priority", 0, "0", "stp_reported_root_unresolved"),
            ("reported_root_mac", "aBcD.EF01.2345", "aBcD.EF01.2345", "stp_reported_root_unresolved")):
            fact = "l2.stp." + suffix
            frame = _unknown("not_collected", detail, "node:demo:a", "iosxe.show_spanning_tree_interface_detail",
                (("port", "Gi1/0/1"),), both_roots if suffix in ("reported_root_mac", "reported_root_priority") else (fact,),
                ("l2.stp/parse_root_guard",)) if case == "none" else _known(value, "observed", raw)
            add("tree", fact, frame)
        for suffix, value, basis, raw, detail in (("reported_protocol", "lacp", "observed", "LACP", "etherchannel_protocol_unresolved"),
            ("reported_member_tokens", "Gi1/0/1(P)", "derived", None, "etherchannel_member_tokens_unresolved")):
            fact = "l2.etherchannel." + suffix
            frame = _unknown("not_collected", detail, "node:demo:b", "iosxe.show_etherchannel_summary", (),
                (fact,), ("l2.etherchannel/parse_protocol",)) if case == "none" else _known(value, basis, raw)
            add("channel", fact, frame)
        for alias, node, interface, group, state, version in HSRP:
            for suffix, raw, operation, step, detail, unprintable in (
                ("reported_state", state, "iosxe.show_standby_brief", "l3.fhrp/parse_hsrp_brief", "hsrp_state_unresolved", ()),
                ("reported_protocol_version", version, "iosxe.show_standby_all", "l3.fhrp/parse_hsrp_all_version",
                    "hsrp_version_unresolved", ("explicit_reported_protocol_version",))):
                fact = "l3.fhrp." + suffix
                missing = case == "none" or node == "b" or suffix == "reported_protocol_version" and case in ("no_all_capture", "no_all_target")
                if missing or raw is None:
                    frame = _unknown("not_collected" if missing else "subject_absent_from_capture", detail, "node:demo:" + node,
                        operation, (("group", group), ("interface", interface)), (fact,), (step,), unprintable)
                else:
                    frame = _known(raw.lower() if suffix == "reported_state" else raw, "observed", raw)
                add(alias, fact, frame)
    if case != "zero_vrrp":
        for alias, interface, group in (("v0", "Vlan61", "100"), ("v1", "Vl61", "101")):
            reason = ("not_collected" if case in ("none", "cold_vrrp") else "empty_unregistered" if case == "empty"
                else "parse_partial" if case == "partial" else "subject_absent_from_capture" if alias == "v1" else None)
            fact = "l3.fhrp.reported_vrrp_state"
            frame = _known("backup", "observed", "Backup") if reason is None else _unknown(reason, "vrrp_state_unresolved",
                "node:demo:a", "iosxe.show_vrrp", (("group", group), ("interface", interface)), (fact,), ("l3.fhrp/parse_vrrp",))
            add(alias, fact, frame)
    return states


def expected_bundle(case: str, members: dict[str, bytes], registration_sha256: str) -> dict[str, bytes]:
    evidence = evidence_tables(case, members, registration_sha256)
    custody = claim_leaves(case, members, registration_sha256)
    states = _states(case)
    claims = custody["claims"]
    _need(all(set(row) == {"kind", "fact", "subject", "local", "registry", "evidence"} for row in claims)
        and len(claims) == len(states) and {(row["fact"], row["subject"]) for row in claims} == set(states), "population")
    counts = (0, 0, 0, 2) if case == "only_vrrp" else (1, 1, 5, 0) if case == "zero_vrrp" else (1, 1, 5, 2)
    header = {"schema": "atlas-brain.p4-root-mixed-observations/1", "semantic_group": "declared_synthetic",
        "scope": "observations_only", "qualification": "synthetic_observations_only", "checks": "not_implemented",
        "group": "demo", "context": "round", "registration_sha256": registration_sha256,
        "root_scope": "local_reported_priority_and_mac_not_intended_root",
        "denominator": {name: {"kind": kind, "declared": count} for name, kind, count in zip(
            ("stp", "etherchannel", "hsrp", "vrrp"), (*KINDS, "fhrp_local"), counts, strict=True)},
        "raws": evidence["raws"], "registries": evidence["registries"], "captures": evidence["captures"],
        "registry_records": custody["registry_records"]}
    rows = {kind: [] for kind in KINDS}
    for claim in claims:
        fact, subject = claim["fact"], claim["subject"]
        kind = "stp_port_vlan" if fact.startswith("l2.stp.") else "etherchannel_group" if fact.startswith("l2.etherchannel.") else "fhrp_local"
        _need(claim["kind"] == kind, "population")
        rows[kind].append({"fact": fact, "subject": subject, "local": claim["local"], "value": states[fact, subject],
            "registry": claim["registry"], "evidence": claim["evidence"]})
    files = {"result.json": _json(header)}
    for kind in KINDS:
        files[f"facts/{kind}.jsonl"] = b"".join(_json(row) + b"\n" for row in sorted(rows[kind], key=lambda row: (row["subject"], row["fact"])))
    files["MANIFEST.sha256"] = "".join(f"{sha256(files[name]).hexdigest()}  {name}\n" for name in sorted(files)).encode("utf-8")
    return {name: files[name] for name in sorted(files)}
