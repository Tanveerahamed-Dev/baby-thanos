"""Literal original-fixture custody goldens and real report projection; values and Needs remain outside scope."""
import json
from copy import deepcopy
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import Budgets
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS
from atlas_brain.runner.p4_root_mixed_report import analyse_root_mixed_folder
from tools import p4_root_mixed_cases as cases
from tools import p4_root_mixed_leaves as oracle
from tools.p4_root_mixed_evidence import evidence_tables

MODES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all_capture", "no_all_target", "zero_vrrp")
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
ORDER = ("node-b", "context", "channel", "node-a", "tree", "brief-b", "all-b", "brief-a", "all-a", "vrrp")
VPOINTS = ("interface", "heading", "group", "state_line", "state", "vip_line", "vip", "master_down")
HSPEC = (("a0", "a", "Vl20", "0", 0), ("a1", "a", "Vl10", "1", 1),
    ("a2", "a", "BD3329", "129", 2), ("a3", "a", "Vl99", "2", None), ("b0", "b", "Vl30", "2", None))


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(raw):
    return sha256(raw).hexdigest()


@pytest.fixture
def registration():
    compiled = compile_packs(DECLARATIONS)
    assert sum(len(pack.facts) for pack in DECLARATIONS) == 9 and len(compiled.operations) == 5
    assert compiled.registration_sha256 == digest(compiled.registration_bytes)
    return compiled.registration_sha256


def expected(mode, members, registration):
    tables = evidence_tables(mode, members, registration)
    p2, p4 = digest(members["p2.json"]), digest(members["p4.json"])
    base, side = (json.loads(members[path]) for path in ("p2.json", "p4.json"))
    keys = {"context": ("synthetic_p4.context", "round", p4, "/context")}
    keys.update({f"node-{row['id']}": ("synthetic_p2.nodes", row["id"], p2, f"/nodes/{i}") for i, row in enumerate(base["nodes"])})
    keys.update({row["id"]: ("synthetic_p4.targets", row["id"], p4, f"/targets/{i}") for i, row in enumerate(side["targets"])})
    by_key = {(row["table"], row["row_id"], row["table_sha256"], row["pointer"]): row for row in tables["registry_catalogue"]}
    order = ("node-a", "context", "vrrp") if mode == "only_vrrp" else tuple(alias for alias in ORDER
        if not (mode == "no_all_target" and alias in ("all-a", "all-b")) and not (mode == "zero_vrrp" and alias == "vrrp"))
    ordinal = {alias: f"registry-{index}" for index, alias in enumerate(order)}
    captures = {row["path"]: "cap:" + digest(encoded(("atlas-brain.synthetic-p4/1", p4, p2, "round",
        row["target"], row["path"], digest(members[row["path"]]), registration))) for row in side["captures"]}
    claims = []
    def add(alias, kind, fact, local, registry, path, role, names):
        refs = [] if path is None or path not in captures else [{"type": "capture", "layer": "p4", "capture": captures[path],
            "role": role, **deepcopy(tables["anchors"][path][name])} for name in names]
        claims.append({"kind": kind, "fact": fact, "subject": SUBJECTS[alias], "local": local,
            "registry": [ordinal[item] for item in registry], "evidence": refs})
    if mode != "only_vrrp":
        for fact, names in (("root_guard", ("guard_token", "guard", "port", "vlan", "header")),
            ("reported_role", ("header", "port", "vlan", "role", "state")),
            ("reported_root_mac", ("header", "port", "vlan", "root", "priority", "mac")),
            ("reported_root_priority", ("header", "port", "vlan", "root", "priority", "mac"))):
            add("tree", "stp_port_vlan", "l2.stp." + fact, {"protocol": "stp", "node": "node:demo:a", "port": "Gi1/0/1", "vlan": 1},
                ["node-a", "context", "tree"], "tree.txt", "subject", names)
        for fact, names in (("reported_protocol", ("group", "protocol", "row")),
            ("reported_member_tokens", ("group", "row", "channel", "port", "member", "flag"))):
            add("channel", "etherchannel_group", "l2.etherchannel." + fact,
                {"protocol": "etherchannel", "node": "node:demo:b", "group": "1"}, ["node-b", "context", "channel"], "channel.txt", "subject", names)
        for alias, node, interface, group, index in HSPEC:
            local = {"protocol": "hsrp", "node": "node:demo:" + node, "interface": interface, "group": group}
            for fact, path in (("reported_state", "brief.txt"), ("reported_protocol_version", "all.txt")):
                registry = ["node-" + node, "context", "brief-" + node]
                if fact == "reported_protocol_version" and mode != "no_all_target":
                    registry.append("all-" + node)
                if index is None:
                    names, role = ("whole",), "witness"
                elif fact == "reported_protocol_version":
                    names, role = tuple(f"{index}." + name for name in
                        ("interface", "heading", "group", "version", "vip_line", "vip", "group_name")), "subject"
                else:
                    suffixes = {0: ("interface", "row", "group", "state", "vip"),
                        1: ("interface", "row", "group", "state", "standby", "vip"), 2: ("interface", "row", "group", "state", "active", "vip")}
                    names, role = tuple(f"{index}." + name for name in suffixes[index]), "subject"
                add(alias, "fhrp_local", "l3.fhrp." + fact, {**local}, registry, path if node == "a" else None, role, names)
    if mode != "zero_vrrp":
        for alias, interface, group in (("v0", "Vlan61", "100"), ("v1", "Vl61", "101")):
            names, role = VPOINTS, "subject"
            if alias == "v1" or mode == "empty":
                names, role = ("whole",), "witness"
            elif mode == "partial":
                names, role = ("whole", *VPOINTS), "witness"
            add(alias, "fhrp_local", "l3.fhrp.reported_vrrp_state",
                {"protocol": "vrrp", "node": "node:demo:a", "interface": interface, "group": group},
                ["node-a", "context", "vrrp"], "vrrp.txt", role, names)
    return {"claims": sorted(claims, key=lambda row: (row["fact"], row["subject"])),
        "registry_records": [{"id": ordinal[alias], **by_key[keys[alias]]} for alias in order]}


def project(files):
    claims = []
    for path, raw in files.items():
        if not path.startswith("facts/"):
            continue
        kind = path.removeprefix("facts/").removesuffix(".jsonl")
        rows = [json.loads(line) for line in raw.splitlines()]
        assert [(row["subject"], row["fact"]) for row in rows] == sorted((row["subject"], row["fact"]) for row in rows)
        for row in rows:
            assert set(row) == {"fact", "subject", "local", "value", "registry", "evidence"}
            claims.append({"kind": kind, **{key: value for key, value in row.items() if key != "value"}})
    return {"claims": sorted(claims, key=lambda row: (row["fact"], row["subject"])),
        "registry_records": json.loads(files["result.json"])["registry_records"]}


@pytest.mark.parametrize("mode", MODES)
def test_nine_literal_subject_scope_order_and_first_use_goldens_match_real_report_custody_only(tmp_path, mode, registration):
    inputs = cases.members(mode)
    original = deepcopy(inputs)
    wanted = expected(mode, inputs, registration)
    actual = oracle.claim_leaves(mode, inputs, registration)
    assert encoded(actual) == encoded(wanted) and inputs == original
    assert all(set(row) == {"kind", "fact", "subject", "local", "registry", "evidence"} for row in actual["claims"])
    assert encoded(actual) == encoded(oracle.claim_leaves(mode, dict(reversed(inputs.items())), registration))
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)
    files = analyse_root_mixed_folder(tmp_path, Budgets(1000000, 1000000, 128))
    assert encoded(project(files)) == encoded(wanted)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == original


@pytest.mark.parametrize("plant", ("subject", "schema", "node", "row_donor", "rehashed_span", "role", "scope",
    "leaf_order", "registry_order", "duplicate", "omission", "ordinal", "record_order", "canonical"))
def test_independent_custody_comparison_refuses_validly_rehashed_wrong_subject_rows_roles_orders_and_ids(plant, registration):
    inputs = cases.members("normal")
    value = oracle.claim_leaves("normal", inputs, registration)
    wanted = expected("normal", inputs, registration)
    assert encoded(value) == encoded(wanted)
    first = value["claims"][0]
    if plant == "subject":
        first["subject"] += "0"
    elif plant in ("schema", "node"):
        row = next(row for row in value["claims"] if row["subject"] == SUBJECTS["a1"])
        node = "node:demo:b" if plant == "node" else "node:demo:a"
        row["subject"] = "fhrp_local:" + digest(encoded(("atlas-brain.vrrp-local/1" if plant == "schema" else "atlas-brain.fhrp-local/1",
            "round", node, "Vl10", "ipv4", "vrrp" if plant == "schema" else "hsrp", "1")))
        row["local"]["node"] = node
    elif plant == "row_donor":
        target = next(row for row in value["claims"] if row["subject"] == SUBJECTS["a1"] and row["fact"] == "l3.fhrp.reported_state")
        donor = next(row for row in value["claims"] if row["subject"] == SUBJECTS["a2"] and row["fact"] == target["fact"])
        target["evidence"] = deepcopy(donor["evidence"])
    elif plant == "rehashed_span":
        row = next(row for row in value["claims"] if row["fact"] == "l2.stp.reported_role")
        point = row["evidence"][0]
        point["locator"]["end"] += 1
        point["excerpt_sha256"] = digest(inputs["tree.txt"][point["locator"]["start"]:point["locator"]["end"]])
    elif plant == "role":
        first["evidence"][0]["role"] = "witness"
    elif plant == "scope":
        first["evidence"][0]["layer"] = "p2"
    elif plant == "leaf_order":
        first["evidence"].reverse()
    elif plant == "registry_order":
        first["registry"].reverse()
    elif plant == "duplicate":
        first["evidence"].append(deepcopy(first["evidence"][0]))
    elif plant == "omission":
        first["evidence"].pop()
    elif plant == "ordinal":
        renamed = {row["id"]: f"registry-{index + 1}" for index, row in enumerate(value["registry_records"])}
        for row in value["registry_records"]:
            row["id"] = renamed[row["id"]]
        for row in value["claims"]:
            row["registry"] = [renamed[item] for item in row["registry"]]
    elif plant == "record_order":
        value["registry_records"].reverse()
    else:
        value["registry_records"][0]["canonical"] = value["registry_records"][-1]["canonical"]
    assert encoded(value) != encoded(wanted)


@pytest.mark.parametrize("mode", ("none", "empty", "partial", "no_all_target"))
def test_special_modes_reject_metadata_donation_empty_spans_partial_whole_omission_and_missing_vrrp(mode, registration):
    inputs = cases.members(mode)
    value = oracle.claim_leaves(mode, inputs, registration)
    wanted = expected(mode, inputs, registration)
    assert encoded(value) == encoded(wanted)
    row = next(row for row in value["claims"] if row["subject"] == SUBJECTS["v0"])
    if mode == "none":
        row["evidence"] = deepcopy(evidence_tables(mode, inputs, registration)["captures"][0]["metadata"]["integrity_evidence"])
    elif mode == "empty":
        row["evidence"][0]["locator"] = {"kind": "bytes", "start": 0, "end": 0}
    elif mode == "partial":
        row["evidence"].pop(0)
    else:
        value["claims"] = [row for row in value["claims"] if row["subject"] != SUBJECTS["v1"]]
    assert encoded(value) != encoded(wanted)


@pytest.mark.parametrize("plant", ("node", "owner", "context", "raw", "read_scope", "metadata_scope"))
def test_expected_data_helpers_do_not_bypass_literal_capture_scope_closure(monkeypatch, plant, registration):
    inputs = cases.members("normal")
    assert encoded(oracle.claim_leaves("normal", inputs, registration)) == encoded(expected("normal", inputs, registration))
    def corrupted(*args):
        value = evidence_tables(*args)
        row = next(row for row in value["captures"] if row["layer"] == "p4" and row["path"] == "tree.txt")
        if plant == "metadata_scope":
            row["metadata"]["scope"]["context"] = "round"
        else:
            row[plant] = "node:demo:b" if plant == "node" else "full_evidenced" if plant == "read_scope" else "other"
        return value
    monkeypatch.setattr(oracle, "evidence_tables", corrupted)
    with pytest.raises(ValueError, match="^p4_root_mixed_leaves_scope$"):
        oracle.claim_leaves("normal", inputs, registration)


def test_results_have_no_cross_case_or_returned_object_cache_authority(registration):
    for mode in reversed(MODES):
        inputs = cases.members(mode)
        first, second = oracle.claim_leaves(mode, inputs, registration), oracle.claim_leaves(mode, inputs, registration)
        assert encoded(first) == encoded(second) == encoded(expected(mode, inputs, registration))
        first["registry_records"][0]["canonical"] = "00"
        first["claims"][0]["local"]["node"] = "caller mutation"
        assert encoded(second) == encoded(oracle.claim_leaves(mode, inputs, registration))


@pytest.mark.parametrize("plant", ("table", "row_id", "table_sha256", "pointer", "duplicate"))
def test_registry_joins_require_every_full_reference_coordinate_and_uniqueness(monkeypatch, plant, registration):
    inputs = cases.members("normal")
    assert encoded(oracle.claim_leaves("normal", inputs, registration)) == encoded(expected("normal", inputs, registration))
    def corrupted(*args):
        value = evidence_tables(*args)
        row = next(row for row in value["registry_catalogue"] if row["table"] == "synthetic_p2.nodes" and row["row_id"] == "a")
        if plant == "duplicate":
            value["registry_catalogue"].append(deepcopy(row))
        else:
            row[plant] = "0" * 64 if plant == "table_sha256" else "other"
        return value
    monkeypatch.setattr(oracle, "evidence_tables", corrupted)
    with pytest.raises(ValueError, match="^p4_root_mixed_leaves_registry$"):
        oracle.claim_leaves("normal", inputs, registration)
