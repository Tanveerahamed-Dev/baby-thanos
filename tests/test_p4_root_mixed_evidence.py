"""Independent fixture-wire and anchor oracles; no runtime report or semantic acceptance claim."""
import json
from copy import deepcopy
from enum import StrEnum
from hashlib import sha256

import pytest

from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS
from tools import p4_root_mixed_cases as cases
from tools import p4_root_mixed_evidence as oracle

MODES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all_capture", "no_all_target", "zero_vrrp")
FIXTURES = {
    "normal": ("9f43a912847610c462170f60376edb9297bc5d2c43d6926fd75bef3b8129ffc9", 8),
    "none": ("04891f92b9adfeb49f57c6f8d8921643581a61ef3b3f2a8cf75e483db34d9959", 3),
    "cold_vrrp": ("26e818357a02b58587766e46cc18aec3d11e501431a4d206ca55dcc6e8ea434c", 7),
    "only_vrrp": ("b353aca6d2f2e7f799da3da6a44776e49693e9d80ccea2c9d1aadf790662aa28", 4),
    "empty": ("e0ede30fee5a75d8d2dcb08880032e8d262ec30f3d4ecc650a32ca916996c47e", 8),
    "partial": ("6cf1958ba44ef49bc0a4e64ff3c52a5ab628f5dd62a75770016511b95bd66c26", 8),
    "no_all_capture": ("04b43cfc93584031a71b18acbed5da7137e5ce7f91efac1549240066272b7b23", 7),
    "no_all_target": ("f7f39b1342a6f9d5be2475c9b3dae7ae8f4e9fa9547c6df556b2065b5b5b4e2d", 7),
    "zero_vrrp": ("be9ac768c2b2eb8bc211e39c1cbb2c6d8cd51cc155520e2635e828e345ae1786", 7),
}
BASE = "f18480e532632f1dfca73b36dc310c9520f6300641c1b44f017d5cfee48b6cf6"
BINDINGS = {
    "iosxe.show_standby_brief": ("l3.fhrp/parse_hsrp_brief", "show standby brief"),
    "iosxe.show_standby_all": ("l3.fhrp/parse_hsrp_all_version", "show standby all"),
    "iosxe.show_spanning_tree_interface_detail": ("l2.stp/parse_root_guard", "show spanning-tree interface Gi1/0/1 detail"),
    "iosxe.show_etherchannel_summary": ("l2.etherchannel/parse_protocol", "show etherchannel summary"),
    "iosxe.show_vrrp": ("l3.fhrp/parse_vrrp", "show vrrp")}
FACTS = {"l2.stp.root_guard", "l2.stp.reported_role", "l2.stp.reported_root_priority", "l2.stp.reported_root_mac",
    "l2.etherchannel.reported_protocol", "l2.etherchannel.reported_member_tokens",
    "l3.fhrp.reported_state", "l3.fhrp.reported_protocol_version", "l3.fhrp.reported_vrrp_state"}


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(raw):
    return sha256(raw).hexdigest()


@pytest.fixture
def registration():
    compiled = compile_packs(DECLARATIONS)
    assert sum(len(pack.facts) for pack in DECLARATIONS) == 9
    assert {fact.id for pack in DECLARATIONS for fact in pack.facts} == FACTS
    assert {row.operation: row.step for row in compiled.operations} == {op: spec[0] for op, spec in BINDINGS.items()}
    assert len(compiled.operations) == 5 and compiled.registration_sha256 == digest(compiled.registration_bytes)
    return compiled.registration_sha256


def metadata(identifier, layer, node, raw):
    ref = {"type": "capture", "layer": layer, "capture": identifier, "role": "subject",
        "locator": {"kind": "whole_capture"}, "excerpt_sha256": digest(raw)}
    return {"channel": "cli", "scope": dict(node=node, vrf=None, context=None, vdc=None, tenant=None, afi=None, instance=None, plane="exec"),
        "collected_utc": dict(state="unknown", reason="as_of_missing", detail="no_collector_time",
            candidates=[], next_evidence=[], evidence=[ref]), "error": None,
        "integrity_evidence": [deepcopy(ref)], "read_scope_evidence": [], "envelope": None}


def anchors(members):
    result = {}
    def add(path, name, number, needle=None, column=None):
        lines = members[path].splitlines(keepends=True)
        line = lines[number].removesuffix(b"\n")
        start = sum(map(len, lines[:number]))
        if needle is not None:
            offset = line.index(needle) if column is None else column
            assert line[offset:offset + len(needle)] == needle
            start, end = start + offset, start + offset + len(needle)
        else:
            end = start + len(line)
        result[path][name] = {"locator": {"kind": "bytes", "start": start, "end": end},
            "excerpt_sha256": digest(members[path][start:end])}
    for path, raw in members.items():
        if path.endswith(".txt"):
            result[path] = {"whole": {"locator": {"kind": "whole_capture"}, "excerpt_sha256": digest(raw)}}
    if "tree.txt" in members:
        for name, line, token, column in (("header", 0, None, None), ("port", 0, b"Gi1/0/1", None),
            ("vlan", 0, b"0001", None), ("role", 0, b"designated", None), ("state", 0, b"forwarding", None),
            ("guard", 1, None, None), ("guard_token", 1, b"disabled", None), ("root", 2, None, None),
            ("priority", 2, b"0", len(b"   Designated root has priority ")), ("mac", 2, b"aBcD.EF01.2345", None)):
            add("tree.txt", name, line, token, column)
    if "channel.txt" in members:
        for name, token, column in (("row", None, None), ("group", b"1", 0), ("channel", b"Po1", None),
            ("protocol", b"LACP", None), ("member", b"Gi1/0/1(P)", None), ("port", b"Gi1/0/1", None), ("flag", b"P", 23)):
            add("channel.txt", name, 4, token, column)
    if "brief.txt" in members:
        for row in range(3):
            add("brief.txt", f"{row}.row", row + 3)
            line = members["brief.txt"].splitlines()[row + 3]
            words = line.split()
            positions = (0, 1, 3, 4, 5, 6) if row == 0 else (0, 1, 4, 5, 6, 7)
            cursor = 0
            for index, word in enumerate(words):
                column = line.index(word, cursor)
                if index in positions:
                    name = ("interface", "group", "state", "active", "standby", "vip")[positions.index(index)]
                    add("brief.txt", f"{row}.{name}", row + 3, word, column)
                cursor = column + len(word)
    if "all.txt" in members:
        for row, (interface, group, version) in enumerate(((b"Vl20", b"0", b"2"), (b"Vl10", b"1", b"1"), (b"BD3329", b"129", b"2"))):
            heading = members["all.txt"].splitlines()[row * 11]
            for name, token, column in (("heading", None, None), ("interface", interface, 0),
                ("group", group, heading.index(b"Group ") + 6), ("version", version, heading.index(b"version ") + 8)):
                add("all.txt", f"{row}.{name}", row * 11, token, column)
            add("all.txt", f"{row}.vip_line", row * 11 + 2)
            add("all.txt", f"{row}.vip", row * 11 + 2, b"192.0.2.1")
            add("all.txt", f"{row}.group_name", row * 11 + 10)
    if members.get("vrrp.txt"):
        for name, line, token in (("heading", 0, None), ("interface", 0, b"Vlan61"), ("group", 0, b"100"),
            ("state_line", 1, None), ("state", 1, b"Backup"), ("vip_line", 2, None),
            ("vip", 2, b"198.51.100.41"), ("master_down", 10, None)):
            add("vrrp.txt", name, line, token)
    return result


def expected(mode, members, registration):
    assert digest(members["p2.json"]) == BASE and digest(members["p4.json"]) == FIXTURES[mode][0]
    assert len(members) == FIXTURES[mode][1]
    base, side = (json.loads(members[name]) for name in ("p2.json", "p4.json"))
    assert encoded(base) == members["p2.json"] and encoded(side) == members["p4.json"]
    p2, p4 = BASE, FIXTURES[mode][0]
    identifier = "cap:" + digest(encoded(("atlas-brain.synthetic-p2/1", "demo", p2, "discovery.txt", "a",
        "iosxe.show_cdp_neighbors_detail", digest(members["discovery.txt"]))))
    captures = [(identifier, "p2", "a", "iosxe.show_cdp_neighbors_detail", "show cdp neighbors detail", "discovery.txt", None)]
    targets = {row["id"]: row for row in side["targets"]}
    extra = []
    for member in side["captures"]:
        identifier = "cap:" + digest(encoded(("atlas-brain.synthetic-p4/1", p4, p2, "round", member["target"],
            member["path"], digest(members[member["path"]]), registration)))
        target = targets[member["target"]]
        extra.append((identifier, "p4", target["node"], target["operation"], BINDINGS[target["operation"]][1], member["path"], target))
    captures += sorted(extra)
    wire = []
    for identifier, layer, node, operation, command, path, target in captures:
        value = dict(layer=layer, id=identifier, raw=digest(members[path]), node="node:demo:" + node,
            operation=operation, rendered=command, codec="utf-8", integrity="empty" if path == "vrrp.txt" and mode == "empty" else "complete",
            read_scope="unknown", view="unknown", metadata_recorded=False, metadata=metadata(identifier, layer, "node:demo:" + node, members[path]))
        if target is not None:
            value.update(path=path, target=target["id"], owner=BINDINGS[operation][0], context="round",
                registration_sha256=registration, parse_quality="partial" if path == "vrrp.txt" and mode in ("empty", "partial") else "complete",
                params=target["params"])
        wire.append(value)
    catalogue = []
    for table, prefix, table_hash, rows in (("synthetic_p2.nodes", "nodes", p2, base["nodes"]),
        ("synthetic_p4.targets", "targets", p4, side["targets"])):
        for index, row in enumerate(rows):
            catalogue.append(dict(table=table, row_id=row["id"], table_sha256=table_hash, pointer=f"/{prefix}/{index}",
                raw=table_hash, encoding="hex", canonical=encoded(row).hex()))
    catalogue.append(dict(table="synthetic_p4.context", row_id="round", table_sha256=p4, pointer="/context",
        raw=p4, encoding="hex", canonical=encoded("round").hex()))
    blobs = {digest(raw): raw for raw in members.values()}
    return dict(raws=[dict(sha256=key, bytes=len(raw), encoding="hex", data=raw.hex()) for key, raw in sorted(blobs.items())],
        registries=[dict(layer="p2", raw=p2), dict(layer="p4", raw=p4)], captures=wire, registry_catalogue=catalogue,
        anchors=anchors(members), physical_inputs=dict(files=FIXTURES[mode][1], bytes=sum(map(len, members.values()))))


@pytest.mark.parametrize("mode", MODES)
def test_all_nine_original_fixtures_match_independent_complete_wire_id_metadata_catalogue_and_byte_anchors(mode, registration):
    inputs = cases.members(mode)
    pristine = deepcopy(inputs)
    actual = oracle.evidence_tables(mode, inputs, registration)
    assert encoded(actual) == encoded(expected(mode, inputs, registration))
    assert inputs == pristine and encoded(actual) == encoded(oracle.evidence_tables(mode, dict(reversed(inputs.items())), registration))
    again = oracle.evidence_tables(mode, inputs, registration)
    actual["captures"][0]["metadata"]["scope"]["context"] = "caller mutation"
    assert encoded(again) == encoded(expected(mode, inputs, registration))


@pytest.mark.parametrize("plant", ("raw", "rehashed_donor", "missing", "extra", "context", "id", "node", "operation",
    "target_order", "capture_order", "digest", "base_hash", "p2_order", "noncanonical", "case_census"))
def test_wrong_raws_rehashed_anchor_donors_registry_ids_order_canonical_bytes_and_case_labels_refuse(plant, registration):
    inputs = cases.members("normal")
    side = json.loads(inputs["p4.json"])
    if plant in ("raw", "rehashed_donor"):
        inputs["tree.txt"] = inputs["tree.txt"].replace(b"disabled", b"enabled")
        if plant == "rehashed_donor":
            next(row for row in side["captures"] if row["target"] == "tree")["sha256"] = digest(inputs["tree.txt"])
    elif plant == "missing":
        inputs.pop("tree.txt")
    elif plant == "extra":
        inputs["unlisted.txt"] = b"donor"
    elif plant in ("context", "base_hash"):
        side["context" if plant == "context" else "base_sha256"] = "other" if plant == "context" else "0" * 64
    elif plant in ("id", "node", "operation"):
        side["targets"][0][plant] = {"id": "other", "node": "b", "operation": "iosxe.show_vrrp"}[plant]
    elif plant == "target_order":
        side["targets"].reverse()
    elif plant == "capture_order":
        side["captures"].reverse()
    elif plant == "digest":
        side["captures"][0]["sha256"] = "0" * 64
    elif plant == "p2_order":
        base = json.loads(inputs["p2.json"])
        base["nodes"].reverse()
        inputs["p2.json"] = encoded(base)
        side["base_sha256"] = digest(inputs["p2.json"])
    inputs["p4.json"] = json.dumps(side, indent=2).encode() if plant == "noncanonical" else encoded(side)
    with pytest.raises(ValueError, match="^p4_root_mixed_evidence_(raw|members|registry)$"):
        oracle.evidence_tables("no_all_capture" if plant == "case_census" else "normal", inputs, registration)


@pytest.mark.parametrize("plant", ("raw", "digest", "id", "pointer", "canonical", "anchor_bounds", "newline",
    "layer", "owner", "context", "role", "unknown_scope", "false_int", "duplicate", "omission"))
def test_complete_independent_wire_comparison_detects_material_output_plants(plant, registration):
    inputs = cases.members("normal")
    value = oracle.evidence_tables("normal", inputs, registration)
    assert encoded(value) == encoded(expected("normal", inputs, registration))
    if plant in ("raw", "digest"):
        value["raws"][0]["data" if plant == "raw" else "sha256"] = "00"
    elif plant in ("pointer", "canonical"):
        value["registry_catalogue"][0][plant] = "/nodes/1" if plant == "pointer" else b"other".hex()
    elif plant in ("anchor_bounds", "newline"):
        point = value["anchors"]["tree.txt"]["header"]["locator"]
        point["end"] = 0 if plant == "anchor_bounds" else point["end"] + 1
    elif plant in ("id", "layer", "owner", "context"):
        value["captures"][1][plant] = "other"
    elif plant == "role":
        value["captures"][0]["metadata"]["integrity_evidence"][0]["role"] = "witness"
    elif plant == "unknown_scope":
        value["captures"][0]["read_scope"] = "full_evidenced"
    elif plant == "false_int":
        value["captures"][0]["metadata_recorded"] = 0
    elif plant == "duplicate":
        value["captures"].append(deepcopy(value["captures"][0]))
    else:
        value["registry_catalogue"].pop()
    assert encoded(value) != encoded(expected("normal", inputs, registration))


class Alias(StrEnum):
    NORMAL = "normal"


@pytest.mark.parametrize("case", ("unknown", "", None, False, [], Alias.NORMAL))
def test_unknown_nonplain_case_refuses_before_input_interpretation(case, registration):
    with pytest.raises(ValueError, match="^p4_root_mixed_evidence_case$"):
        oracle.evidence_tables(case, cases.members("normal"), registration)


@pytest.mark.parametrize("registration", ("", "A" * 64, "g" * 64, "0" * 63, None, False))
def test_registration_requires_plain_lowercase_full_sha(registration):
    with pytest.raises(ValueError, match="^p4_root_mixed_evidence_registration$"):
        oracle.evidence_tables("normal", cases.members("normal"), registration)
