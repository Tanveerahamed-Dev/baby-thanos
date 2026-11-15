"""Pin generated synthetic bytes and ordinary admission identities; no report or network truth oracle."""
import json
from enum import StrEnum
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p4_admission import admit_folder
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS
from tools import p4_root_mixed_cases as cases

MODES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial",
    "no_all_capture", "no_all_target", "zero_vrrp")
OPS = ("iosxe.show_standby_brief", "iosxe.show_standby_all", "iosxe.show_spanning_tree_interface_detail",
    "iosxe.show_etherchannel_summary", "iosxe.show_vrrp")
GROUPS = [["Vl20", "0"], ["Vl10", "1"], ["BD3329", "129"], ["Vl99", "2"]]
DISCOVERY = b"Device ID: fixture-b\n"
TREE = (b"Port 1 (Gi1/0/1) of VLAN0001 is designated forwarding\n"
    b"   Root guard is disabled on the port\n   Designated root has priority 0, address aBcD.EF01.2345\n")
CHANNEL = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
    b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")
BRIEF = (b"                     P indicates configured to preempt.\n                     |\n"
    b"Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
    b"Vl20        0    100   Init    unknown         unknown         203.0.113.1\n"
    b"Vl10        1    110 P Active  local           192.0.2.2       192.0.2.1\n"
    b"BD3329      129  90 P Standby 198.51.100.2    local           198.51.100.1\n")
DETAIL = (b"  State is Active\n  Virtual IP address is 192.0.2.1\n"
    b"  Active virtual MAC address is 0000.0000.0000 (MAC In Use)\n"
    b"    Local virtual MAC address is 0000.0000.0000 (v2 default)\n"
    b"  Hello time 3 sec, hold time 10 sec\n  Preemption enabled\n  Active router is local\n"
    b"  Standby router is 192.0.2.2, priority 100 (expires in 1.000 sec)\n"
    b"  Priority 100 (default 100)\n"
    b'  Group name is "synthetic-other-interface-99" (default)\n')
ALL_RAW = (b"Vl20 - Group 0 (version 2)\n" + DETAIL + b"Vl10 - Group 1 (version 1)\n" + DETAIL
    + b"BD3329 - Group 129 (version 2)\n" + DETAIL)
VRRP = (b"Vlan61 - Group 100\n  State is Backup\n  Virtual IP address is 198.51.100.41\n"
    b"  Virtual MAC address is 0011.2233.4455\n  Advertisement interval is 1.250 sec\n"
    b"  Preemption disabled\n  Priority is 109\n"
    b'  Authentication text "synthetic-lab"\n'
    b"  Master Router is 192.0.2.17, priority is 113\n"
    b"  Master Advertisement interval is 2.375 sec\n  Master Down interval is 9.125 sec\n")
RAW = {"discovery.txt": DISCOVERY, "tree.txt": TREE, "channel.txt": CHANNEL, "brief.txt": BRIEF,
    "all.txt": ALL_RAW, "vrrp.txt": VRRP}
TARGETS = (
    {"id": "brief-a", "node": "a", "operation": OPS[0], "params": {"groups": GROUPS}},
    {"id": "brief-b", "node": "b", "operation": OPS[0], "params": {"groups": [["Vl30", "2"]]}},
    {"id": "all-a", "node": "a", "operation": OPS[1], "params": {"groups": GROUPS}},
    {"id": "all-b", "node": "b", "operation": OPS[1], "params": {"groups": [["Vl30", "2"]]}},
    {"id": "tree", "node": "a", "operation": OPS[2], "params": {"port": "Gi1/0/1", "vlans": [1]}},
    {"id": "channel", "node": "b", "operation": OPS[3], "params": {"groups": ["1"], "ports": ["Gi1/0/1"]}},
    {"id": "vrrp", "node": "a", "operation": OPS[4], "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]}})
ALL_IDS = tuple(row["id"] for row in TARGETS)
CAPTURES = (("brief-a", "brief.txt"), ("all-a", "all.txt"), ("tree", "tree.txt"),
    ("channel", "channel.txt"), ("vrrp", "vrrp.txt"))
CENSUS = {
    "normal": (ALL_IDS, CAPTURES, (1, 1, 5, 2)),
    "none": (ALL_IDS, (), (1, 1, 5, 2)),
    "cold_vrrp": (ALL_IDS, CAPTURES[:4], (1, 1, 5, 2)),
    "only_vrrp": (("vrrp",), CAPTURES[4:], (0, 0, 0, 2)),
    "empty": (ALL_IDS, CAPTURES, (1, 1, 5, 2)),
    "partial": (ALL_IDS, CAPTURES, (1, 1, 5, 2)),
    "no_all_capture": (ALL_IDS, (CAPTURES[0], *CAPTURES[2:]), (1, 1, 5, 2)),
    "no_all_target": (("brief-a", "brief-b", "tree", "channel", "vrrp"),
        (CAPTURES[0], *CAPTURES[2:]), (1, 1, 5, 2)),
    "zero_vrrp": (ALL_IDS[:6], CAPTURES[:4], (1, 1, 5, 0))}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def expected(mode):
    ids, captured, _ = CENSUS[mode]
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": name, "discovery_id": "fixture-" + name, "ports": ["Gi1/0/1"]} for name in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
            "sha256": sha256(DISCOVERY).hexdigest()}]}
    files = {"p2.json": encoded(base), "discovery.txt": DISCOVERY,
        **{path: RAW[path] for _, path in captured}}
    if mode == "empty":
        files["vrrp.txt"] = b""
    elif mode == "partial":
        files["vrrp.txt"] = VRRP + b"unrecognized\n"
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "round",
        "base_sha256": sha256(files["p2.json"]).hexdigest(),
        "targets": [row for row in TARGETS if row["id"] in ids],
        "captures": [{"target": target, "path": path, "sha256": sha256(files[path]).hexdigest()} for target, path in captured]}
    return {**files, "p4.json": encoded(side)}


@pytest.mark.parametrize("mode", MODES)
def test_every_generated_member_is_an_exact_original_literal_or_registry_hash_transition(mode):
    actual, wanted = cases.members(mode), expected(mode)
    assert cases.CASES == MODES and actual == wanted
    assert all(type(name) is str and type(raw) is bytes for name, raw in actual.items())
    base, side = (json.loads(actual[name]) for name in ("p2.json", "p4.json"))
    assert actual["p2.json"] == encoded(base) and actual["p4.json"] == encoded(side)
    assert side["base_sha256"] == sha256(actual["p2.json"]).hexdigest()
    assert tuple(row["id"] for row in side["targets"]) == CENSUS[mode][0]
    assert tuple((row["target"], row["path"]) for row in side["captures"]) == CENSUS[mode][1]
    assert set(actual) == {"p2.json", "p4.json", "discovery.txt", *(row["path"] for row in side["captures"])}
    assert len(side["captures"]) == len({row["target"] for row in side["captures"]}) == len({row["path"] for row in side["captures"]})
    assert all(row["sha256"] == sha256(actual[row["path"]]).hexdigest() for row in side["captures"])
    assert actual["p2.json"] == cases.members("normal")["p2.json"]


@pytest.mark.parametrize("mode", MODES)
def test_ordinary_admission_pins_full_registration_ids_raws_refs_and_creation_order_invariance(tmp_path, mode):
    inputs = cases.members(mode)
    compiled = compile_packs(DECLARATIONS)
    registration = sha256(compiled.registration_bytes).hexdigest()
    assert compiled.registration_sha256 == registration and len(compiled.operations) == 5
    assert {fact.id for declaration in DECLARATIONS for fact in declaration.facts} == {
        "l2.stp.root_guard", "l2.stp.reported_role", "l2.stp.reported_root_priority", "l2.stp.reported_root_mac",
        "l2.etherchannel.reported_protocol", "l2.etherchannel.reported_member_tokens",
        "l3.fhrp.reported_state", "l3.fhrp.reported_protocol_version", "l3.fhrp.reported_vrrp_state"}
    signatures = []
    for reverse in (False, True):
        root = tmp_path / str(reverse)
        root.mkdir()
        for name in sorted(inputs, reverse=reverse):
            (root / name).write_bytes(inputs[name])
        assert {path.name: path.read_bytes() for path in root.iterdir()} == inputs
        envelope = admit_folder(root, Budgets(1000000, 1000000, 128), declarations=DECLARATIONS)
        side = json.loads(inputs["p4.json"])
        p2hash, p4hash = sha256(inputs["p2.json"]).hexdigest(), sha256(inputs["p4.json"]).hexdigest()
        assert envelope.registration_sha256 == registration and envelope.raw == inputs["p4.json"]
        assert tuple(node.id for node in envelope.base.nodes) == ("a", "b")
        assert tuple(node.key for node in envelope.base.nodes) == ("node:demo:a", "node:demo:b")
        for index, node in enumerate(envelope.base.nodes):
            ref, = node.declaration.evidence
            assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == ("synthetic_p2.nodes", node.id, p2hash, f"/nodes/{index}")
        assert len(envelope.base.captures) == 1
        discovery, = envelope.base.captures
        expected_discovery = "cap:" + sha256(encoded(("atlas-brain.synthetic-p2/1", "demo", p2hash,
            "discovery.txt", "a", "iosxe.show_cdp_neighbors_detail", sha256(DISCOVERY).hexdigest()))).hexdigest()
        assert discovery.id == expected_discovery and discovery.raw == DISCOVERY and discovery.source == "node:demo:a"
        assert tuple(target.id for target in envelope.targets) == tuple(sorted(CENSUS[mode][0]))
        targets = {target.id: target for target in envelope.targets}
        for target in envelope.targets:
            index, declared = next((index, row) for index, row in enumerate(side["targets"]) if row["id"] == target.id)
            assert target.node is envelope.base.nodes[0 if declared["node"] == "a" else 1]
            assert target.operation == declared["operation"] and target.params == encoded(declared["params"])
            ref, = target.declaration.evidence
            assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == ("synthetic_p4.targets", target.id, p4hash, f"/targets/{index}")
        ref, = envelope.declaration.evidence
        assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == ("synthetic_p4.context", "round", p4hash, "/context")
        assert tuple(member.path for member in envelope.captures) == tuple(sorted(path for _, path in CENSUS[mode][1]))
        identities = []
        for member in envelope.captures:
            target = targets[member.target.id]
            digest = sha256(inputs[member.path]).hexdigest()
            expected_id = "cap:" + sha256(encoded(("atlas-brain.synthetic-p4/1", p4hash, p2hash, "round",
                target.id, member.path, digest, registration))).hexdigest()
            assert member.id == expected_id and member.target is target
            assert member.raw == inputs[member.path] and member.sha256 == digest
            identities.append((member.id, target.id, member.path, member.sha256))
        count = (
            sum(len(json.loads(target.params)["vlans"]) for target in envelope.targets if target.operation == OPS[2]),
            sum(len(json.loads(target.params)["groups"]) for target in envelope.targets if target.operation == OPS[3]),
            sum(len(json.loads(target.params)["groups"]) for target in envelope.targets if target.operation == OPS[0]),
            sum(len(json.loads(target.params)["groups"]) for target in envelope.targets if target.operation == OPS[4]))
        assert count == CENSUS[mode][2]
        assert {path.name: path.read_bytes() for path in root.iterdir()} == inputs
        signatures.append((envelope.registration_sha256, identities))
    assert signatures[0] == signatures[1]


def test_members_return_fresh_isolated_dictionaries_in_any_case_call_order():
    originals = {mode: expected(mode) for mode in MODES}
    for mode in reversed(MODES):
        first, second = cases.members(mode), cases.members(mode)
        assert first is not second and first == second == originals[mode]
        first["p2.json"] = b"changed"
        first.pop("discovery.txt")
        first["unlisted"] = b"caller mutation"
        assert second == originals[mode] and cases.members(mode) == originals[mode]


class Alias(StrEnum):
    NORMAL = "normal"


@pytest.mark.parametrize("mode", ["unknown", "", None, False, [], Alias.NORMAL])
def test_unknown_or_nonplain_case_names_are_refused(mode):
    with pytest.raises(ValueError, match="^p4_root_mixed_cases_case$"):
        cases.members(mode)
