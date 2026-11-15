"""Full five-file original-fixture comparison and re-manifested semantic plants; no general network acceptance."""
import json
from copy import deepcopy
from hashlib import sha256

import pytest

from atlas_brain.evidence.admission import Budgets
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS
from atlas_brain.runner.p4_root_mixed_report import analyse_root_mixed_folder
from tools import p4_root_mixed_cases as cases
from tools import p4_root_mixed_expected as oracle
from tools.p4_root_mixed_leaves import claim_leaves

KINDS = ("etherchannel_group", "fhrp_local", "stp_port_vlan")
NAMES = ("MANIFEST.sha256", *(f"facts/{kind}.jsonl" for kind in KINDS), "result.json")
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
H = ("Init", "Active", "Standby", "absent", "not_collected")
V = ("2", "1", "2", "absent", "not_collected")
R = ("Backup", "absent")
MATRIX = {
    "normal": ("present", "present", H, V, R),
    "none": ("not_collected", "not_collected", ("not_collected",) * 5, ("not_collected",) * 5, ("not_collected",) * 2),
    "cold_vrrp": ("present", "present", H, V, ("not_collected",) * 2),
    "only_vrrp": (None, None, None, None, R),
    "empty": ("present", "present", H, V, ("empty_unregistered",) * 2),
    "partial": ("present", "present", H, V, ("parse_partial",) * 2),
    "no_all_capture": ("present", "present", H, ("not_collected",) * 5, R),
    "no_all_target": ("present", "present", H, ("not_collected",) * 5, R),
    "zero_vrrp": ("present", "present", H, V, None)}
HSPEC = (("a0", "a", "Vl20", "0"), ("a1", "a", "Vl10", "1"), ("a2", "a", "BD3329", "129"),
    ("a3", "a", "Vl99", "2"), ("b0", "b", "Vl30", "2"))


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


@pytest.fixture
def registration():
    compiled = compile_packs(DECLARATIONS)
    assert sum(len(pack.facts) for pack in DECLARATIONS) == 9 and len(compiled.operations) == 5
    assert compiled.registration_sha256 == sha256(compiled.registration_bytes).hexdigest()
    return compiled.registration_sha256


def known(value, raw, basis="observed"):
    return {"state": "known", "basis": basis, "value": value, "raw": raw}


def unknown(reason, detail, node, operation, params, resolves, step, unprintable=()):
    return {"state": "unknown", "reason": "subject_absent_from_capture" if reason == "absent" else reason,
        "detail": detail, "candidates": [], "next_evidence": [{"node": node, "operation": operation,
            "params": params, "resolves": resolves, "reruns": [step], "after_s": None, "unprintable": unprintable}]}


def literal_frames(mode):
    tree, ec, state, version, vrrp = MATRIX[mode]
    result = {}
    if tree is not None:
        for suffix, value, raw, detail in (("root_guard", False, "disabled", "stp_root_guard_unresolved"),
            ("reported_role", "designated", "designated", "stp_reported_role_unresolved"),
            ("reported_root_priority", 0, "0", "stp_reported_root_unresolved"),
            ("reported_root_mac", "aBcD.EF01.2345", "aBcD.EF01.2345", "stp_reported_root_unresolved")):
            fact = "l2.stp." + suffix
            resolves = ["l2.stp.reported_root_mac", "l2.stp.reported_root_priority"] if suffix in (
                "reported_root_mac", "reported_root_priority") else [fact]
            result[fact, SUBJECTS["tree"]] = known(value, raw) if tree == "present" else unknown(tree, detail,
                "node:demo:a", "iosxe.show_spanning_tree_interface_detail", [["port", "Gi1/0/1"]], resolves, "l2.stp/parse_root_guard")
    if ec is not None:
        for suffix, value, raw, basis, detail in (("reported_protocol", "lacp", "LACP", "observed", "etherchannel_protocol_unresolved"),
            ("reported_member_tokens", "Gi1/0/1(P)", None, "derived", "etherchannel_member_tokens_unresolved")):
            fact = "l2.etherchannel." + suffix
            result[fact, SUBJECTS["channel"]] = known(value, raw, basis) if ec == "present" else unknown(ec, detail,
                "node:demo:b", "iosxe.show_etherchannel_summary", [], [fact], "l2.etherchannel/parse_protocol")
    for tokens, suffix, operation, step, detail, marker in (
        (state, "reported_state", "iosxe.show_standby_brief", "l3.fhrp/parse_hsrp_brief", "hsrp_state_unresolved", []),
        (version, "reported_protocol_version", "iosxe.show_standby_all", "l3.fhrp/parse_hsrp_all_version",
            "hsrp_version_unresolved", ["explicit_reported_protocol_version"])):
        if tokens is not None:
            for token, (alias, node, interface, group) in zip(tokens, HSPEC, strict=True):
                fact = "l3.fhrp." + suffix
                result[fact, SUBJECTS[alias]] = known(token.lower() if suffix == "reported_state" else token, token) if token in (
                    "Init", "Active", "Standby", "1", "2") else unknown(token, detail, "node:demo:" + node, operation,
                    [["group", group], ["interface", interface]], [fact], step, marker)
    if vrrp is not None:
        for token, (alias, interface, group) in zip(vrrp, (("v0", "Vlan61", "100"), ("v1", "Vl61", "101")), strict=True):
            fact = "l3.fhrp.reported_vrrp_state"
            result[fact, SUBJECTS[alias]] = known("backup", "Backup") if token == "Backup" else unknown(token,
                "vrrp_state_unresolved", "node:demo:a", "iosxe.show_vrrp", [["group", group], ["interface", interface]], [fact], "l3.fhrp/parse_vrrp")
    return result


def rows(files):
    return [json.loads(line) for kind in KINDS for line in files[f"facts/{kind}.jsonl"].splitlines()]


def manifest(files):
    return b"".join(sha256(files[name]).hexdigest().encode("ascii") + b"  " + name.encode("ascii") + b"\n"
        for name in sorted(files) if name != "MANIFEST.sha256")


def rerender(files, header, facts):
    files["result.json"] = encoded(header)
    for kind in KINDS:
        files[f"facts/{kind}.jsonl"] = b"".join(encoded(row) + b"\n" for row in facts[kind])
    files["MANIFEST.sha256"] = manifest(files)


@pytest.mark.parametrize("mode", tuple(MATRIX))
def test_all_nine_full_five_file_bytes_match_report_and_literal_complete_semantic_need_matrix(tmp_path, mode, registration):
    inputs = cases.members(mode)
    pristine = deepcopy(inputs)
    wanted = oracle.expected_bundle(mode, inputs, registration)
    assert tuple(wanted) == NAMES and all(type(raw) is bytes for raw in wanted.values())
    assert wanted["MANIFEST.sha256"] == manifest(wanted)
    values = rows(wanted)
    assert len(values) == len({(row["fact"], row["subject"]) for row in values})
    assert encoded({f"{row['fact']}|{row['subject']}": row["value"] for row in values}) == encoded(
        {f"{fact}|{subject}": value for (fact, subject), value in literal_frames(mode).items()})
    assert all(set(row) == {"fact", "subject", "local", "value", "registry", "evidence"} for row in values)
    header = json.loads(wanted["result.json"])
    assert {key: header[key] for key in ("schema", "semantic_group", "scope", "qualification", "checks", "group", "context",
        "registration_sha256", "root_scope")} == {"schema": "atlas-brain.p4-root-mixed-observations/1",
        "semantic_group": "declared_synthetic", "scope": "observations_only", "qualification": "synthetic_observations_only",
        "checks": "not_implemented", "group": "demo", "context": "round", "registration_sha256": registration,
        "root_scope": "local_reported_priority_and_mac_not_intended_root"}
    counts = (0, 0, 0, 2) if mode == "only_vrrp" else (1, 1, 5, 0) if mode == "zero_vrrp" else (1, 1, 5, 2)
    assert header["denominator"] == {name: {"kind": kind, "declared": count} for name, kind, count in zip(
        ("stp", "etherchannel", "hsrp", "vrrp"), ("stp_port_vlan", "etherchannel_group", "fhrp_local", "fhrp_local"), counts, strict=True)}
    assert not {"registry_catalogue", "anchors", "physical_inputs"} & set(header)
    for kind in KINDS:
        data = wanted[f"facts/{kind}.jsonl"]
        keys = [(row["subject"], row["fact"]) for row in map(json.loads, data.splitlines())]
        assert keys == sorted(keys) and (not data or data.endswith(b"\n"))
    if mode == "only_vrrp":
        assert wanted["facts/stp_port_vlan.jsonl"] == wanted["facts/etherchannel_group.jsonl"] == b""
    assert wanted == oracle.expected_bundle(mode, dict(reversed(inputs.items())), registration) and inputs == pristine
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)
    assert analyse_root_mixed_folder(tmp_path, Budgets(1000000, 1000000, 128)) == wanted
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == pristine


PLANTS = ("false_int", "priority_bool", "mac_case", "member_basis", "member_raw", "known_raw", "reason", "detail", "candidates",
    "need_node", "need_operation", "need_params", "need_params_type", "need_resolves", "need_reruns", "need_after_s", "need_unprintable",
    "root_need_resolves", "root_need_order", "version_marker", "needs_empty", "collector_time", "scope", "metadata_flag", "capture_field",
    "denominator_stp", "denominator_etherchannel", "denominator_hsrp", "denominator_vrrp",
    "coalescence", "missing_row", "row_order", "empty_lf", "partial_reason", "no_all_denominator", "extra_file", "header_flag")


@pytest.mark.parametrize("plant", PLANTS)
def test_consistent_recomputed_manifest_never_authenticates_wrong_scalar_need_metadata_denominator_or_row(plant, registration):
    mode = {"root_need_resolves": "none", "root_need_order": "none", "empty_lf": "only_vrrp", "partial_reason": "partial",
        "no_all_denominator": "no_all_target"}.get(plant, "normal")
    inputs = cases.members(mode)
    original = oracle.expected_bundle(mode, inputs, registration)
    assert original["MANIFEST.sha256"] == manifest(original)
    assert encoded({f"{row['fact']}|{row['subject']}": row["value"] for row in rows(original)}) == encoded(
        {f"{fact}|{subject}": value for (fact, subject), value in literal_frames(mode).items()})
    changed = deepcopy(original)
    header = json.loads(changed["result.json"])
    facts = {kind: [json.loads(line) for line in changed[f"facts/{kind}.jsonl"].splitlines()] for kind in KINDS}
    flat = [row for kind in KINDS for row in facts[kind]]
    def cell(fact, alias):
        return next(row["value"] for row in flat if row["fact"] == fact and row["subject"] == SUBJECTS[alias])
    if plant == "false_int":
        cell("l2.stp.root_guard", "tree")["value"] = 0
    elif plant == "priority_bool":
        cell("l2.stp.reported_root_priority", "tree")["value"] = False
    elif plant == "mac_case":
        cell("l2.stp.reported_root_mac", "tree")["value"] = "abcd.ef01.2345"
    elif plant in ("member_basis", "member_raw"):
        cell("l2.etherchannel.reported_member_tokens", "channel")["basis" if plant == "member_basis" else "raw"] = (
            "observed" if plant == "member_basis" else "Gi1/0/1(P)")
    elif plant == "known_raw":
        cell("l2.stp.reported_root_priority", "tree")["raw"] = 0
    elif plant in ("reason", "detail", "candidates"):
        cell("l3.fhrp.reported_state", "a3")[plant] = [SUBJECTS["a0"]] if plant == "candidates" else "not_collected" if plant == "reason" else "other_detail"
    elif plant == "need_params_type":
        cell("l3.fhrp.reported_state", "a3")["next_evidence"][0]["params"][0][1] = 2
    elif plant.startswith("need_"):
        need = cell("l3.fhrp.reported_state", "a3")["next_evidence"][0]
        replacements = {"node": "node:demo:b", "operation": "iosxe.show_standby_all", "params": [["interface", "Vl99"], ["group", "2"]],
            "resolves": ["l3.fhrp.reported_protocol_version"], "reruns": ["l3.fhrp/parse_hsrp_all_version"],
            "after_s": 0, "unprintable": ["explicit_reported_protocol_version"]}
        key = plant.removeprefix("need_")
        need[key] = replacements[key]
    elif plant == "root_need_resolves":
        cell("l2.stp.reported_root_mac", "tree")["next_evidence"][0]["resolves"] = ["l2.stp.reported_root_mac"]
    elif plant == "root_need_order":
        cell("l2.stp.reported_root_priority", "tree")["next_evidence"][0]["resolves"].reverse()
    elif plant == "needs_empty":
        cell("l3.fhrp.reported_state", "a3")["next_evidence"] = []
    elif plant == "version_marker":
        cell("l3.fhrp.reported_protocol_version", "a3")["next_evidence"][0]["unprintable"] = []
    elif plant == "header_flag":
        header["qualification"] = "qualified"
    elif plant == "collector_time":
        header["captures"][0]["metadata"]["collected_utc"]["next_evidence"] = [{"fabricated": True}]
    elif plant == "scope":
        header["captures"][0]["metadata"]["scope"]["context"] = "round"
    elif plant == "metadata_flag":
        header["captures"][0]["metadata_recorded"] = 0
    elif plant == "capture_field":
        next(row for row in header["captures"] if row["layer"] == "p4")["parse_quality"] = "partial"
    elif plant.startswith("denominator_"):
        header["denominator"][plant.removeprefix("denominator_")]["declared"] -= 1
    elif plant == "no_all_denominator":
        header["denominator"]["hsrp"]["declared"] = 0
    elif plant == "coalescence":
        facts["fhrp_local"] = list({row["subject"]: row for row in facts["fhrp_local"]}.values())
    elif plant == "missing_row":
        facts["stp_port_vlan"].pop()
    elif plant == "row_order":
        facts["fhrp_local"].reverse()
    elif plant == "partial_reason":
        cell("l3.fhrp.reported_vrrp_state", "v1")["reason"] = "subject_absent_from_capture"
    rerender(changed, header, facts)
    if plant == "empty_lf":
        changed["facts/stp_port_vlan.jsonl"] = b"\n"
        changed["MANIFEST.sha256"] = manifest(changed)
    if plant == "extra_file":
        changed["checks/l2.stp.jsonl"] = b""
        changed["MANIFEST.sha256"] = manifest(changed)
    assert changed != original and changed["MANIFEST.sha256"] == manifest(changed)
    assert changed != oracle.expected_bundle(mode, inputs, registration)


@pytest.mark.parametrize("plant", ("missing", "duplicate", "foreign_subject", "wrong_kind"))
def test_assembly_requires_complete_literal_fact_subject_population_before_any_coalescing(monkeypatch, plant, registration):
    inputs = cases.members("normal")
    assert oracle.expected_bundle("normal", inputs, registration)["MANIFEST.sha256"]
    def corrupted(*args):
        value = claim_leaves(*args)
        if plant == "missing":
            value["claims"].pop()
        elif plant == "duplicate":
            value["claims"][-1] = deepcopy(value["claims"][0])
        elif plant == "foreign_subject":
            value["claims"][0]["subject"] = SUBJECTS["v0"]
        else:
            value["claims"][0]["kind"] = "fhrp_local"
        return value
    monkeypatch.setattr(oracle, "claim_leaves", corrupted)
    with pytest.raises(ValueError, match="^p4_root_mixed_expected_population$"):
        oracle.expected_bundle("normal", inputs, registration)
