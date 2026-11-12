"""Three-family generated observations stay bound to literal source claims, never health."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.runner import p4
from tools import p4_estate_cases as d

FACTS = ("facts/stp_port_vlan.jsonl", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl")
ROOT, ROLE = "l2.stp.root_guard", "l2.stp.reported_role"
PROTOCOL, MEMBERS, STATE = "l2.etherchannel.reported_protocol", "l2.etherchannel.reported_member_tokens", "l3.fhrp.reported_state"
PORT = "GigabitEthernet1/0/1"


def prepared(root, case):
    inputs = d.members(canonical, case)
    source = root / "inputs"
    source.mkdir()
    for name, raw in inputs.items():
        (source / name).write_bytes(raw)
    reports = p4.analyse_folder(source, Budgets(1000000, 1000000, 1000))
    return inputs, reports


def documents(reports):
    return {name: [json.loads(line) for line in raw.splitlines()] if name in FACTS else json.loads(raw)
        for name, raw in reports.items() if name != "MANIFEST.sha256"}


def save(reports, values):
    for name, value in values.items():
        reports[name] = b"".join(canonical(row) + b"\n" for row in value) if name in FACTS else canonical(value)
    reports["MANIFEST.sha256"] = b"".join(f"{sha256(reports[name]).hexdigest()}  {name}\n".encode()
        for name in sorted(reports) if name != "MANIFEST.sha256")


def wanted(case):
    rows = {}
    def add(fact, kind, parts, node, target, value, raw, basis, reason=None):
        subject = kind + ":" + sha256(canonical(("atlas-brain." + {
            "stp_port_vlan": "stp-port-vlan", "etherchannel_group": "etherchannel-group", "fhrp_local": "fhrp-local"}[kind]
            + "/1", "round", "node:demo:" + node, *parts))).hexdigest()
        rows[fact, subject] = (node, target, value, raw, basis, reason)
    absent = "subject_absent_from_capture"
    for vlan in (1, 2, 3):
        for fact, value, raw in ((ROOT, False, "disabled"), (ROLE, "designated", "designated")):
            add(fact, "stp_port_vlan", (PORT, vlan), "a", "tree", value if vlan < 3 else None,
                raw if vlan < 3 else None, "observed" if vlan < 3 else None, absent if vlan == 3 else None)
    for node, target, groups in (("b", "ec", ("1", "2", "3")), ("a", "cold", ("4",))):
        for group in groups:
            reason = "not_collected" if case == "missing" or group == "4" else absent if group == "3" else None
            protocol = ("lacp", "LACP") if group == "1" else ("pagp", "PAgP") if case == "pagp" else ("none_reported", "-")
            for fact, value, raw, basis in ((PROTOCOL, *protocol, "observed"),
                    (MEMBERS, "Gi1/0/1(P)" if group == "1" else "Gi1/0/2(D)", None, "derived")):
                add(fact, "etherchannel_group", (group,), node, target, None if reason else value,
                    None if reason else raw, None if reason else basis, reason)
    for node, target, interface, group, raw in (("a", "hsrp", "Vl20", "0", "Init"), ("a", "hsrp", "Vl10", "1", "Active"),
            ("a", "hsrp", "BD3329", "129", "Standby"), ("a", "hsrp", "Vl99", "2", None), ("b", "hsrp-cold", "Vl30", "2", None)):
        reason = "not_collected" if case == "missing" or target == "hsrp-cold" else absent if raw is None else None
        add(STATE, "fhrp_local", (interface, "ipv4", "hsrp", group), node, target,
            None if reason else raw.lower(), None if reason else raw, None if reason else "observed", reason)
    return rows


def hsrp_spans(raw, interface):
    line = next(line for line in raw.splitlines(keepends=True) if line.startswith(interface.encode() + b" "))
    start, cursor, spans = raw.index(line), raw.index(line), []
    for token in line.split():
        position = raw.index(token, cursor)
        spans.append((position, position + len(token)))
        cursor = position + len(token)
    tokens = line.split()
    state = 4 if tokens[3] == b"P" else 3
    selected = {spans[0], spans[1], spans[state], (start, start + len(line.rstrip(b"\r\n")))}
    selected.update(span for token, span in zip(tokens[-3:], spans[-3:], strict=True) if b"." in token)
    return sorted(selected)


@pytest.mark.parametrize("case", ["baseline", "pagp", "missing"])
def test_real_three_family_reports_have_the_literal_roster_values_keys_and_proofs(tmp_path, monkeypatch, case):
    inputs, reports = prepared(tmp_path, case)
    before = dict(inputs)
    values, expected = documents(reports), wanted(case)
    rows = [row for name in FACTS for row in values[name]]
    assert len(rows) == 19 and {(row["fact"], row["subject"]) for row in rows} == set(expected)
    head = values["result.json"]
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}
    assert (head["scope"], head["checks"], head["variant_support"]) == ("observations_only", "not_implemented", "allowlisted")
    assert set(inputs) == {"p2.json", "p4.json", "discovery.txt", "tree.txt"} | (set() if case == "missing" else {"ec.txt", "hsrp.txt"})
    for row in rows:
        node, target, value, raw, basis, reason = expected[row["fact"], row["subject"]]
        assert (row["node"], row["target"], row["context"]) == (node, target, "round")
        if reason:
            assert row["state"] == "unknown" and row["reason"] == reason
            assert not {"value", "raw", "basis"} & row.keys()
            need, = row["next_evidence"]
            assert need["node"] == "node:demo:" + node and need["resolves"] == [row["fact"]] and need["after_s"] is None
        else:
            assert (row["state"], row["value"], row["raw"], row["basis"]) == ("known", value, raw, basis)
            assert type(row["value"]) is type(value)
            if row["fact"] == STATE:
                refs = row["evidence"][3:]
                assert [(ref["start"], ref["end"]) for ref in refs] == hsrp_spans(inputs["hsrp.txt"], row["interface"])
        for ref in row["evidence"][3:]:
            assert ref["target"] == target and ref["source"] == "node:demo:" + node
            selected = inputs[ref["path"]]
            excerpt = selected if ref["locator"] == "whole_capture" else selected[ref["start"]:ref["end"]]
            assert ref["sha256"] == sha256(excerpt).hexdigest()
            assert ref["role"] == ("witness" if reason else "subject")
    monkeypatch.setattr(p4, "analyse_folder", lambda *args: pytest.fail("oracle invoked application analysis"))
    receipt = d.validate(reports, inputs, case, canonical)
    assert receipt["qualification"] == "synthetic_observations_only" and receipt["facts"] == 19
    assert (receipt["known"], receipt["unknown"]) == ((4, 15) if case == "missing" else (11, 8))
    assert receipt["source"] == {name: sha256(raw).hexdigest() for name, raw in inputs.items()}
    assert receipt["reports"] == {name: sha256(raw).hexdigest() for name, raw in reports.items()}
    assert {name: (tmp_path / "inputs" / name).read_bytes() for name in inputs} == before


@pytest.mark.parametrize("plant", ["source", "missing", "manifest", "census_drop", "census_duplicate", "root_int", "role_bool",
    "dash_static", "protocol_raw", "member_basis", "member_flag", "unknown_false", "unknown_reason", "unknown_need",
    "hsrp_state", "hsrp_interface", "hsrp_group", "hsrp_af", "hsrp_subject", "fact_node", "fact_context", "foreign_decl",
    "proof_span", "proof_hash", "proof_role", "proof_order", "proof_whole", "foreign_capture",
    "profile", "denominator_bool", "metadata_target", "metadata_time", "metadata_scope", "registry_digest"])
def test_resealing_cannot_qualify_semantic_census_proof_or_source_forgeries(tmp_path, plant):
    inputs, reports = prepared(tmp_path, "baseline")
    if plant in ("source", "missing", "manifest"):
        if plant == "source":
            inputs["tree.txt"] += b"x"
        elif plant == "missing":
            reports.pop(FACTS[1])
        else:
            reports["MANIFEST.sha256"] += b"x"
    else:
        values = documents(reports)
        head, stp, ec, hsrp = values["result.json"], values[FACTS[0]], values[FACTS[1]], values[FACTS[2]]
        root = next(row for row in stp if row["fact"] == ROOT and row["vlan"] == 1)
        role = next(row for row in stp if row["fact"] == ROLE and row["vlan"] == 1)
        protocol = next(row for row in ec if row["fact"] == PROTOCOL and row["group"] == "2")
        member = next(row for row in ec if row["fact"] == MEMBERS and row["group"] == "2")
        unknown = next(row for row in hsrp if row["target"] == "hsrp-cold")
        known = next(row for row in hsrp if row["state"] == "known")
        if plant == "census_drop":
            hsrp.pop()
        elif plant == "census_duplicate":
            hsrp[-1] = hsrp[0]
        elif plant in ("root_int", "role_bool", "dash_static", "protocol_raw", "member_basis", "member_flag"):
            row, field, value = {"root_int": (root, "value", 0), "role_bool": (role, "value", True),
                "dash_static": (protocol, "value", "static"), "protocol_raw": (protocol, "raw", "none_reported"),
                "member_basis": (member, "basis", "observed"), "member_flag": (member, "value", "Gi1/0/2(P)")}[plant]
            row[field] = value
        elif plant.startswith("unknown_"):
            if plant == "unknown_false":
                unknown.update(value=False, raw="disabled", basis="observed")
            else:
                unknown["reason" if plant == "unknown_reason" else "next_evidence"] = "subject_absent_from_capture" if plant == "unknown_reason" else []
        elif plant.startswith("hsrp_"):
            field, value = {"hsrp_state": ("value", "healthy"), "hsrp_interface": ("interface", "Vl99"),
                "hsrp_group": ("group", "9"), "hsrp_af": ("address_family", "ipv6"), "hsrp_subject": ("subject", root["subject"])}[plant]
            known[field] = value
        elif plant in ("fact_node", "fact_context", "foreign_decl"):
            if plant == "foreign_decl":
                root["evidence"][0] = protocol["evidence"][0]
            else:
                root["node" if plant == "fact_node" else "context"] = "foreign"
        elif plant.startswith("proof_") or plant == "foreign_capture":
            ref = root["evidence"][3]
            if plant == "proof_span":
                ref["start"], ref["end"] = root["evidence"][5]["start"], root["evidence"][5]["end"]
                ref["sha256"] = sha256(inputs[ref["path"]][ref["start"]:ref["end"]]).hexdigest()
            elif plant == "proof_hash":
                ref["sha256"] = "0" * 64
            elif plant == "proof_role":
                ref["role"] = "witness"
            elif plant == "proof_order":
                root["evidence"][3:5] = reversed(root["evidence"][3:5])
            elif plant == "proof_whole":
                ref.update(locator="whole_capture", sha256=sha256(inputs[ref["path"]]).hexdigest())
                ref.pop("start")
                ref.pop("end")
            else:
                root["evidence"][3:] = protocol["evidence"][3:]
        elif plant == "profile":
            head["registration_sha256"] = "0" * 64
        elif plant == "denominator_bool":
            head["denominator"]["l2.stp"] = True
        elif plant.startswith("metadata_"):
            capture = head["captures"][0]
            if plant == "metadata_time":
                capture["collected_utc"]["state"] = "known"
            else:
                capture["target" if plant == "metadata_target" else "scope"] = "foreign" if plant == "metadata_target" else {**capture["scope"], "plane": "config"}
        else:
            root["evidence"][0]["table_digest"] = "0" * 64
        save(reports, values)
    with pytest.raises(ValueError, match="^p4_estate_demo_" + ("generated_source" if plant == "source" else "report") + "$"):
        d.validate(reports, inputs, "baseline", canonical)
