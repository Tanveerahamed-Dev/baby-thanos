"""Generated guard evidence is independently qualified from retained source bytes."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.runner.p4_guard_policy import policy, report_guard_comparisons
from tools import p4_guard_cases as d


def prepared(root, case="mismatch"):
    inputs = d.members(canonical, case)
    evidence = root / "inputs"
    evidence.mkdir()
    for name, content in inputs.items():
        (evidence / name).write_bytes(content)
    caller = policy.GuardPolicy(id="same_guard", domain="demo", expectation="same_reported_root_guard",
        participants=tuple(policy.GuardParticipant(target_id=name, vlan=1, declared_mode="pvst",
            position="designated_downstream") for name in ("left", "right")))
    return inputs, report_guard_comparisons(evidence, Budgets(1000000, 1000000, 1000), (caller,))


def reseal(reports):
    reports["MANIFEST.sha256"] = b"".join(f"{sha256(reports[name]).hexdigest()}  {name}\n".encode()
        for name in sorted(reports) if name != "MANIFEST.sha256")


@pytest.mark.parametrize("case,wanted", [
    ("mismatch", ("problem", None, "reported_root_guard")),
    ("omitted_guard", ("unknown", "field_not_printed", "reported_root_guard")),
    ("equal_untimed", ("unknown", "as_of_missing", "reported_root_guard")),
    ("role_excludes", ("not_applicable", "role_excludes", "reported_role"))])
def test_real_original_inputs_and_five_reports_qualify_all_declared_cases(tmp_path, case, wanted):
    inputs, reports = prepared(tmp_path, case)
    receipt = d.validate(reports, inputs, case, canonical)
    assert (receipt["state"], receipt["reason"], receipt["last_hop"]) == wanted
    assert receipt["source"] == {name: sha256(content).hexdigest() for name, content in inputs.items()}
    assert receipt["reports"] == {name: sha256(content).hexdigest() for name, content in reports.items()}


def test_expected_label_is_not_a_semantic_source_oracle(tmp_path, monkeypatch):
    inputs, reports = prepared(tmp_path, "equal_untimed")
    monkeypatch.setattr(d, "members", lambda *args: inputs)
    finding, = [json.loads(line) for line in reports[d.CHECKS].splitlines()]
    finding["state"], finding["reason"] = "problem", None
    last = finding["hops"][-1]["state"]
    finding["hops"][-1]["state"] = {"state": "known", "basis": "derived", "value": True, "raw": None, "evidence": last["evidence"]}
    reports[d.CHECKS] = canonical(finding) + b"\n"
    reseal(reports)
    with pytest.raises(ValueError, match="^p4_guard_demo_source_tokens$"):
        d.validate(reports, inputs, "mismatch", canonical)


def objects(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from objects(item)
    elif isinstance(value, list):
        for item in value:
            yield from objects(item)


def documents(reports):
    return {name: [json.loads(line) for line in content.splitlines()] if name in (d.FACTS, d.CHECKS) else json.loads(content)
        for name, content in reports.items() if name != "MANIFEST.sha256"}


def save(reports, values):
    for name, value in values.items():
        reports[name] = b"".join(canonical(row) + b"\n" for row in value) if name in (d.FACTS, d.CHECKS) else canonical(value)
    reseal(reports)


def echo(values, row):
    for item in tuple(objects(values)):
        if item.get("kind") == "fact" and (item["subject"], item["fact"]) == (row["subject"], row["fact"]):
            item["value"] = json.loads(canonical(row))


def policy_pins(values):
    digest = sha256(canonical(values[d.POLICY])).hexdigest()
    values["result.json"]["policy_registry"]["sha256"] = digest
    for item in tuple(objects(values)):
        if item.get("kind") == "registry" and item["table"] == "declared_stp_guard_policies":
            item["table_digest"] = digest
            item["value"] = json.loads(canonical(values[d.POLICY]["policies"][0]))


@pytest.mark.parametrize("plant,code", [
    ("source", "generated_source"), ("span", "report"), ("hash", "report"), ("manifest", "report"), ("missing", "report"),
    ("policy", "report"), ("participant", "report"), ("outcome", "report"), ("pair", "report"), ("no_right", "report"),
    ("proof_whole", "report"), ("proof_role", "report"), ("proof_order", "report"), ("proof_own_foreign", "report"),
    ("fact_pack", "report"), ("fact_context", "report"), ("unknown_false", "report"), ("foreign_decl", "report"),
    ("meta_target", "report"), ("meta_time", "report"), ("scope_rowid", "report"), ("scope_digest", "report"),
    ("scope_pointer", "report"), ("scope_table", "report"), ("scope_value", "report"),
    ("guard_int", "report"), ("echo_int", "report"), ("denominator_bool", "report"),
    ("hop_int", "report"), ("profile", "report"), ("context", "report"),
    ("policy_missing", "report"), ("policy_duplicate", "report"), ("policy_domain", "report"),
    ("capture_binding", "report"), ("operand_proof", "report"), ("flat", "report"), ("need", "report"), ("unknown_need", "report")])
def test_canonical_resealing_does_not_qualify_coherent_contract_or_operand_forgeries(tmp_path, plant, code):
    case = "equal_untimed" if plant == "capture_binding" else "omitted_guard" if plant in ("unknown_need", "unknown_false") else "mismatch"
    inputs, reports = prepared(tmp_path, case)
    values = documents(reports)
    head, facts, finding = values["result.json"], values[d.FACTS], values[d.CHECKS][0]
    left = next(row for row in facts if row["target"] == "left" and row["fact"] == "l2.stp.root_guard")
    if plant in ("source", "manifest", "missing"):
        if plant == "source":
            inputs["left.txt"] += b"x"
        elif plant == "manifest":
            reports["MANIFEST.sha256"] += b"x"
        else:
            reports.pop(d.FACTS)
        with pytest.raises(ValueError, match="^p4_guard_demo_" + code + "$"):
            d.validate(reports, inputs, case, canonical)
        return
    if plant.startswith("proof_") or plant in ("fact_pack", "fact_context", "foreign_decl", "unknown_false"):
        if plant == "unknown_false":
            left = next(row for row in facts if row["target"] == "right" and row["fact"] == "l2.stp.root_guard")
            left.update(value=False, raw="disabled", basis="observed")
        elif plant == "fact_pack":
            left["pack"] = "l3.fhrp"
        elif plant == "fact_context":
            left["context"] = "other"
        elif plant == "foreign_decl":
            left["evidence"][0] = next(row for row in facts if row["target"] == "right")["evidence"][0]
        elif plant == "proof_whole":
            left["evidence"][3] = {**left["evidence"][3], "locator": "whole_capture", "sha256": sha256(inputs["left.txt"]).hexdigest()}
            left["evidence"][3].pop("start")
            left["evidence"][3].pop("end")
        elif plant == "proof_role":
            left["evidence"][3]["role"] = "witness"
        elif plant == "proof_order":
            left["evidence"][3:5] = reversed(left["evidence"][3:5])
        else:
            left["evidence"][3] = left["evidence"][5]
        echo(values, left)
    elif plant.startswith("scope_"):
        field, content = {"scope_rowid": ("row_id", "other"), "scope_digest": ("table_digest", "0" * 64),
            "scope_pointer": ("citation", "/policies/1"), "scope_table": ("table", "synthetic_p4.context"),
            "scope_value": ("value", {"id": "other"})}[plant]
        for item in tuple(objects(values)):
            if item.get("kind") == "registry" and item["table"] == "declared_stp_guard_policies":
                item[field] = content
    elif plant.startswith("meta_"):
        capture = head["captures"][0]
        if plant == "meta_target":
            capture["target"] = "foreign"
        else:
            capture["collected_utc"]["state"] = "known"
    elif plant in ("span", "hash"):
        ref = next(ref for ref in left["evidence"] if ref["kind"] == "capture")
        ref["end" if plant == "span" else "sha256"] = 1000000 if plant == "span" else "0" * 64
        echo(values, left)
    elif plant in ("guard_int", "capture_binding", "unknown_need"):
        if plant == "guard_int":
            left["value"] = 1
        elif plant == "unknown_need":
            left = next(row for row in facts if row["target"] == "right" and row["fact"] == "l2.stp.root_guard")
            left["next_evidence"] = []
        else:
            right = next(row for row in facts if row["target"] == "right" and row["fact"] == left["fact"])
            foreign = iter(ref for ref in right["evidence"] if ref["kind"] == "capture")
            left["evidence"] = [next(foreign) if ref["kind"] == "capture" else ref for ref in left["evidence"]]
        echo(values, left)
    elif plant == "echo_int":
        for item in objects(finding):
            if item.get("kind") == "fact" and (item["fact"], item["subject"]) == (left["fact"], left["subject"]):
                item["value"]["value"] = 1
    elif plant == "denominator_bool":
        head["denominator"]["declared_policies"] = True
    elif plant == "hop_int":
        finding["hops"][0]["state"]["value"] = 1
    elif plant == "profile":
        head["registration_sha256"] = values[d.POLICY]["registration_sha256"] = "0" * 64
        policy_pins(values)
    elif plant == "context":
        head["context"] = "other"
    elif plant.startswith("policy_") or plant in ("policy", "participant"):
        record = values[d.POLICY]["policies"][0]
        if plant in ("policy_missing", "participant"):
            record["participants"] = record["participants"][:1]
        elif plant == "policy_duplicate":
            record["participants"] = [record["participants"][0], record["participants"][0]]
        else:
            record["domain"] = "other"
        policy_pins(values)
    elif plant == "operand_proof":
        for row in facts:
            if row["target"] == "right":
                row["evidence"] = [ref for ref in row["evidence"] if ref["kind"] != "capture"]
                echo(values, row)
    elif plant == "outcome":
        finding["state"] = "unknown"
    elif plant == "pair":
        finding["evidence"][-1]["subject"] = "subject:foreign"
    elif plant == "no_right":
        finding["evidence"] = [ref for ref in finding["evidence"] if ref.get("subject") == finding["left"] or ref["kind"] == "registry"]
    elif plant == "flat":
        finding["evidence"] = finding["evidence"][:-1]
    else:
        finding["next_evidence"] = []
    save(reports, values)
    with pytest.raises(ValueError, match="^p4_guard_demo_" + code + "$"):
        d.validate(reports, inputs, case, canonical)
