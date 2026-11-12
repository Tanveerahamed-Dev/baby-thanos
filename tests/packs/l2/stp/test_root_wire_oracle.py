"""Independent fixed Root wire/source oracle and pinned unchanged default reports."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from atlas_brain.runner import p4
from tools import p4_estate_cases as cases

CASES = ("baseline", "pagp", "missing", "unprinted", "uncaptured")
KNOWN = (15, 15, 8, 13, 7)
PRIORITY, ADDRESS = "l2.stp.reported_root_priority", "l2.stp.reported_root_mac"
FACTS = "facts/stp_port_vlan.jsonl"
LIMITS = p4.Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128)
# Measured MANIFEST.sha256 byte hashes from native136 P4_ESTATE_RECEIPT.
OLD_MANIFESTS = {"baseline": "08a9cdea961285985198a0b3d1b09845a94d8538d0e431f70e326e4ac58d73d4",
    "pagp": "42887ea89810c940e7b54572e17964dfaba92077174029be404e452aff401746",
    "missing": "8c3bb2be18120574ff019df2d5f2f36c93a420f019b5fb3f36b9726789ddca13"}


def reports(root, inputs):
    root.mkdir(parents=True)
    for name, raw in inputs.items():
        (root / name).write_bytes(raw)
    return p4.analyse_root_observations_folder(root, LIMITS)


def decoded(files):
    return json.loads(files["result.json"]), [json.loads(row) for row in files[FACTS].splitlines()]


def reseal(files, head, rows):
    files["result.json"] = canonical(head)
    files[FACTS] = b"".join(canonical(row) + b"\n" for row in rows)
    files["MANIFEST.sha256"] = manifest({name: raw for name, raw in files.items() if name != "MANIFEST.sha256"})


@pytest.mark.parametrize("case,known", tuple(zip(CASES, KNOWN, strict=True)))
def test_all_root_twins_have_literal_values_six_original_byte_proofs_and_unknown_census(tmp_path, case, known):
    inputs = cases.root_members(canonical, case)
    files = reports(tmp_path / "inputs", inputs)
    receipt = cases.validate_root(files, inputs, case, canonical)
    assert receipt["facts"] == 25 and (receipt["known"], receipt["unknown"]) == (known, 25 - known)
    assert receipt["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}
    assert receipt["source"] == {name: sha256(raw).hexdigest() for name, raw in inputs.items()}
    head, rows = decoded(files)
    assert head["schema"] == "atlas-brain.p4-root-observations/1" and len(rows) == 12
    for row in rows:
        if row["fact"] not in (PRIORITY, ADDRESS):
            continue
        vlan = row["vlan"]
        if case == "uncaptured" or vlan == 3 or case == "unprinted" and vlan == 1:
            expected = "not_collected" if case == "uncaptured" else "subject_absent_from_capture" if vlan == 3 else "field_not_printed"
            assert row["state"] == "unknown" and row["reason"] == expected and "value" not in row
            assert row["next_evidence"][0]["resolves"] == [ADDRESS, PRIORITY]
            continue
        value, raw = ((0, "0") if vlan == 1 else (32769, "32769")) if row["fact"] == PRIORITY else (
            ("ABCD.EF01.2345", "ABCD.EF01.2345") if vlan == 1 else ("0011.2233.4455", "0011.2233.4455"))
        assert type(row["value"]) is type(value) and (row["value"], row["raw"], row["basis"]) == (value, raw, "observed")
        source = inputs["tree.txt"]
        header = source.index(f"Port 1 ({cases.PORT}) of VLAN{vlan:04d} ".encode())
        end = source.index(b"\n", header)
        port = source.index(cases.PORT.encode(), header)
        vid = source.index(f"VLAN{vlan:04d}".encode(), header) + 4
        root = source.index(b"   Designated root has priority ", end)
        priority = root + len(b"   Designated root has priority ")
        comma = source.index(b", address ", priority)
        mac = comma + len(b", address ")
        expected = ((header, end), (port, port + len(cases.PORT)), (vid, vid + 4),
            (root, source.index(b"\n", root)), (priority, comma), (mac, mac + 14))
        refs = row["evidence"][3:]
        assert tuple((ref["start"], ref["end"]) for ref in refs) == expected
        assert all(ref["target"] == "tree" and ref["role"] == "subject"
            and ref["sha256"] == sha256(source[ref["start"]:ref["end"]]).hexdigest() for ref in refs)


@pytest.mark.parametrize("case", ("baseline", "pagp", "missing"))
def test_default_estate_members_and_validator_keep_pinned_native136_five_file_bytes(tmp_path, case):
    inputs = cases.members(canonical, case)
    root = tmp_path / "inputs"
    root.mkdir()
    for name, raw in inputs.items():
        (root / name).write_bytes(raw)
    files = p4.analyse_folder(root, LIMITS)
    assert cases.validate(files, inputs, case, canonical)["facts"] == 19
    assert sha256(files["MANIFEST.sha256"]).hexdigest() == OLD_MANIFESTS[case]


@pytest.mark.parametrize("plant", ["bool", "priority", "mac", "neighbor", "order", "whole", "hash", "profile",
    "registry", "capture", "missing", "unknown", "unknown_value", "need", "clock", "schema"])
def test_coherently_resealed_root_forgeries_cannot_qualify_against_saved_original_source(tmp_path, plant):
    inputs = cases.root_members(canonical, "baseline")
    files = reports(tmp_path / "inputs", inputs)
    head, rows = decoded(files)
    first = next(row for row in rows if row["fact"] == PRIORITY and row["vlan"] == 1)
    second = next(row for row in rows if row["fact"] == PRIORITY and row["vlan"] == 2)
    unknown = next(row for row in rows if row["fact"] == PRIORITY and row["vlan"] == 3)
    if plant in ("bool", "priority"):
        first["value"] = False if plant == "bool" else 1
    elif plant == "mac":
        next(row for row in rows if row["fact"] == ADDRESS and row["vlan"] == 1)["value"] = "abcd.ef01.2345"
    elif plant == "neighbor":
        assert first["evidence"][4]["sha256"] == second["evidence"][4]["sha256"]
        first["evidence"][4] = second["evidence"][4]
    elif plant == "order":
        first["evidence"][3:5] = first["evidence"][4:2:-1]
    elif plant == "whole":
        leaf = first["evidence"][3]
        first["evidence"] = first["evidence"][:3] + [{**{k: v for k, v in leaf.items() if k not in ("start", "end")},
            "locator": "whole_capture", "role": "witness", "sha256": sha256(inputs["tree.txt"]).hexdigest()}]
    elif plant == "hash":
        first["evidence"][7]["sha256"] = "0" * 64
    elif plant == "profile":
        head["registration_sha256"] = "0" * 64
    elif plant == "registry":
        first["evidence"][0]["table_digest"] = "0" * 64
    elif plant == "capture":
        foreign = next(capture for capture in head["captures"] if capture["target"] == "ec")
        first["evidence"][3]["capture"] = foreign["id"]
    elif plant == "missing":
        rows.remove(unknown)
    elif plant == "unknown":
        unknown["reason"] = "field_not_printed"
    elif plant == "unknown_value":
        unknown.update(value=False, raw="False", basis="observed")
    elif plant == "need":
        unknown["next_evidence"][0]["resolves"] = [PRIORITY]
    elif plant == "clock":
        head["captures"][0]["collected_utc"]["reason"] = "not_collected"
    else:
        head["schema"] = "atlas-brain.p4-observations/1"
    reseal(files, head, rows)
    with pytest.raises(ValueError, match="^p4_estate_demo_report$"):
        cases.validate_root(files, inputs, "baseline", canonical)


def test_source_labels_and_report_expectations_do_not_get_their_truth_from_generator_or_engine(tmp_path, monkeypatch):
    inputs = cases.root_members(canonical, "unprinted")
    files = reports(tmp_path / "inputs", inputs)
    monkeypatch.setattr(cases, "root_members", lambda *_: inputs)
    with pytest.raises(ValueError, match="^p4_estate_demo_source_tokens$"):
        cases.validate_root(files, inputs, "baseline", canonical)
    monkeypatch.setattr(p4, "analyse_root_observations_folder", lambda *_: pytest.fail("oracle called engine"))
    monkeypatch.setattr(p4.stp.stp, "parse_capture", lambda *_: pytest.fail("oracle replayed parser"))
    assert cases.validate_root(files, inputs, "unprinted", canonical)["known"] == 13
