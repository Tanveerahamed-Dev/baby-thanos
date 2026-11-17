"""Named R10 ordinary-API twins; retained evidence is comparison data, not admission."""
from dataclasses import replace

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import protocol_check as check
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.runner import p4
from atlas_brain.runner import p4_etherchannel_policy as runner
from tools import p4_etherchannel_cases as cases

LIMITS = p4.Budgets(1000000, 1000000, 1000)


def folder(root, case):
    files = cases.members(canonical, case)
    root.mkdir()
    for name, raw in reversed(tuple(files.items())):
        (root / name).write_bytes(raw)
    return files


@pytest.mark.parametrize("case", cases.CASES)
def test_named_original_input_twins_match_complete_independent_oracle(tmp_path, monkeypatch, capsys, case):
    root = tmp_path / "inputs"
    files = folder(root, case)
    expected = cases.oracle(canonical, case, compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256)
    prepare, read = runner.prepare_protocol_comparisons, FactReader.read
    preparations, reads = [], []
    def preparing(*args, **kwargs):
        result = prepare(*args, **kwargs)
        preparations.append(result)
        return result
    def reading(self, **kwargs):
        if self.step.id == check.STEP.id:
            reads.append((kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    monkeypatch.setattr(runner, "prepare_protocol_comparisons", preparing)
    monkeypatch.setattr(FactReader, "read", reading)
    result = runner.evaluate_protocol_comparisons(root, LIMITS, cases.policies())
    original, = preparations
    assert result.source is original.source and result.execution is original.execution and result.plan is original.plan
    assert result.plan.envelope is result.execution.envelope
    assert reads == [(ec.REPORTED_PROTOCOL, subject) for subject in sorted(row.subject for row in result.source.rows)]
    assert len(result.source.rows) == 4 and len(result.source.store.values) == 8
    for row in result.source.rows:
        assert any(row.target.node is target.node for target in result.execution.envelope.targets)
        for fact, value in ((ec.REPORTED_PROTOCOL, row.value), (ec.REPORTED_MEMBER_TOKENS, row.member_tokens)):
            assert result.source.store.values[k.FactRef(fact=fact, subject=row.subject)] is value
    for output in result.source.executed:
        assert any(output.receipt is item.receipt and output.value is item.value for item in result.execution.executed)
    record = cases.observe(result, files, case)
    assert record == expected
    assert canonical(record) == canonical(expected)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == files
    assert record["historical_catalogue"] == "UNVERIFIED"
    assert record["open_obligations"] == ["expected_members_min_links_predicate_absent"]
    with capsys.disabled():
        print("P4_R10_RETAINED " + canonical(record).decode("ascii"))


@pytest.mark.parametrize("plant", ["protocol", "wrapped_members", "unselected_unknown_need"])
def test_coherent_original_source_damage_refuses_before_the_protocol_checker(tmp_path, monkeypatch, plant):
    root = tmp_path / "inputs"
    files = folder(root, "C02")
    finish = runner.SummaryPack.finish
    def changed(self, execution):
        result = finish(self, execution)
        row = next(row for row in result.rows if row.target.node.id == "a"
            and row.group == ("2" if plant == "unselected_unknown_need" else "1"))
        if plant == "wrapped_members":
            fact, field = ec.REPORTED_MEMBER_TOKENS, "member_tokens"
            value = replace(row.member_tokens, value="Gi1/0/1(P)")
        else:
            fact, field = ec.REPORTED_PROTOCOL, "value"
            value = replace(row.value, next_evidence=()) if plant == "unselected_unknown_need" else replace(row.value, value="pagp", raw="PAgP")
        result.store.values[k.FactRef(fact=fact, subject=row.subject)] = value
        return replace(result, rows=tuple(replace(item, **{field: value}) if item is row else item for item in result.rows))
    def forbidden(*args, **kwargs):
        pytest.fail("checker reached before complete original source closure")
    monkeypatch.setattr(runner.SummaryPack, "finish", changed)
    monkeypatch.setattr(runner.check, "evaluate_declared", forbidden)
    with pytest.raises(ValueError):
        runner.evaluate_protocol_comparisons(root, LIMITS, cases.policies())
    assert {path.name: path.read_bytes() for path in root.iterdir()} == files


@pytest.mark.parametrize("case,plant", [
    ("F01", "outcome"), ("C02", "member"), ("C02", "span"), ("F01", "proof_hash"),
    ("U02_two_gaps", "secondary_need"), ("U03_missing", "denominator"),
    ("F01", "source_bytes"), ("F01", "owner"), ("F01", "policy"),
])
def test_independent_oracle_detects_outcome_custody_and_secondary_gap_damage(tmp_path, case, plant):
    root = tmp_path / "inputs"
    files = folder(root, case)
    registration = compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256
    result = runner.evaluate_protocol_comparisons(root, LIMITS, cases.policies())
    record = cases.observe(result, files, case)
    assert cases.validate_retained(record, canonical, case, registration) is record
    if plant == "outcome":record["findings"][0]["state"] = "unknown"
    elif plant == "member":record["operands"][0]["members"]["value"] = "Gi1/0/1(P)"
    elif plant == "span":record["operands"][0]["members"]["evidence"][-1]["locator"]["end"] += 1
    elif plant == "proof_hash":record["operands"][0]["protocol"]["evidence"][-1]["excerpt_sha256"] = "0" * 64
    elif plant == "secondary_need":record["operands"][2]["protocol"]["next_evidence"] = []
    elif plant == "denominator":record["denominator"][1][1] = 1
    elif plant == "source_bytes":record["source"]["left.txt"]["hex"] += "00"
    elif plant == "owner":record["captures"][0]["owner"] = "foreign/owner"
    else:record["policy"]["policies"][0]["participants"][0]["group"] = "2"
    with pytest.raises(ValueError, match="^p4_r10_oracle$"):
        cases.validate_retained(record, canonical, case, registration)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == files


@pytest.mark.parametrize("plant", ["conditional_bool_to_int", "denominator_int_to_bool", "span_int_to_float", "count_int_to_float"])
def test_retained_validator_rejects_numeric_type_changes_hidden_by_python_equality(tmp_path, plant):
    root = tmp_path / "inputs"
    files = folder(root, "F01")
    registration = compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256
    result = runner.evaluate_protocol_comparisons(root, LIMITS, cases.policies())
    record = cases.observe(result, files, "F01")
    original = cases.oracle(canonical, "F01", registration)
    assert cases.validate_retained(record, canonical, "F01", registration) is record
    if plant == "conditional_bool_to_int":record["findings"][0]["conditional"] = 1
    elif plant == "denominator_int_to_bool":record["denominator"][0][1] = True
    elif plant == "span_int_to_float":
        point = record["operands"][0]["members"]["evidence"][-1]["locator"]
        point["end"] = float(point["end"])
    else:record["source_denominator"]["owned_cells"] = float(record["source_denominator"]["owned_cells"])
    assert record == original
    if plant in ("conditional_bool_to_int", "denominator_int_to_bool"):
        assert canonical(record) != canonical(original)
    else:
        with pytest.raises(TypeError, match="^non_json_type$"):canonical(record)
    with pytest.raises(ValueError, match="^p4_r10_oracle$"):
        cases.validate_retained(record, canonical, "F01", registration)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == files


def test_retained_validator_preserves_genuine_identity_without_trusting_foreign_equality():
    registration = compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256
    record = cases.oracle(canonical, "F01", registration)
    assert cases.validate_retained(record, canonical, "F01", registration) is record
    calls = []
    class Foreign:
        def __eq__(self, other):
            calls.append("equality")
            return True
    record["findings"][0]["conditional"] = Foreign()
    with pytest.raises(ValueError, match="^p4_r10_oracle$"):
        cases.validate_retained(record, canonical, "F01", registration)
    assert calls == []
