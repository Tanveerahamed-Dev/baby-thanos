"""M1 resource refusal plants; no unbounded JSON object construction."""
import json
from unittest.mock import patch

import pytest

from atlas_brain.evidence import admission as a


def test_depth_limit_runs_before_json_decoder():
    with (patch.object(a.json, "loads", side_effect=AssertionError("decoder reached")),
          pytest.raises(a.BudgetExceeded) as refused):
        a.strict_json(b"[" * 65 + b"0" + b"]" * 65)
    assert refused.value.member == "json"


@pytest.mark.parametrize("raw", [b"[" * 64 + b"0" + b"]" * 64,
                                  b'{"a":' * 64 + b"0" + b"}" * 64])
def test_exact_depth_is_admitted(raw):
    assert a.strict_json(raw) is not None


def test_quoted_brackets_and_escaped_quotes_are_not_structure():
    raw = json.dumps({"text": ('\\\"[{}]' * 100), "nested": [0]}).encode()
    assert a.strict_json(raw, nesting_depth=2) == json.loads(raw)


@pytest.mark.parametrize("raw", [b"9" * 41, b"-" + b"9" * 41,
                                  b"0." + b"1" * 40, b"1e" + b"0" * 40])
def test_numeric_digit_limit_runs_before_json_decoder(raw):
    with (patch.object(a.json, "loads", side_effect=AssertionError("decoder reached")),
          pytest.raises(a.AdmissionRefused, match="numeric_literal_too_long")):
        a.strict_json(raw)


@pytest.mark.parametrize("raw", [b"9" * 40, b"-" + b"9" * 40,
                                  b"0." + b"1" * 39, b"1e" + b"0" * 39])
def test_exact_numeric_digit_limit_is_admitted(raw):
    assert a.strict_json(raw) == json.loads(raw)


def test_string_digits_do_not_count_as_numeric_literals():
    assert a.strict_json(b'"' + b"9" * 100 + b'"') == "9" * 100


@pytest.mark.parametrize("field", ["nesting_depth", "numeric_digits"])
def test_limits_are_positive_integer_hashed_run_options(field):
    baseline = a.Budgets(10000, 10000, 10)
    assert baseline.sha256 != a.Budgets(10000, 10000, 10, **{field: 3}).sha256
    for invalid in (0, -1, True):
        with pytest.raises(ValueError, match="invalid_budget"):
            a.Budgets(10000, 10000, 10, **{field: invalid})


@pytest.mark.parametrize("raw", [b"[[[0]]]", b'{"a":{"b":{"c":0}}}'])
def test_folder_structured_depth_uses_hashed_limit(tmp_path, raw):
    (tmp_path / "input.JSON").write_bytes(raw)
    with pytest.raises(a.BudgetExceeded) as refused:
        a.folder_members(tmp_path, a.Budgets(10000, 10000, 10, nesting_depth=2))
    assert refused.value.member == "input.JSON"


def test_folder_numeric_limit_uses_hashed_limit(tmp_path):
    (tmp_path / "input.json").write_bytes(b"1234")
    with pytest.raises(a.AdmissionRefused, match="numeric_literal_too_long"):
        a.folder_members(tmp_path, a.Budgets(10000, 10000, 10, numeric_digits=3))


def test_folder_depth_refuses_before_descendant_walk(tmp_path):
    (tmp_path / "a" / "b" / "c").mkdir(parents=True)
    with pytest.raises(a.BudgetExceeded) as refused:
        a.folder_members(tmp_path, a.Budgets(10000, 10000, 10, nesting_depth=2))
    assert refused.value.member == "a/b/c"


def test_folder_exact_depth_and_structured_limits_pass(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "input.json").write_bytes(b"[[123]]")
    assert a.folder_members(tmp_path, a.Budgets(10000, 10000, 10, nesting_depth=2,
                                               numeric_digits=3)) == {"a/input.json": b"[[123]]"}


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b"NaN", b"Infinity", b"1e999",
                                  b"\xff", b"[}", b"[01]", b'"unterminated'])
def test_existing_invalid_json_refusals_remain(raw):
    with pytest.raises(a.AdmissionRefused):
        a.strict_json(raw)
