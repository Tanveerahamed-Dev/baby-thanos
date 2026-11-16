"""Differential parity against the retained qualified encoder; no timing or cache acceptance."""
import json
import math
import re
import time
from copy import deepcopy
from statistics import median
from typing import cast

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp.root_mixed_profile import DECLARATIONS

PREVIOUS_SAFE = re.compile(r"[\x20-\x21\x23-\x5b\x5d-\x7e]*")


def previous_bytes(value: object) -> bytes:
    return previous_encode(value).encode("utf-8")


def previous_encode(value: object) -> str:
    if type(value) not in (type(None), bool, int, str, list, tuple, dict):
        raise TypeError("non_json_type")
    if isinstance(value, str):
        if PREVIOUS_SAFE.fullmatch(value):
            return f'"{value}"'
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (type(None), bool)):
        return json.dumps(value)
    if isinstance(value, int):
        if value not in range(-9007199254740991, 9007199254740992):
            raise ValueError("integer_out_of_range")
        return str(value)
    if isinstance(value, (list, tuple)):
        items = cast("list[object] | tuple[object, ...]", value)
        return f"[{','.join(map(previous_encode, items))}]"
    entries = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in entries):
        raise TypeError("non_string_key")
    obj = cast(dict[str, object], value)
    keys = sorted(obj, key=lambda key: key.encode("utf-16be"))
    members = (f"{previous_encode(key)}:{previous_encode(obj[key])}" for key in keys)
    return f"{{{','.join(members)}}}"


def outcome(encoder, value):
    try:
        return "bytes", encoder(value)
    except (TypeError, ValueError, LookupError) as error:
        return "error", type(error), str(error)


def test_every_ascii_scalar_and_nested_unicode_matches_qualified_bytes():
    values = [*(chr(code) for code in range(128)), "".join(map(chr, range(128))),
        "", "ordinary safe ASCII []{},:!/", r"literal\n\\path", '"quoted"',
        "\x80", "\u00e9", "e\u0301", "\u2028\u2029", "\ue000", "\U0001f600", "\U0010ffff"]
    for index, value in enumerate(values):
        nested = {"\ue000": (value, None, True, False), "\U0001f600": [value, {"key": value}], "\r": value}
        assert canonical(value) == previous_bytes(value), index
        assert canonical(nested) == previous_bytes(nested), index
    assert canonical({"\ue000": 3, "\U0001f600": 2, "\r": 1}) == '{"\\r":1,"\U0001f600":2,"\ue000":3}'.encode("utf-8")


@pytest.mark.parametrize("value", [
    None, True, False, -9007199254740991, -1, 0, 1, 9007199254740991,
    [], (), {}, [None, False, 0], (True, 1, "1"),
    {"z": [True, 1, None], "a": (False, 0)},
])
def test_closed_scalar_and_container_shapes_match_reference(value):
    assert canonical(value) == previous_bytes(value)


INVALID = [
    (-9007199254740992, ValueError, "integer_out_of_range"),
    (9007199254740992, ValueError, "integer_out_of_range"),
    (1.0, TypeError, "non_json_type"),
    (float("nan"), TypeError, "non_json_type"),
    (float("inf"), TypeError, "non_json_type"),
    (float("-inf"), TypeError, "non_json_type"),
    (b"text", TypeError, "non_json_type"),
    (bytearray(b"text"), TypeError, "non_json_type"),
    ({1, 2}, TypeError, "non_json_type"),
    (object(), TypeError, "non_json_type"),
    (type("IntAlias", (int,), {})(1), TypeError, "non_json_type"),
    (type("StrAlias", (str,), {})("text"), TypeError, "non_json_type"),
    (type("ListAlias", (list,), {})([1]), TypeError, "non_json_type"),
    (type("TupleAlias", (tuple,), {})((1,)), TypeError, "non_json_type"),
    (type("DictAlias", (dict,), {})({"key": 1}), TypeError, "non_json_type"),
]


@pytest.mark.parametrize("value,kind,reason", INVALID)
@pytest.mark.parametrize("container", ["scalar", "list", "tuple", "mapping"])
def test_refusal_class_message_and_nested_dispatch_match_reference(value, kind, reason, container):
    wrapped = {"scalar": value, "list": [value], "tuple": (value,), "mapping": {"item": value}}[container]
    expected = "error", kind, reason
    assert outcome(previous_bytes, wrapped) == expected
    assert outcome(canonical, wrapped) == expected


@pytest.mark.parametrize("value,reason", [
    ({1: "value"}, "non_string_key"),
    ({False: "value"}, "non_string_key"),
    ({("tuple",): "value"}, "non_string_key"),
    ({"first": 9007199254740992, 1: "later"}, "non_string_key"),
    ({"a": 1.0, "z": 9007199254740992}, "non_json_type"),
    ({"a": 9007199254740992, "z": 1.0}, "integer_out_of_range"),
    ({type("StrKeyAlias", (str,), {})("key"): "value"}, "non_json_type"),
])
def test_dictionary_key_validation_and_first_value_refusal_order_are_preserved(value, reason):
    expected = "error", TypeError if reason != "integer_out_of_range" else ValueError, reason
    assert outcome(previous_bytes, value) == expected
    assert outcome(canonical, value) == expected


def test_string_subclass_key_encode_precedence_is_unchanged():
    class Key(str):
        def encode(self, *args, **kwargs):
            raise LookupError("key_encoding_precedes_value")
    value = {Key("key"): 9007199254740992}
    expected = "error", LookupError, "key_encoding_precedes_value"
    assert outcome(previous_bytes, value) == expected
    assert outcome(canonical, value) == expected
    assert outcome(canonical, Key("value")) == ("error", TypeError, "non_json_type")


@pytest.mark.parametrize("value", [
    "\ud800", "\udfff", "x\ud800y", ["\udfff"], {"valid": "\ud800"},
    {"\udfff": "valid"}, {"nested": {"\ud800": None}},
])
def test_surrogate_exception_and_following_call_match_reference(value):
    expected = outcome(previous_bytes, value)
    assert expected[0] == "error" and expected[1] is UnicodeEncodeError
    assert outcome(canonical, value) == expected
    assert canonical("after refusal") == previous_bytes("after refusal")


def test_dumps_routing_keeps_exact_scalar_types_values_and_options(monkeypatch):
    original, calls = json.dumps, []
    def observe(value, **kwargs):
        calls.append((type(value), value, kwargs))
        return original(value, **kwargs)
    monkeypatch.setattr(json, "dumps", observe)
    values = [None, True, False, 0, 1, "safe", "\x7f", "e\u0301", ["quoted\"", {"key": False}]]
    expected = [previous_bytes(value) for value in values]
    previous_calls = calls[:]
    calls.clear()
    assert [canonical(value) for value in values] == expected
    assert calls == previous_calls
    assert calls[:3] == [(type(None), None, {}), (bool, True, {}), (bool, False, {})]


def test_repeated_mutation_is_observed_without_reusing_any_prior_container_result():
    shared = [None, True, False, 1, "ascii", "\u00e9"]
    value = {"z": shared, "a": {"same": shared}, "n": -9007199254740991}
    original = deepcopy(value)
    before = canonical(value)
    assert before == previous_bytes(original)
    for token in ("new", 0, "\U0001f600"):
        shared.append(token)
        assert canonical(value) == previous_bytes(value) != before
        assert value["z"] is shared and value["a"]["same"] is shared
    shared.append(1.0)
    assert outcome(canonical, value) == outcome(previous_bytes, value) == ("error", TypeError, "non_json_type")
    shared.pop()
    value["a"]["extra"] = ("changed",)
    assert canonical(value) == previous_bytes(value) != before
    assert original != value and before == previous_bytes(original)


def test_bounded_same_process_metadata_diagnostic_preserves_bytes_before_timing(capsys):
    """Wall-clock samples are diagnostic only; there is no speed threshold or qualification claim."""
    compiled = compile_packs(DECLARATIONS)
    expected = (compiled.catalogue_bytes, compiled.registration_bytes)
    fixtures = tuple(json.loads(raw) for raw in expected)
    assert tuple(previous_bytes(value) for value in fixtures) == expected
    assert tuple(canonical(value) for value in fixtures) == expected
    samples = {"baseline": [], "candidate": []}
    encoders = {"baseline": previous_bytes, "candidate": canonical}
    for repetition in range(8):
        order = ("baseline", "candidate") if repetition % 2 == 0 else ("candidate", "baseline")
        for label in order:
            encode = encoders[label]
            started = time.perf_counter()
            for _ in range(128):
                for value in fixtures:
                    encode(value)
            elapsed_ms = (time.perf_counter() - started) * 1000
            assert math.isfinite(elapsed_ms) and elapsed_ms >= 0
            samples[label].append(elapsed_ms)
    assert tuple(canonical(value) for value in fixtures) == expected
    assert tuple(previous_bytes(value) for value in fixtures) == expected
    record = {"schema": "atlas-brain.canonical-bench/1", "scope": "synthetic_same_process_diagnostic",
        "baseline_blob": "1a88377c6fcee92277603de23190b78f44bc8b4c", "fixtures": 2,
        "repetitions": 8, "iterations_per_sample": 128,
        "baseline_ms": [round(value, 3) for value in samples["baseline"]],
        "candidate_ms": [round(value, 3) for value in samples["candidate"]],
        "baseline_median_ms": round(median(samples["baseline"]), 3),
        "candidate_median_ms": round(median(samples["candidate"]), 3)}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
    assert raw.isascii() and len(raw) < 4096
    with capsys.disabled():
        print("P4_CANONICAL_BENCH " + raw)


def test_hostile_metaclass_equality_cannot_spoof_plain_json_or_run_iteration_hooks():
    """Narrow hardening: hostile non-JSON objects no longer exploit the old equality guard."""
    hooks = []
    class EqualityAlias(type):
        def __eq__(cls, other):
            hooks.append("equality")
            return True
    class NonJson(metaclass=EqualityAlias):
        def __iter__(self):
            hooks.append("iteration")
            return iter(())
    value = NonJson()
    assert previous_bytes(value) == b"{}"
    assert "equality" in hooks and "iteration" in hooks
    hooks.clear()
    with pytest.raises(TypeError, match="^non_json_type$"):
        canonical(value)
    assert hooks == []
