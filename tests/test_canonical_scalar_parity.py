"""Byte and refusal parity for the admitted unescaped ASCII fast path."""
import json
from copy import deepcopy

import pytest

from atlas_brain.contract.canonical import canonical


def fresh_bytes(value):
    """Independent whole-value encoding using the previous fresh dumps options."""
    def ordered(item):
        if isinstance(item, dict):
            pairs = sorted(item.items(), key=lambda pair: pair[0].encode("utf-16-be"))
            return {key: ordered(child) for key, child in pairs}
        if isinstance(item, (list, tuple)):
            return [ordered(child) for child in item]
        return item

    return json.dumps(
        ordered(value), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def test_ascii_scalars_keep_old_bytes_and_route_only_escaped_text(monkeypatch):
    values = [None, True, False, "", *(chr(code) for code in range(127))]
    values.append("".join(chr(code) for code in range(127)))
    values.extend([
        "prefix with spaces/suffix![]{}", "0123456789:,.?<>|=+-_",
        "".join(chr(code) for code in range(32, 127) if code not in (34, 92)),
    ])
    expected = [fresh_bytes(value) for value in values]
    original = json.dumps
    calls = []

    def observe(value, **kwargs):
        calls.append((value, kwargs))
        return original(value, **kwargs)

    monkeypatch.setattr(json, "dumps", observe)
    assert [canonical(value) for value in values] == expected
    escaped = [
        *(chr(code) for code in range(32)), '"', "\\",
        "".join(chr(code) for code in range(127)),
    ]
    assert calls == [(None, {}), (True, {}), (False, {})] + [
        (value, {"ensure_ascii": False, "separators": (",", ":")})
        for value in escaped
    ]


def test_del_and_unicode_keep_the_original_explicit_dumps_options(monkeypatch):
    values = [
        "\x7f", "before\x7fafter", "\x80", "\u00e9", "e\u0301",
        "\u2028\u2029", "\ue000", "\U0001f600", "\U0010ffff",
        "".join(chr(code) for code in range(128)),
    ]
    expected = [fresh_bytes(value) for value in values]
    original = json.dumps
    calls = []

    def observe(value, **kwargs):
        calls.append((value, kwargs))
        return original(value, **kwargs)

    monkeypatch.setattr(json, "dumps", observe)
    assert [canonical(value) for value in values] == expected
    assert calls == [
        (value, {"ensure_ascii": False, "separators": (",", ":")})
        for value in values
    ]
    assert canonical("\x7f") == b'"\x7f"'
    assert original("\x7f").encode("utf-8") != b'"\x7f"'


def test_unsafe_characters_anywhere_cannot_escape_the_original_encoder(monkeypatch):
    special = [
        *(chr(code) for code in range(32)), '"', "\\", "\x7f", "\x80",
        "\u00e9", "\U0001f600",
    ]
    values = [
        prefix + character + suffix
        for character in special
        for prefix, suffix in [("", "suffix"), ("prefix", ""), ("prefix", "suffix")]
    ]
    values.extend([
        'safe","injected":true,"tail":"safe', r"prefix\nsuffix",
        'prefix\\"suffix', "safe\r\nsuffix", "safe\tend",
    ])
    expected = [fresh_bytes(value) for value in values]
    nested = {value: ("safe", value) for value in values}
    expected_nested = fresh_bytes(nested)
    original = json.dumps
    calls = []

    def observe(value, **kwargs):
        calls.append((value, kwargs))
        return original(value, **kwargs)

    monkeypatch.setattr(json, "dumps", observe)
    actual = [canonical(value) for value in values]
    assert actual == expected
    assert [json.loads(encoded) for encoded in actual] == values
    assert calls == [
        (value, {"ensure_ascii": False, "separators": (",", ":")})
        for value in values
    ]
    assert canonical(nested) == expected_nested


def test_nested_keys_and_values_match_whole_value_fresh_encoding():
    for code in range(128):
        scalar = chr(code)
        value = {
            "\ue000": {"z": scalar, "a": (None, True, False)},
            "\U0001f600": [scalar, {"mixed": "e\u0301\u00e9\u2028"}],
            scalar: (9007199254740991, -9007199254740991, 0),
        }
        assert canonical(value) == fresh_bytes(value)
    value = {"\ue000": 3, "\U0001f600": 2, "\r": 1}
    expected = '{"\\r":1,"\U0001f600":2,"\ue000":3}'.encode("utf-8")
    assert canonical(value) == fresh_bytes(value) == expected


@pytest.mark.parametrize("value", [
    -9007199254740991, -1, 0, 1, 9007199254740991,
])
def test_integer_boundaries_bypass_scalar_dumps(monkeypatch, value):
    expected = fresh_bytes(value)

    def forbidden(*args, **kwargs):
        pytest.fail("integers must retain the bounded integer writer")

    monkeypatch.setattr(json, "dumps", forbidden)
    assert canonical(value) == expected


@pytest.mark.parametrize("value,kind,reason", [
    (-9007199254740992, ValueError, "integer_out_of_range"),
    (9007199254740992, ValueError, "integer_out_of_range"),
    (1.0, TypeError, "non_json_type"),
    (float("nan"), TypeError, "non_json_type"),
    (float("inf"), TypeError, "non_json_type"),
    (float("-inf"), TypeError, "non_json_type"),
    (b"text", TypeError, "non_json_type"),
    ({1: "text"}, TypeError, "non_string_key"),
    (type("IntegerSubclass", (int,), {})(1), TypeError, "non_json_type"),
    (type("StringSubclass", (str,), {})("x"), TypeError, "non_json_type"),
    (type("ListSubclass", (list,), {})([1]), TypeError, "non_json_type"),
    (type("TupleSubclass", (tuple,), {})((1,)), TypeError, "non_json_type"),
    (type("DictSubclass", (dict,), {})({"x": 1}), TypeError, "non_json_type"),
])
def test_refusal_guards_run_before_any_scalar_dumps(
    monkeypatch, value, kind, reason
):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid input reached json.dumps")

    monkeypatch.setattr(json, "dumps", forbidden)
    with pytest.raises(kind, match=f"^{reason}$"):
        canonical(value)


@pytest.mark.parametrize("value", [
    chr(0xD800), chr(0xDFFF), "x\ud800y", ["\udfff"],
    {"valid": "\ud800"}, {"\udfff": "valid"}, {"nested": {"\ud800": None}},
])
def test_surrogate_refusal_matches_fresh_encoding(value):
    with pytest.raises(UnicodeEncodeError):
        fresh_bytes(value)
    with pytest.raises(UnicodeEncodeError):
        canonical(value)
    assert canonical("after failure") == fresh_bytes("after failure")


def test_repeated_calls_leave_inputs_and_standard_dumps_unchanged():
    shared = [None, True, False, "ascii", "\x7f", "\u00e9", "\U0001f600"]
    value = {"z": shared, "a": {"same": shared}, "n": -9007199254740991}
    snapshot = deepcopy(value)
    key_order = tuple(value)
    ordinary_before = json.dumps(["\u00e9", "\x7f", None, True])
    for _ in range(4):
        assert canonical(value) == fresh_bytes(snapshot)
        with pytest.raises(UnicodeEncodeError):
            canonical({"bad": "\ud800"})
        assert value == snapshot
        assert tuple(value) == key_order
        assert value["z"] is shared and value["a"]["same"] is shared
    shared.append("new content")
    assert canonical(value) == fresh_bytes(value)
    assert canonical(value) != fresh_bytes(snapshot)
    assert json.dumps(["\u00e9", "\x7f", None, True]) == ordinary_before
