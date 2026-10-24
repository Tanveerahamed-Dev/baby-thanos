"""Planted contract violations; acceptance runs on the pinned hosted interpreter."""
from dataclasses import dataclass
from typing import Literal

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest
from tools.contract_schema import schema_for, verify_revision


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf"),
    {"nested": [0.5]}, 9007199254740992, -9007199254740992,
    "\ud800", {"\udfff": 1}, {1: "bad"}, {"x": object()}, {1, 2}])
def test_writer_refuses_planted_values(value):
    with pytest.raises((ValueError, TypeError, UnicodeError)):
        canonical(value)


def test_rfc8785_utf16_key_order_and_escapes():
    value = {"\ue000": 3, "\U0001f600": 2, "\r": "\b\t\n\f\r\x00\x1f\"\\/"}
    assert canonical(value) == ('{"\\r":"\\b\\t\\n\\f\\r\\u0000\\u001f\\\"\\\\/",'
        '"\U0001f600":2,"\ue000":3}').encode()
    assert canonical({"b": [True, None, False], "a": -9007199254740991}) == (
        b'{"a":-9007199254740991,"b":[true,null,false]}')
    assert canonical(9007199254740991) == b"9007199254740991"
    assert canonical("e\u0301") != canonical("\u00e9")


def test_manifest_known_hash_and_sorted_posix_paths():
    files = {"result.json": b"{}", "facts/node.jsonl": b""}
    assert manifest(files) == (
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  facts/node.jsonl\n"
        b"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a  result.json\n")
    assert manifest(dict(reversed(list(files.items())))) == manifest(files)


@pytest.mark.parametrize("name", ["../x.json", "/x.json", "facts//x.jsonl",
    "facts\\x.jsonl", "facts/../x.jsonl", "result.json\nother", "MANIFEST.sha256",
    "Facts/node.jsonl", "receipt.json", "facts/x.jsonl\x00"])
def test_manifest_refuses_unsafe_or_noncontract_names(name):
    with pytest.raises(ValueError):
        manifest({"result.json": b"{}", name: b""})
    with pytest.raises(ValueError):
        manifest({"facts/node.jsonl": b""})


@dataclass(frozen=True, slots=True)
class Sample:
    schema_version: Literal["0.1.0"]
    counter: int
    labels: tuple[str, ...]


def test_schema_is_202012_generated_and_integer_bounded():
    schema = schema_for(Sample, "0.1.0")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    root = schema["$defs"]["Sample"]
    assert root["required"] == ["schema_version", "counter", "labels"]
    assert root["additionalProperties"] is False
    assert root["properties"]["counter"] == {
        "type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}
    assert root["properties"]["labels"] == {"type": "array", "items": {"type": "string"}}
    verify_revision(schema, schema)
    changed = schema_for(Sample, "0.1.0")
    changed["$defs"]["Sample"]["properties"]["extra"] = {"type": "string"}
    with pytest.raises(ValueError, match="schema_version"):
        verify_revision(schema, changed)
    changed["x-schema-version"] = "0.2.0"
    verify_revision(schema, changed)


@pytest.mark.parametrize("annotation", [float, set[str], object, tuple[int, ..., str]])
def test_schema_fails_closed_on_unsupported_types(annotation):
    with pytest.raises(TypeError):
        schema_for(annotation, "0.1.0")


def test_canonical_recursive_roundtrip_property():
    import json

    from hypothesis import given
    from hypothesis import strategies as st
    strings = st.text(st.characters(exclude_categories=("Cs",)))
    leaves = st.none() | st.booleans() | st.integers(-9007199254740991, 9007199254740991) | strings
    values = st.recursive(leaves, lambda v: st.lists(v) | st.dictionaries(strings, v), max_leaves=30)

    @given(values)
    def roundtrip(value):
        encoded = canonical(value)
        assert canonical(json.loads(encoded)) == encoded
    roundtrip()

@pytest.mark.parametrize("value,expected", [
    (None, b"null"), (True, b"true"), (False, b"false"), (0, b"0"), (-1, b"-1"),
    ("text", b'"text"'), ([], b"[]"), ((), b"[]"), ({}, b"{}"),
    ((True, 1, None), b"[true,1,null]"),
    ({"z": {"b": False, "a": []}, "a": (0, "x")},
        b'{"a":[0,"x"],"z":{"a":[],"b":false}}'),
])
def test_writer_structural_dispatch_preserves_canonical_bytes(value, expected):
    assert canonical(value) == expected


@pytest.mark.parametrize("value", [type("IntegerSubclass", (int,), {})(1),
    type("StringSubclass", (str,), {})("text"), type("ListSubclass", (list,), {})([1]),
    type("DictionarySubclass", (dict,), {})({"a": 1})])
def test_writer_rejects_python_subclasses_before_dispatch(value):
    with pytest.raises(TypeError, match="non_json_type"):
        canonical(value)
