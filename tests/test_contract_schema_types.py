"""Schema capabilities required by actual merged kernel evidence declarations."""
import pytest

from atlas_brain.kernel.states import Evidence, EvidenceNeed, Fact
from tools.contract_schema import schema_for


def test_actual_kernel_evidence_alias_generates_closed_record_alternatives():
    schema = schema_for(Evidence, "0.1.0")
    assert schema["anyOf"] == [{"$ref": f"#/$defs/{name}"}
        for name in ("EvidenceRef", "FactRef", "RegistryRef")]
    definitions = schema["$defs"]
    for name in ("EvidenceRef", "FactRef", "RegistryRef"):
        assert definitions[name]["additionalProperties"] is False
    assert definitions["FactRef"]["properties"] == {
        "fact": {"type": "string"}, "subject": {"type": "string"}}
    assert {"ByteSpan", "FieldPointer", "XmlPath", "WholeCapture"} <= set(definitions)


def test_actual_kernel_evidence_need_preserves_parameter_pair_cardinality():
    schema = schema_for(EvidenceNeed, "0.1.0")
    record = schema["$defs"]["EvidenceNeed"]
    assert record["required"] == ["node", "operation", "params", "resolves", "reruns",
        "after_s", "unprintable"]
    assert record["properties"]["params"] == {"type": "array", "items": {
        "type": "array", "prefixItems": [{"type": "string"}, {"type": "string"}],
        "minItems": 2, "maxItems": 2}}
    assert {"type": "null"} in record["properties"]["after_s"]["anyOf"]


def test_fixed_tuple_positions_and_empty_tuple_are_explicit():
    shape = schema_for(tuple[str, int], "0.1.0")
    assert shape["type"] == "array"
    assert shape["prefixItems"] == [{"type": "string"}, {
        "type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}]
    assert shape["minItems"] == shape["maxItems"] == 2
    empty = schema_for(tuple[()], "0.1.0")
    assert empty["type"] == "array" and empty["maxItems"] == 0
    assert "prefixItems" not in empty


@pytest.mark.parametrize("annotation", [list[str], tuple[str, ...]])
def test_homogeneous_arrays_keep_the_existing_unbounded_shape(annotation):
    shape = schema_for(annotation, "0.1.0")
    assert shape["type"] == "array" and shape["items"] == {"type": "string"}
    assert "prefixItems" not in shape and "maxItems" not in shape


@pytest.mark.parametrize("annotation", [list, list[()], list[str, int], dict, dict[()],
    dict[str], dict[str, int, bool], dict[int, str], tuple, tuple[int, ..., str],
    tuple[int, float], tuple[set[str], ...], Fact[int]])
def test_malformed_or_unsupported_generic_shapes_refuse(annotation):
    with pytest.raises(TypeError, match="unsupported_contract_type"):
        schema_for(annotation, "0.1.0")


@pytest.mark.parametrize("annotation", [tuple[str, int, ...], tuple[str, float, ...],
    tuple[str, ..., ...], tuple[..., str, ...], list[tuple[str, int, ...]],
    dict[str, tuple[str, int, ...]]])
def test_variadic_tuple_requires_exactly_one_element_type(annotation):
    with pytest.raises(TypeError, match="unsupported_contract_type"):
        schema_for(annotation, "0.1.0")
