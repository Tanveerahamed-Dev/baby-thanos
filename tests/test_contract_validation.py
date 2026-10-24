"""A standard consumer checks generated schemas and actual wire bytes offline."""
import json
import socket
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, SchemaError, ValidationError

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.header import (
    AnalysisAsOf,
    EffectiveSemantics,
    ResultHeader,
    encode_header,
)
from atlas_brain.kernel.states import EntityKey, Evidence, EvidenceNeed
from tools.contract_schema import schema_for
from tools.fence import source_allowed
from tools.publish_contract_schema import generated_header
from tools.validate_contract import validate_wire


def header():
    return ResultHeader(schema="atlas-brain.result", schema_version="0.1.0",
        semantics={"core": 1}, effective_semantics=EffectiveSemantics(packs={}, checks={}),
        catalogue_digest="a" * 64, pack_build_fingerprints={},
        input_manifest_sha256="b" * 64, options_sha256="c" * 64,
        analysis_as_of=AnalysisAsOf(utc=None, source="unknown", evidence=()), status="incomplete")


@pytest.mark.parametrize("root", [ResultHeader, Evidence, EvidenceNeed, tuple[str, int], tuple[()]])
def test_generated_schemas_pass_the_real_202012_metaschema(root):
    Draft202012Validator.check_schema(schema_for(root, "0.1.0"))


def test_real_encoded_header_validates_and_stays_incomplete():
    data = encode_header(header())
    validate_wire(generated_header(), data)
    assert json.loads(data)["status"] == "incomplete"


@pytest.mark.parametrize("field,value", [("status", "ok"), ("schema_version", "0.2.0"),
    ("semantics", {"core": True}), ("effective_semantics", {"packs": {}, "checks": {"a": 1}}),
    ("analysis_as_of", {"utc": None, "source": "clock", "evidence": []}),
    ("options_sha256", 1), ("timing_ms", 1)])
def test_published_shape_refuses_malformed_instances(field, value):
    instance = json.loads(encode_header(header()))
    instance[field] = value
    with pytest.raises(ValidationError):
        validate_wire(generated_header(), canonical(instance))


def test_missing_required_header_field_is_not_success():
    instance = json.loads(encode_header(header()))
    del instance["status"]
    with pytest.raises(ValidationError):
        validate_wire(generated_header(), canonical(instance))


@pytest.mark.parametrize("wire", [b'["key"]', b'["key",1,2]', b'[1,"key"]'])
def test_fixed_tuple_consumer_refuses_wrong_cardinality_or_position(wire):
    with pytest.raises(ValidationError):
        validate_wire(schema_for(tuple[str, int], "0.1.0"), wire)


def test_kernel_evidence_need_jsonl_and_empty_stream_validate():
    need = EvidenceNeed(node=EntityKey("node:sw-a"), operation="example.read",
        params=(("interface", "x"),), resolves=("example.fact",), reruns=("example.check",),
        after_s=None, unprintable=())
    schema = schema_for(EvidenceNeed, "0.1.0")
    data = canonical(asdict(need))
    validate_wire(schema, data + b"\n", jsonl=True)
    validate_wire(schema, b"", jsonl=True)
    broken = json.loads(data)
    broken["params"] = [["interface", 1]]
    with pytest.raises(ValidationError):
        validate_wire(schema, canonical(broken) + b"\n", jsonl=True)


@pytest.mark.parametrize("wire,jsonl", [(b'{ "value":1}', False),
    (b'\xef\xbb\xbf{}', False), (b'{}\n', False), (b'{}', True),
    (b'{}\r\n', True), (b'{}\n\n', True)])
def test_noncanonical_bytes_and_jsonl_framing_refuse(wire, jsonl):
    with pytest.raises(ValueError):
        validate_wire({"type": "object"}, wire, jsonl=jsonl)


@pytest.mark.parametrize("wire", [b'1.0', b'NaN', b'Infinity', b'9007199254740992'])
def test_contract_numeric_policy_is_stricter_than_schema_integer_semantics(wire):
    with pytest.raises((ValueError, TypeError)):
        validate_wire({"type": "integer"}, wire)


@pytest.mark.parametrize("schema", [{"$ref": "https://example.invalid/schema"},
    {"$id": "https://example.invalid/schema", "$ref": "#"},
    {"$defs": {"R": {"$dynamicRef": "https://example.invalid/schema"}}}])
def test_external_schema_references_refuse_before_any_network(monkeypatch, schema):
    def network_forbidden(*args, **kwargs):
        raise AssertionError("network_attempted")
    monkeypatch.setattr(socket, "socket", network_forbidden)
    with pytest.raises(ValueError, match="external_schema_reference"):
        validate_wire(schema, b"{}")
    validate_wire(generated_header(), encode_header(header()))


def test_validator_dependency_is_not_admitted_to_runtime_engine():
    assert not source_allowed("from jsonschema import Draft202012Validator", path="atlas_brain/contract/probe.py")


def test_real_consumer_cli_success_and_refusal(tmp_path):
    path = tmp_path / "result.json"
    path.write_bytes(encode_header(header()))
    command = [sys.executable, "-m", "tools.validate_contract", str(path)]
    assert subprocess.run(command, capture_output=True, check=False).returncode == 0
    path.write_bytes(b"{}")
    failed = subprocess.run(command, capture_output=True, check=False)
    assert failed.returncode == 1
    assert b"contract validation refused" in failed.stdout
    assert Path("docs/contract/header.schema.json").is_file()

def test_invalid_schema_is_not_a_vacuous_empty_jsonl_success():
    with pytest.raises(SchemaError):
        validate_wire({"type": "not_a_json_type"}, b"", jsonl=True)
