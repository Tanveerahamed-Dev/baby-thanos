"""Declared-synthetic frame/model preparation only; no admission, body or production seal."""
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_hsrp_all import BODY, block
from test_parse_hsrp_brief import capture as brief_capture
from test_version_inputs import fixture, plant

from atlas_brain.evidence import p4_admission, synthetic
from atlas_brain.evidence.capture import Capture, Channel, Scope
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser
from atlas_brain.packs.l3.fhrp import version_inputs as inputs
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest

ID, SOURCE, CONTEXT = "cap:prepared", "node:synthetic:a", "round"


class Text(StrEnum):
    CONTEXT = "round"
    ID = "cap:prepared"
    SOURCE = "node:synthetic:a"


def prepare(raw=BODY, **changes):
    return inputs.prepare_version_request(**({"capture_id": ID, "source": SOURCE, "context": CONTEXT, "raw": raw} | changes))


def standby(raw, line):
    old = next(item for item in raw.splitlines(keepends=True) if item.startswith(b"  Standby router is "))
    return raw.replace(old, line + b"\n")


def forbid_replay(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("frame/model helper replayed parser, admission, runtime, Writer or snapshot")
    for module, names in (
        (parser, ("parse_capture", "run_rules")), (pack_runtime, ("execute_parsers",)),
        (p4_admission, ("admit_folder",)), (synthetic, ("admit_members",)),
        (FactWriter, ("write",)), (inputs, ("asdict",)),
        (inputs.custody, ("asdict", "retain_requests", "validate_retained_requests")),
    ):
        for name in names:
            monkeypatch.setattr(module, name, forbidden)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt", "prompt_space"])
@pytest.mark.parametrize("final_lf", [False, True])
def test_fixed_request_preserves_every_original_byte_line_and_model_default_without_replay(monkeypatch, ending, frame, final_lf):
    raw = BODY if frame == "body" else b"show standby all\n" + BODY
    if frame.startswith("prompt"):
        raw = (b"fixture# " if frame == "prompt_space" else b"fixture#") + raw + b"fixture#\n"
    raw = raw.replace(b"\n", ending)
    raw = raw if final_lf else raw[:-len(ending)]
    forbid_replay(monkeypatch)
    validate, calls = inputs.validate_version_request, []
    def checking(request):
        calls.append(request)
        return validate(request)
    monkeypatch.setattr(inputs, "validate_version_request", checking)
    result = prepare(raw)
    sample = result.capture
    assert type(sample) is Capture
    assert calls == [result] and calls[0] is result and type(result) is CaptureRequest
    assert (sample.id, sample.source, result.context) == (ID, SOURCE, CONTEXT)
    assert sample.operation == parser.OP and sample.rendered == parser.COMMAND and sample.codec == "utf-8"
    assert sample.raw is raw and sample.bytes_sha256 == sha256(raw).hexdigest()
    assert sample.integrity is k.IntegrityState.COMPLETE and sample.lines == text_lines(raw, "utf-8")
    assert sample.read_scope is k.ReadScope.UNKNOWN and sample.view is k.ViewConsistency.UNKNOWN and sample.metadata is None
    assert sample.scope == Scope(node=SOURCE, plane="exec", context=None, vrf=None, instance=None, vdc=None, tenant=None, afi=None)
    assert sample.channel is Channel.CLI and type(sample.collected_utc) is k.Unknown
    assert sample.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert inputs.validate_fhrp_request_graph(result) is None


@pytest.mark.parametrize("line", [
    b"  Standby router is unknown",
    b"  Standby router is 192.0.2.2, priority 100 (expires in 1.000 sec)",
])
def test_exact_standby_observation_prefix_remains_a_valid_body_line(line):
    raw = standby(BODY, line)
    result = prepare(raw)
    assert result.capture.integrity is k.IntegrityState.COMPLETE
    parsed = parser.parse_capture(result.capture)
    assert parsed.reason is None and len(parsed.rows) == 1


@pytest.mark.parametrize("raw", [
    standby(BODY, b"  Standby router is 192.0.2.2, priority 100 (expires in 1.000 sec); show clock"),
    standby(BODY, b"  Standby router is opaque malformed body"),
    BODY + b"unrecognised body\n", BODY + b"unrecognised \xc3\xa9\n",
    BODY.replace(b"(version 2)", b"(version 3)"),
])
def test_invalid_body_is_retained_with_complete_framing_for_the_owning_parser(monkeypatch, raw):
    parse = parser.parse_capture
    with monkeypatch.context() as guard:
        forbid_replay(guard)
        result = prepare(raw)
    assert result.capture.raw is raw and result.capture.integrity is k.IntegrityState.COMPLETE
    parsed = parse(result.capture)
    assert parsed.reason is k.UnknownReason.PARSE_PARTIAL and parsed.parse.quality == "partial"
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL for row in parsed.rows)


@pytest.mark.parametrize("raw,expected", [
    (b"", k.IntegrityState.EMPTY), (b"\n \t\r\n", k.IntegrityState.EMPTY),
    (b"show standby all\n", k.IntegrityState.EMPTY), (b"fixture#show standby all\nfixture#\n", k.IntegrityState.EMPTY),
    (BODY + b"% Invalid input detected\n", k.IntegrityState.ERROR),
    (BODY + b" Command authorization failed. \n", k.IntegrityState.ERROR),
    (BODY + b"--More--\n", k.IntegrityState.PAGING_ARTIFACTS),
    (BODY + b"<--- More --->\n", k.IntegrityState.PAGING_ARTIFACTS),
    (BODY + b"--(more)--\n", k.IntegrityState.PAGING_ARTIFACTS),
    (BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED),
    (BODY + b"<OUTPUT TRUNCATED>\n", k.IntegrityState.TRUNCATED),
    (BODY + b"[truncated]\n--More--\n% error\n", k.IntegrityState.ERROR),
    (BODY + b"[truncated]\n--More--\n", k.IntegrityState.PAGING_ARTIFACTS),
    (b"fixture#show standby all\n" + BODY + b"% error\n", k.IntegrityState.ERROR),
    (b"fixture#show standby all\n" + BODY + b"--More--\n", k.IntegrityState.PAGING_ARTIFACTS),
    (b"fixture#show standby all\n" + BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED),
])
def test_integrity_markers_have_exact_precedence_without_claiming_body_completeness(monkeypatch, raw, expected):
    forbid_replay(monkeypatch)
    assert parser.capture_integrity(raw) is expected
    result = prepare(raw)
    assert result.capture.raw is raw and result.capture.integrity is expected
    assert result.capture.lines == text_lines(raw, "utf-8")


@pytest.mark.parametrize("raw", [
    b"fixture#show standby\n" + BODY + b"fixture#\n",
    b"fixture#show standby all\n" + BODY,
    b"fixture#show standby all\n" + BODY + b"other#\n",
    BODY + b"show clock\n", BODY + b"configure terminal\n", BODY + b"!\n",
    BODY + b"\x00", BODY.replace(b"\n", b"\r"), b"\xff",
    BODY + b"sh clock\n", BODY + b"sho clock\n", BODY + b"do show clock\n",
    BODY + b"show standby all\n", BODY + b"fixture#\n",
    BODY + b"fixture(config)#standby 10 ip 192.0.2.1\n",
    BODY + b"standby 10 ip 192.0.2.1\n", BODY + b"  standby 10 ip 192.0.2.1\n",
    BODY + b"banner motd synthetic\n", BODY + b"% error\nconfigure terminal\n",
    BODY + b"\x1b", BODY + b"\x7f", BODY + b"\xc2\x85", BODY + b"\xe2\x80\xa8", BODY + b"\xe2\x80\xa9",
    b"fixture#show standby all\n" + BODY + b"fixture#\nshow clock\n",
])
def test_separate_commands_prompts_config_and_terminal_control_bytes_are_refused(monkeypatch, raw):
    forbid_replay(monkeypatch)
    with pytest.raises(ValueError):
        parser.capture_integrity(raw)
    with pytest.raises(ValueError):
        prepare(raw)


@pytest.mark.parametrize("line", [
    b"   Standby router is unknown", b"\tStandby router is unknown",
    b"  Standby router is", b"  Standby router isX unknown", b"  Standby 10 ip 192.0.2.1",
])
def test_only_the_exact_observation_prefix_is_exempt_from_config_classification(line):
    raw = standby(BODY, line)
    with pytest.raises(ValueError):
        parser.capture_integrity(raw)


@pytest.mark.parametrize("field,value", [
    ("capture_id", ""), ("capture_id", Text.ID), ("capture_id", []),
    ("source", ""), ("source", Text.SOURCE), ("source", []),
    ("context", ""), ("context", None), ("context", Text.CONTEXT), ("context", []),
    ("raw", bytearray(BODY)), ("raw", "body"),
])
def test_public_factory_refuses_nonplain_coordinates_and_mutable_raw_without_replay(monkeypatch, field, value):
    forbid_replay(monkeypatch)
    with pytest.raises(ValueError):
        prepare(**{field: value})


@pytest.mark.parametrize("extra", [{"codec": "ascii"}, {"integrity": k.IntegrityState.COMPLETE},
    {"operation": "iosxe.show_standby_brief"}, {"profile": "other"}, {"mode": "other"}])
def test_factory_exposes_no_caller_selected_classification_or_protocol_flags(extra):
    with pytest.raises(TypeError):
        prepare(**extra)


@pytest.mark.parametrize("operation", ["all", "brief", "unregistered"])
@pytest.mark.parametrize("timed", [False, True])
def test_graph_only_guard_accepts_valid_models_without_operation_scope_or_origin_credentials(monkeypatch, operation, timed):
    _, request = fixture(timed=timed)
    sample = request.capture
    if operation == "brief":
        sample = replace(sample, operation="iosxe.show_standby_brief", rendered="show standby brief")
    metadata = sample.resolved_metadata
    sample = replace(sample, operation="iosxe.other" if operation == "unregistered" else sample.operation,
        rendered="show other" if operation == "unregistered" else sample.rendered,
        metadata=replace(metadata, scope=replace(metadata.scope, vrf="blue", context="declared")))
    request = CaptureRequest(capture=sample, context=CONTEXT)
    forbid_replay(monkeypatch)
    assert inputs.validate_fhrp_request_graph(request) is None
    assert inputs.validate_fhrp_request_graph(replace(request, context=None)) is None
    assert inputs.validate_fhrp_request_graph(replace(request, capture=replace(sample))) is None
    with pytest.raises(ValueError):
        inputs.validate_version_request(request)


@pytest.mark.parametrize("field", [
    "span_start", "span_end_bool", "offsets", "line_text", "scope", "time_endpoint",
    "unknown_needs", "unknown_candidates", "unknown_evidence", "need_params", "need_resolves",
    "fact_subject", "field_pointer", "xml_path", "witness_span", "integrity_evidence", "channel",
])
def test_public_graph_guard_refuses_finite_malformed_builtin_fields_before_any_snapshot(monkeypatch, field):
    item, request = fixture(timed=field == "time_endpoint")
    plant(item, request, field)
    forbid_replay(monkeypatch)
    with pytest.raises(ValueError):
        inputs.validate_fhrp_request_graph(request)


@pytest.mark.parametrize("field", ["request_context", "capture_object", "capture_lines", "capture_raw", "capture_integrity",
    "metadata_error", "metadata_envelope", "registry_digest", "span_bool_alias", "time_bool_alias"])
def test_current_request_metadata_scalar_types_and_equal_boolean_aliases_are_closed(monkeypatch, field):
    _, request = fixture(timed=field == "time_bool_alias")
    sample, metadata = request.capture, request.capture.metadata
    if field == "request_context":
        object.__setattr__(request, "context", [])
    elif field == "capture_object":
        object.__setattr__(request, "capture", object())
    elif field in ("capture_lines", "capture_raw", "capture_integrity"):
        name = field.removeprefix("capture_")
        object.__setattr__(sample, name, list(sample.lines) if name == "lines" else bytearray(sample.raw) if name == "raw" else "complete")
    elif field in ("metadata_error", "metadata_envelope"):
        object.__setattr__(metadata, field.removeprefix("metadata_"), "timeout" if field.endswith("error") else [])
    elif field == "registry_digest":
        reference = next(ref for ref in metadata.read_scope_evidence if type(ref) is k.RegistryRef)
        object.__setattr__(reference, "table_digest", [])
    elif field == "span_bool_alias":
        assert sample.lines[0].span.start == 0
        object.__setattr__(sample.lines[0].span, "start", False)
    else:
        time = TimeInterval(earliest=0, latest=2, clock="collector:fixture", bound=BoundSource.COLLECTOR_RECORDED)
        sample = replace(sample, metadata=replace(metadata, collected_utc=time))
        request = replace(request, capture=sample)
        object.__setattr__(time, "earliest", False)
    forbid_replay(monkeypatch)
    with pytest.raises(ValueError):
        inputs.validate_fhrp_request_graph(request)


@pytest.mark.parametrize("value", [object(), None])
def test_graph_guard_requires_an_actual_capture_request(value):
    with pytest.raises(ValueError):
        inputs.validate_fhrp_request_graph(value)


@pytest.mark.parametrize("raw", [bytearray(BODY), memoryview(BODY), "body", None])
def test_direct_classifier_requires_immutable_bytes_before_decoding_or_model_work(monkeypatch, raw):
    forbid_replay(monkeypatch)
    with pytest.raises(ValueError):
        parser.capture_integrity(raw)


def test_actual_brief_model_graph_is_supported_without_preparation_or_parser_replay(monkeypatch):
    request = CaptureRequest(capture=brief_capture(), context=CONTEXT)
    forbid_replay(monkeypatch)
    assert inputs.validate_fhrp_request_graph(request) is None


def test_multiple_detail_blocks_and_blank_separators_are_preserved_without_body_dispatch(monkeypatch):
    raw = BODY + b"\n\t\n" + block("1", "Vlan20", "1") + block("2", "BD3329", "129")
    forbid_replay(monkeypatch)
    result = prepare(raw)
    assert result.capture.raw is raw and result.capture.lines == text_lines(raw, "utf-8")
    assert result.capture.integrity is k.IntegrityState.COMPLETE
