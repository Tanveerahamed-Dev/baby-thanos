"""Synthetic VRRP request framing; COMPLETE is not body truth, admission or population closure."""
from copy import deepcopy
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_vrrp import BODY, block, capture
from test_peer_execution import forbidden

from atlas_brain.evidence.capture import Channel, Scope
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import vrrp_inputs as inputs
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest


def prepare(raw=BODY, **changes):
    return inputs.prepare_vrrp_request(**({"capture_id": "cap:caller", "source": "node:synthetic:a",
        "context": "round", "raw": raw} | changes))


def freeze(monkeypatch):
    for module, name in ((profile.parser, "parse_capture"), (profile.parser, "run_rules"),
            (pack_runtime, "execute_parsers"), (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


@pytest.fixture
def baseline(monkeypatch):
    freeze(monkeypatch)
    request = prepare()
    assert request.capture.integrity is k.IntegrityState.COMPLETE
    assert inputs.validate_vrrp_request(request) is None
    return request


def custody(request, raw):
    sample = request.capture
    assert type(request) is CaptureRequest and sample.raw is raw
    assert (sample.id, sample.source, request.context) == ("cap:caller", "node:synthetic:a", "round")
    assert (sample.operation, sample.rendered, sample.codec) == ("iosxe.show_vrrp", "show vrrp", "utf-8")
    assert sample.lines == text_lines(raw, "utf-8") and sample.bytes_sha256 == sha256(raw).hexdigest()
    assert sample.byte_len == len(raw) and sample.metadata is None and sample.error is None
    assert sample.channel is Channel.CLI and sample.envelope is None
    assert sample.scope == Scope(node=sample.source, plane="exec", vrf=None, context=None,
        vdc=None, tenant=None, afi=None, instance=None)
    assert sample.read_scope is k.ReadScope.UNKNOWN and sample.view is k.ViewConsistency.UNKNOWN
    assert sample.read_scope_evidence == ()
    witness, = sample.integrity_evidence
    assert witness.capture == sample.id and type(witness.locator) is k.WholeCapture
    assert witness.role is k.EvidenceRole.SUBJECT and witness.excerpt_sha256 == sha256(raw).hexdigest()
    time = sample.collected_utc
    assert type(time) is k.Unknown and time.reason is k.UnknownReason.AS_OF_MISSING
    assert time.detail == "no_collector_time" and time.evidence == (witness,)
    assert time.candidates == time.next_evidence == ()
    assert inputs.validate_vrrp_request(request) is None


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("final_newline", [False, True])
@pytest.mark.parametrize("frame", ["body", "command", "prompt", "spaced_prompt", "user_prompt"])
@pytest.mark.parametrize("state", ["Init", "INIT", "Master", "MASTER", "Backup", "BACKUP"])
def test_original_supported_frames_state_spellings_and_line_endings_keep_all_bytes(baseline, ending, final_newline, frame, state):
    raw = block(state=state)
    if frame == "command":
        raw = b"show vrrp\n" + raw
    elif frame != "body":
        prompt = b"synthetic-a>" if frame == "user_prompt" else b"synthetic-a#"
        raw = prompt + (b" " if frame == "spaced_prompt" else b"") + b"show vrrp\n" + raw + prompt + b"\n"
    raw = raw.replace(b"\n", ending)
    if not final_newline:
        raw = raw[:-len(ending)]
    request = prepare(raw)
    assert inputs.classify_vrrp_frame(raw) is request.capture.integrity is k.IntegrityState.COMPLETE
    custody(request, raw)
    assert request == deepcopy(request) and inputs.validate_vrrp_request(replace(request)) is None


@pytest.mark.parametrize("raw,expected", [
    (b"", k.IntegrityState.EMPTY), (b" \t\r\n", k.IntegrityState.EMPTY),
    (b"show vrrp\n", k.IntegrityState.EMPTY),
    (b"synthetic-a#show vrrp\nsynthetic-a#\n", k.IntegrityState.EMPTY),
    (b"synthetic-a#show vrrp\n" + BODY, k.IntegrityState.UNVERIFIED_PROMPT),
    (BODY + b"synthetic-a#\n", k.IntegrityState.UNVERIFIED_PROMPT),
    (b"show vrrp\n" + BODY + b"synthetic-a#\n", k.IntegrityState.UNVERIFIED_PROMPT),
    (b"synthetic-a#show vrrp\n", k.IntegrityState.UNVERIFIED_PROMPT),
    (b"synthetic-a#\n", k.IntegrityState.UNVERIFIED_PROMPT),
    (b"not a recognized heading\n", k.IntegrityState.UNKNOWN_FORMAT),
    ("unmodelled printable \u00e9\n".encode(), k.IntegrityState.UNKNOWN_FORMAT),
    (b" Vlan61 - Group 100\n", k.IntegrityState.UNKNOWN_FORMAT),
    (block(group="9" * 65), k.IntegrityState.UNKNOWN_FORMAT),
    (BODY + b"% synthetic error\n--More--\n[truncated]\n", k.IntegrityState.ERROR),
    (BODY + b"Command authorization failed.\n", k.IntegrityState.ERROR),
    (BODY + b"<--- MORE --->\n[truncated]\n", k.IntegrityState.PAGING_ARTIFACTS),
    (BODY + b"--(more)--\n", k.IntegrityState.PAGING_ARTIFACTS),
    (BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED),
    (BODY + b"<output truncated>\n", k.IntegrityState.TRUNCATED),
    (b"synthetic-a#show vrrp\n" + BODY + b"% synthetic error\n", k.IntegrityState.ERROR),
    (b"synthetic-a#show vrrp\n" + BODY + b"--More--\n", k.IntegrityState.PAGING_ARTIFACTS),
    (b"synthetic-a#show vrrp\n" + BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED),
])
def test_damage_empty_unknown_and_uncertain_prompt_priority_never_invents_complete(baseline, raw, expected):
    request = prepare(raw)
    assert inputs.classify_vrrp_frame(raw) is request.capture.integrity is expected
    assert expected is not k.IntegrityState.COMPLETE
    custody(request, raw)


@pytest.mark.parametrize("raw", [
    b"show vrrp brief\n" + BODY, b"show standby brief\n" + BODY, b"sh vrrp\n" + BODY,
    b"sho vrrp\n" + BODY, b"do show vrrp\n" + BODY, b"SHOW VRRP\n" + BODY,
    b" show vrrp\n" + BODY, b"show vrrp \n" + BODY, b"show\tvrrp\n" + BODY,
    b"synthetic-a#  show vrrp\n" + BODY + b"synthetic-a#\n",
    b"synthetic-a#show vrrp\n" + BODY + b"other#\n",
    b"synthetic-a#show vrrp\n" + BODY + b"synthetic-a>\n",
    BODY + b"synthetic-a#\n" + BODY, BODY + b"show vrrp\n",
    b"synthetic-a(config)#show vrrp\n" + BODY,
    BODY.replace(b"\n", b"\r\n") + b"Building configuration...\r\n",
    BODY + b"Building configuration... \tadditional synthetic text\n",
    *[BODY + line + b"\n" for line in (b"!", b"end", b"exit", b"configure terminal",
        b"Building configuration...", b"Current configuration:", b"banner motd ^", b"interface Vlan61",
        b"router ospf 1", b"vlan 61", b"hostname synthetic-a", b"spanning-tree mode rapid-pvst",
        b"switchport mode trunk", b"standby 100 ip 198.51.100.41", b"vrrp 100 ip 198.51.100.41",
        b"description config", b"shutdown", b"no shutdown", b"default interface Vlan61")],
])
def test_foreign_commands_config_and_interior_or_mismatched_prompts_refuse_before_error_markers(baseline, raw):
    for contaminated in (raw, raw + b"% synthetic error\n"):
        with pytest.raises(ValueError, match="^vrrp_inputs_frame$"):
            inputs.classify_vrrp_frame(contaminated)
        with pytest.raises(ValueError, match="^vrrp_inputs_frame$"):
            prepare(contaminated)


@pytest.mark.parametrize("raw", [BODY.replace(b"\n", b"\r"), BODY + b"\xff", BODY + b"\x00",
    BODY + b"\x1b[0m", BODY + b"\x7f", BODY + "\u0085".encode(), BODY + "\u2028".encode(),
    BODY + "\u2029".encode(), BODY + b"\x0b", BODY + b"\x0c"])
def test_invalid_utf8_controls_and_lone_cr_are_never_silently_rewritten(baseline, raw):
    with pytest.raises(ValueError, match="^vrrp_inputs_frame$"):
        prepare(raw)
    with pytest.raises(ValueError, match="^vrrp_inputs_frame$"):
        inputs.classify_vrrp_frame(raw)


class TextAlias(str):
    pass


class BytesAlias(bytes):
    pass


@pytest.mark.parametrize("raw", [None, [], {}, "text", bytearray(BODY), memoryview(BODY), BytesAlias(BODY)])
def test_raw_requires_exact_immutable_bytes_before_decoding(baseline, raw):
    with pytest.raises(ValueError, match="^vrrp_inputs_frame$"):
        inputs.classify_vrrp_frame(raw)
    with pytest.raises(ValueError, match="^vrrp_inputs_frame$"):
        prepare(raw)


@pytest.mark.parametrize("field", ["capture_id", "source", "context"])
@pytest.mark.parametrize("value", ["", None, [], {}, False, 1, TextAlias("alias"), StrEnum("Alias", {"VALUE": "alias"}).VALUE])
def test_caller_coordinates_are_finite_nonempty_plain_strings_before_frame_work(baseline, monkeypatch, field, value):
    monkeypatch.setattr(inputs, "classify_vrrp_frame", forbidden)
    with pytest.raises(ValueError, match="^vrrp_inputs_request$"):
        prepare(**{field: value})


@pytest.mark.parametrize("field,value", [("integrity", k.IntegrityState.COMPLETE), ("prompt_verified", True),
    ("succeeded", "yes"), ("metadata", None), ("operation", "iosxe.show_vrrp"), ("rendered", "show vrrp"),
    ("codec", "ascii"), ("read_scope", k.ReadScope.UNKNOWN), ("profile", profile.DECLARATION)])
def test_callers_cannot_supply_classification_metadata_commands_or_profiles(baseline, field, value):
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        prepare(**{field: value})
    with pytest.raises(TypeError, match="positional"):
        inputs.prepare_vrrp_request("cap:caller", "node:synthetic:a", "round", BODY)


@pytest.mark.parametrize("field", ["PACK", "REPORTED_VRRP_STATE", "OP", "COMMAND", "SYNTHETIC_GROUPS", "STEP", "BINDING", "DECLARATION"])
def test_both_entry_points_reclose_current_fixed_metadata_without_cached_profile(baseline, monkeypatch, field):
    module = profile.parser if field in ("OP", "COMMAND", "SYNTHETIC_GROUPS") else profile
    original = getattr(module, field)
    value = StrEnum("Alias", {"VALUE": original}).VALUE if type(original) is str else (
        ("101",) if field == "SYNTHETIC_GROUPS" else replace(original, **(
            {"evaluator": "l3.fhrp.other"} if field == "STEP" else {"operation": "iosxe.other"} if field == "BINDING"
            else {"steps": ()})))
    monkeypatch.setattr(module, field, value)
    with pytest.raises(ValueError, match="^vrrp_profile$"):
        inputs.classify_vrrp_frame(BODY)
    with pytest.raises(ValueError, match="^vrrp_profile$"):
        prepare()


@pytest.mark.parametrize("raw", [BODY.splitlines(keepends=True)[0], BODY[:-12], BODY.replace(b"Backup", b"Active"),
    block(group="200"), block(group="abc"), BODY.replace(b"Group 100", b"Group 100 - Address-Family IPv6"),
    BODY.replace(b"198.51.100.41", b"2001:db8::1"), BODY + BODY])
def test_recognized_frame_is_not_body_semantics_or_positive_state(monkeypatch, raw):
    assert profile.parser.parse_capture(capture()).reason is None
    parsed = profile.parser.parse_capture(capture(raw))
    assert parsed.reason is not None and parsed.parse.quality == "partial"
    assert all(row.reason is parsed.reason for row in parsed.rows)
    freeze(monkeypatch)
    request = prepare(raw)
    assert request.capture.integrity is k.IntegrityState.COMPLETE
    custody(request, raw)


@pytest.mark.parametrize("name", ["vrrp", "interface", "router", "vlan", "show", "building"])
def test_keyword_shaped_interface_headings_remain_frames_instead_of_config_commands(baseline, name):
    raw = block(interface=name)
    assert prepare(raw).capture.integrity is k.IntegrityState.COMPLETE


def test_two_blocks_blank_lines_and_caller_owned_coordinate_copies_remain_distinct(baseline):
    raw = b"\n\t\n" + BODY + b" \t\n" + block("Vl61", "101", "Master") + b"\n"
    request = prepare(raw)
    custody(request, raw)
    other = prepare(raw, capture_id="cap:other", source="node:synthetic:b", context="other")
    assert other.capture.raw is raw and other.capture.bytes_sha256 == request.capture.bytes_sha256
    assert (other.capture.id, other.capture.source, other.context) == ("cap:other", "node:synthetic:b", "other")
    assert other.capture.scope.node == other.capture.source and other.capture.scope.context is None
    assert other is not request and other.capture is not request.capture
    assert prepare(raw) == request


@pytest.mark.parametrize("field,code", [("operation_alias", "hsrp_version_inputs_capture"),
    ("rendered_alias", "hsrp_version_inputs_capture"), ("raw_alias", "hsrp_version_inputs_capture"),
    ("line_drop", "hsrp_version_inputs_line"), ("context_alias", "pack_receipts_context"),
    ("scope", "vrrp_inputs_request"), ("time_candidates", "hsrp_version_inputs_unknown")])
def test_prepared_current_graph_still_rejects_aliases_nested_damage_and_scope_drift(baseline, field, code):
    request = deepcopy(baseline)
    sample = request.capture
    if field in ("operation_alias", "rendered_alias"):
        name = field.removesuffix("_alias")
        object.__setattr__(sample, name, StrEnum("Alias", {"VALUE": getattr(sample, name)}).VALUE)
    elif field == "raw_alias":
        object.__setattr__(sample, "raw", BytesAlias(sample.raw))
    elif field == "line_drop":
        object.__setattr__(sample, "lines", sample.lines[:-1])
    elif field == "context_alias":
        object.__setattr__(request, "context", TextAlias(request.context))
    else:
        metadata = sample.resolved_metadata
        object.__setattr__(sample, "metadata", metadata)
        if field == "scope":
            object.__setattr__(metadata.scope, "vrf", "other")
        else:
            object.__setattr__(metadata.collected_utc, "candidates", ([],))
    with pytest.raises(ValueError, match="^" + code + "$"):
        inputs.validate_vrrp_request(request)
