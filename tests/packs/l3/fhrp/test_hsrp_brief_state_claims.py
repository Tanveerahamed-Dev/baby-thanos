"""Byte-anchored typed state mapping only; no row, AF, completeness, origin or admission claim."""
from dataclasses import asdict, replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_hsrp_brief import BODY, capture

from atlas_brain.evidence.parsekit.rules import Captured
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as parser
from atlas_brain.runner import pack_runtime


class Text(StrEnum):
    SUBJECT = "subject"
    RAW = "Active"
    VALUE = "active"
    CODEC = "utf-8"
    IDENTIFIER = "cap:typed"


def original(raw=BODY):
    sample = capture(raw)
    return sample, parser.parse_capture(sample)


def anchored(word, value, integrity=k.IntegrityState.COMPLETE):
    raw = word.encode("ascii")
    sample = capture(raw, integrity)
    point = k.ByteSpan(start=0, end=len(raw))
    if value is None:
        ref = k.EvidenceRef(capture=sample.id, locator=point, role=k.EvidenceRole.SUBJECT, excerpt_sha256=sha256(raw).hexdigest())
        value = k.Unknown(reason=k.UnknownReason.PARSE_PARTIAL, detail="unmapped_token",
            evidence=(ref,), candidates=(), next_evidence=())
    return sample, Captured(word, point, value)


@pytest.mark.parametrize("word,value", [("Init", parser.State.INIT), ("Active", parser.State.ACTIVE),
    ("Standby", parser.State.STANDBY), ("Listen", None), ("ACTIVE", None)])
@pytest.mark.parametrize("integrity", [k.IntegrityState.COMPLETE, k.IntegrityState.TRUNCATED])
def test_one_byte_anchor_returns_original_typed_mapping_without_parser_writer_or_table_claim(monkeypatch, word, value, integrity):
    sample, token = anchored(word, value, integrity)
    before = sample.raw, asdict(token)
    def forbidden(*args, **kwargs):
        pytest.fail("token validation replayed parser, runtime or Writer")
    monkeypatch.setattr(parser, "parse_capture", forbidden)
    monkeypatch.setattr(parser, "run_rules", forbidden)
    monkeypatch.setattr(pack_runtime, "execute_parsers", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    assert parser.validate_state_token_claim(sample, token) is token.value
    assert type(token.value) is (parser.State if value is not None else k.Unknown)
    assert (sample.raw, asdict(token)) == before


def test_equal_mapped_token_and_span_copies_remain_valid_byte_anchors_without_origin_credentials():
    sample, token = anchored("Active", parser.State.ACTIVE)
    copied = replace(token, span=replace(token.span))
    assert copied is not token and copied.span is not token.span and copied == token
    assert parser.validate_state_token_claim(sample, copied) is parser.State.ACTIVE


@pytest.mark.parametrize("field", ["reason", "detail", "candidates", "next_evidence", "capture", "role", "hash", "locator", "evidence"])
def test_unmapped_unknown_must_keep_canonical_owning_state_evidence(field):
    sample, result = original(BODY.replace(b"Init", b"Listen"))
    token, value = result.rows[0].state, result.rows[0].state.value
    ref, = value.evidence
    if field in ("reason", "detail", "candidates", "next_evidence", "evidence"):
        changes = {"reason": k.UnknownReason.NOT_OBSERVABLE, "detail": "forged", "candidates": ("init",),
            "next_evidence": (object(),), "evidence": ()}
        value = replace(value, **{field: changes[field]}) if field not in ("next_evidence", "evidence") else value
        if field in ("next_evidence", "evidence"):
            object.__setattr__(value, field, changes[field])
    else:
        changes = {"capture": "cap:wrong", "role": Text.SUBJECT, "hash": "0" * 64, "locator": replace(token.span)}
        ref = replace(ref, **{("excerpt_sha256" if field == "hash" else field): changes[field]}) if field != "role" else ref
        if field == "role":
            ref = replace(ref)
            object.__setattr__(ref, "role", Text.SUBJECT)
        value = replace(value, evidence=(ref,))
    with pytest.raises(ValueError):
        parser.validate_state_token_claim(sample, replace(token, value=value))


@pytest.mark.parametrize("field,changed", [("operation", "iosxe.other"), ("rendered", "show standby"), ("codec", "latin-1"), ("raw", bytearray(BODY))])
def test_capture_form_and_raw_type_are_not_granted_by_a_typed_carrier(field, changed):
    sample, result = original()
    object.__setattr__(sample, field, changed)
    with pytest.raises(ValueError):
        parser.validate_state_token_claim(sample, result.rows[0].state)


@pytest.mark.parametrize("field,value", [
    ("id", ""), ("id", 1), ("id", Text.IDENTIFIER), ("codec", Text.CODEC),
    ("token.raw", Text.RAW), ("token.raw", ""), ("token.raw", "A"), ("token.raw", "ActiveActiveActive"),
    ("token.raw", "Act1ve"), ("token.raw", "\u00c4ctive"),
    ("token.value", "active"), ("token.value", Text.VALUE), ("token.value", parser.State.INIT),
    ("span.start", False), ("span.start", []), ("span.end", 999), ("span", object()),
])
def test_typed_carriers_cannot_replace_plain_inputs_lexeme_bounds_or_mapped_enum(field, value):
    sample, token = anchored("Active", parser.State.ACTIVE)
    if field.startswith("token."):
        object.__setattr__(token, field.removeprefix("token."), value)
    elif field.startswith("span."):
        object.__setattr__(token.span, field.removeprefix("span."), value)
    elif field == "span":
        object.__setattr__(token, "span", value)
    else:
        object.__setattr__(sample, field, value)
    with pytest.raises(ValueError):
        parser.validate_state_token_claim(sample, token)


@pytest.mark.parametrize("part", ["capture", "token", "unmapped_value", "raw_mismatch", "negative_span"])
def test_actual_capture_token_shape_and_unmapped_value_are_required(part):
    sample, token = anchored("Listen", None)
    if part == "capture":
        sample = object()
    elif part == "token":
        token = object()
    elif part == "unmapped_value":
        object.__setattr__(token, "value", parser.State.ACTIVE)
    elif part == "negative_span":
        object.__setattr__(token.span, "start", -1)
    else:
        object.__setattr__(sample, "raw", b"Lixten")
    with pytest.raises(ValueError):
        parser.validate_state_token_claim(sample, token)
