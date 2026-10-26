"""Generated thin CLI controls; no imported public fixture or device claims."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.mtu import parse as parser

P, Q = "GigabitEthernet1", "GigabitEthernet2"
BODY = (b"GigabitEthernet1 is up, line protocol is up\n"
        b"  MTU is 9000 bytes\n")


def capture(raw=BODY):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
                   operation=parser.OP, rendered=parser.COMMAND, codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                   read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_known_field_proves_header_full_line_and_original_token(ending):
    raw = BODY.replace(b"\n", ending)
    result = parser.parse_capture(capture(raw), (P, Q))
    first, missing = result.rows
    assert result.reason is None and first.reason is None
    field = dict(first.fields)[parser.FIELD]
    assert field.raw == field.value == "9000" and raw[field.span.start:field.span.end] == b"9000"
    assert len(first.spans) == 2 and raw[first.spans[0].start:first.spans[0].end].startswith(P.encode())
    assert raw[first.spans[1].start:first.spans[1].end].startswith(b"  MTU ")
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw
    assert missing.port == Q and missing.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE


@pytest.mark.parametrize("token", [b"0", b"06500", b"65536", b"999999999999", b"-1", b""])
def test_invalid_numeric_field_poison_is_not_a_default(token):
    result = parser.parse_capture(capture(BODY.replace(b"9000", token)), (P, Q))
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL for row in result.rows)


def test_omitted_mtu_never_becomes_1500():
    row, = parser.parse_capture(capture(BODY.splitlines(keepends=True)[0]), (P,)).rows
    assert row.reason is k.UnknownReason.FIELD_NOT_PRINTED and parser.FIELD not in dict(row.fields)


@pytest.mark.parametrize("raw", [BODY * 2, BODY + BODY.splitlines(keepends=True)[1]])
def test_equal_duplicates_conflict(raw):
    row, = parser.parse_capture(capture(raw), (P,)).rows
    assert row.reason is k.UnknownReason.CONFLICTING_EVIDENCE


@pytest.mark.parametrize("raw", [
    BODY + b"  unknown extra\n", BODY.replace(b"MTU is", b"MTU   is"),
    BODY + b"sw#\n" + BODY, b"sw#show ip interface\n" + BODY + b"other#\n",
    b"show ip interface\nshow ip interface\n" + BODY,
])
def test_unknown_indentation_late_body_and_envelope_mismatch_poison(raw):
    result = parser.parse_capture(capture(raw), (P, Q))
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL for row in result.rows)


@pytest.mark.parametrize("integrity,reason", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
])
def test_integrity_dominates_plausible_or_partial_body(integrity, reason):
    result = parser.parse_capture(replace(capture(BODY + b"extra\n"), integrity=integrity), (P, Q))
    assert result.reason is reason and all(row.reason is reason for row in result.rows)


@pytest.mark.parametrize("tail", [b"GigabitEthernet99 is up, line protocol is up\n",
                                  b"GigabitEthernet99 is malformed\n"])
def test_foreign_local_port_refuses_even_when_malformed(tail):
    with pytest.raises(ValueError, match="^undeclared_local_port$"):
        parser.parse_capture(capture(BODY + tail), (P,))


@pytest.mark.parametrize("opening,closing", [(b"", b""), (b"show ip interface\n", b""),
                                              (b"sw#show ip interface\n", b"sw#\n")])
def test_exact_optional_envelopes(opening, closing):
    assert parser.parse_capture(capture(opening + BODY + closing), (P,)).rows[0].reason is None


@pytest.mark.parametrize("change", [{"operation": "iosxe.show_interfaces"},
                                    {"rendered": "show interface"}, {"codec": "latin-1"}])
def test_operation_identity_is_exact(change):
    with pytest.raises(ValueError, match="^unsupported_mtu_capture$"):
        parser.parse_capture(replace(capture(), **change), (P,))


def test_eof_without_final_newline_preserves_record_ids_fields_and_exact_spans():
    raw = BODY.rstrip(b"\n")
    assert b"\n" in raw and not raw.endswith(b"\n")
    result = parser.parse_capture(capture(raw), (P,))
    row, = result.rows
    assert result.reason is row.reason is None and result.parse.quality == "complete"
    header, mtu = result.parse.records
    split = raw.index(b"\n")
    assert header.rule_id.startswith("port_") and mtu.rule_id == "mtu"
    assert header.span == k.ByteSpan(start=0, end=split)
    assert mtu.span == k.ByteSpan(start=split + 1, end=len(raw))
    header_fields, mtu_fields = dict(header.fields), dict(mtu.fields)
    assert set(header_fields) == {"port"}
    assert header_fields["port"].raw == P
    assert header_fields["port"].span == k.ByteSpan(start=0, end=len(P))
    assert set(mtu_fields) == {"ip_bytes"}
    token = mtu_fields[parser.FIELD]
    start = raw.index(b"9000")
    assert token.raw == token.value == "9000"
    assert token.span == k.ByteSpan(start=start, end=start + 4)
    for record in (header, mtu):
        assert 0 <= record.span.start < record.span.end <= len(raw)
        for _, field in record.fields:
            assert record.span.start <= field.span.start <= field.span.end <= record.span.end
            assert raw[field.span.start:field.span.end] == field.raw.encode()
    assert row.spans == (header.span, mtu.span)
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw
