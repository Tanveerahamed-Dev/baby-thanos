"""Generated neighbor controls; no fixture import and no adjacency health claim."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.ospf import neighbor as parser

P, Q = "GigabitEthernet1", "GigabitEthernet2"
HEADER = b"Neighbor ID Pri State Dead Time Address Interface\n"
ROW = b"192.0.2.2 0 EXSTART/- 00:00:30 198.51.100.2 GigabitEthernet1\n"
BODY = HEADER + ROW


def capture(raw=BODY):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
                   operation=parser.OP, rendered=parser.COMMAND, codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                   read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_state_identity_and_header_row_token_proofs(ending):
    raw = BODY.replace(b"\n", ending)
    result = parser.parse_capture(capture(raw), (P, Q))
    first, missing = result.rows
    assert result.reason is first.reason is None
    fields = dict(first.fields)
    assert fields["state"].value is parser.State.EXSTART
    assert fields["role"].value is parser.Role.NONE
    assert fields["neighbor_id"].raw == "192.0.2.2" and fields["address"].raw == "198.51.100.2"
    assert len(first.spans) == 2
    for field in fields.values():
        assert raw[field.span.start:field.span.end] == field.raw.encode()
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw
    assert missing.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE


@pytest.mark.parametrize("state", [b"FULL", b"2WAY", b"EXCHANGE", b"INIT"])
def test_other_closed_states_are_observations_without_health_or_stuck_verdict(state):
    row, = parser.parse_capture(capture(BODY.replace(b"EXSTART", state)), (P,)).rows
    assert row.reason is None and dict(row.fields)["state"].raw == state.decode()
    assert not hasattr(row, "verdict")


def test_distinct_neighbors_are_retained_but_exact_duplicate_identity_conflicts():
    other = ROW.replace(b"192.0.2.2", b"192.0.2.3").replace(b"198.51.100.2", b"198.51.100.3")
    rows = parser.parse_capture(capture(BODY + other), (P,)).rows
    assert len(rows) == 2 and all(row.reason is None for row in rows)
    row, = parser.parse_capture(capture(BODY + ROW.replace(b"EXSTART", b"FULL")), (P,)).rows
    assert row.reason is k.UnknownReason.CONFLICTING_EVIDENCE


@pytest.mark.parametrize("old,new", [
    (b"EXSTART", b"BOGUS"), (b"/-", b"/OTHER"), (b"192.0.2.2", b"999.0.2.2"),
    (b" 0 ", b" 256 "), (b"00:00:30", b"00:99:30"), (b"198.51.100.2", b"198.051.100.2"),
])
def test_invalid_identity_enum_priority_and_dead_time_poison(old, new):
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL
               for row in parser.parse_capture(capture(BODY.replace(old, new)), (P, Q)).rows)


@pytest.mark.parametrize("raw", [ROW, BODY + b"unexpected\n", BODY + b"sw#\n" + ROW,
                                 b"sw#show ip ospf neighbor\n" + BODY + b"other#\n"])
def test_incomplete_and_mixed_context_poison_every_declared_port(raw):
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL
               for row in parser.parse_capture(capture(raw), (P, Q)).rows)


@pytest.mark.parametrize("tail", [ROW.replace(P.encode(), b"GigabitEthernet99"),
                                  b"192.0.2.2 malformed GigabitEthernet99\n"])
def test_foreign_port_refuses_even_malformed_row(tail):
    with pytest.raises(ValueError, match="^undeclared_local_port$"):
        parser.parse_capture(capture(BODY + tail), (P,))


@pytest.mark.parametrize("integrity,reason", [(k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
                                            (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED)])
def test_integrity_dominates_plausible_state(integrity, reason):
    result = parser.parse_capture(replace(capture(), integrity=integrity), (P, Q))
    assert result.reason is reason and all(row.reason is reason for row in result.rows)


def test_header_only_is_missing_neighbor_not_empty_healthy():
    row, = parser.parse_capture(capture(HEADER), (P,)).rows
    assert row.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE


def test_exact_wrapped_command_and_spaced_dash_role():
    raw = b"sw#show ip ospf neighbor\n" + BODY.replace(b"/-", b"/  -") + b"sw#\n"
    assert parser.parse_capture(capture(raw), (P,)).rows[0].reason is None


def test_unterminated_neighbor_row_keeps_formal_records_and_exact_spans():
    raw = BODY.rstrip(b"\n")
    result = parser.parse_capture(capture(raw), (P,))
    assert result.reason is None and result.rows[0].reason is None and result.parse.quality == "complete"
    header, row = result.parse.records
    assert header.rule_id.startswith("header_") and row.rule_id == "neighbor"
    assert set(dict(header.fields)) == {"header"}
    assert set(dict(row.fields)) == {"neighbor_id", "priority", "state", "role", "dead_time", "address", "port"}
    assert result.rows[0].spans == (header.span, row.span)
    for record in (header, row):
        for _, field in record.fields:
            assert record.span.start <= field.span.start <= field.span.end <= record.span.end
            assert raw[field.span.start:field.span.end] == field.raw.encode()
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw
