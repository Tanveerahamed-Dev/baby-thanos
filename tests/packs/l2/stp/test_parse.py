"""Generated STP cases; source syntax reference is not device qualification."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.stp import parse as parser

PORT = "GigabitEthernet1/0/1"
HEADER = b"Port 1 (GigabitEthernet1/0/1) of VLAN0001 is designated forwarding\n"
BODY = (HEADER
        + b"   Port path cost 20000, Port priority 128, Port Identifier 128.1.\n"
        + b"   Designated root has priority 32769, address 0200.0000.0001\n"
        + b"   Designated bridge has priority 32769, address 0200.0000.0002\n"
        + b"   Designated port id is 128.1, designated path cost 20000\n"
        + b"   Timers: message age 0, forward delay 15, hold 0\n"
        + b"   Number of transitions to forwarding state: 1\n"
        + b"   The port is in the portfast mode\n"
        + b"   Link type is point-to-point by default\n"
        + b"   Bpdu guard is enabled\n"
        + b"   Bpdu filter is disabled\n"
        + b"   Root guard is enabled on the port\n"
        + b"   Loop guard is disabled on the port\n"
        + b"   BPDU: sent 9, received 0\n")


def capture(raw=BODY):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
                   operation=parser.OP, rendered=parser.command(PORT), codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                   read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_distinct_observations_have_exact_original_spans_and_closed_tokens(ending):
    raw = BODY.replace(b"\n", ending)
    result = parser.parse_capture(capture(raw), PORT, (2, 1))
    first, missing = result.rows
    assert result.reason is first.reason is None and result.parse.quality == "complete"
    assert (first.port, first.vlan, missing.vlan) == (PORT, 1, 2)
    assert missing.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    fields = dict(first.fields)
    assert fields["root_mac"].raw == "0200.0000.0001"
    assert fields["bridge_mac"].raw == "0200.0000.0002"
    assert fields["role"].value is parser.Role.DESIGNATED
    assert fields["state"].value is parser.State.FORWARDING
    assert fields["root_guard"].value is fields["bpdu_guard"].value is parser.Switch.ENABLED
    assert fields["loop_guard"].value is fields["bpdu_filter"].value is parser.Switch.DISABLED
    assert fields["portfast"].value == "portfast"
    assert "intended_root" not in fields
    for record in result.parse.records:
        for _, field in record.fields:
            assert raw[field.span.start:field.span.end] == field.raw.encode()
            assert record.span.start <= field.span.start < field.span.end <= record.span.end
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw


def test_omitted_guard_and_portfast_have_no_disabled_value():
    raw = b"".join(line for line in BODY.splitlines(keepends=True)
                   if b"guard" not in line and b"filter" not in line and b"portfast" not in line)
    row, = parser.parse_capture(capture(raw), PORT, (1,)).rows
    assert row.reason is None
    assert not (set(parser.GUARDS) | {"portfast"}) & dict(row.fields).keys()
    assert dict(row.fields)["root_priority"].raw == "32769"


@pytest.mark.parametrize("raw", [BODY * 2, BODY + b"   Root guard is enabled on the port\n",
                                  BODY + b"   Root guard is disabled on the port\n"])
def test_equal_and_different_duplicate_fields_conflict_without_last_value_wins(raw):
    row, = parser.parse_capture(capture(raw), PORT, (1,)).rows
    assert row.reason is k.UnknownReason.CONFLICTING_EVIDENCE


@pytest.mark.parametrize("raw", [
    BODY + b"unknown trailing data\n", BODY.replace(b"enabled on", b"inherit on"),
    BODY.replace(b"designated forwarding", b"mystery forwarding"),
    BODY.replace(b"designated forwarding", b"designated mystery"),
    BODY.replace(b"Loop guard is disabled on", b"Loop guard is enabled by default on"),
    b"sw#" + parser.command(PORT).encode() + b"\n" + BODY + b"other#\n",
    BODY + b"sw#\n" + BODY,
    BODY.replace(b"32769", b"65536"), BODY.replace(b"32769", b"032769"),
    BODY.replace(b"0200.0000.0001", b"invalid"),
])
def test_partial_response_poisons_every_expected_row(raw):
    result = parser.parse_capture(capture(raw), PORT, (1, 2))
    assert result.reason is k.UnknownReason.PARSE_PARTIAL
    assert all(row.reason is result.reason for row in result.rows)


def test_mst_does_not_borrow_vlan_identity_without_region_scope():
    result = parser.parse_capture(capture(BODY.replace(b"VLAN0001", b"MST0")), PORT, (1,))
    assert result.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT
    assert result.rows[0].reason is result.reason


@pytest.mark.parametrize("change", [
    {"integrity": k.IntegrityState.ERROR}, {"integrity": k.IntegrityState.TRUNCATED},
    {"integrity": k.IntegrityState.PAGING_ARTIFACTS}, {"integrity": k.IntegrityState.EMPTY},
])
def test_capture_integrity_dominates_apparently_valid_fields(change):
    result = parser.parse_capture(replace(capture(), **change), PORT, (1, 2))
    assert result.reason in (k.UnknownReason.CAPTURE_ERROR, k.UnknownReason.CAPTURE_TRUNCATED,
                             k.UnknownReason.EMPTY_UNREGISTERED)
    assert all(row.reason is result.reason for row in result.rows)


@pytest.mark.parametrize("raw,code", [
    (BODY.replace(PORT.encode(), b"GigabitEthernet9"), "undeclared_stp_port"),
    (BODY + b"Port broken (GigabitEthernet9) of VLAN0001 is malformed\n", "undeclared_stp_port"),
    (BODY.replace(b"VLAN0001", b"VLAN0009"), "undeclared_stp_vlan"),
])
def test_foreign_population_cannot_supply_declared_subject(raw, code):
    with pytest.raises(ValueError, match="^" + code + "$"):
        parser.parse_capture(capture(raw), PORT, (1,))


@pytest.mark.parametrize("vlans", [(), (True,), (0,), (4095,), (1, 1), [1], tuple(range(1, 18))])
def test_population_shape_is_closed(vlans):
    with pytest.raises(ValueError, match="^invalid_stp_vlans$"):
        parser.parse_capture(capture(), PORT, vlans)


@pytest.mark.parametrize("change", [{"operation": "other"}, {"rendered": "show spanning-tree"},
                                    {"codec": "latin-1"}])
def test_operation_and_rendered_command_are_bound(change):
    with pytest.raises(ValueError, match="^unsupported_stp_capture$"):
        parser.parse_capture(replace(capture(), **change), PORT, (1,))


@pytest.mark.parametrize("port", ["", "Gi1\nshow version", "Gi1;other", "Gi1)", "Gi1é"])
def test_port_is_not_command_text(port):
    with pytest.raises(ValueError, match="^invalid_stp_port$"):
        parser.parse_capture(capture(), port, (1,))


@pytest.mark.parametrize("wrapper", ["none", "bare", "prompt", "eof"])
def test_exact_envelopes_and_eof_keep_observations(wrapper):
    raw = BODY
    if wrapper == "bare":
        raw = parser.command(PORT).encode() + b"\n" + raw
    elif wrapper == "prompt":
        raw = b"sw#" + parser.command(PORT).encode() + b"\n" + raw + b"sw#\n"
    elif wrapper == "eof":
        raw = raw.rstrip(b"\n")
    result = parser.parse_capture(capture(raw), PORT, (1,))
    assert result.reason is result.rows[0].reason is None


def test_two_vlans_have_separate_observations_independent_of_declared_order():
    raw = BODY + BODY.replace(b"VLAN0001", b"VLAN0002").replace(b"0200.0000.0001", b"0200.0000.0003")
    result = parser.parse_capture(capture(raw), PORT, (2, 1))
    assert [row.vlan for row in result.rows] == [1, 2]
    assert [dict(row.fields)["root_mac"].raw for row in result.rows] == ["0200.0000.0001", "0200.0000.0003"]
    assert all(row.reason is None for row in result.rows)
