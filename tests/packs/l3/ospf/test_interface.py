"""Generated OSPF interface identity controls; no default VRF or device claims."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.ospf import interface as parser

P, Q = "GigabitEthernet1", "GigabitEthernet2"
BODY = (b"GigabitEthernet1 is up, line protocol is up\n"
        b"  Internet Address 198.51.100.1/30, Interface ID 7, Area 0\n"
        b"  Process ID 1, Router ID 192.0.2.1, Network Type POINT_TO_POINT, Cost: 10\n")


def capture(raw=BODY):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
                   operation=parser.OP, rendered=parser.COMMAND, codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                   read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_complete_identity_keeps_full_context_and_original_tokens(ending):
    raw = BODY.replace(b"\n", ending)
    first, missing = parser.parse_capture(capture(raw), (P, Q)).rows
    fields = dict(first.fields)
    assert first.reason is None and missing.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert fields["network_type"].value is parser.NetworkType.POINT_TO_POINT
    assert fields["process"].raw == "1" and fields["router_id"].raw == "192.0.2.1"
    assert "vrf" not in fields and len(first.spans) == 3
    for field in fields.values():
        assert raw[field.span.start:field.span.end] == field.raw.encode()


@pytest.mark.parametrize("area,value", [(b"0", "0"), (b"192.0.2.1", "3221225985"),
                                       (b"192.0.2.255", "3221226239"), (b"4294967295", "4294967295")])
def test_area_normalization_preserves_raw_spans(area, value):
    raw = BODY.replace(b"Area 0", b"Area " + area)
    field = dict(parser.parse_capture(capture(raw), (P,)).rows[0].fields)["area"]
    assert field.raw == area.decode() and field.value == value
    assert raw[field.span.start:field.span.end] == area


@pytest.mark.parametrize("old,new", [
    (b"Area 0", b"Area 4294967296"), (b"Area 0", b"Area 00"), (b"Area 0", b"Area 256.0.0.0"),
    (b"Process ID 1", b"Process ID 0"), (b"Process ID 1", b"Process ID 65536"),
    (b"/30", b"/33"), (b"192.0.2.1", b"192.00.2.1"), (b"POINT_TO_POINT", b"UNKNOWN"),
])
def test_invalid_scope_and_closed_network_type_poison(old, new):
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL
               for row in parser.parse_capture(capture(BODY.replace(old, new)), (P, Q)).rows)


@pytest.mark.parametrize("line", BODY.splitlines(keepends=True)[1:])
def test_omitted_identity_field_is_unknown(line):
    row, = parser.parse_capture(capture(BODY.replace(line, b"")), (P,)).rows
    assert row.reason is k.UnknownReason.FIELD_NOT_PRINTED


def test_duplicate_process_does_not_override_or_vote():
    raw = BODY + BODY.splitlines(keepends=True)[2]
    assert parser.parse_capture(capture(raw), (P,)).rows[0].reason is k.UnknownReason.CONFLICTING_EVIDENCE


def test_explicit_printed_vrf_is_retained_and_never_defaulted():
    raw = BODY.replace(b"Process ID 1, Router", b"Process ID 1, VRF BLUE Router")
    fields = dict(parser.parse_capture(capture(raw), (P,)).rows[0].fields)
    assert fields["vrf"].raw == "BLUE"
    assert "vrf" not in dict(parser.parse_capture(capture(), (P,)).rows[0].fields)


@pytest.mark.parametrize("extra", [b"  unknown policy\n", b"sw#\n" + BODY,
                                   b"  Interface is unnumbered, Area 0\n"])
def test_unmodeled_or_late_body_poison_all_rows(extra):
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL
               for row in parser.parse_capture(capture(BODY + extra), (P, Q)).rows)


def test_integrity_and_undeclared_interface_boundaries():
    result = parser.parse_capture(replace(capture(), integrity=k.IntegrityState.TRUNCATED), (P, Q))
    assert all(row.reason is k.UnknownReason.CAPTURE_TRUNCATED for row in result.rows)
    with pytest.raises(ValueError, match="^undeclared_local_port$"):
        parser.parse_capture(capture(BODY + b"GigabitEthernet99 is malformed\n"), (P,))


def test_exact_envelope_and_optional_interface_id():
    raw = b"sw#show ip ospf interface\n" + BODY.replace(b" Interface ID 7,", b"") + b"sw#\n"
    result = parser.parse_capture(capture(raw), (P,))
    assert result.rows[0].reason is None and result.reason is None


def test_unterminated_process_row_keeps_formal_records_and_exact_spans():
    raw = BODY.rstrip(b"\n")
    result = parser.parse_capture(capture(raw), (P,))
    assert result.reason is None and result.rows[0].reason is None and result.parse.quality == "complete"
    header, address, process = result.parse.records
    assert header.rule_id.startswith("port_") and address.rule_id == "address_id" and process.rule_id == "process"
    assert set(dict(header.fields)) == {"port"}
    assert set(dict(address.fields)) == {"address", "prefix", "area", "interface_id"}
    assert set(dict(process.fields)) == {"process", "router_id", "network_type", "cost"}
    assert result.rows[0].spans == (header.span, address.span, process.span)
    for record in (header, address, process):
        for _, field in record.fields:
            assert record.span.start <= field.span.start <= field.span.end <= record.span.end
            assert raw[field.span.start:field.span.end] == field.raw.encode()
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw
