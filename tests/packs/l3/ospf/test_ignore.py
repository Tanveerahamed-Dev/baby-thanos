"""Generated explicit-control tests; omission is never a false control."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.ospf import ignore as parser

P, Q = "GigabitEthernet1", "GigabitEthernet2"
BODY = b"interface GigabitEthernet1\n no ip ospf mtu-ignore\n!\nend\n"


def capture(raw=BODY):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
                   operation=parser.OP, rendered=parser.COMMAND, codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                   read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


@pytest.mark.parametrize("statement,value", [(b"ip ospf mtu-ignore", "enabled"),
                                             (b"no ip ospf mtu-ignore", "disabled")])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_explicit_controls_retain_original_statement_and_full_context(statement, value, ending):
    raw = BODY.replace(b"no ip ospf mtu-ignore", statement).replace(b"\n", ending)
    result = parser.parse_capture(capture(raw), (P, Q))
    first, missing = result.rows
    field = dict(first.fields)["mtu_ignore"]
    assert first.reason is result.reason is None and field.value == value
    assert field.raw == statement.decode() and raw[field.span.start:field.span.end] == statement
    assert len(first.spans) == 2 and missing.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw


def test_omission_never_means_disabled():
    row, = parser.parse_capture(capture(BODY.replace(b" no ip ospf mtu-ignore\n", b"")), (P,)).rows
    assert row.reason is k.UnknownReason.FIELD_NOT_PRINTED and "mtu_ignore" not in dict(row.fields)


@pytest.mark.parametrize("extra", [b" no ip ospf mtu-ignore\n", b" ip ospf mtu-ignore\n"])
def test_duplicate_and_conflicting_statements_never_vote_or_take_last(extra):
    row, = parser.parse_capture(capture(BODY.replace(b"!\n", extra + b"!\n")), (P,)).rows
    assert row.reason is k.UnknownReason.CONFLICTING_EVIDENCE


def test_duplicate_interface_blocks_conflict():
    raw = BODY.removesuffix(b"end\n") + BODY
    assert parser.parse_capture(capture(raw), (P,)).rows[0].reason is k.UnknownReason.CONFLICTING_EVIDENCE


@pytest.mark.parametrize("extra", [b" source template BASE\n", b" default ip ospf mtu-ignore\n",
                                   b" no shutdown\n", b"template BASE\n"])
def test_inheritance_default_and_other_negation_poison_all_ports(extra):
    result = parser.parse_capture(capture(BODY.replace(b"!\n", extra + b"!\n")), (P, Q))
    assert all(row.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT for row in result.rows)


@pytest.mark.parametrize("raw", [
    BODY.removesuffix(b"end\n"), BODY + b" ip ospf mtu-ignore\n", BODY + b"end\n",
    BODY.replace(b" no ip", b"no ip"), BODY.replace(b"!\n", b" unknown\n!\n"),
    b"sw#show running-config all\n" + BODY + b"other#\n",
])
def test_unknown_context_missing_end_and_late_input_poison_all_ports(raw):
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL
               for row in parser.parse_capture(capture(raw), (P, Q)).rows)


def test_positive_control_does_not_override_failed_capture():
    raw = BODY.replace(b"no ip", b"ip")
    result = parser.parse_capture(replace(capture(raw), integrity=k.IntegrityState.ERROR), (P, Q))
    assert all(row.reason is k.UnknownReason.CAPTURE_ERROR for row in result.rows)


@pytest.mark.parametrize("line", [b"interface GigabitEthernet99\n", b"interface GigabitEthernet99 malformed\n"])
def test_undeclared_port_refuses_before_any_result(line):
    with pytest.raises(ValueError, match="^undeclared_local_port$"):
        parser.parse_capture(capture(BODY.replace(b"end\n", line + b"end\n")), (P,))


def test_exact_read_only_operation_and_optional_envelope():
    raw = b"sw#show running-config all\n" + BODY + b"sw#\n"
    assert parser.parse_capture(capture(raw), (P,)).rows[0].reason is None
    with pytest.raises(ValueError, match="^unsupported_ospf_ignore_capture$"):
        parser.parse_capture(replace(capture(), rendered="show running-config"), (P,))


@pytest.mark.parametrize("header,ports", [
    (b"interface range GigabitEthernet1 - 2\n", (P, Q)),
    (b"interface range\n", ("range",)),
    (b"interface RANGE\n", ("RANGE",)),
])
def test_range_keyword_cannot_be_laundered_as_a_declared_interface(header, ports):
    raw = header + b" no ip ospf mtu-ignore\n!\nend\n"
    result = parser.parse_capture(capture(raw), ports)
    assert result.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT
    assert all(row.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT for row in result.rows)


def test_unterminated_end_record_and_statement_spans_are_complete():
    raw = BODY.rstrip(b"\n")
    result = parser.parse_capture(capture(raw), (P,))
    assert result.reason is None and result.rows[0].reason is None
    records = result.parse.records
    assert len(records) == 4
    assert records[0].rule_id.startswith("port_") and records[1].rule_id == "disabled"
    assert records[2].rule_id.startswith("separator_") and records[3].rule_id.startswith("end_")
    assert [set(dict(record.fields)) for record in records] == [{"port"}, {"mtu_ignore"}, {"separator"}, {"end"}]
    for record in records:
        for _, field in record.fields:
            assert record.span.start <= field.span.start <= field.span.end <= record.span.end
            assert raw[field.span.start:field.span.end] == field.raw.encode()
    assert result.rows[0].spans == tuple(record.span for record in records[:2])
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw
