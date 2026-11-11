"""Synthetic HSRP brief format twins; no imported device capture or train claims."""
from dataclasses import replace
from hashlib import sha256
from itertools import pairwise

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as parser

LEGEND = b"                     P indicates configured to preempt.\n                     |\n"
HEADER = b"Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
INIT = b"Vl20        0    100   Init    unknown         unknown         203.0.113.1\n"
ACTIVE = b"Vl10        1    110 P Active  local           192.0.2.2       192.0.2.1\n"
STANDBY = b"BD3329      129  90 P Standby 198.51.100.2    local           198.51.100.1\n"
BODY = LEGEND + HEADER + INIT + ACTIVE + STANDBY


def capture(raw=BODY, integrity=k.IntegrityState.COMPLETE):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
        operation=parser.OP, rendered=parser.COMMAND, codec="utf-8", raw=raw, integrity=integrity,
        lines=text_lines(raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


def assert_columns(raw, result):
    records = tuple(record for record in result.parse.records if record.rule_id in ("row", "row_preempt"))
    assert tuple(record.span for record in records) == tuple(row.span for row in result.rows)
    assert tuple(line.span for line in result.parse.lines) == tuple(line.span for line in text_lines(raw, "utf-8"))
    for row in result.rows:
        record = next(record for record in result.parse.records if record.span == row.span)
        tokens = (row.interface, row.group, row.priority) + (() if row.preempt is None else (row.preempt,)) + (
            row.state, row.active.token, row.standby.token, row.virtual_ip.token)
        assert all(any(token is original for _, original in record.fields) for token in tokens)
        assert [token.span.start for token in tokens] == sorted(token.span.start for token in tokens)
        assert raw[row.span.start:row.span.end] in raw.splitlines()
        assert row.span.start == tokens[0].span.start and row.span.end == tokens[-1].span.end
        for token in tokens:
            assert row.span.start <= token.span.start < token.span.end <= row.span.end
            assert raw[token.span.start:token.span.end] == token.raw.encode("ascii")
        for left, right in pairwise(tokens):
            gap = raw[left.span.end:right.span.start]
            assert gap and not gap.strip(b" \t")


def poisoned(raw, reason, integrity=k.IntegrityState.COMPLETE):
    result = parser.parse_capture(capture(raw, integrity))
    assert result.reason is reason and result.parse.quality == "partial"
    assert all(row.reason is reason for row in result.rows)
    assert_columns(raw, result)
    return result


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("final_newline", [False, True])
def test_supported_synthetic_rows_preserve_physical_columns_and_explicit_af_witnesses(ending, frame, final_newline):
    raw = BODY
    if frame != "body":
        raw = parser.COMMAND.encode() + b"\n" + raw
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    raw = raw.replace(b"\n", ending)
    if not final_newline:
        raw = raw[:-len(ending)]
    sample = capture(raw)
    result = parser.parse_capture(sample)
    assert result.reason is None and result.parse.quality == "complete"
    assert [(row.interface.raw, row.group.raw, row.priority.raw) for row in result.rows] == [("Vl20", "0", "100"), ("Vl10", "1", "110"), ("BD3329", "129", "90")]
    assert tuple(row.state.value for row in result.rows) == (parser.State.INIT, parser.State.ACTIVE, parser.State.STANDBY)
    assert result.rows[0].preempt is None and all(row.preempt.raw == row.preempt.value == "P" for row in result.rows[1:])
    for row in result.rows:
        assert row.interface.value == row.interface.raw and row.group.value == row.group.raw and row.priority.value == row.priority.raw
        endpoints = (row.active, row.standby, row.virtual_ip)
        assert row.address_family == "ipv4"
        assert row.af_spans == tuple(endpoint.token.span for endpoint in endpoints if endpoint.kind == "ipv4")
        assert all(raw[span.start:span.end].count(b".") == 3 for span in row.af_spans)
    assert [endpoint.kind for endpoint in (result.rows[0].active, result.rows[0].standby, result.rows[0].virtual_ip)] == ["unknown", "unknown", "ipv4"]
    assert result.rows[1].active.kind == result.rows[2].standby.kind == "local"
    assert_columns(raw, result)
    assert sample.raw == raw and sample.bytes_sha256 == sha256(raw).hexdigest()
    assert parser.parse_capture(sample) == result
    with pytest.raises(AttributeError):
        result.rows[0].address_family = None


@pytest.mark.parametrize("raw,reason,interfaces", [
    (BODY + ACTIVE, k.UnknownReason.CONFLICTING_EVIDENCE, ("Vl20", "Vl10", "BD3329", "Vl10")),
    (BODY + ACTIVE.replace(b"192.0.2.1", b"192.0.2.9"), k.UnknownReason.CONFLICTING_EVIDENCE, ("Vl20", "Vl10", "BD3329", "Vl10")),
    (LEGEND + HEADER + INIT.replace(b"203.0.113.1", b"unknown"), k.UnknownReason.IDENTITY_UNRESOLVED, ("Vl20",)),
    (BODY + INIT.replace(b"203.0.113.1", b"unknown"), k.UnknownReason.IDENTITY_UNRESOLVED, ("Vl20", "Vl10", "BD3329", "Vl20")),
])
def test_duplicates_and_one_unresolved_af_poison_the_whole_result_without_losing_rows(raw, reason, interfaces):
    result = poisoned(raw, reason)
    assert tuple(row.interface.raw for row in result.rows) == interfaces
    if reason is k.UnknownReason.CONFLICTING_EVIDENCE:
        assert [row.virtual_ip.token.raw for row in result.rows if row.interface.raw == "Vl10"] == ["192.0.2.1", "192.0.2.9" if b"192.0.2.9" in raw else "192.0.2.1"]
    else:
        assert result.rows[-1].address_family is None and result.rows[-1].af_spans == ()


@pytest.mark.parametrize("group,priority", [("0", "0"), ("4095", "255")])
def test_canonical_numeric_edges_and_interface_spelling_are_observations_only(group, priority):
    row = ACTIVE.replace(b"Vl10", b"Vl010").replace(b"1    110", (group + "    " + priority).encode())
    result = parser.parse_capture(capture(LEGEND + HEADER + row))
    parsed, = result.rows
    assert result.reason is None and parsed.interface.raw == parsed.interface.value == "Vl010"
    assert (parsed.group.raw, parsed.group.value, parsed.priority.raw, parsed.priority.value) == (group, group, priority, priority)


@pytest.mark.parametrize("field,value", [("group", "01"), ("group", "4096"), ("group", "-1"),
    ("priority", "010"), ("priority", "256"), ("priority", "-1"), ("state", "Listen"), ("state", "ACTIVE")])
def test_noncanonical_or_unsupported_lexemes_never_become_complete(field, value):
    substitutions = {"group": (b"1    110", value.encode() + b"    110"),
        "priority": (b"1    110", b"1    " + value.encode()), "state": (b"Active", value.encode())}
    old, new = substitutions[field]
    poisoned(LEGEND + HEADER + ACTIVE.replace(old, new), k.UnknownReason.PARSE_PARTIAL)


@pytest.mark.parametrize("row,recognized", [
    (ACTIVE.replace(b"192.0.2.2", b"192.000.2.2"), True), (ACTIVE.replace(b"192.0.2.2", b"256.0.2.2"), True),
    (ACTIVE.replace(b"192.0.2.1", b"local"), True), (ACTIVE.replace(b"192.0.2.2", b"2001:db8::2"), True),
    (b"Vl11        0    200 P Active  local           2001:db8::2\n                                                               2001:db8::5\n", False),
])
def test_invalid_address_ipv6_and_wrapped_forms_poison_recognized_ipv4_rows(row, recognized):
    raw = LEGEND + HEADER + INIT + row + STANDBY
    result = poisoned(raw, k.UnknownReason.PARSE_PARTIAL)
    assert [r.interface.raw for r in result.rows] == ["Vl20"] + (["Vl10"] if recognized else []) + ["BD3329"]
    if recognized:
        endpoints = (result.rows[1].active, result.rows[1].standby, result.rows[1].virtual_ip)
        assert any(endpoint.kind is None for endpoint in endpoints)
        assert result.rows[1].af_spans == tuple(endpoint.token.span for endpoint in endpoints if endpoint.kind == "ipv4")
    assert_columns(raw, result)


@pytest.mark.parametrize("integrity,reason", [(k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT)])
def test_capture_damage_dominates_rows_that_look_valid(integrity, reason):
    result = poisoned(BODY, reason, integrity)
    assert len(result.rows) == 3


@pytest.mark.parametrize("field", ["group", "priority"])
def test_huge_numeric_tokens_stay_bounded_unrecognized_rows(field):
    old = b"1    110"
    new = b"9" * 10000 + b"    110" if field == "group" else b"1    " + b"9" * 10000
    result = parser.parse_capture(capture(LEGEND + HEADER + ACTIVE.replace(old, new) + STANDBY))
    assert result.reason is k.UnknownReason.PARSE_PARTIAL and [row.interface.raw for row in result.rows] == ["BD3329"]


@pytest.mark.parametrize("change", [{"operation": "iosxe.other"}, {"rendered": "show standby"}, {"codec": "latin-1"}])
def test_capture_form_refuses_before_any_semantic_claim(change):
    with pytest.raises(ValueError):
        parser.parse_capture(replace(capture(), **change))


def test_empty_capture_has_no_rows_or_positive_claim():
    result = parser.parse_capture(capture(b""))
    assert result.reason is k.UnknownReason.EMPTY_UNREGISTERED and result.parse.quality == "partial" and result.rows == ()


@pytest.mark.parametrize("raw", [
    HEADER + ACTIVE, LEGEND + ACTIVE, LEGEND + HEADER.replace(b"Virtual IP", b"Virtual IPv4") + ACTIVE,
    LEGEND + HEADER + ACTIVE + HEADER + STANDBY, BODY + b"unrecognised synthetic line\n",
    *[LEGEND + HEADER + ACTIVE.replace(b"110 P", b"110" + gap + b"P") for gap in (b"\xc2\xa0", b"\xe2\x80\x83")],
    b"fixture#" + parser.COMMAND.encode() + b"\n" + BODY + b"other#\n",
    b"fixture#" + parser.COMMAND.encode() + b"\n" + BODY + b"fixture#\n" + ACTIVE,
])
def test_missing_or_mixed_format_never_recovers_a_positive_table(raw):
    poisoned(raw, k.UnknownReason.PARSE_PARTIAL)


@pytest.mark.parametrize("interface", [b"Vlan10", b"BD10"])
def test_same_group_on_distinct_exact_interfaces_is_not_normalized_or_coalesced(interface):
    raw = LEGEND + HEADER + ACTIVE + ACTIVE.replace(b"Vl10", interface)
    result = parser.parse_capture(capture(raw))
    assert result.reason is None and [row.interface.raw for row in result.rows] == ["Vl10", interface.decode()]
    assert [row.group.raw for row in result.rows] == ["1", "1"]
    assert_columns(raw, result)


@pytest.mark.parametrize("operands,indices", [
    (("192.0.2.7", "unknown", "unknown"), (0,)),
    (("unknown", "192.0.2.7", "unknown"), (1,)),
    (("192.0.2.7", "192.0.2.7", "unknown"), (0, 1)),
])
def test_every_ipv4_operand_can_prove_af_and_equal_literals_keep_distinct_witnesses(operands, indices):
    active, standby, vip = operands
    row = f"Vl30        2    100   Init    {active:<15} {standby:<15} {vip}\n".encode()
    raw = LEGEND + HEADER + row
    result = parser.parse_capture(capture(raw))
    parsed, = result.rows
    endpoints = (parsed.active, parsed.standby, parsed.virtual_ip)
    assert result.reason is None and parsed.address_family == "ipv4"
    assert parsed.af_spans == tuple(endpoints[index].token.span for index in indices)
    assert len(set(parsed.af_spans)) == len(indices) and parsed.virtual_ip.kind == "unknown"
    assert_columns(raw, result)


def test_capture_error_wins_over_bad_format_duplicates_and_unresolved_af():
    raw = BODY + ACTIVE + INIT.replace(b"203.0.113.1", b"unknown") + b"unrecognised synthetic line\n"
    result = poisoned(raw, k.UnknownReason.CAPTURE_ERROR, k.IntegrityState.ERROR)
    assert len(result.rows) == 5


def test_allowlisted_provenance_is_pinned_to_the_four_read_only_format_floors():
    prefix = ("https://github.com/CiscoTestAutomation/genieparser/blob/6e0b25eb76be058e787e2859a89bc6edfa4e0bf6/"
              "src/genie/libs/parser/iosxe/tests/ShowStandbyBrief/cli/equal/")
    assert parser.SOURCES == tuple(prefix + f"golden_output{number}_output.txt" for number in (1, 2, 3, 4))
    assert parser.VARIANT_SUPPORT == "allowlisted"


@pytest.mark.parametrize("literal,valid", [
    ("0.0.0.0", True), ("255.255.255.255", True), ("192.0.2.1", True),
    ("01.2.3.4", False), ("256.0.0.1", False), ("1.2.3", False), ("1.2.3.4.5", False),
    (" 192.0.2.1", False), ("192.0.2.1/24", False), ("2001:db8::1", False), ("local", False),
    ("unknown", False), ("\u0661.2.3.4", False),
])
def test_public_ipv4_literal_predicate_preserves_canonical_ascii_boundaries(literal, valid):
    assert parser.ipv4_literal(literal) is valid


@pytest.mark.parametrize("extra,reason", [(b"", k.UnknownReason.CONFLICTING_EVIDENCE),
    (b"unrecognised synthetic line\n", k.UnknownReason.PARSE_PARTIAL)])
def test_format_then_conflict_then_unresolved_identity_precedence(extra, reason):
    raw = BODY + ACTIVE + INIT.replace(b"203.0.113.1", b"unknown") + extra
    result = poisoned(raw, reason)
    assert len(result.rows) == 5
