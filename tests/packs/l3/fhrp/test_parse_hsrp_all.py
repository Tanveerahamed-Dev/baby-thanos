"""Declared-synthetic detail-form twins; explicit version 1 is no observed platform floor."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_brief import capture as legacy_capture

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser

DETAIL = (
    b"  State is Active\n"
    b"  Virtual IP address is 192.0.2.1\n"
    b"  Active virtual MAC address is 0000.0000.0000 (MAC In Use)\n"
    b"    Local virtual MAC address is 0000.0000.0000 (v2 default)\n"
    b"  Hello time 3 sec, hold time 10 sec\n"
    b"  Preemption enabled\n"
    b"  Active router is local\n"
    b"  Standby router is 192.0.2.2, priority 100 (expires in 1.000 sec)\n"
    b"  Priority 100 (default 100)\n"
    b'  Group name is "synthetic-other-interface-99" (default)\n'
)


def block(version="2", interface="Vlan10", group="0"):
    suffix = "" if version is None else " (version " + version + ")"
    return (interface + " - Group " + group + suffix + "\n").encode("ascii") + DETAIL


BODY = block()


def capture(raw=BODY, integrity=k.IntegrityState.COMPLETE):
    return replace(legacy_capture(raw, integrity), operation=parser.OP, rendered=parser.COMMAND)


def custody(raw, result):
    assert tuple(line.span for line in result.parse.lines) == tuple(line.span for line in text_lines(raw, "utf-8"))
    for index, row in enumerate(result.rows):
        assert any(row.header is record for record in result.parse.records)
        fields = dict(row.header.fields)
        for name in ("interface", "group", "version"):
            token = getattr(row, name)
            if token is not None:
                assert token is fields[name]
        end = result.rows[index + 1].header.span.start if index + 1 < len(result.rows) else len(raw)
        for record in row.body:
            assert any(record is original for original in result.parse.records)
            assert row.header.span.end <= record.span.start < record.span.end <= end
        if row.virtual_ip is not None:
            assert any(row.virtual_ip is token for record in row.body for _, token in record.fields)
        for record in (row.header, *row.body):
            assert raw[record.span.start:record.span.end] in raw.splitlines()
            for _, token in record.fields:
                assert record.span.start <= token.span.start < token.span.end <= record.span.end
                assert raw[token.span.start:token.span.end] == token.raw.encode("ascii")
                assert type(token.value) is str and token.value == token.raw


def poisoned(raw, reason, integrity=k.IntegrityState.COMPLETE):
    result = parser.parse_capture(capture(raw, integrity))
    assert result.reason is reason and result.parse.quality == "partial"
    assert all(row.reason is reason for row in result.rows)
    custody(raw, result)
    return result


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("final_newline", [False, True])
@pytest.mark.parametrize("version", ["1", "2"])
def test_explicit_synthetic_versions_own_exact_columns_and_ipv4_block(ending, frame, final_newline, version):
    raw = block(version)
    if frame != "body":
        raw = parser.COMMAND.encode() + b"\n" + raw
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    if not final_newline:
        raw = raw[:-1]
    raw = raw.replace(b"\n", ending)
    sample = capture(raw)
    result = parser.parse_capture(sample)
    row, = result.rows
    assert result.reason is None and result.parse.quality == "complete" and row.reason is None
    assert (row.interface.raw, row.group.raw, row.version.raw, row.address_family) == ("Vlan10", "0", version, "ipv4")
    assert row.virtual_ip.raw == "192.0.2.1" and len(row.body) == 10
    assert sample.raw == raw and sample.bytes_sha256 == sha256(raw).hexdigest()
    assert sample.read_scope is k.ReadScope.UNKNOWN and sample.view is k.ViewConsistency.UNKNOWN
    assert parser.parse_capture(sample) == result
    custody(raw, result)
    with pytest.raises(AttributeError):
        row.address_family = None


@pytest.mark.parametrize("group", ["0", "255", "256", "4095"])
@pytest.mark.parametrize("mac_version", [b"v1", b"v2"])
def test_bare_heading_never_infers_version_from_mac_default_group_or_ipv4(group, mac_version):
    raw = block(None, group=group).replace(b"v2 default", mac_version + b" default")
    result = parser.parse_capture(capture(raw))
    row, = result.rows
    assert result.reason is None and result.parse.quality == "complete"
    assert row.version is None and row.reason is k.UnknownReason.NOT_OBSERVABLE
    assert row.address_family == "ipv4"
    custody(raw, result)


def test_explicit_version_needs_own_positive_canonical_ipv4_vip():
    raw = BODY + block(interface="Vlan20").replace(b"192.0.2.1", b"unknown")
    result = parser.parse_capture(capture(raw))
    assert result.reason is None and result.parse.quality == "complete" and len(result.rows) == 2
    assert result.rows[0].reason is None and result.rows[0].address_family == "ipv4"
    assert result.rows[1].reason is k.UnknownReason.IDENTITY_UNRESOLVED and result.rows[1].address_family is None
    assert result.rows[1].version.raw == "2"
    custody(raw, result)


@pytest.mark.parametrize("second", [
    BODY, block("1"), BODY.replace(b"192.0.2.1", b"192.0.2.9"), BODY.replace(b"192.0.2.1", b"unknown"),
])
def test_identical_and_conflicting_duplicates_keep_every_block_without_last_wins(second):
    result = poisoned(BODY + second, k.UnknownReason.CONFLICTING_EVIDENCE)
    assert len(result.rows) == 2 and result.rows[0].header is not result.rows[1].header
    assert [row.version.raw for row in result.rows] == ["2", "1" if second == block("1") else "2"]


def test_exact_interfaces_groups_and_order_are_not_normalized():
    raw = BODY + block("1", "Vl10") + block("2", group="1")
    result = parser.parse_capture(capture(raw))
    assert result.reason is None and [row.reason for row in result.rows] == [None] * 3
    assert [(row.interface.raw, row.group.raw) for row in result.rows] == [("Vlan10", "0"), ("Vl10", "0"), ("Vlan10", "1")]
    custody(raw, result)


@pytest.mark.parametrize("raw", [
    *[BODY.replace(line, b"") for line in DETAIL.splitlines(keepends=True)],
    *[BODY.replace(line, line + line) for line in DETAIL.splitlines(keepends=True)],
    *[block(version) for version in ("3", "01", "0", "9" * 10000)],
    *[block(group=group) for group in ("01", "4096", "-1", "9" * 10000)],
    *[BODY.replace(b"192.0.2.1", token) for token in (b"192.000.2.1", b"256.0.2.1", b"2001:db8::1", b"local")],
    BODY.replace(b"Virtual IP address is 192.0.2.1", b"Virtual IPv6 address is 2001:db8::1"),
    BODY.replace(b"  State is Active", b"Address-Family IPv4"),
    BODY + b"unrecognized synthetic detail\n", BODY + b"--More--\n", BODY[:-7],
    BODY.replace(b" - Group ", b" - Grp "), BODY.replace(b" (default)\n", b"\n"),
    BODY.replace(b"Vlan10 -", b"Vlan10\xc2\xa0-"), DETAIL,
    b"show standby\n" + BODY,
    b"fixture#show standby all\n" + BODY,
    b"fixture#show standby all\n" + BODY + b"other#\n",
    b"fixture#show standby all\n" + BODY + b"fixture#\n" + BODY,
    BODY + BODY.splitlines(keepends=True)[0], BODY + b"fixture#\n",
    b"show standby all\n" + BODY + b"fixture#\n", b"show standby all\n",
    b"show standby all\n" + BODY + b"show standby all\n",
])
def test_incomplete_repeated_unclaimed_and_mixed_format_never_become_complete(raw):
    poisoned(raw, k.UnknownReason.PARSE_PARTIAL)


@pytest.mark.parametrize("integrity,reason", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (k.IntegrityState.UNVERIFIED_PROMPT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
])
def test_capture_damage_dominates_valid_rows_and_conflicting_bad_blocks(integrity, reason):
    result = poisoned(BODY + block("1") + b"unrecognized\n", reason, integrity)
    assert len(result.rows) == 2


@pytest.mark.parametrize("damaged", [False, True])
def test_metadata_error_dominates_even_complete_integrity(damaged):
    sample = capture(BODY + block("1") + b"unrecognized\n" if damaged else BODY)
    result = parser.parse_capture(replace(sample, metadata=replace(sample.resolved_metadata, error=ErrorKind.TIMEOUT)))
    assert result.reason is k.UnknownReason.CAPTURE_ERROR and all(row.reason is result.reason for row in result.rows)


@pytest.mark.parametrize("raw", [b"", b" \t\r\n"])
def test_empty_capture_never_claims_a_row(raw):
    result = poisoned(raw, k.UnknownReason.EMPTY_UNREGISTERED)
    assert result.rows == ()


@pytest.mark.parametrize("change", [
    {"operation": "iosxe.show_standby_brief"}, {"rendered": "show standby"}, {"codec": "latin-1"},
])
def test_other_operation_rendering_or_codec_is_refused(change):
    with pytest.raises(ValueError):
        parser.parse_capture(replace(capture(), **change))


def test_pinned_format_lesson_is_allowlisted_without_platform_or_train_claim():
    assert parser.OP == "iosxe.show_standby_all" and parser.COMMAND == "show standby all"
    assert parser.VARIANT_SUPPORT == "allowlisted"
    assert parser.SOURCE == ("https://github.com/CiscoTestAutomation/genieparser/blob/"
        "6e0b25eb76be058e787e2859a89bc6edfa4e0bf6/src/genie/libs/parser/"
        "iosxe/tests/ShowStandbyAll/cli/equal/golden_output2_output.txt")


@pytest.mark.parametrize("state", [b"Active", b"Standby", b"Init", b"Disabled"])
def test_optional_reported_details_are_owned_and_groupname_supplies_no_identity(state):
    optional = (b"    2 state changes, last state change 00:00:01\n"
        b"    Track object 2 (unknown)\n"
        b"    Next hello sent in 1.500 secs\n"
        b'  Authentication MD5, key-chain "fixture"\n')
    raw = BODY.replace(b"  State is Active\n", b"  State is " + state + b"\n" + optional)
    result = parser.parse_capture(capture(raw))
    row, = result.rows
    assert result.reason is None and row.reason is None and len(row.body) == 14
    assert (row.interface.raw, row.group.raw) == ("Vlan10", "0")
    custody(raw, result)
    for line in optional.splitlines(keepends=True):
        poisoned(raw.replace(line, line + line), k.UnknownReason.PARSE_PARTIAL)
