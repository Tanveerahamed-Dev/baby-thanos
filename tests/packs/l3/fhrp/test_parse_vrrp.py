"""Original synthetic VRRP detail twins; no donor bytes, version or platform qualification."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_brief import capture as legacy_capture

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_vrrp as parser

DETAIL = (
    b"  State is Backup\n"
    b"  Virtual IP address is 198.51.100.41\n"
    b"  Virtual MAC address is 0011.2233.4455\n"
    b"  Advertisement interval is 1.250 sec\n"
    b"  Preemption disabled\n"
    b"  Priority is 109\n"
    b'  Authentication text "synthetic-lab"\n'
    b"  Master Router is 192.0.2.17, priority is 113\n"
    b"  Master Advertisement interval is 2.375 sec\n"
    b"  Master Down interval is 9.125 sec\n"
)
CATEGORIES = ("state", "virtual_ip", "virtual_mac", "advertisement", "preemption",
    "priority", "authentication", "master", "master_advertisement", "master_down")


def block(interface="Vlan61", group="100", state="Backup"):
    return (interface + " - Group " + group + "\n").encode("ascii") + DETAIL.replace(b"Backup", state.encode("ascii"))


BODY = block()


def capture(raw=BODY, integrity=k.IntegrityState.COMPLETE):
    return replace(legacy_capture(raw, integrity), operation=parser.OP, rendered=parser.COMMAND)


def custody(raw, result):
    assert tuple(line.span for line in result.parse.lines) == tuple(line.span for line in text_lines(raw, "utf-8"))
    for record in result.parse.records:
        assert raw[record.span.start:record.span.end] in raw.splitlines()
        for _, token in record.fields:
            assert record.span.start <= token.span.start <= token.span.end <= record.span.end
            assert raw[token.span.start:token.span.end] == token.raw.encode("ascii")
    for index, row in enumerate(result.rows):
        assert any(row.header is record for record in result.parse.records)
        fields = dict(row.header.fields)
        assert row.interface is fields["interface"] and row.group is fields["group"]
        stop = result.rows[index + 1].header.span.start if index + 1 < len(result.rows) else len(raw)
        for record in row.body:
            assert any(record is original for original in result.parse.records)
            assert row.header.span.end <= record.span.start < record.span.end <= stop
        assert row.span.start == row.header.span.start
        assert row.span.end == (row.body[-1].span.end if row.body else row.header.span.end)
        for name, token in (("state", row.state), ("virtual_ip", row.virtual_ip)):
            if token is not None:
                assert any(field == name and token is original for record in row.body for field, original in record.fields)


def poisoned(raw, reason=k.UnknownReason.PARSE_PARTIAL, integrity=k.IntegrityState.COMPLETE):
    result = parser.parse_capture(capture(raw, integrity))
    assert result.reason is reason and result.parse.quality == "partial"
    assert all(row.reason is reason for row in result.rows)
    custody(raw, result)
    return result


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("final_newline", [False, True])
@pytest.mark.parametrize("state", ["Init", "INIT", "Master", "MASTER", "Backup", "BACKUP"])
@pytest.mark.parametrize("preemption", ["enabled", "disabled"])
def test_synthetic_states_frames_and_every_column_keep_original_bytes(ending, frame, final_newline, state, preemption):
    raw = block(state=state).replace(b"Preemption disabled", b"Preemption " + preemption.encode())
    if frame != "body":
        raw = parser.COMMAND.encode() + b"\n" + raw
    if frame == "prompt":
        raw = b"synthetic-a#" + raw + b"synthetic-a#\n"
    raw = raw.replace(b"\n", ending)
    if not final_newline:
        raw = raw[:-len(ending)]
    sample = capture(raw)
    original = replace(sample)
    result = parser.parse_capture(sample)
    row, = result.rows
    assert result.reason is row.reason is None and result.parse.quality == "complete"
    assert (row.interface.raw, row.group.raw, row.virtual_ip.raw, row.address_family) == ("Vlan61", "100", "198.51.100.41", "ipv4")
    assert row.state.raw == state and row.state.value is parser.VRRPState(state.lower())
    assert tuple(record.rule_id for record in row.body) == CATEGORIES
    assert tuple((name, token.raw) for record in row.body for name, token in record.fields) == (
        ("state", state), ("virtual_ip", "198.51.100.41"), ("virtual_mac", "0011.2233.4455"),
        ("advertisement", "1.250"), ("preemption", preemption), ("priority", "109"),
        ("authentication", "synthetic-lab"), ("master", "192.0.2.17"), ("master_priority", "113"),
        ("master_advertisement", "2.375"), ("master_down", "9.125"))
    assert sample == original and sample.raw is raw and sample.bytes_sha256 == sha256(raw).hexdigest()
    assert sample.read_scope is k.ReadScope.UNKNOWN and sample.view is k.ViewConsistency.UNKNOWN
    assert type(sample.collected_utc) is k.Unknown and sample.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert parser.parse_capture(sample) == result
    custody(raw, result)
    with pytest.raises(AttributeError):
        row.address_family = None


@pytest.mark.parametrize("group", ["100", "101"])
@pytest.mark.parametrize("mac", [b"0011.2233.4455", b"0000.5e00.0164", b"0000.5e00.0265"])
def test_group_mac_and_ipv4_supply_no_operating_version(group, mac):
    raw = block(group=group).replace(b"0011.2233.4455", mac)
    result = parser.parse_capture(capture(raw))
    row, = result.rows
    assert result.reason is None and row.reason is None and row.group.raw == group
    assert not hasattr(row, "version") and not hasattr(row, "subject")
    custody(raw, result)


def test_separate_blocks_and_blank_records_retain_their_own_header_and_footer():
    raw = b"\n" + BODY + b" \t\n" + block("Vl061", "101", "Master") + b"\n"
    result = parser.parse_capture(capture(raw))
    assert result.reason is None and result.parse.quality == "complete"
    assert [(row.interface.raw, row.group.raw) for row in result.rows] == [("Vlan61", "100"), ("Vl061", "101")]
    assert result.rows[0].body[-1] is not result.rows[1].body[-1]
    assert result.rows[0].span.end < result.rows[1].span.start
    custody(raw, result)


@pytest.mark.parametrize("index", range(10))
@pytest.mark.parametrize("plant", ["missing", "duplicate", "reorder"])
def test_every_required_body_category_is_once_in_order_and_never_borrowed(index, plant):
    lines = DETAIL.splitlines(keepends=True)
    if plant == "missing":
        lines.pop(index)
    elif plant == "duplicate":
        lines.insert(index, lines[index])
    else:
        other = (index + 1) % len(lines)
        lines[index], lines[other] = lines[other], lines[index]
    result = poisoned(BODY.splitlines(keepends=True)[0] + b"".join(lines))
    assert len(result.rows) == 1


@pytest.mark.parametrize("group", ["10000", "abc"])
def test_unsupported_new_heading_cannot_donate_footer_to_previous_incomplete_block(group):
    first = BODY.rsplit(b"  Master Down interval", 1)[0]
    second = block("Vl62", group)
    result = poisoned(first + second)
    assert len(result.rows) == 2 and [row.group.raw for row in result.rows] == ["100", group]
    assert len(result.rows[0].body) == 9 and len(result.rows[1].body) == 10
    assert all(record.rule_id != "master_down" for record in result.rows[0].body)
    assert result.rows[0].span.end < result.rows[1].header.span.start


@pytest.mark.parametrize("group", ["0", "99", "255", "256", "0100", "-1", "10000", "abc", "9" * 65])
def test_only_declared_synthetic_groups_are_supported_without_numeric_floor_claim(group):
    poisoned(block(group=group))


@pytest.mark.parametrize("raw", [
    *[BODY.replace(b"Backup", state) for state in (b"Initialize", b"BACKup", b"Active", b"Unknown")],
    *[BODY.replace(b"198.51.100.41", vip) for vip in (b"198.051.100.41", b"256.0.2.1", b"2001:db8::1", b"local")],
    *[BODY.replace(b"192.0.2.17", master) for master in (b"local", b"unknown", b"2001:db8::1")],
    *[BODY.replace(b"Group 100", b"Group 100 - Address-Family " + af) for af in (b"IPv4", b"IPv6", b"IP")],
    BODY.replace(b"Preemption disabled", b"Preemption unknown"),
    BODY.replace(b"Advertisement interval is 1.250 sec", b"Advertisement interval is 1250 msec"),
    BODY.replace(b"priority is 113", b"priority is unknown"),
    BODY.replace(b"Virtual IP address", b"Virtual IPv6 address"),
    *[BODY + tail for tail in (b"  Description synthetic\n", b"  Track object 5\n",
        b"  v2 Advertisement packets sent: 3\n", b"  v3 Advertisement packets received: 4\n",
        b"  v2 packets: 3\n  v3 packets: 4\n", b"unexpected detail\n", b"--More--\n", b"[truncated]\n")],
    *[prefix + BODY + suffix for prefix, suffix in (
        (b"show vrrp brief\n", b""), (b"synthetic-a#show vrrp\n", b"other#\n"),
        (b"synthetic-a#show vrrp\n", b""), (b"", b"synthetic-a#\n"),
        (b"show vrrp\n", b"show vrrp\n"), (b"show vrrp\n", b"synthetic-a#\n"))],
    b"synthetic-a#show vrrp\n" + BODY + b"synthetic-a#\n" + BODY,
    BODY[:-12], DETAIL,
])
def test_unmodelled_tokens_extensions_and_frames_never_grant_complete_rows(raw):
    poisoned(raw)


@pytest.mark.parametrize("second", [BODY, block(state="Master"), BODY.replace(b"198.51.100.41", b"198.51.100.42")])
def test_duplicate_identity_retains_both_blocks_and_never_uses_last_wins(second):
    result = poisoned(BODY + second, k.UnknownReason.CONFLICTING_EVIDENCE)
    assert len(result.rows) == 2 and result.rows[0].header is not result.rows[1].header


def test_unknown_state_token_is_evidence_bound_and_unknown_vip_never_establishes_af():
    result = poisoned(BODY.replace(b"Backup", b"Unknown"))
    state = result.rows[0].state
    assert type(state.value) is k.Unknown and state.value.reason is k.UnknownReason.PARSE_PARTIAL
    ref, = state.value.evidence
    assert ref.locator == state.span and ref.excerpt_sha256 == sha256(b"Unknown").hexdigest()
    result = poisoned(BODY.replace(b"198.51.100.41", b"unknown"), k.UnknownReason.IDENTITY_UNRESOLVED)
    assert result.rows[0].address_family is None


@pytest.mark.parametrize("integrity,reason", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (k.IntegrityState.UNVERIFIED_PROMPT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
])
def test_capture_damage_dominates_complete_and_duplicate_rows(integrity, reason):
    assert len(poisoned(BODY + BODY + b"unrecognized\n", reason, integrity).rows) == 2


@pytest.mark.parametrize("error", [ErrorKind.TIMEOUT, ErrorKind.INVALID_INPUT])
def test_explicit_metadata_error_dominates_and_original_scope_view_time_are_preserved(error):
    sample = capture()
    metadata = replace(sample.resolved_metadata, error=error, scope=replace(sample.scope, context="synthetic-context"))
    sample = replace(sample, metadata=metadata)
    before = replace(sample)
    result = parser.parse_capture(sample)
    assert result.reason is k.UnknownReason.CAPTURE_ERROR and result.rows[0].reason is result.reason
    assert sample == before and sample.metadata is metadata and sample.scope.context == "synthetic-context"


@pytest.mark.parametrize("raw", [b"", b" \t\r\n", b"show vrrp\n"])
def test_empty_or_command_only_capture_does_not_create_a_row(raw):
    result = poisoned(raw, k.UnknownReason.EMPTY_UNREGISTERED if not raw.strip() else k.UnknownReason.PARSE_PARTIAL)
    assert result.rows == ()


@pytest.mark.parametrize("change", [{"operation": "iosxe.show_standby_all"}, {"operation": None},
    {"rendered": "show vrrp brief"}, {"codec": "latin-1"}])
def test_other_operation_rendering_and_codec_are_refused(change):
    with pytest.raises(ValueError, match="^unsupported_vrrp$"):
        parser.parse_capture(replace(capture(), **change))


def test_parser_is_only_an_allowlisted_synthetic_observation_surface():
    assert parser.OP == "iosxe.show_vrrp" and parser.COMMAND == "show vrrp"
    assert parser.VARIANT_SUPPORT == "allowlisted" and parser.SYNTHETIC_GROUPS == ("100", "101")
    assert parser.SOURCES == (parser.SOURCE,)


@pytest.mark.parametrize("field", ["capture", "id", "source", "operation", "rendered", "codec", "raw", "integrity"])
def test_finite_input_types_refuse_before_parser_or_metadata_access(field):
    sample = capture()
    assert parser.parse_capture(sample).reason is None
    if field == "capture":
        sample = object()
    else:
        object.__setattr__(sample, field, [])
    with pytest.raises(ValueError, match="^unsupported_vrrp$"):
        parser.parse_capture(sample)
