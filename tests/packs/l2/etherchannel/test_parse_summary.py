"""Generated EtherChannel twins; no imported device capture or train claims."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import parse_summary as parser

PORTS = ("Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4")
HEADER = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\n"
          b"Group  Port-channel  Protocol    Ports\n------+-------------+-----------+----\n")
ROW = b"1  Po1(SU)  LACP  Gi1/0/1(P) Gi1/0/2(s)\n"
BODY = HEADER + ROW + b"   Gi1/0/3(D)\n"


def capture(raw=BODY):
    return Capture(id=k.CaptureId("cap:" + sha256(raw).hexdigest()), source=k.EntityKey("node:synthetic:a"),
                   operation=parser.OP, rendered=parser.COMMAND, codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                   read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


def parse(raw=BODY, groups=("1",), ports=PORTS):
    return parser.parse_capture(capture(raw), groups, ports)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("final_newline", [True, False])
def test_wrapped_nonactive_members_keep_every_original_token_and_line(ending, final_newline):
    raw = BODY.replace(b"\n", ending)
    if not final_newline:
        raw = raw.rstrip(b"\r\n")
    result = parse(raw)
    row, = result.rows
    assert result.reason is row.reason is None
    assert result.parse.quality == "complete" and result.missing_ports == ("Gi1/0/4",)
    assert [(m.port.raw, m.flag.raw) for m in row.members] == list(zip(PORTS, ("P", "s", "D"), strict=False))
    assert len(row.spans) == 2
    for member in row.members:
        assert raw[member.span.start:member.span.end] == (member.port.raw + "(" + member.flag.raw + ")").encode()
        for token in (member.port, member.flag):
            assert member.span.start <= token.span.start < token.span.end <= member.span.end
            assert raw[token.span.start:token.span.end] == token.raw.encode()
    assert b"".join(raw[line.span.start:line.span.end] for line in result.parse.lines) == raw


@pytest.mark.parametrize("protocol,expected", [(b"LACP", parser.Protocol.LACP), (b"PAgP", parser.Protocol.PAGP),
                                              (b"-", parser.Protocol.NONE)])
def test_protocol_is_observed_separately_and_never_infers_static_mode(protocol, expected):
    result = parse(BODY.replace(b"LACP", protocol))
    row, = result.rows
    fields = dict(row.fields)
    assert result.reason is None and fields["protocol"].value is expected
    assert "mode" not in fields and "minimum_links" not in fields
    assert len(row.members) == 3


@pytest.mark.parametrize("flag", [b"P", b"bndl", b"D", b"I", b"s", b"susp", b"H", b"hot-sby", b"u", b"w", b"d", b"f"])
def test_every_supported_member_state_remains_in_population(flag):
    result = parse(HEADER + b"1 Po1(SU) LACP Gi1/0/1(" + flag + b")\n")
    assert result.reason is None and len(result.rows[0].members) == 1
    assert result.rows[0].members[0].flag.raw == flag.decode()
    assert result.missing_ports == PORTS[1:]


def test_declared_groups_do_not_assign_membership_or_create_intent():
    raw = HEADER.replace(b"in use: 1", b"in use: 2").replace(b"aggregators: 1", b"aggregators: 2")
    raw += b"2 Po2(SU) PAgP Gi1/0/1(P)\n1 Po1(SD) -\n"
    result = parse(raw, ("2", "1"))
    assert result.reason is None and [row.group for row in result.rows] == ["1", "2"]
    assert result.rows[0].members == () and result.rows[1].members[0].port.raw == PORTS[0]


def test_missing_expected_bundle_and_ports_stay_visible_without_loss_verdict():
    result = parse(groups=("2", "1"))
    missing = result.rows[1]
    assert missing.group == "2" and missing.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert missing.fields == missing.members == missing.spans == ()
    assert result.missing_ports == ("Gi1/0/4",)


def test_valid_zero_table_is_distinct_from_blank_failed_or_legend_only_response():
    raw = HEADER.replace(b"in use: 1", b"in use: 0").replace(b"aggregators: 1", b"aggregators: 0")
    result = parse(raw)
    assert result.reason is None and result.rows[0].reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert result.missing_ports == PORTS and result.rows[0].members == ()
    assert parse(b"").reason is k.UnknownReason.EMPTY_UNREGISTERED
    assert parse(b"Flags: D - down P - bundled in port-channel\n").reason is k.UnknownReason.PARSE_PARTIAL
    assert parse(b"% Invalid input detected\n").reason is k.UnknownReason.PARSE_PARTIAL


def test_supported_legends_never_become_member_donors():
    raw = (b"Flags:  D - down        P - bundled in port-channel\n"
           b"        I - stand-alone s - suspended\n        H - Hot-standby (LACP only)\n") + BODY
    result = parse(raw)
    assert result.reason is None and len(result.rows[0].members) == 3
    poisoned = parse(b"Gi1/0/4(P) - invented legend\n" + BODY)
    assert poisoned.reason is k.UnknownReason.PARSE_PARTIAL and poisoned.missing_ports == ("Gi1/0/4",)


@pytest.mark.parametrize("raw", [
    HEADER + ROW + ROW, HEADER + ROW + b" Gi1/0/1(P)\n",
    HEADER.replace(b"in use: 1", b"in use: 2") + ROW + b"2 Po2(SU) LACP Gi1/0/1(P)\n",
])
def test_duplicate_bundles_or_members_conflict_even_when_equal(raw):
    result = parse(raw, ("1", "2"))
    assert result.reason is k.UnknownReason.CONFLICTING_EVIDENCE
    assert all(row.reason is result.reason for row in result.rows)


@pytest.mark.parametrize("raw", [
    BODY.replace(b"in use: 1", b"in use:"), BODY.replace(b"in use: 1", b"in use: 01"),
    BODY.replace(b"in use: 1", b"in use: 2"), BODY.replace(b"Po1", b"Po2"),
    BODY.replace(b"SU", b"XX"), BODY.replace(b"SU", b"SR"), BODY.replace(b"(P)", b"(unknown)"),
    BODY.replace(b"aggregators: 1", b"aggregators: 0"), HEADER.split(b"Group")[0].replace(b": 1", b": 0"),
    BODY.replace(b"LACP", b"passive"), BODY.replace(b"LACP", b"on"),
    BODY + b"unmodelled tail\n", BODY.replace(b"Gi1/0/1(P)", b"Gi1/0/1"),
    HEADER + b" Gi1/0/1(P)\n" + ROW, BODY.replace(b"------+-------------+-----------+----\n", b""),
])
def test_unusable_or_unrecognised_input_poison_is_not_a_complete_observation(raw):
    result = parse(raw)
    assert result.reason is k.UnknownReason.PARSE_PARTIAL
    assert result.parse.quality == "partial" and all(row.reason is result.reason for row in result.rows)


@pytest.mark.parametrize("integrity,reason", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
])
def test_integrity_dominates_plausible_and_partial_rows(integrity, reason):
    result = parser.parse_capture(replace(capture(BODY + b"bad\n"), integrity=integrity), ("1",), PORTS)
    assert result.reason is reason and result.rows[0].reason is reason


@pytest.mark.parametrize("opening,closing", [(b"", b""), (b"show etherchannel summary\n", b""),
                                            (b"sw#show etherchannel summary\n", b"sw#\n")])
def test_exact_optional_envelopes(opening, closing):
    assert parse(opening + BODY + closing).reason is None


def test_prompt_mismatch_and_concatenated_command_are_partial():
    assert parse(b"sw#show etherchannel summary\n" + BODY + b"other#\n").reason is k.UnknownReason.PARSE_PARTIAL
    assert parse(BODY + b"sw#\n" + BODY).reason is k.UnknownReason.PARSE_PARTIAL


@pytest.mark.parametrize("raw,code", [(BODY.replace(b"1  Po1", b"9  Po9"), "undeclared_etherchannel_group"),
                                    (BODY.replace(b"Gi1/0/1", b"Gi1/0/99"), "undeclared_etherchannel_port")])
def test_foreign_subjects_refuse(raw, code):
    with pytest.raises(ValueError, match="^" + code + "$"):
        parse(raw)


@pytest.mark.parametrize("groups,ports", [((), PORTS), (("01",), PORTS), (("65536",), PORTS),
                                        (("1", "1"), PORTS), (("1",), ("Gi1", "Gi1")),
                                        (("1",), ("bad port",)), (("1",), ("G\u0131",))])
def test_invalid_declared_populations_refuse(groups, ports):
    with pytest.raises(ValueError, match="^invalid_etherchannel_population$"):
        parse(groups=groups, ports=ports)


@pytest.mark.parametrize("change", [{"operation": "iosxe.show_etherchannel_detail"},
                                    {"rendered": "show etherchannel"}, {"codec": "latin-1"}])
def test_capture_command_identity_is_exact(change):
    with pytest.raises(ValueError, match="^unsupported_etherchannel_summary$"):
        parser.parse_capture(replace(capture(), **change), ("1",), PORTS)


@pytest.mark.parametrize("raw", [
    BODY.replace(b"aggregators: 1", b"aggregators: 2"),
    HEADER.replace(b"in use: 1", b"in use: 2") + ROW + b"2 Po2(SD) -\n",
])
def test_count_relation_outside_allowlist_is_partial_not_subject_absence(raw):
    result = parse(raw, ("2", "1"))
    assert result.reason is k.UnknownReason.PARSE_PARTIAL
    assert result.parse.quality == "partial"
    assert [row.group for row in result.rows] == ["1", "2"]
    assert all(row.reason is result.reason for row in result.rows)
