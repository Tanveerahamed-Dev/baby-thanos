"""Literal synthetic census framing, retained bytes and unresolved controls."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture, ErrorKind
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census

NODE = k.EntityKey("node:demo:a")
SCOPE = b"baby-thanos.hsrp-census/1 node=node:demo:a interface=Vl10 af=ipv4 protocol=hsrp groups=all\n"
ROW_ZERO = b"group node=node:demo:a interface=Vl10 id=0\n"
ROW_MAX = b"group node=node:demo:a interface=Vl10 id=4095\n"
BODY = SCOPE + ROW_ZERO + ROW_MAX
FULL = BODY + b"success rows=2 sha256=4c83e3c8b3ed40976b90e17805ac7c8ac6b60cdabf18795116694dfb3ad1cafd\n"
EMPTY = SCOPE + b"success rows=0 sha256=aa56a60dd058ef7972dbf831eef5b0e16f49a71d55082ad9e2b85a967038a9f3\n"
PARTIAL = k.UnknownReason.PARSE_PARTIAL
OUTSIDE = k.UnknownReason.OUT_OF_SCOPE


def _capture(raw, *, source=NODE, codec="ascii", integrity=k.IntegrityState.UNKNOWN_FORMAT):
    return Capture(id=k.CaptureId("literal-census-input"), source=source, operation=census.OP,
                   rendered=census.COMMAND, codec=codec, raw=raw, integrity=integrity,
                   lines=text_lines(raw, codec), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


def _footer(body, count):
    return b"success rows=" + str(count).encode("ascii") + b" sha256=" + sha256(body).hexdigest().encode("ascii") + b"\n"


def _framed(body, count):
    return body + _footer(body, count)


def _fields(record):
    return tuple((name, token.raw, token.span.start, token.span.end) for name, token in record.fields)


def _assert_unresolved(result, reason, detail):
    assert result.census is None and result.reason is reason and result.detail == detail
    assert result.parse is None or result.parse.quality == "partial"


def test_literal_nonempty_census_retains_the_entire_wire_and_actual_fields():
    source = _capture(FULL)
    result = census.parse_capture(source, node=NODE, interface="Vl10")
    accepted = result.census
    assert result.reason is None and result.detail is None and accepted.scope_raw == SCOPE
    assert accepted.body_span == k.ByteSpan(start=0, end=180)
    assert tuple(row.number for row in accepted.groups) == (0, 4095)
    assert _fields(accepted.scope) == (
        ("schema", "baby-thanos.hsrp-census/1", 0, 25), ("node", "node:demo:a", 31, 42),
        ("interface", "Vl10", 53, 57), ("af", "ipv4", 61, 65),
        ("protocol", "hsrp", 75, 79), ("coverage", "all", 87, 90),
    )
    zero, maximum = (row.record for row in accepted.groups)
    assert _fields(zero) == (("node", "node:demo:a", 102, 113), ("interface", "Vl10", 124, 128), ("group", "0", 132, 133))
    assert _fields(maximum) == (("node", "node:demo:a", 145, 156), ("interface", "Vl10", 167, 171), ("group", "4095", 175, 179))
    assert _fields(accepted.footer) == (
        ("completion", "success", 180, 187), ("count", "2", 193, 194),
        ("digest", "4c83e3c8b3ed40976b90e17805ac7c8ac6b60cdabf18795116694dfb3ad1cafd", 202, 266),
    )
    assert result.parse.quality == "complete" and result.parse.tokens == ()
    assert tuple((line.span.start, line.span.end, line.status) for line in result.parse.lines) == (
        (0, 91, "consumed"), (91, 134, "consumed"), (134, 180, "consumed"), (180, 267, "consumed"),
    )
    assert tuple(FULL[record.span.start:record.span.end] for record in result.parse.records) == (
        SCOPE[:-1], ROW_ZERO[:-1], ROW_MAX[:-1], FULL[180:-1],
    )
    assert source.read_scope is k.ReadScope.UNKNOWN and source.view is k.ViewConsistency.UNKNOWN


def test_literal_success_zero_is_framed_and_retains_footer_fields():
    result = census.parse_capture(_capture(EMPTY, codec="utf-8"), node=NODE, interface="Vl10")
    accepted = result.census
    assert result.reason is None and result.parse.quality == "complete"
    assert accepted.scope_raw == SCOPE and accepted.groups == ()
    assert accepted.body_span == k.ByteSpan(start=0, end=91)
    assert _fields(accepted.footer) == (
        ("completion", "success", 91, 98), ("count", "0", 104, 105),
        ("digest", "aa56a60dd058ef7972dbf831eef5b0e16f49a71d55082ad9e2b85a967038a9f3", 113, 177),
    )


def _row(number):
    return b"group node=node:demo:a interface=Vl10 id=" + str(number).encode("ascii") + b"\n"


def test_entire_numeric_group_domain_at_the_cardinality_ceiling():
    body = SCOPE + b"".join(_row(number) for number in range(4096))
    node, interface = k.EntityKey("node:" + "a" * 32 + ":" + "b" * 32), "V" * 64
    body = body.replace(b"node:demo:a", node.encode("ascii")).replace(b"Vl10", interface.encode("ascii"))
    result = census.parse_capture(_capture(_framed(body, 4096), source=node), node=node, interface=interface)
    assert result.reason is None and len(result.parse.lines) == 4098
    assert [group.number for group in result.census.groups] == list(range(4096))


@pytest.mark.parametrize(("raw", "reason", "detail"), (
    pytest.param(b"", k.UnknownReason.EMPTY_UNREGISTERED, "empty_capture", id="bare-empty"),
    pytest.param(SCOPE, PARTIAL, "wire_shape", id="header-only"),
    pytest.param(BODY, PARTIAL, "wire_shape", id="missing-footer"),
    pytest.param(_framed(ROW_ZERO, 1), PARTIAL, "wire_shape", id="missing-header"),
    pytest.param(EMPTY.replace(b"success", b"failure"), PARTIAL, "wire_shape", id="failed-footer"),
    pytest.param(FULL.replace(b"rows=2", b"rows=1"), PARTIAL, "footer_count", id="wrong-count"),
    pytest.param(FULL.replace(b"rows=2", b"rows=02"), PARTIAL, "footer_count", id="noncanonical-count"),
    pytest.param(FULL.replace(b"sha256=4", b"sha256=9"), PARTIAL, "footer_hash", id="wrong-digest"),
    pytest.param(FULL.replace(b"sha256=4c", b"sha256=4C"), PARTIAL, "wire_shape", id="uppercase-digest"),
    pytest.param(FULL.replace(b"id=4095", b"id=4094"), PARTIAL, "footer_hash", id="changed-row"),
    pytest.param(BODY + _footer(BODY[:-1], 2), PARTIAL, "footer_hash", id="hash-omits-last-lf"),
    pytest.param(_framed(SCOPE.replace(b"af=ipv4", b"af=ipv6"), 0), PARTIAL, "wire_shape", id="ipv6"),
    pytest.param(_framed(SCOPE.replace(b"protocol=hsrp", b"protocol=vrrp"), 0), PARTIAL, "wire_shape", id="vrrp"),
    pytest.param(_framed(SCOPE.replace(b"groups=all", b"groups=one"), 0), PARTIAL, "wire_shape", id="limited"),
    pytest.param(_framed(SCOPE + _row(4096), 1), PARTIAL, "group_number", id="group-too-large"),
    pytest.param(_framed(SCOPE + _row("00"), 1), PARTIAL, "group_number", id="leading-zero"),
    pytest.param(_framed(SCOPE + _row(-1), 1), PARTIAL, "wire_shape", id="negative-group"),
    pytest.param(_framed(SCOPE + ROW_ZERO * 2, 2), k.UnknownReason.CONFLICTING_EVIDENCE, "duplicate_group", id="duplicate"),
    pytest.param(_framed(SCOPE + ROW_ZERO.replace(b"node:demo:a", b"node:demo:b"), 1), OUTSIDE, "row_scope", id="rehashed-foreign-node-row"),
    pytest.param(_framed(SCOPE + ROW_ZERO.replace(b"Vl10", b"Vl11"), 1), OUTSIDE, "row_scope", id="rehashed-foreign-interface-row"),
    pytest.param(_framed(SCOPE.replace(b"Vl10", b"Vl11"), 0), OUTSIDE, "header_scope", id="rehashed-foreign-header"),
    pytest.param(_framed(SCOPE.replace(b"Vl10", b"vl10"), 0), OUTSIDE, "header_scope", id="interface-case"),
    pytest.param(FULL + b"router#\n", PARTIAL, "wire_shape", id="trailing-prompt"),
    pytest.param(FULL + b"\n", PARTIAL, "wire_shape", id="trailing-empty-line"),
    pytest.param(FULL + ROW_ZERO, PARTIAL, "wire_shape", id="trailing-row"),
    pytest.param(FULL + _footer(BODY, 2), PARTIAL, "wire_shape", id="duplicate-footer"),
    pytest.param(_framed(SCOPE + b"% Command failed\n", 0), PARTIAL, "wire_shape", id="rehash-error-line"),
    pytest.param(_framed(SCOPE + b"--More--\n", 0), PARTIAL, "wire_shape", id="rehash-paging-line"),
    pytest.param(_framed(SCOPE + b"[truncated]\n", 0), PARTIAL, "wire_shape", id="rehash-truncation-line"),
    pytest.param(FULL.replace(b"\n", b"\r\n"), PARTIAL, "noncanonical_line_end", id="crlf"),
    pytest.param(FULL[:-1], k.UnknownReason.CAPTURE_TRUNCATED, "missing_final_lf", id="missing-final-lf"),
    pytest.param(b"\xef\xbb\xbf" + FULL, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_encoding", id="bom"),
    pytest.param(FULL.replace(b"Vl10", b"Vl\xff0"), k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_encoding", id="non-ascii"),
))
def test_invalid_raw_never_yields_a_census(raw, reason, detail):
    _assert_unresolved(census.parse_capture(_capture(raw), node=NODE, interface="Vl10"), reason, detail)


@pytest.mark.parametrize(("integrity", "reason", "detail"), (
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR, "capture_error"),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED, "capture_incomplete"),
    (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED, "capture_incomplete"),
    (k.IntegrityState.UNVERIFIED_PROMPT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_integrity"),
    (k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED, "empty_capture"),
))
def test_negative_capture_integrity_vetoes_even_a_valid_footer(integrity, reason, detail):
    _assert_unresolved(census.parse_capture(_capture(FULL, integrity=integrity), node=NODE, interface="Vl10"), reason, detail)


def test_footer_authenticates_the_original_header_even_when_no_groups_exist():
    source = _capture(EMPTY.replace(b"Vl10", b"Vl11"))
    _assert_unresolved(census.parse_capture(source, node=NODE, interface="Vl11"), PARTIAL, "footer_hash")


def test_ascii_bytes_in_an_unadmitted_codec_are_unresolved():
    result = census.parse_capture(_capture(FULL, codec="latin-1"), node=NODE, interface="Vl10")
    _assert_unresolved(result, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_encoding")


def test_capture_source_cannot_donate_an_otherwise_valid_scope():
    result = census.parse_capture(_capture(FULL, source=k.EntityKey("node:demo:b")), node=NODE, interface="Vl10")
    _assert_unresolved(result, OUTSIDE, "capture_source")


def test_positive_metadata_cannot_turn_header_only_into_a_census():
    source = _capture(SCOPE, integrity=k.IntegrityState.COMPLETE)
    meta = source.resolved_metadata
    source = replace(source, read_scope=k.ReadScope.FULL_EVIDENCED, view=k.ViewConsistency.ATOMIC,
                     metadata=replace(meta, read_scope_evidence=meta.integrity_evidence))
    _assert_unresolved(census.parse_capture(source, node=NODE, interface="Vl10"), PARTIAL, "wire_shape")


@pytest.mark.parametrize(("error", "reason", "detail"), (
    (ErrorKind.UNAUTHORIZED, k.UnknownReason.CAPTURE_ERROR, "capture_error"),
    (ErrorKind.INCOMPLETE, k.UnknownReason.CAPTURE_TRUNCATED, "capture_incomplete"),
))
def test_negative_metadata_vetoes_valid_syntax(error, reason, detail):
    source = _capture(FULL)
    source = replace(source, metadata=replace(source.resolved_metadata, error=error))
    _assert_unresolved(census.parse_capture(source, node=NODE, interface="Vl10"), reason, detail)


@pytest.mark.parametrize("raw", (b"x" * 680_001, b"x\n" * 4099), ids=("byte-bound", "line-bound"))
def test_wire_budget_refuses_before_rule_dispatch(raw, monkeypatch):
    source = replace(_capture(b""), raw=raw)
    monkeypatch.setattr(census.rules, "run_rules", lambda *_: pytest.fail("unbounded wire reached parsekit"))
    _assert_unresolved(census.parse_capture(source, node=NODE, interface="Vl10"), k.UnknownReason.BUDGET_EXCEEDED, "wire_bounds")


def test_existing_cisco_operation_cannot_be_admitted_by_the_synthetic_parser():
    source = replace(_capture(FULL), operation=brief.OP, rendered=brief.COMMAND)
    with pytest.raises(ValueError, match="^hsrp_census_source$"):
        census.parse_capture(source, node=NODE, interface="Vl10")


def test_hostile_capture_field_cannot_dispatch_a_comparison():
    class Hostile(str):
        def __eq__(self, original):
            pytest.fail("unclosed carrier field was used")

    source = _capture(FULL)
    object.__setattr__(source, "source", Hostile(NODE))
    with pytest.raises(ValueError, match="^hsrp_census_source$"):
        census.parse_capture(source, node=NODE, interface="Vl10")
