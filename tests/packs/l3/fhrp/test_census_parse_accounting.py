"""Real census refusals retain original bytes, reasons and physical accounting."""
from dataclasses import replace

import pytest

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import census_parse_accounting as accounting
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census

NODE = k.EntityKey("node:demo:a")
SCOPE = b"baby-thanos.hsrp-census/1 node=node:demo:a interface=Vl10 af=ipv4 protocol=hsrp groups=all\n"
ZERO = SCOPE + b"success rows=0 sha256=aa56a60dd058ef7972dbf831eef5b0e16f49a71d55082ad9e2b85a967038a9f3\n"
BAD_DIGEST = ZERO.replace(b"sha256=aa", b"sha256=ba")


def _capture(raw, *, codec="ascii", integrity=k.IntegrityState.UNKNOWN_FORMAT):
    return Capture(
        id=k.CaptureId("census-accounting-input"), source=NODE, operation=census.OP,
        rendered=census.COMMAND, codec=codec, raw=raw, integrity=integrity,
        lines=text_lines(raw, codec), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN,
    )


@pytest.mark.parametrize(
    "raw, codec, integrity, reason, detail, spans",
    [
        (b"", "ascii", k.IntegrityState.UNKNOWN_FORMAT,
         k.UnknownReason.EMPTY_UNREGISTERED, "empty_capture", ()),
        (b"\xff\r\nx\nz", "ascii", k.IntegrityState.UNKNOWN_FORMAT,
         k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_encoding", ((0, 3), (3, 5), (5, 6))),
        (b"\xc3\xa9\n\n\x0b\x0c\x85\r", "utf-8", k.IntegrityState.UNKNOWN_FORMAT,
         k.UnknownReason.PARSE_UNSUPPORTED_VARIANT, "capture_encoding", ((0, 3), (3, 4), (4, 8))),
        (b"% Error\r\n\n", "ascii", k.IntegrityState.ERROR,
         k.UnknownReason.CAPTURE_ERROR, "capture_error", ((0, 9), (9, 10))),
    ],
)
def test_real_preflight_refusals_get_only_exact_unrecognised_physical_lf_lines(raw, codec, integrity, reason, detail, spans):
    source = _capture(raw, codec=codec, integrity=integrity)
    result = census.parse_capture(source, node=NODE, interface="Vl10")
    assert result.census is None and result.parse is None and result.reason is reason and result.detail == detail
    parsed = accounting.refused_parse_accounting(result, source.raw, max_bytes=len(raw), max_lines=len(spans))
    assert parsed.quality == "partial" and parsed.records == parsed.tokens == ()
    assert tuple((line.span.start, line.span.end) for line in parsed.lines) == spans
    assert tuple(line.span for line in parsed.lines) == tuple(line.span for line in source.lines)
    assert all((line.status, line.rule_id, line.reason) == ("unrecognised", "", detail) for line in parsed.lines)
    assert b"".join(source.raw[line.span.start:line.span.end] for line in parsed.lines) == raw
    assert source.raw is raw and source.read_scope is k.ReadScope.UNKNOWN and source.view is k.ViewConsistency.UNKNOWN
    assert result.census is None and result.parse is None and result.reason is reason and result.detail == detail


@pytest.mark.parametrize("limit", ["bytes", "lines"])
def test_reduced_resource_ceiling_refuses_before_new_physical_line_allocation(monkeypatch, limit):
    raw = b"\xff\n\nend"
    result = census.parse_capture(_capture(raw), node=NODE, interface="Vl10")
    assert result.parse is None and result.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT

    def forbid_line(*_args, **_kwargs):
        pytest.fail("fallback allocated a line before enforcing its limits")

    monkeypatch.setattr(accounting.rules, "LineAccounting", forbid_line)
    with pytest.raises(BudgetExceeded) as refusal:
        accounting.refused_parse_accounting(
            result, raw, max_bytes=len(raw) - (limit == "bytes"), max_lines=3 - (limit == "lines"),
        )
    assert refusal.value.member == "hsrp_census_negative_accounting"


def test_syntactically_consumed_digest_failure_keeps_actual_partial_result_by_identity():
    result = census.parse_capture(_capture(BAD_DIGEST), node=NODE, interface="Vl10")
    assert result.census is None and result.reason is k.UnknownReason.PARSE_PARTIAL and result.detail == "footer_hash"
    assert result.parse.quality == "partial"
    assert [line.status for line in result.parse.lines] == ["consumed", "consumed"]
    assert accounting.refused_parse_accounting(result, BAD_DIGEST, max_bytes=0, max_lines=0) is result.parse


@pytest.mark.parametrize("shape", ["success", "reason_missing", "detail_missing", "complete_negative"])
def test_fallback_rejects_unsupported_result_shapes(shape):
    raw = ZERO if shape == "success" else BAD_DIGEST
    actual = census.parse_capture(_capture(raw), node=NODE, interface="Vl10")
    if shape == "success":
        assert actual.census is not None and actual.parse.quality == "complete"
    elif shape == "reason_missing":
        actual = replace(actual, reason=None)
    elif shape == "detail_missing":
        actual = replace(actual, detail=None)
    else:
        actual = replace(actual, parse=replace(actual.parse, quality="complete"))
    with pytest.raises(ValueError, match="^hsrp_census_negative_accounting$"):
        accounting.refused_parse_accounting(actual, raw, max_bytes=len(raw), max_lines=2)


def test_fallback_rejects_bytes_subclass_before_length_or_scan():
    class ForeignBytes(bytes):
        def __len__(self):
            raise AssertionError("measured an open raw payload")

        def count(self, *_args, **_kwargs):
            pytest.fail("scanned an open raw payload")

    result = census.parse_capture(_capture(b""), node=NODE, interface="Vl10")
    with pytest.raises(ValueError, match="^hsrp_census_negative_accounting$"):
        accounting.refused_parse_accounting(result, ForeignBytes(b""), max_bytes=0, max_lines=0)
