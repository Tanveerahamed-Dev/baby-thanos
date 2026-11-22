"""Validate actual and planted census products against original wire bytes."""
from dataclasses import replace

import pytest
from test_parse_hsrp_census import EMPTY, FULL, NODE, _capture

from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import census_product_snapshot as snapshot
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census

BAD_HASH = EMPTY[:-2] + b"0\n"
BAD_COUNT = EMPTY.replace(b"rows=0", b"rows=1")


def _forbid_dispatch(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("product validation dispatched parsing again")

    monkeypatch.setattr(census, "parse_capture", forbidden)
    monkeypatch.setattr(census.rules, "run_rules", forbidden)


@pytest.mark.parametrize("raw, interface, detail", [
    (EMPTY, "Vl10", None), (FULL, "Vl10", None),
    (BAD_HASH, "Vl10", "footer_hash"), (BAD_COUNT, "Vl10", "footer_count"),
    (EMPTY, "Vl20", "header_scope"), (EMPTY[:-1], "Vl10", "missing_final_lf"),
    (EMPTY.replace(b"\n", b"\r\n"), "Vl10", "noncanonical_line_end"),
    (EMPTY + b"ignored garbage\n", "Vl10", "wire_shape"),
    (b"\xff\n", "Vl10", "capture_encoding"), (b"", "Vl10", "empty_capture"),
])
def test_actual_products_validate_without_another_parser_dispatch(monkeypatch, raw, interface, detail):
    capture = _capture(raw)
    result = census.parse_capture(capture, node=NODE, interface=interface)
    assert result.detail == detail
    original = result.parse
    _forbid_dispatch(monkeypatch)
    census.validate_product(capture, node=NODE, interface=interface, value=result)
    assert result.parse is original


def forged_success(capture, result):
    parsed = replace(result.parse, quality="complete")
    header, footer = parsed.records
    frame = census.Census(scope=header, scope_raw=capture.raw[:parsed.lines[0].span.end], groups=(),
                          footer=footer, body_span=k.ByteSpan(start=0, end=footer.span.start))
    return census.Result(census=frame, parse=parsed, reason=None, detail=None)


@pytest.mark.parametrize("raw", [BAD_HASH, BAD_COUNT])
def test_genuine_refusal_cannot_become_a_success_over_the_same_original_bytes(monkeypatch, raw):
    capture = _capture(raw)
    refused = census.parse_capture(capture, node=NODE, interface="Vl10")
    assert refused.census is None and all(line.status == "consumed" for line in refused.parse.lines)
    value = forged_success(capture, refused)
    _forbid_dispatch(monkeypatch)
    with pytest.raises(ValueError, match="^hsrp_census_product_result$"):
        census.validate_product(capture, node=NODE, interface="Vl10", value=value)


@pytest.mark.parametrize("fault, error", [
    ("token", "token"), ("status", "accounting"), ("trailing_line", "accounting"),
    ("missing_record", "accounting"), ("wrong_scope_claim", "result"),
])
def test_detached_or_changed_product_claims_refuse_against_actual_wire(monkeypatch, fault, error):
    capture = _capture(EMPTY)
    result = census.parse_capture(capture, node=NODE, interface="Vl10")
    parsed = result.parse
    if fault == "token":
        object.__setattr__(parsed.records[0].fields[0][1], "span", k.ByteSpan(start=1, end=25))
    elif fault == "status":
        object.__setattr__(parsed.lines[0], "status", "unrecognised")
    elif fault == "trailing_line":
        object.__setattr__(parsed, "lines", (*parsed.lines, parsed.lines[-1]))
    elif fault == "missing_record":
        object.__setattr__(parsed, "records", parsed.records[:1])
    else:
        object.__setattr__(result.census, "scope_raw", b"different")
    _forbid_dispatch(monkeypatch)
    with pytest.raises(ValueError, match=f"^hsrp_census_product_{error}$"):
        census.validate_product(capture, node=NODE, interface="Vl10", value=result)


def test_snapshot_keeps_detached_original_fields_for_later_comparison():
    capture = _capture(BAD_HASH)
    result = census.parse_capture(capture, node=NODE, interface="Vl10")
    original = snapshot.snapshot_product(result, result.parse, capture)
    object.__setattr__(result, "detail", "changed")
    assert snapshot.snapshot_product(result, result.parse, capture) != original


@pytest.mark.parametrize("fault, error", [
    ("capture", "capture"), ("raw", "capture"), ("lines", "capture"),
    ("line", "accounting"), ("span", "span"), ("coordinate", "span"),
])
def test_real_product_refuses_open_cached_capture_accounting_before_use(monkeypatch, fault, error):
    capture = _capture(EMPTY)
    value = census.parse_capture(capture, node=NODE, interface="Vl10")
    line = capture.lines[0]
    span = line.span

    def opened(*_args):
        pytest.fail("snapshot used an open capture or cached accounting value")

    if fault == "capture":
        class OpenCapture(type(capture)):
            __slots__ = ()
            __getattribute__ = opened

        object.__setattr__(capture, "__class__", OpenCapture)
    elif fault == "raw":
        class OpenRaw(bytes):
            __len__ = opened
            __getitem__ = opened

        object.__setattr__(capture, "raw", OpenRaw(capture.raw))
    elif fault == "lines":
        class OpenLines(tuple):
            __len__ = opened
            __iter__ = opened

        object.__setattr__(capture, "lines", OpenLines(capture.lines))
    elif fault == "line":
        class OpenLine(type(line)):
            __slots__ = ()
            __getattribute__ = opened

        object.__setattr__(line, "__class__", OpenLine)
    elif fault == "span":
        class OpenSpan(type(span)):
            __slots__ = ()
            __getattribute__ = opened

        object.__setattr__(span, "__class__", OpenSpan)
    else:
        class OpenCoordinate(int):
            __eq__ = opened
            __ge__ = opened

        object.__setattr__(span, "start", OpenCoordinate(span.start))
    _forbid_dispatch(monkeypatch)
    with pytest.raises(ValueError, match=f"^hsrp_census_owner_{error}$"):
        snapshot.snapshot_product(value, value.parse, capture)
