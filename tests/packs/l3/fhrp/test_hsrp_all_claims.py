"""Independent synthetic raw-proof forgeries; no carrier grants admission or network truth."""
from dataclasses import asdict, replace
from enum import StrEnum

import pytest
from test_parse_hsrp_all import BODY, block, capture

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.evidence.parsekit.rules import Captured, Record
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as parser
from atlas_brain.runner import pack_runtime


class Text(StrEnum):
    VERSION = "2"
    FAMILY = "ipv4"
    QUALITY = "complete"


def original(raw=BODY, integrity=k.IntegrityState.COMPLETE):
    sample = capture(raw, integrity)
    return sample, parser.parse_capture(sample)


def proofs(sample, result):
    checked = parser.validate_claims(sample, result)
    assert type(checked) is tuple and len(checked) == len(result.rows)
    for row, (owned, spans) in zip(result.rows, checked, strict=True):
        assert owned is row and type(spans) is tuple
        expected = {row.header.span, row.interface.span, row.group.span}
        if row.version is not None:
            expected.add(row.version.span)
        for record in row.body:
            if record.rule_id == "virtual_ip":
                expected.add(record.span)
                expected.add(dict(record.fields)["virtual_ip"].span)
            if record.rule_id == "group_name":
                expected.add(record.span)
        assert spans == tuple(sorted(expected, key=lambda point: (point.start, point.end)))
        assert all(type(span) is k.ByteSpan and 0 <= span.start < span.end <= len(sample.raw) for span in spans)
    return checked


def replace_token(result, name, token):
    row = result.rows[0]
    old = getattr(row, name)
    changed = {}
    for record in (row.header, *row.body):
        if any(value is old for _, value in record.fields):
            changed[id(record)] = replace(record, fields=tuple((key, token if value is old else value)
                                                               for key, value in record.fields))
    header = changed.get(id(row.header), row.header)
    body = tuple(changed.get(id(record), record) for record in row.body)
    row = replace(row, **{name: token}, header=header, body=body)
    parsed = replace(result.parse, records=tuple(changed.get(id(record), record) for record in result.parse.records))
    return replace(result, rows=(row, *result.rows[1:]), parse=parsed)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("version", ["1", "2"])
def test_authenticates_original_rows_columns_closure_and_spans_without_replay(monkeypatch, ending, frame, version):
    raw = block(version)
    if frame != "body":
        raw = b"show standby all\n" + raw
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    sample, result = original(raw.replace(b"\n", ending))
    def forbidden(*args, **kwargs):
        pytest.fail("proof validation replayed parser, dispatcher or writer")
    monkeypatch.setattr(parser, "parse_capture", forbidden)
    monkeypatch.setattr(parser, "run_rules", forbidden)
    monkeypatch.setattr(pack_runtime, "execute_parsers", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    before = (sample.raw, asdict(result))
    checked = proofs(sample, result)
    assert checked[0][0].reason is None
    assert (sample.raw, asdict(result)) == before


@pytest.mark.parametrize("raw,integrity,reason", [
    (block(None), k.IntegrityState.COMPLETE, k.UnknownReason.NOT_OBSERVABLE),
    (BODY.replace(b"192.0.2.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + BODY, k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + b"unsupported synthetic line\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY, k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY, k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (BODY, k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (BODY, k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (b"", k.IntegrityState.COMPLETE, k.UnknownReason.EMPTY_UNREGISTERED),
    (BODY + BODY + b"unsupported synthetic line\n", k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY + BODY + b"unsupported synthetic line\n", k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (BODY + BODY + b"unsupported synthetic line\n", k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
])
def test_unknown_rows_keep_authenticated_witnesses_without_positive_grants(raw, integrity, reason):
    sample, result = original(raw, integrity)
    checked = proofs(sample, result)
    assert all(row.reason is reason for row, _ in checked)


@pytest.mark.parametrize("name,change", [
    ("version", {"raw": Text.VERSION}), ("version", {"value": Text.VERSION}),
    ("version", {"value": 2}), ("version", {"raw": "1", "value": "1"}),
    ("group", {"raw": "1", "value": "1"}),
    ("virtual_ip", {"raw": "192.0.2.9", "value": "192.0.2.9"}),
])
def test_coherent_token_pointer_replacement_cannot_forge_raw_columns_or_plain_types(name, change):
    sample, result = original()
    changed = replace_token(result, name, replace(getattr(result.rows[0], name), **change))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, changed)


@pytest.mark.parametrize("part", ["header", "body", "version_span", "vip_span", "row_af", "row_reason", "quality"])
def test_equal_copies_wrong_spans_and_claim_metadata_are_refused(part):
    sample, result = original()
    row = result.rows[0]
    if part == "header":
        changed = replace(result, rows=(replace(row, header=replace(row.header)),))
    elif part == "body":
        changed = replace(result, rows=(replace(row, body=(replace(row.body[0]), *row.body[1:])),))
    elif part in ("version_span", "vip_span"):
        name = "version" if part == "version_span" else "virtual_ip"
        token = getattr(row, name)
        changed = replace_token(result, name, replace(token, span=k.ByteSpan(start=token.span.start + 1, end=token.span.end)))
    elif part == "row_af":
        changed = replace(result, rows=(replace(row, address_family=Text.FAMILY),))
    elif part == "row_reason":
        changed = replace(result, rows=(replace(row, reason=k.UnknownReason.NOT_OBSERVABLE),))
    else:
        changed = replace(result, parse=replace(result.parse, quality=Text.QUALITY))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, changed)


@pytest.mark.parametrize("part", ["record_order", "extra_record", "missing_record", "row_order", "extra_row", "missing_row",
                                  "line_span", "line_status", "line_rule", "line_reason", "tokens", "global_reason"])
def test_whole_physical_accounting_and_row_census_are_closed(part):
    sample, result = original(BODY + block(interface="Vlan20"))
    parsed, rows = result.parse, result.rows
    records, lines = parsed.records, parsed.lines
    if part == "record_order":
        parsed = replace(parsed, records=(records[1], records[0], *records[2:]))
    elif part == "extra_record":
        parsed = replace(parsed, records=(*records, records[-1]))
    elif part == "missing_record":
        parsed = replace(parsed, records=records[:-1])
    elif part == "row_order":
        rows = tuple(reversed(rows))
    elif part == "extra_row":
        rows = (*rows, rows[-1])
    elif part == "missing_row":
        rows = rows[:-1]
    elif part.startswith("line_"):
        field = {"line_span": "span", "line_status": "status", "line_rule": "rule_id", "line_reason": "reason"}[part]
        value = lines[1].span if field == "span" else "unrecognised" if field == "status" else "forged"
        change = {field: value}
        parsed = replace(parsed, lines=(replace(lines[0], **change), *lines[1:]))
    elif part == "tokens":
        parsed = replace(parsed, tokens=(("version", rows[0].version),))
    else:
        result = replace(result, reason=k.UnknownReason.CONFLICTING_EVIDENCE)
    with pytest.raises(ValueError):
        parser.validate_claims(sample, replace(result, rows=rows, parse=parsed))


def test_physical_record_reordering_cannot_donate_ipv4_from_another_block():
    sample, result = original(BODY.replace(b"192.0.2.1", b"unknown") + block(interface="Vlan20"))
    first, second = result.rows
    left = next(record for record in first.body if record.rule_id == "virtual_ip")
    right = next(record for record in second.body if record.rule_id == "virtual_ip")
    def swapped(records):
        return tuple(right if record is left else left if record is right else record for record in records)
    first = replace(first, body=swapped(first.body), virtual_ip=second.virtual_ip, address_family="ipv4", reason=None)
    second = replace(second, body=swapped(second.body), virtual_ip=left.fields[0][1],
                     address_family=None, reason=k.UnknownReason.IDENTITY_UNRESOLVED)
    changed = replace(result, rows=(first, second), parse=replace(result.parse, records=swapped(result.parse.records)))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, changed)


def test_coherent_forged_footer_category_must_authenticate_actual_footer_bytes():
    raw = BODY.replace(BODY.splitlines(keepends=True)[-1], b"  Synthetic closure only\n")
    sample, result = original(raw)
    row = result.rows[0]
    line = sample.lines[-1]
    span = k.ByteSpan(start=line.span.start, end=line.span.end - 1)
    text = raw[span.start:span.end].decode("ascii")
    footer = Record("group_name", span, (("body", Captured(text, span, text)),))
    parsed = replace(result.parse, records=(*result.parse.records, footer), quality="complete",
        lines=(*result.parse.lines[:-1], replace(result.parse.lines[-1], status="consumed", rule_id="group_name")))
    changed = replace(result, rows=(replace(row, body=(*row.body, footer), reason=None),), parse=parsed, reason=None)
    with pytest.raises(ValueError):
        parser.validate_claims(sample, changed)


def test_literal_command_without_record_is_still_authenticated():
    sample, result = original(b"show standby all\n" + BODY)
    raw = sample.raw.replace(b"show standby all", b"show standby bad")
    sample = replace(sample, raw=raw, lines=text_lines(raw, "utf-8"))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, result)


def test_coherent_unrecognised_downgrade_is_only_a_fail_closed_unknown():
    sample, result = original()
    row = result.rows[0]
    footer = row.body[-1]
    parsed = replace(result.parse, records=tuple(record for record in result.parse.records if record is not footer),
        lines=(*result.parse.lines[:-1], replace(result.parse.lines[-1], status="unrecognised", rule_id="", reason="")),
        quality="partial")
    row = replace(row, body=row.body[:-1], reason=k.UnknownReason.PARSE_PARTIAL)
    changed = replace(result, rows=(row,), parse=parsed, reason=k.UnknownReason.PARSE_PARTIAL)
    assert proofs(sample, changed)[0][0].reason is k.UnknownReason.PARSE_PARTIAL


@pytest.mark.parametrize("part", ["rows", "records", "lines", "tokens"])
def test_mutable_carrier_collections_are_not_an_authentication_seal(part):
    sample, result = original()
    if part == "rows":
        changed = replace(result, rows=list(result.rows))
    else:
        changed = replace(result, parse=replace(result.parse, **{part: list(getattr(result.parse, part))}))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, changed)


def test_metadata_error_precedes_unrecognised_lines_and_conflicting_duplicates():
    sample = capture(BODY + BODY + b"unsupported synthetic line\n")
    sample = replace(sample, metadata=replace(sample.resolved_metadata, error=ErrorKind.TIMEOUT))
    result = parser.parse_capture(sample)
    assert result.reason is k.UnknownReason.CAPTURE_ERROR
    assert all(row.reason is k.UnknownReason.CAPTURE_ERROR for row, _ in proofs(sample, result))
