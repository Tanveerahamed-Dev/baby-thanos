"""Independent BRIEF owning-claim forgeries; no parser replay, admission or peer truth."""
from dataclasses import asdict, replace
from enum import StrEnum

import pytest
from test_parse_hsrp_brief import ACTIVE, BODY, HEADER, INIT, LEGEND, capture

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.evidence.parsekit.rules import Captured, Record
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as parser
from atlas_brain.runner import pack_runtime


class Text(StrEnum):
    ZERO = "0"
    STATE = "init"
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
        expected = {row.interface.span, row.group.span, row.state.span, row.span, *row.af_spans}
        assert spans == tuple(sorted(expected, key=lambda point: (point.start, point.end)))
        assert all(type(point) is k.ByteSpan and type(point.start) is int and type(point.end) is int
            and 0 <= point.start < point.end <= len(sample.raw) for point in spans)
    return checked


def retoken(result, name, changed):
    row = result.rows[0]
    record = next(item for item in result.parse.records if item.span is row.span)
    old = dict(record.fields)[name]
    record_copy = replace(record, fields=tuple((key, changed if token is old else token) for key, token in record.fields))
    row_changes = {name: replace(getattr(row, name), token=changed)} if name in ("active", "standby", "virtual_ip") else {name: changed}
    row = replace(row, **row_changes)
    parsed = replace(result.parse, records=tuple(record_copy if item is record else item for item in result.parse.records),
        tokens=tuple((key, changed if token is old else token) for key, token in result.parse.tokens))
    return replace(result, rows=(row, *result.rows[1:]), parse=parsed)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("final_lf", [False, True])
def test_original_rows_spans_mapped_states_and_endpoint_tokens_without_replay(monkeypatch, ending, frame, final_lf):
    raw = BODY if frame == "body" else parser.COMMAND.encode() + b"\n" + BODY
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    raw = raw.replace(b"\n", ending)
    sample, result = original(raw if final_lf else raw[:-len(ending)])
    before = sample.raw, asdict(result)
    def forbidden(*args, **kwargs):
        pytest.fail("claim validator replayed parser, dispatcher or Writer")
    monkeypatch.setattr(parser, "parse_capture", forbidden)
    monkeypatch.setattr(parser, "run_rules", forbidden)
    monkeypatch.setattr(pack_runtime, "execute_parsers", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    assert tuple(row.state.value for row, _ in proofs(sample, result)) == (parser.State.INIT, parser.State.ACTIVE, parser.State.STANDBY)
    assert all(type(token.value) is parser.State for _, token in result.parse.tokens)
    assert (sample.raw, asdict(result)) == before


@pytest.mark.parametrize("raw,integrity,reason", [
    (BODY + ACTIVE, k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + ACTIVE.replace(b"192.0.2.1", b"192.0.2.9"), k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (LEGEND + HEADER + INIT.replace(b"203.0.113.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + b"unrecognised\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"Init", b"Listen"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"0    100", b"01    100"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"0    100", b"4096    100"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"0    100", b"0    256"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"0    100", b"0    010"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"203.0.113.1", b"203.00.113.1"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY + ACTIVE + INIT.replace(b"203.0.113.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY.replace(b"203.0.113.1", b"2001:db8::1"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"203.0.113.1", b"local"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY, k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY, k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (BODY, k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (BODY, k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (b"", k.IntegrityState.COMPLETE, k.UnknownReason.EMPTY_UNREGISTERED),
    (BODY, k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
    (b"", k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (b"", k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (b"", k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.EMPTY_UNREGISTERED),
    (BODY + b"unrecognised\n", k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (HEADER + ACTIVE, k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (b"fixture#show standby brief\n" + BODY + b"other#\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
])
def test_unknown_and_unmapped_states_keep_the_full_original_witness_population(raw, integrity, reason):
    sample, result = original(raw, integrity)
    assert result.reason is reason
    assert all(row.reason is reason for row, _ in proofs(sample, result))


@pytest.mark.parametrize("integrity,reason", [(k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED), (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED)])
def test_stronger_capture_damage_precedes_duplicate_unmapped_and_unrecognised_claims(integrity, reason):
    sample, result = original(BODY.replace(b"Init", b"Listen") + ACTIVE + b"unrecognised\n", integrity)
    assert result.reason is reason and all(row.reason is reason for row, _ in proofs(sample, result))


def test_metadata_error_precedence_and_canonical_unmapped_token_witness():
    sample, _ = original(BODY.replace(b"Init", b"Listen") + ACTIVE + b"unrecognised\n")
    sample = replace(sample, metadata=replace(sample.resolved_metadata, error=ErrorKind.TIMEOUT))
    result = parser.parse_capture(sample)
    assert result.reason is k.UnknownReason.CAPTURE_ERROR
    proofs(sample, result)
    sample, result = original(BODY.replace(b"Init", b"Listen"))
    token = result.rows[0].state
    ref, = token.value.evidence
    assert ref.locator is token.span and ref.capture == sample.id and ref.role is k.EvidenceRole.SUBJECT
    proofs(sample, result)


@pytest.mark.parametrize("name,changes", [
    ("group", {"raw": Text.ZERO}), ("group", {"value": Text.ZERO}), ("group", {"raw": "1", "value": "1"}),
    ("priority", {"value": 100}), ("state", {"value": Text.STATE}), ("state", {"value": "init"}),
    ("state", {"value": parser.State.ACTIVE}), ("active", {"raw": "local", "value": "local"}),
    ("virtual_ip", {"raw": "203.0.113.9", "value": "203.0.113.9"}),
])
def test_coherent_row_record_and_token_census_cannot_forge_bytes_or_mapped_types(name, changes):
    sample, result = original()
    token = getattr(result.rows[0], name)
    token = token.token if name in ("active", "virtual_ip") else token
    with pytest.raises(ValueError):
        parser.validate_claims(sample, retoken(result, name, replace(token, **changes)))


@pytest.mark.parametrize("part", ["span", "interface_copy", "state_copy", "endpoint_copy", "endpoint_kind", "af_kind",
    "af_span_copy", "af_spans", "row_reason", "quality"])
def test_equal_pointers_endpoint_af_and_reason_metadata_cannot_replace_owning_claims(part):
    sample, result = original()
    row = result.rows[0]
    if part == "span":
        row = replace(row, span=replace(row.span))
    elif part in ("interface_copy", "state_copy"):
        name = part.removesuffix("_copy")
        row = replace(row, **{name: replace(getattr(row, name))})
    elif part in ("endpoint_copy", "endpoint_kind"):
        row = replace(row, active=replace(row.active, **({"token": replace(row.active.token)} if part == "endpoint_copy" else {"kind": "local"})))
    elif part == "af_kind":
        row = replace(row, address_family=Text.FAMILY)
    elif part == "af_span_copy":
        row = replace(row, af_spans=tuple(replace(point) for point in row.af_spans))
    elif part == "af_spans":
        row = replace(row, af_spans=())
    elif part == "row_reason":
        row = replace(row, reason=k.UnknownReason.NOT_OBSERVABLE)
    else:
        result = replace(result, parse=replace(result.parse, quality=Text.QUALITY))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, replace(result, rows=(row, *result.rows[1:])))


@pytest.mark.parametrize("part", ["record_order", "extra_record", "missing_record", "row_order", "extra_row", "missing_row",
    "line_span", "line_status", "line_rule", "line_reason", "tokens_missing", "tokens_extra", "tokens_copy", "tokens_name",
    "record_span_bool", "record_fields", "global_reason"])
def test_exhaustive_physical_lines_records_and_mapped_token_census_are_closed(part):
    sample, result = original()
    parsed, rows = result.parse, result.rows
    records, lines, tokens = parsed.records, parsed.lines, parsed.tokens
    if part in ("record_order", "extra_record", "missing_record"):
        changed = (records[1], records[0], *records[2:]) if part == "record_order" else (
            (*records, records[-1]) if part == "extra_record" else records[:-1])
        parsed = replace(parsed, records=changed)
    elif part in ("row_order", "extra_row", "missing_row"):
        rows = tuple(reversed(rows)) if part == "row_order" else (*rows, rows[-1]) if part == "extra_row" else rows[:-1]
    elif part.startswith("line_"):
        field = {"line_span": "span", "line_status": "status", "line_rule": "rule_id", "line_reason": "reason"}[part]
        changed = lines[1].span if field == "span" else "unrecognised" if field == "status" else "forged"
        parsed = replace(parsed, lines=(replace(lines[0], **{field: changed}), *lines[1:]))
    elif part == "record_span_bool":
        object.__setattr__(records[0].span, "start", False)
    elif part == "record_fields":
        object.__setattr__(records[0], "fields", list(records[0].fields))
    elif part.startswith("tokens_"):
        changed = tokens[:-1] if part == "tokens_missing" else (*tokens, tokens[-1]) if part == "tokens_extra" else (
            (("state", replace(tokens[0][1])), *tokens[1:]) if part == "tokens_copy" else (("forged", tokens[0][1]), *tokens[1:]))
        parsed = replace(parsed, tokens=changed)
    else:
        result = replace(result, reason=k.UnknownReason.CONFLICTING_EVIDENCE)
    with pytest.raises(ValueError):
        parser.validate_claims(sample, replace(result, rows=rows, parse=parsed))


def test_coherent_partial_to_complete_reason_and_quality_upgrade_is_rejected():
    sample, result = original(BODY + b"unrecognised body\n")
    assert result.reason is k.UnknownReason.PARSE_PARTIAL and sample.integrity is k.IntegrityState.COMPLETE
    object.__setattr__(result, "reason", None)
    object.__setattr__(result.parse, "quality", "complete")
    for row in result.rows:
        object.__setattr__(row, "reason", None)
    with pytest.raises(ValueError):
        parser.validate_claims(sample, result)


def test_claimed_rule_authenticates_literal_command_even_without_a_record():
    sample, result = original(b"show standby brief\n" + BODY)
    raw = sample.raw.replace(b"show standby brief", b"show standby wrong")
    sample = replace(sample, raw=raw, lines=text_lines(raw, "utf-8"))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, result)


@pytest.mark.parametrize("part", ["rows", "records", "lines", "tokens"])
def test_mutable_carrier_collections_do_not_authenticate_claims(part):
    sample, result = original()
    changed = replace(result, rows=list(result.rows)) if part == "rows" else replace(
        result, parse=replace(result.parse, **{part: list(getattr(result.parse, part))}))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, changed)


def test_claimed_consumed_header_cannot_forge_an_unrecognised_physical_line():
    raw = BODY.replace(HEADER, b"synthetic unknown header\n")
    sample, result = original(raw)
    line = next(line for line in sample.lines if line.text == "synthetic unknown header")
    span = k.ByteSpan(start=line.span.start, end=line.span.end - 1)
    token = Captured("synthetic unknown header", span, "synthetic unknown header")
    record = Record("header", span, (("header", token),))
    parsed = replace(result.parse, records=tuple(sorted((*result.parse.records, record), key=lambda item: item.span.start)),
        lines=tuple(replace(item, status="consumed", rule_id="header") if item.span.start == span.start else item for item in result.parse.lines))
    with pytest.raises(ValueError):
        parser.validate_claims(sample, replace(result, parse=parsed))


def test_coherent_unrecognised_row_downgrade_only_retains_fail_closed_witnesses():
    sample, result = original()
    first = result.rows[0]
    parsed = replace(result.parse, records=tuple(item for item in result.parse.records if item.span is not first.span),
        tokens=tuple(pair for pair in result.parse.tokens if pair[1] is not first.state), quality="partial",
        lines=tuple(replace(line, status="unrecognised", rule_id="", reason="") if line.span.start == first.span.start else line
            for line in result.parse.lines))
    rows = tuple(replace(row, reason=k.UnknownReason.PARSE_PARTIAL) for row in result.rows[1:])
    changed = replace(result, rows=rows, parse=parsed, reason=k.UnknownReason.PARSE_PARTIAL)
    assert len(proofs(sample, changed)) == 2 and all(row.reason is k.UnknownReason.PARSE_PARTIAL for row in changed.rows)


@pytest.mark.parametrize("active,standby,vip", [("192.0.2.2", "unknown", "unknown"),
    ("unknown", "192.0.2.2", "unknown"), ("unknown", "unknown", "0.0.0.0")])
def test_each_actual_same_row_ipv4_anchor_and_numeric_boundary_remains_observable(active, standby, vip):
    raw = LEGEND + HEADER + INIT.replace(b"0    100", b"4095    255").replace(
        b"unknown         unknown         203.0.113.1", (active + " " + standby + " " + vip).encode())
    sample, result = original(b"\n" + raw + b"\n")
    checked = proofs(sample, result)
    assert result.reason is None and len(checked) == 1
    row, = result.rows
    assert row.group.raw == "4095" and row.priority.raw == "255" and len(row.af_spans) == 1


def test_coherent_equal_lexeme_at_a_different_physical_column_is_not_the_group_operand():
    sample, result = original()
    token = result.rows[0].group
    start = sample.raw.index(token.raw.encode(), token.span.end)
    changed = replace(token, span=k.ByteSpan(start=start, end=start + len(token.raw)))
    assert sample.raw[changed.span.start:changed.span.end] == token.raw.encode() and changed.span != token.span
    with pytest.raises(ValueError):
        parser.validate_claims(sample, retoken(result, "group", changed))
