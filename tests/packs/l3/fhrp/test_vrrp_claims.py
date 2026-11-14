"""VRRP raw-claim correspondence on original synthetic data; no admission or origin seal."""
from copy import deepcopy
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_vrrp import BODY, DETAIL, block, capture

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.evidence.parsekit import rules
from atlas_brain.evidence.parsekit.rules import TokenMap
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import parse_vrrp as parser
from atlas_brain.runner import p4_pipeline as pipeline


class Alias(StrEnum):
    STATE = "Backup"
    CONSUMED = "consumed"
    KEY = "state"
    COMPLETE = "complete"


def forbidden(*args, **kwargs):
    pytest.fail("raw-claim validation replayed parser, token resolver, dispatcher or Writer")


def actual(monkeypatch, raw=BODY, integrity=k.IntegrityState.COMPLETE, error=None):
    sample = capture(raw, integrity)
    if error is not None:
        sample = replace(sample, metadata=replace(sample.resolved_metadata, error=error))
    result = parser.parse_capture(sample)
    assert len(parser.validate_claims(sample, result)) == len(result.rows)
    for module, name in ((parser, "parse_capture"), (parser, "run_rules"), (rules, "run_rules"),
            (TokenMap, "resolve"), (pipeline, "execute_parsers"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)
    assert len(parser.validate_claims(sample, result)) == len(result.rows)
    return sample, result


def token_change(result, row, record, name, token):
    original = dict(record.fields)[name]
    changed = replace(record, fields=tuple((field, token if field == name else value) for field, value in record.fields))
    updated = replace(row, header=changed if row.header is record else row.header,
        body=tuple(changed if item is record else item for item in row.body),
        **({name: token} if name in ("interface", "group", "state", "virtual_ip") else {}))
    parsed = replace(result.parse, records=tuple(changed if item is record else item for item in result.parse.records),
        tokens=tuple((field, token if value is original else value) for field, value in result.parse.tokens))
    return replace(result, parse=parsed, rows=tuple(updated if item is row else item for item in result.rows))


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
@pytest.mark.parametrize("final_newline", [False, True])
@pytest.mark.parametrize("state", ["Init", "INIT", "Master", "MASTER", "Backup", "BACKUP"])
def test_exact_original_rows_and_sorted_state_only_points_without_replay(monkeypatch, ending, frame, final_newline, state):
    raw = block(state=state)
    if frame != "body":
        raw = parser.COMMAND.encode() + b"\n" + raw
    if frame == "prompt":
        raw = b"synthetic-a#" + raw + b"synthetic-a#\n"
    raw = raw.replace(b"\n", ending)
    sample, result = actual(monkeypatch, raw if final_newline else raw[:-len(ending)])
    before = replace(sample)
    ((row, points),) = parser.validate_claims(sample, result)
    body = {record.rule_id: record for record in row.body}
    expected = {row.header.span, row.interface.span, row.group.span, body["state"].span, row.state.span,
        body["virtual_ip"].span, row.virtual_ip.span, body["master_down"].span}
    assert row is result.rows[0] and points == tuple(sorted(expected, key=lambda span: (span.start, span.end)))
    excluded = {token.span for record in row.body for _, token in record.fields if record.rule_id not in ("state", "virtual_ip")}
    assert not excluded.intersection(points) and row.span not in points
    assert sample == before and sample.raw == before.raw and sample.bytes_sha256 == sha256(sample.raw).hexdigest()
    assert sample.scope == before.scope and sample.collected_utc == before.collected_utc


@pytest.mark.parametrize("raw", [BODY + b"unrecognized\n", BODY + BODY, block(group="10000"),
    BODY.replace(b"Backup", b"Unknown"), BODY.replace(b"198.51.100.41", b"unknown"),
    BODY.replace(b"Group 100", b"Group 100 - Address-Family IPv4"), BODY[:-12], b"", b" \t\n",
    b"show vrrp\n", b"synthetic-a#show vrrp\n" + BODY + b"other#\n",
    BODY.replace(DETAIL.splitlines(keepends=True)[0], b""),
    BODY.rsplit(b"  Master Down interval", 1)[0] + block("Vl62", "abc")])
def test_authentic_partial_empty_and_conflicting_claims_remain_valid_data(monkeypatch, raw):
    sample, result = actual(monkeypatch, raw)
    proofs = parser.validate_claims(sample, result)
    assert result.reason is not None and result.parse.quality == "partial"
    assert len(proofs) == len(result.rows) and all(row is result.rows[index] for index, (row, _) in enumerate(proofs))


@pytest.mark.parametrize("integrity,error", [(k.IntegrityState.ERROR, None), (k.IntegrityState.TRUNCATED, None),
    (k.IntegrityState.PAGING_ARTIFACTS, None), (k.IntegrityState.UNKNOWN_FORMAT, None),
    (k.IntegrityState.UNVERIFIED_PROMPT, None), (k.IntegrityState.EMPTY, None),
    (k.IntegrityState.COMPLETE, ErrorKind.TIMEOUT)])
def test_real_damage_and_error_precedence_is_checked_without_reclassification(monkeypatch, integrity, error):
    sample, result = actual(monkeypatch, BODY + BODY, integrity, error)
    before = deepcopy(sample)
    assert result.reason is not None and all(row.reason is result.reason for row, _ in parser.validate_claims(sample, result))
    assert sample == before


@pytest.mark.parametrize("unknown", [False, True])
def test_coherent_copies_preserve_associations_but_are_not_origin_credentials(monkeypatch, unknown):
    sample, result = actual(monkeypatch, BODY.replace(b"Backup", b"Unknown") if unknown else BODY)
    copied = deepcopy(result)
    assert copied is not result and copied.rows[0] is not result.rows[0]
    proofs = parser.validate_claims(deepcopy(sample), copied)
    assert proofs[0][0] is copied.rows[0] and proofs == parser.validate_claims(sample, copied)


@pytest.mark.parametrize("field", ["interface", "group", "state_raw", "state_value", "state_alias", "raw_alias",
    "virtual_ip", "authentication", "master", "master_priority", "advertisement", "master_advertisement", "master_down", "span"])
def test_coherent_row_record_token_and_state_pair_forgeries_are_byte_authenticated(monkeypatch, field):
    sample, result = actual(monkeypatch)
    row = result.rows[0]
    name = "state" if field in ("state_raw", "state_value", "state_alias", "raw_alias", "span") else field
    record = row.header if name in ("interface", "group") else next(item for item in row.body if name in dict(item.fields))
    token = dict(record.fields)[name]
    changes = {"value": parser.VRRPState.MASTER} if field == "state_value" else {"value": "backup"} if field == "state_alias" else (
        {"raw": Alias.STATE} if field == "raw_alias" else {"span": k.ByteSpan(start=token.span.start - 1, end=token.span.end - 1)}
        if field == "span" else {"raw": "forged", "value": "forged"})
    forged = token_change(result, row, record, name, replace(token, **changes))
    if name == "state":
        assert forged.parse.tokens[0][1] is forged.rows[0].state
    code = "state" if field in ("state_value", "state_alias") else "column"
    with pytest.raises(ValueError, match="^vrrp_claims_" + code + "$"):
        parser.validate_claims(sample, forged)


@pytest.mark.parametrize("plant", ["all", "state", "footer"])
def test_recognized_physical_lines_cannot_be_hidden_as_genuine_no_match(monkeypatch, plant):
    sample, result = actual(monkeypatch)
    row = result.rows[0]
    removed = {record.span.start for record in result.parse.records if plant == "all" or record.rule_id == (
        "state" if plant == "state" else "master_down")}
    records = tuple(record for record in result.parse.records if record.span.start not in removed)
    lines = tuple(replace(line, status="unrecognised", rule_id="", reason="") if line.span.start in removed else line
        for line in result.parse.lines)
    body = tuple(record for record in row.body if record.span.start not in removed)
    rows = () if plant == "all" else (replace(row, body=body, state=None if plant == "state" else row.state,
        span=k.ByteSpan(start=row.span.start, end=body[-1].span.end)),)
    parsed = replace(result.parse, records=records, lines=lines, tokens=() if plant in ("all", "state") else result.parse.tokens, quality="partial")
    forged = replace(result, parse=parsed, rows=rows, reason=k.UnknownReason.PARSE_PARTIAL)
    with pytest.raises(ValueError, match="^vrrp_claims_phase$"):
        parser.validate_claims(sample, forged)


@pytest.mark.parametrize("plant", ["line_missing", "line_extra", "line_foreign", "line_order", "record_missing", "record_extra", "record_foreign", "record_order",
    "row_missing", "row_extra", "row_foreign", "row_order", "token_missing", "token_extra", "token_foreign", "token_copy", "token_name",
    "header", "state", "vip", "footer", "family", "reason", "quality", "span"])
def test_complete_ledgers_pointer_custody_and_neighbor_block_footer_never_mix(monkeypatch, plant):
    sample, result = actual(monkeypatch, BODY + block("Vl62", "101", "Master"))
    first, second = result.rows
    parsed = result.parse
    family = plant.split("_")[0]
    if family in ("line", "record", "token"):
        name = {"line": "lines", "record": "records", "token": "tokens"}[family]
        items = getattr(parsed, name)
        changed = items[:-1] if plant.endswith("missing") else items + items[:1] if plant.endswith("extra") else tuple(reversed(items))
        if plant.endswith("foreign"):
            changed = (items[-1], *items[1:])
        elif plant == "token_copy":
            changed = ((items[0][0], replace(items[0][1])), *items[1:])
        elif plant == "token_name":
            changed = (("other", items[0][1]), *items[1:])
        parsed = replace(parsed, **{name: changed})
    elif family == "row":
        result = replace(result, rows=result.rows[:-1] if plant.endswith("missing") else result.rows + result.rows[:1]
            if plant.endswith("extra") else (second, second) if plant.endswith("foreign") else tuple(reversed(result.rows)))
    elif plant == "quality":
        parsed = replace(parsed, quality="partial")
    else:
        changes = {"header": {"header": second.header, "interface": second.interface, "group": second.group},
            "state": {"state": replace(first.state)}, "vip": {"virtual_ip": second.virtual_ip},
            "footer": {"body": first.body[:-1] + second.body[-1:], "span": k.ByteSpan(start=first.span.start, end=second.span.end)},
            "family": {"address_family": "ipv6"}, "reason": {"reason": k.UnknownReason.PARSE_PARTIAL},
            "span": {"span": k.ByteSpan(start=first.span.start, end=first.span.end - 1)}}[plant]
        result = replace(result, rows=(replace(first, **changes), second))
    code = "accounting" if family == "line" else "order" if plant == "record_order" else "record" if family == "record" else (
        "tokens" if family == "token" else "reason" if plant in ("row_missing", "row_extra", "quality") else "row")
    with pytest.raises(ValueError, match="^vrrp_claims_" + code + "$"):
        parser.validate_claims(sample, replace(result, parse=parsed))


@pytest.mark.parametrize("plant", ["reason", "detail", "candidates", "needs", "deep_candidates", "deep_needs", "evidence", "capture", "locator", "role", "digest"])
def test_unmapped_state_is_the_exact_canonical_unknown_with_own_token_evidence(monkeypatch, plant):
    sample, result = actual(monkeypatch, BODY.replace(b"Backup", b"Unknown"))
    value, token = result.rows[0].state.value, result.rows[0].state
    if plant in ("reason", "detail", "candidates", "needs", "deep_candidates", "deep_needs", "evidence"):
        need = k.EvidenceNeed(node=sample.source, operation=parser.OP, params=(), resolves=("synthetic.field",), reruns=(), after_s=None, unprintable=())
        changes = {"reason": k.UnknownReason.NOT_COLLECTED, "detail": "other", "candidates": ("synthetic:other",),
            "needs": (need,), "deep_candidates": ([],), "deep_needs": ([],), "evidence": ()}
        object.__setattr__(value, "next_evidence" if plant.endswith("needs") else "candidates" if plant == "deep_candidates" else plant, changes[plant])
    else:
        ref = value.evidence[0]
        changes = {"capture": {"capture": "cap:other"}, "locator": {"locator": replace(token.span)},
            "role": {"role": k.EvidenceRole.WITNESS}, "digest": {"excerpt_sha256": "0" * 64}}[plant]
        object.__setattr__(value, "evidence", (replace(ref, **changes),))
    with pytest.raises(ValueError, match="^vrrp_claims_state$"):
        parser.validate_claims(sample, result)


@pytest.mark.parametrize("plant", ["capture", "result", "raw", "id", "integrity", "metadata", "metadata_error", "capture_lines", "records", "lines", "rows", "tokens", "quality",
    "record_key", "record_bool", "record_rule", "record_pair", "offsets", "token_raw", "token_span", "row_span", "line_status", "token_pair", "token_key"])
def test_finite_exact_shapes_refuse_deep_unhashable_or_aliased_fields_before_hashes(monkeypatch, plant):
    sample, result = actual(monkeypatch)
    if plant in ("capture", "result"):
        if plant == "capture":
            sample = object()
        else:
            result = object()
    elif plant in ("raw", "id", "integrity", "metadata", "metadata_error", "capture_lines"):
        if plant == "metadata_error":
            object.__setattr__(sample, "metadata", replace(sample.resolved_metadata))
            object.__setattr__(sample.metadata, "error", [])
        else:
            object.__setattr__(sample, "lines" if plant == "capture_lines" else plant, Alias.COMPLETE if plant == "integrity" else [])
    elif plant in ("records", "lines", "rows", "tokens", "quality"):
        object.__setattr__(result if plant == "rows" else result.parse, plant, Alias.COMPLETE if plant == "quality" else [])
    elif plant == "offsets":
        object.__setattr__(sample.lines[0], "offsets", ([],))
    elif plant.startswith("record_"):
        record = result.parse.records[0]
        object.__setattr__(record.span if plant in ("record_key", "record_bool") else record,
            "start" if plant in ("record_key", "record_bool") else "rule_id" if plant == "record_rule" else "fields",
            False if plant == "record_bool" else [] if plant != "record_pair" else (([], record.fields[0][1]),))
    elif plant in ("token_raw", "token_span", "row_span"):
        token = result.rows[0].group
        object.__setattr__(result.rows[0].span if plant == "row_span" else token,
            "start" if plant == "row_span" else "raw" if plant == "token_raw" else "span", [])
    elif plant == "line_status":
        object.__setattr__(result.parse.lines[0], "status", Alias.CONSUMED)
    else:
        object.__setattr__(result.parse, "tokens", (([] if plant == "token_pair" else Alias.KEY, result.rows[0].state),))
    code = ("input" if plant in ("capture", "result", "raw", "id", "integrity", "metadata", "metadata_error") else
        "shape" if plant in ("records", "lines", "rows", "tokens", "quality") else "record" if plant.startswith("record_") else
        "accounting" if plant in ("capture_lines", "offsets", "line_status") else "column" if plant in ("token_raw", "token_span") else "row" if plant == "row_span" else "tokens")
    with pytest.raises(ValueError, match="^vrrp_claims_" + code + "$"):
        parser.validate_claims(sample, result)
