"""Guard-independent header byte custody; no role fact, eligibility, health or grant."""
from dataclasses import replace

import pytest
from test_build import P, Q, body, request, target
from test_root_guard_proofs import made, rebound, token_plant
from test_root_guard_proofs import oracle as root_oracle

from atlas_brain.evidence.capture import Capture, ErrorKind
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner.pack_receipts import ParseReceipt
from atlas_brain.runner.pack_runtime import Executed


def header_run(*, printed=False, role="designated", state="forwarding", ending=b"\n", indent=b"", padding=b""):
    point = target()
    raw = body(point, "enabled" if printed else None, 1) + body(point, "disabled" if printed else None, 2)
    return made(raw, role=role, state=state, ending=ending, indent=indent, padding=padding)


def header_oracle(raw, port, vlan):
    at = raw.index(b"Port 1 (" + port.encode() + b") of VLAN" + f"{vlan:04d}".encode())
    start, end = raw.rfind(b"\n", 0, at) + 1, raw.find(b"\n", at)
    end = len(raw) if end < 0 else end
    end -= raw[end - 1:end] == b"\r"
    p, v, role = at + len(b"Port 1 ("), raw.index(b"VLAN", at) + 4, raw.index(b" is ", at) + 4
    state = raw.index(b" ", role) + 1
    return ((start, end), (p, p + len(port)), (v, v + 4), (role, state - 1),
            (state, state + len(raw[state:end].split()[0])))


@pytest.mark.parametrize("printed", [False, True])
@pytest.mark.parametrize("role", tuple(b.stp.Role))
@pytest.mark.parametrize("state", tuple(b.stp.State))
@pytest.mark.parametrize("ending,indent,padding", [(b"\n", b"", b""), (b"\n", b" \t", b" \t"), (b"\r\n", b"", b" "), (b"\r\n", b"\t ", b"")])
def test_all_closed_header_tokens_work_without_guard_and_keep_every_original_span(printed, role, state, ending, indent, padding):
    point, output, facts = header_run(printed=printed, role=role.value, state=state.value, ending=ending, indent=indent, padding=padding)
    old = b.reported_root_guard_proofs(point, output)
    before = tuple(row.value for row in facts.rows), dict(facts.store.values), output.receipt.capture.metadata
    rows = b.reported_header_proofs(point, output)
    assert type(rows) is tuple and len(rows) == len(output.value.rows) == 2
    for (row, spans), original, fact in zip(rows, output.value.rows, facts.rows, strict=True):
        expected = header_oracle(output.receipt.capture.raw, P, row.vlan)
        assert row is original and tuple((span.start, span.end) for span in spans) == expected
        fields = dict(row.fields)
        header, = tuple(record for record in output.value.parse.records if record.rule_id.startswith("header_") and record.span in row.spans)
        originals = (header.span, fields["port"].span, fields["vlan"].span, fields["role"].span, fields["state"].span)
        assert len(spans) == 5 and all(type(span) is k.ByteSpan and span is source for span, source in zip(spans, originals, strict=True))
        assert all(span is not fields["number"].span for span in spans)
        if printed:
            positions = root_oracle(output.receipt.capture.raw, row.vlan)
            assert tuple((span.start, span.end) for span in dict(old)[row]) == positions
            refs = tuple(ref for ref in fact.value.evidence if type(ref) is k.EvidenceRef)
            assert tuple((ref.locator.start, ref.locator.end) for ref in refs) == tuple(positions[i] for i in (6, 5, 1, 2, 0))
        else:
            assert row.reason is None and dict(old)[row] == ()
            assert type(fact.value) is k.Unknown and fact.value.reason is k.UnknownReason.FIELD_NOT_PRINTED
    assert b.reported_root_guard_proofs(point, output) == old
    assert (tuple(row.value for row in facts.rows), facts.store.values, output.receipt.capture.metadata) == before


@pytest.mark.parametrize("printed,metadata,codec", [(True, False, "utf-8"), (False, False, "utf-8"), (False, True, "ascii")])
def test_new_path_needs_no_guard_validator_parser_or_fact_runtime(monkeypatch, printed, metadata, codec):
    point, output, facts = header_run(printed=printed)
    if metadata:
        cap = replace(output.receipt.capture, codec=codec, metadata=output.receipt.capture.resolved_metadata)
        output = replace(output, receipt=replace(output.receipt, capture=cap))
    def forbidden(*args, **kwargs):
        pytest.fail("header proof attempted guard dependency, runtime, state creation or bridged metadata")
    with monkeypatch.context() as patch:
        for cls in (Capture, ParseReceipt, Executed, k.Known, k.Unknown, b.stp.Row, b.stp.Result):
            patch.setattr(cls, "__init__", forbidden)
        for module, name in ((b, "_guard_claims"), (b, "_observed"), (b, "reported_root_guard_proofs"),
                (b.stp, "parse_capture"), (b.stp, "run_rules"), (b, "execute_parsers"),
                (b.p4_pipeline, "execute_p4_folder"), (b, "bind_writer"), (FactWriter, "write")):
            patch.setattr(module, name, forbidden)
        patch.setattr(Capture, "resolved_metadata", property(forbidden))
        rows = b.reported_header_proofs(point, output)
    assert all(row is original and len(spans) == 5 for (row, spans), original in zip(rows, output.value.rows, strict=True))
    assert len(facts.store.values) == 4


@pytest.mark.parametrize("plant", ["duplicate", "partial", "empty", "unknown_role", "unknown_state", "unknown_guard", "cleared_unknown", "row_reason"])
def test_genuine_unresolved_or_poisoned_headers_have_no_positive_claims(plant):
    point = target()
    raw = body(point, None, 1) + body(point, None, 2)
    raw = raw * 2 if plant == "duplicate" else raw + b"unmodelled\n" if plant == "partial" else b"" if plant == "empty" else raw
    if plant == "unknown_guard":
        raw = body(point, "mystery", 1) + body(point, "mystery", 2)
    point, output, _ = made(raw, role="mystery" if plant in ("unknown_role", "cleared_unknown") else "designated",
                            state="mystery" if plant == "unknown_state" else "forwarding")
    if plant == "cleared_unknown":
        output = rebound(output, rows=tuple(replace(row, reason=None) for row in output.value.rows),
                         parsed=replace(output.value.parse, quality="complete"), reason=None)
    if plant == "row_reason":
        output = rebound(output, rows=tuple(replace(row, reason=k.UnknownReason.CONFLICTING_EVIDENCE) for row in output.value.rows))
    result = b.reported_header_proofs(point, output)
    assert all(row is original and spans == () for (row, spans), original in zip(result, output.value.rows, strict=True))


@pytest.mark.parametrize("cleared", [False, True])
def test_absent_header_keeps_its_original_row_without_erasing_the_valid_neighbor(cleared):
    point = target()
    point, output, _ = made(body(point, None, 1))
    if cleared:
        output = rebound(output, rows=(output.value.rows[0], replace(output.value.rows[1], reason=None)))
    rows = b.reported_header_proofs(point, output)
    assert rows[0][0] is output.value.rows[0] and len(rows[0][1]) == 5
    assert rows[1][0] is output.value.rows[1] and rows[1][1] == ()


@pytest.mark.parametrize("name", ["number", "port", "vlan", "role", "state"])
@pytest.mark.parametrize("plant", ["raw", "value", "span"])
def test_header_fields_are_bound_to_exact_raw_value_and_absolute_offsets(name, plant):
    point, output, _ = header_run(role="disabled", state="disabled")
    old = dict(output.value.rows[0].fields)[name]
    token = (replace(old, raw=old.raw + "x") if plant == "raw" else
             replace(old, value=old.raw) if name in ("role", "state") and plant == "value" else
             replace(old, value="other") if plant == "value" else
             replace(old, span=replace(old.span, start=old.span.start + 1, end=old.span.end + 1)))
    output = token_plant(output, name, token)
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.reported_header_proofs(point, output)


@pytest.mark.parametrize("name,plant", [(name, plant) for name in ("role", "state")
    for plant in ("other_enum", "record_plain", "record_enum", "inside_alias", "neighbor")]
    + [("number", "inside_alias"), ("port", "neighbor")])
def test_coherent_same_byte_custody_and_strenum_aliases_cannot_borrow_header_proofs(name, plant):
    point, output, _ = header_run(role="disabled", state="disabled")
    row = output.value.rows[0]
    old = dict(row.fields)[name]
    if plant == "neighbor":
        token = dict(output.value.rows[1].fields)[name]
    elif plant == "inside_alias":
        span = dict(row.fields)["vlan"].span if name == "number" else dict(row.fields)["state" if name == "role" else "role"].span
        token = replace(old, span=replace(span, start=span.end - 1) if name == "number" else span)
    else:
        token = replace(old, value="disabled" if plant == "record_plain" else b.stp.State.DISABLED if name == "role" else b.stp.Role.DISABLED)
    output = token_plant(output, name, token, row=not plant.startswith("record_"))
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.reported_header_proofs(point, output)


@pytest.mark.parametrize("plant", ["missing_record", "duplicate_record", "whole_vlan", "whole_port"])
def test_original_header_ownership_cannot_be_removed_duplicated_or_wholly_substituted(plant):
    point, output, _ = header_run()
    first, second = output.value.rows
    if plant == "whole_vlan":
        output = rebound(output, rows=(replace(first, fields=second.fields, spans=second.spans), second))
    elif plant == "whole_port":
        foreign = target(port=Q)
        facts = b.build_root_guard((foreign,), (request(foreign, body(foreign, None, 1) + body(foreign, None, 2)),))
        output, = facts.executed
        cap = replace(output.receipt.capture, rendered=b.stp.command(P))
        output = replace(output, receipt=replace(output.receipt, capture=cap))
        output = rebound(output, rows=tuple(replace(row, port=P) for row in output.value.rows))
    else:
        parsed = output.value.parse
        selected = next(record for record in parsed.records if record.rule_id.startswith("header_") and record.span in first.spans)
        records = tuple(record for record in parsed.records if record is not selected) if plant == "missing_record" else parsed.records + (selected,)
        output = rebound(output, parsed=replace(parsed, records=records))
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.reported_header_proofs(point, output)


@pytest.mark.parametrize("plant", ["input", "parse", "owner", "context", "source", "codec", "census"])
def test_shared_input_binding_and_census_guards_remain_fail_closed(plant):
    point, output, _ = header_run()
    expected = "input" if plant in ("input", "parse") else "population" if plant == "census" else "binding"
    if plant == "input":
        output = object()
    elif plant == "parse":
        output = replace(output, receipt=replace(output.receipt, parse=replace(output.value.parse)))
    elif plant in ("owner", "context"):
        output = replace(output, receipt=replace(output.receipt, **{plant: "other"}))
    elif plant == "census":
        output = rebound(output, rows=tuple(reversed(output.value.rows)))
    else:
        cap = output.receipt.capture
        cap = replace(cap, **({"source": target(port=Q).node.key + ":foreign"} if plant == "source" else {"codec": "latin-1"}))
        output = replace(output, receipt=replace(output.receipt, capture=cap))
    with pytest.raises(ValueError, match="^stp_proof_" + expected + "$"):
        b.reported_header_proofs(point, output)


@pytest.mark.parametrize("kind", [k.IntegrityState.ERROR, k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS, None])
def test_clean_parser_flags_cannot_hide_capture_failure_or_direct_metadata_error(kind):
    point, output, _ = header_run()
    assert output.value.reason is None and output.value.parse.quality == "complete" and all(row.reason is None for row in output.value.rows)
    cap = output.receipt.capture
    cap = replace(cap, metadata=replace(cap.resolved_metadata, error=ErrorKind.TIMEOUT)) if kind is None else replace(cap, integrity=kind)
    output = replace(output, receipt=replace(output.receipt, capture=cap))
    rows = b.reported_header_proofs(point, output)
    assert all(row is original and spans == () for (row, spans), original in zip(rows, output.value.rows, strict=True))


@pytest.mark.parametrize("duplicate", [False, True])
def test_nonempty_claimed_header_fields_cannot_be_omitted_or_duplicated(duplicate):
    point, output, _ = header_run()
    first, parsed = output.value.rows[0], output.value.parse
    token = dict(first.fields)["role"]
    def changed(fields):
        return fields + (("role", token),) if duplicate else tuple((name, value) for name, value in fields if name != "role")
    records = tuple(replace(record, fields=changed(record.fields)) if record.rule_id.startswith("header_") and record.span in first.spans else record for record in parsed.records)
    output = rebound(output, rows=(replace(first, fields=changed(first.fields)),) + output.value.rows[1:],
                     parsed=replace(parsed, records=records, tokens=tuple(field for record in records for field in record.fields if field[0] in ("role", "state"))))
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.reported_header_proofs(point, output)
