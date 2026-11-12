"""Displayed root bytes only; no fact, base-priority arithmetic, intended-root or health claim."""
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest
from test_build import P, body, request, target
from test_root_guard_proofs import made, rebound, token_plant

from atlas_brain.evidence.capture import Capture, ErrorKind
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l2.stp import root_identity as m
from atlas_brain.runner.pack_receipts import ParseReceipt
from atlas_brain.runner.pack_runtime import Executed

MAC = "aBcD.EF01.2345"


def block(vlan, priority="32769", address=MAC, *, guard=False, root=True):
    raw = body(target(), "disabled" if guard else None, vlan)
    return raw + (f"   Designated root has priority {priority}, address {address}\n".encode() if root else b"")


def run(raw=None, *, priority="32769", address=MAC, guard=False, **formatting):
    raw = block(1, priority, address, guard=guard) + block(2, priority, address, guard=guard) if raw is None else raw
    return made(raw, **formatting)


def oracle(raw, vlan):
    header = raw.index(f"Port 1 ({P}) of VLAN{vlan:04d}".encode())
    root = raw.index(b"Designated root has priority ", header)
    def line(at):
        start, end = raw.rfind(b"\n", 0, at) + 1, raw.find(b"\n", at)
        end = len(raw) if end < 0 else end
        return start, end - (raw[end - 1:end] == b"\r")
    port, vid, priority = header + len(b"Port 1 ("), raw.index(b"VLAN", header) + 4, root + len(b"Designated root has priority ")
    address = raw.index(b", address ", priority) + len(b", address ")
    return (line(header), (port, port + len(P)), (vid, vid + 4), line(root),
            (priority, raw.index(b",", priority)), (address, address + 14))


def retained(output, keep):
    parsed = output.value.parse
    records = tuple(record for record in parsed.records if keep(record))
    rows = []
    for row in output.value.rows:
        owned = tuple(record for record in records if any(span is record.span for span in row.spans))
        rows.append(replace(row, fields=tuple(field for record in owned for field in record.fields),
                            spans=tuple(record.span for record in owned), reason=None))
    fields = {id(token) for record in records for _, token in record.fields}
    return rebound(output, rows=tuple(rows), reason=None,
        parsed=replace(parsed, records=records, tokens=tuple((name, token) for name, token in parsed.tokens if id(token) in fields), quality="complete"))


@pytest.mark.parametrize("priority", ["0", "32769", "65535"])
@pytest.mark.parametrize("address", [MAC, "0000.0000.0000"])
@pytest.mark.parametrize("guard", [False, True])
@pytest.mark.parametrize("ending,indent,padding", [(b"\n", b"", b""), (b"\n", b" \t", b" \t"),
    (b"\r\n", b"", b"  "), (b"\r\n", b"\t ", b"")])
def test_displayed_values_and_six_original_absolute_spans_are_guard_independent(priority, address, guard, ending, indent, padding):
    point, output, facts = run(priority=priority, address=address, guard=guard, ending=ending, indent=indent, padding=padding)
    before = facts.rows, dict(facts.store.values), output.receipt.capture.metadata
    old_guard = b.reported_root_guard_proofs(point, output)
    rows = m.reported_root_identity_proofs(point, output)
    assert type(rows) is tuple and len(rows) == 2
    for (row, value, spans), original in zip(rows, output.value.rows, strict=True):
        assert row is original and type(value) is m.DisplayedRoot
        assert (value.priority, value.address) == (int(priority), address) and type(value.priority) is int
        assert tuple((span.start, span.end) for span in spans) == oracle(output.receipt.capture.raw, row.vlan)
        fields = dict(row.fields)
        header, = tuple(record for record in output.value.parse.records if record.rule_id.startswith("header_") and record.span in row.spans)
        root, = tuple(record for record in output.value.parse.records if record.rule_id == "root" and record.span in row.spans)
        originals = (header.span, fields["port"].span, fields["vlan"].span, root.span, fields["root_priority"].span, fields["root_mac"].span)
        assert all(type(span) is k.ByteSpan and span is source for span, source in zip(spans, originals, strict=True))
        assert len(spans) == 6 and not hasattr(value, "__dict__")
        with pytest.raises(FrozenInstanceError):
            value.priority = 1
    assert b.reported_root_guard_proofs(point, output) == old_guard
    assert all(len(spans) == (7 if guard else 0) for _, spans in old_guard)
    assert (facts.rows, facts.store.values, output.receipt.capture.metadata) == before and len(facts.store.values) == 4


class Text(str):
    pass


@pytest.mark.parametrize("priority,address", [(True, MAC), (-1, MAC), (65536, MAC), ("32769", MAC), (1.0, MAC),
    (None, MAC), (1, None), (1, Text(MAC)), (1, "abcd:ef01:2345"), (1, "abcd.ef01.234"), (1, "abcd.ef01.234g")])
def test_displayed_value_constructor_refuses_coercion_and_invalid_bounds(priority, address):
    with pytest.raises(ValueError, match="^stp_root_identity_value$"):
        m.DisplayedRoot(priority=priority, address=address)


@pytest.mark.parametrize("plant", ["none", "bridge", "missing", "partial", "empty", "row", "error", "truncated", "paging", "metadata_error", "cleared_unknown"])
def test_unresolved_roots_preserve_every_original_row_without_a_default_value(plant):
    raw = block(1, root=False) + block(2, root=False) if plant in ("none", "bridge") else block(1) if plant == "missing" else b"" if plant == "empty" else None
    if plant == "bridge":
        raw = raw.replace(b"forwarding\n", b"forwarding\n   Designated bridge has priority 32769, address aBcD.EF01.2345\n")
    point, output, _ = run(raw, role="mystery" if plant == "cleared_unknown" else "designated")
    if plant == "partial":
        output = rebound(output, parsed=replace(output.value.parse, quality="partial"), reason=None)
    if plant in ("row", "cleared_unknown"):
        output = rebound(output, rows=tuple(replace(row, reason=k.UnknownReason.CONFLICTING_EVIDENCE if plant == "row" else None)
            for row in output.value.rows), parsed=replace(output.value.parse, quality="complete"), reason=None)
    if plant in ("error", "truncated", "paging", "metadata_error"):
        cap = output.receipt.capture
        cap = replace(cap, metadata=replace(cap.resolved_metadata, error=ErrorKind.TIMEOUT)) if plant == "metadata_error" else replace(cap,
            integrity={"error": k.IntegrityState.ERROR, "truncated": k.IntegrityState.TRUNCATED, "paging": k.IntegrityState.PAGING_ARTIFACTS}[plant])
        output = replace(output, receipt=replace(output.receipt, capture=cap))
    rows = m.reported_root_identity_proofs(point, output)
    assert all(row is original for (row, _, _), original in zip(rows, output.value.rows, strict=True)) and len(rows) == 2
    if plant == "missing":
        assert rows[0][1] == m.DisplayedRoot(priority=32769, address=MAC) and len(rows[0][2]) == 6
        assert rows[1][1:] == (None, ())
    else:
        assert all(value is None and spans == () for _, value, spans in rows)


def test_public_header_authentication_runs_once_without_parser_runtime_or_fact_construction(monkeypatch):
    point, output, facts = run()
    original, calls = b.reported_header_proofs, []
    def checked(actual_target, actual_output):
        calls.append((actual_target, actual_output))
        return original(actual_target, actual_output)
    def forbidden(*args, **kwargs):
        pytest.fail("root proof replayed parsing, reconstructed input spans, or constructed/wrote facts")
    with monkeypatch.context() as patch:
        patch.setattr(b, "reported_header_proofs", checked)
        for cls in (k.Known, k.Unknown):
            patch.setattr(cls, "__post_init__", forbidden)
        for cls in (Capture, ParseReceipt, Executed, b.stp.Row, b.stp.Result, b.stp.Record, b.stp.Captured, k.ByteSpan):
            patch.setattr(cls, "__init__", forbidden)
        for module, name in ((b.stp, "parse_capture"), (b.stp, "run_rules"), (b, "_observed"), (b, "execute_parsers"),
                (b.p4_pipeline, "execute_p4_folder"), (b, "bind_writer"), (FactWriter, "write")):
            patch.setattr(module, name, forbidden)
        patch.setattr(Capture, "resolved_metadata", property(forbidden))
        rows = m.reported_root_identity_proofs(point, output)
    assert len(calls) == 1 and calls[0][0] is point and calls[0][1] is output
    assert all(row is original and len(spans) == 6 for (row, _, spans), original in zip(rows, output.value.rows, strict=True))
    assert len(facts.store.values) == 4


@pytest.mark.parametrize("name", ["root_priority", "root_mac"])
@pytest.mark.parametrize("plant", ["value", "value_alias", "raw", "offset", "neighbor", "record_clone"])
def test_nominal_valid_root_tokens_cannot_borrow_bytes_offsets_values_or_identity(name, plant):
    point, output, _ = run()
    old = dict(output.value.rows[0].fields)[name]
    token = (replace(old, value=1 if name == "root_priority" else old.raw.lower()) if plant == "value" else
        replace(old, value=Text(old.raw)) if plant == "value_alias" else
        replace(old, raw=old.raw + "x") if plant == "raw" else
        replace(old, span=replace(old.span, start=old.span.start + 1, end=old.span.end + 1)) if plant == "offset" else
        dict(output.value.rows[1].fields)[name] if plant == "neighbor" else replace(old))
    output = token_plant(output, name, token, row=plant != "record_clone")
    assert all(len(spans) == 5 for _, spans in b.reported_header_proofs(point, output))
    with pytest.raises(ValueError, match="^stp_root_identity_" + ("record" if plant == "record_clone" else "witness") + "$"):
        m.reported_root_identity_proofs(point, output)


@pytest.mark.parametrize("priority", ["00", "032769", "65536", "999999"])
def test_cleared_parser_flags_cannot_launder_invalid_printed_priorities(priority):
    point, output, _ = run(priority=priority)
    output = rebound(output, rows=tuple(replace(row, reason=None) for row in output.value.rows),
                     parsed=replace(output.value.parse, quality="complete"), reason=None)
    assert all(len(spans) == 5 for _, spans in b.reported_header_proofs(point, output))
    with pytest.raises(ValueError, match="^stp_root_identity_witness$"):
        m.reported_root_identity_proofs(point, output)


@pytest.mark.parametrize("plant", ["all_metadata", "record", "record_duplicate", "field", "field_duplicate", "record_span_clone"])
def test_raw_root_inventory_and_original_record_custody_cannot_be_pruned_or_duplicated(plant):
    point, output, _ = run()
    first, parsed = output.value.rows[0], output.value.parse
    record = next(record for record in parsed.records if record.rule_id == "root" and record.span in first.spans)
    if plant in ("all_metadata", "record"):
        output = retained(output, lambda item: item.rule_id != "root" if plant == "all_metadata" else item is not record)
    elif plant == "record_duplicate":
        output = rebound(output, parsed=replace(parsed, records=parsed.records + (record,)))
    elif plant == "record_span_clone":
        output = rebound(output, parsed=replace(parsed, records=tuple(replace(item, span=replace(item.span)) if item is record else item for item in parsed.records)))
    else:
        token = dict(first.fields)["root_mac"]
        fields = first.fields + (("root_mac", token),) if plant == "field_duplicate" else tuple(field for field in first.fields if field[0] != "root_mac")
        output = rebound(output, rows=(replace(first, fields=fields),) + output.value.rows[1:])
    assert all(len(spans) == 5 for _, spans in b.reported_header_proofs(point, output))
    with pytest.raises(ValueError, match="^stp_root_identity_record$"):
        m.reported_root_identity_proofs(point, output)


@pytest.mark.parametrize("plant", ["duplicate_root", "duplicate_header", "before", "prompt", "prompt_command", "command", "uppercase_command"])
def test_physical_root_sections_survive_pruned_metadata_and_cleared_flags(plant):
    first, second = block(1), block(2)
    root_line = b"   Designated root has priority 32769, address aBcD.EF01.2345\n"
    barriers = {"prompt": b"switch#\n", "prompt_command": b"switch#show spanning-tree interface " + P.encode() + b" detail\n",
        "command": b"show spanning-tree interface " + P.encode() + b" detail\n", "uppercase_command": b"SHOW\tspanning-tree\n"}
    raw = first + root_line + second if plant == "duplicate_root" else first + first + second if plant == "duplicate_header" else (
        root_line + block(1, root=False) + block(2, root=False) if plant == "before" else body(target(), None, 1) + barriers[plant] + root_line + block(2, root=False))
    point, output, _ = run(raw)
    if plant == "duplicate_header":
        output = retained(output, lambda record: not len(first) <= record.span.start < 2 * len(first))
    elif plant == "duplicate_root":
        duplicate = next(record for record in output.value.parse.records if record.rule_id == "root" and record.span.start == len(first))
        output = retained(output, lambda record: record is not duplicate)
    else:
        output = retained(output, lambda record: True)
    assert len(b.reported_header_proofs(point, output)[0][1]) == 5
    with pytest.raises(ValueError, match="^stp_root_identity_section$"):
        m.reported_root_identity_proofs(point, output)


@pytest.mark.parametrize("prune_header", [False, True])
def test_root_after_next_physical_header_cannot_be_transplanted_into_previous_vlan(prune_header):
    point, output, _ = run(block(1, root=False) + block(2))
    first, second = output.value.rows
    parsed = output.value.parse
    root = next(record for record in parsed.records if record.rule_id == "root")
    rows = (replace(first, fields=first.fields + root.fields, spans=first.spans + (root.span,)), replace(second, fields=(), spans=(), reason=None))
    records = tuple(record for record in parsed.records if not (prune_header and record.rule_id.startswith("header_") and record.span in second.spans))
    output = rebound(output, rows=rows, parsed=replace(parsed, records=records))
    assert len(b.reported_header_proofs(point, output)[0][1]) == 5
    with pytest.raises(ValueError, match="^stp_root_identity_record$"):
        m.reported_root_identity_proofs(point, output)


@pytest.mark.parametrize("plant", ["raw_none", "raw_int", "raw_subclass", "captured_shape", "span_shape"])
def test_root_metadata_shapes_keep_the_unpatched_public_input_refusal(plant):
    point, output, _ = run()
    old = dict(output.value.rows[0].fields)["root_mac"]
    token = replace(old)
    if plant == "captured_shape":
        token = SimpleNamespace(value=old.value, raw=old.raw, span=old.span)
    else:
        name, value = ("span", SimpleNamespace(start=old.span.start, end=old.span.end)) if plant == "span_shape" else (
            "raw", {"raw_none": None, "raw_int": 1, "raw_subclass": Text(old.raw)}[plant])
        object.__setattr__(token, name, value)
    output = token_plant(output, "root_mac", token)
    with pytest.raises(ValueError, match="^stp_proof_input$"):
        m.reported_root_identity_proofs(point, output)


def test_root_record_at_physical_eof_keeps_its_exact_original_spans():
    point = target()
    raw = (block(1) + block(2)).removesuffix(b"\n")
    facts = b.build_root_guard((point,), (request(point, raw),))
    output, = facts.executed
    assert output.receipt.capture.raw == raw and not raw.endswith(b"\n")
    rows = m.reported_root_identity_proofs(point, output)
    assert rows[-1][2][3].end == len(raw) and rows[-1][2][-1].end == len(raw)
    assert all(row is original and value == m.DisplayedRoot(priority=32769, address=MAC)
        and tuple((span.start, span.end) for span in spans) == oracle(raw, row.vlan)
        for (row, value, spans), original in zip(rows, output.value.rows, strict=True))


@pytest.mark.parametrize("poison", [False, True])
def test_one_absent_or_poisoned_root_does_not_erase_the_valid_neighbor(poison):
    point, output, _ = run(None if poison else block(1, root=False) + block(2))
    if poison:
        output = rebound(output, rows=(replace(output.value.rows[0], reason=k.UnknownReason.CONFLICTING_EVIDENCE), output.value.rows[1]))
    rows = m.reported_root_identity_proofs(point, output)
    assert all(row is original for (row, _, _), original in zip(rows, output.value.rows, strict=True))
    assert rows[0][1:] == (None, ()) and rows[1][1] == m.DisplayedRoot(priority=32769, address=MAC) and len(rows[1][2]) == 6
