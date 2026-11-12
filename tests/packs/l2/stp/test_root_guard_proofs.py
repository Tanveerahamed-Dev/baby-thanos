"""Raw STP claims only: no role eligibility, new facts, parser replay or output change."""
from dataclasses import replace

import pytest
from test_build import B, P, Q, body, request, target

from atlas_brain.evidence.capture import Capture, ErrorKind
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner.pack_receipts import ParseReceipt
from atlas_brain.runner.pack_runtime import Executed


def made(raw=None, *, ending=b"\n", indent=b"", padding=b"", role="designated", state="forwarding"):
    item = target()
    raw = body(item, "enabled", 1) + body(item, "disabled", 2) if raw is None else raw
    raw = raw.replace(b"designated forwarding", (role + " " + state).encode())
    raw = ending.join(indent + line + padding for line in raw.splitlines()) + ending if raw else raw
    facts = b.build_root_guard((item,), (request(item, raw),))
    output, = facts.executed
    return item, output, facts


def oracle(raw, vlan):
    h = raw.index(b"Port 1 (" + P.encode() + b") of VLAN" + f"{vlan:04d}".encode())
    g = raw.index(b"Root guard is ", h)
    def line(at):
        start, end = raw.rfind(b"\n", 0, at) + 1, raw.find(b"\n", at)
        end = len(raw) if end < 0 else end
        return start, end - (raw[end - 1:end] == b"\r")
    hs, he = line(h)
    gs, ge = line(g)
    p, v = h + len(b"Port 1 ("), raw.index(b"VLAN", h) + 4
    r = raw.index(b" is ", h) + 4
    s = raw.index(b" ", r) + 1
    return ((hs, he), (p, p + len(P)), (v, v + 4), (r, s - 1),
            (s, s + len(raw[s:he].split()[0])), (gs, ge), (g + 14, g + 14 + len(raw[g + 14:ge].split()[0])))


def rebound(output, *, rows=None, parsed=None, reason="keep"):
    value = replace(output.value, rows=output.value.rows if rows is None else rows,
                    parse=output.value.parse if parsed is None else parsed,
                    reason=output.value.reason if reason == "keep" else reason)
    return replace(output, value=value, receipt=replace(output.receipt, parse=value.parse))


def token_plant(output, name, token, *, row=True, record=True):
    first = output.value.rows[0]
    old = dict(first.fields)[name]
    rows = (replace(first, fields=tuple((key, token if key == name else value) for key, value in first.fields)),) + output.value.rows[1:] if row else output.value.rows
    parsed = output.value.parse
    records = tuple(replace(item, fields=tuple((key, token if value is old else value) for key, value in item.fields)) for item in parsed.records) if record else parsed.records
    tokens = tuple((key, token if value is old else value) for key, value in parsed.tokens)
    return rebound(output, rows=rows, parsed=replace(parsed, records=records, tokens=tokens))


@pytest.mark.parametrize("ending,indent,padding", [(b"\n", b"", b""), (b"\n", b" \t", b" \t"), (b"\r\n", b"", b"  "), (b"\r\n", b"\t ", b"")])
@pytest.mark.parametrize("role", tuple(b.stp.Role))
@pytest.mark.parametrize("state", tuple(b.stp.State))
def test_all_closed_tokens_have_original_rows_and_exact_absolute_raw_claims(ending, indent, padding, role, state):
    item, output, facts = made(ending=ending, indent=indent, padding=padding, role=role.value, state=state.value)
    before = facts.rows, dict(facts.store.values), output.receipt.capture.metadata
    result = b.reported_root_guard_proofs(item, output)
    assert type(result) is tuple and len(result) == 2
    for (row, claims), original, fact in zip(result, output.value.rows, facts.rows, strict=True):
        expected = oracle(output.receipt.capture.raw, row.vlan)
        assert row is original and row.port == P and all(type(span) is k.ByteSpan for span in claims)
        assert tuple((span.start, span.end) for span in claims) == expected
        refs = tuple(ref for ref in fact.value.evidence if type(ref) is k.EvidenceRef)
        assert tuple((ref.locator.start, ref.locator.end) for ref in refs) == tuple(expected[i] for i in (6, 5, 1, 2, 0))
        assert (fact.value.value, fact.value.raw, fact.value.basis) == (row.vlan == 1, "enabled" if row.vlan == 1 else "disabled", k.Basis.OBSERVED)
        assert facts.store.values[k.FactRef(fact=b.ROOT_GUARD, subject=fact.subject)] is fact.value
    assert (facts.rows, facts.store.values, output.receipt.capture.metadata) == before


@pytest.mark.parametrize("metadata,codec", [(False, "utf-8"), (True, "ascii")])
def test_hook_constructs_no_runtime_or_fact_objects_even_for_legacy_metadata(monkeypatch, metadata, codec):
    item, output, facts = made()
    if metadata:
        output = replace(output, receipt=replace(output.receipt, capture=replace(output.receipt.capture, codec=codec, metadata=output.receipt.capture.resolved_metadata)))
    def forbidden(*args, **kwargs):
        pytest.fail("raw proof hook replayed runtime, constructed state, or read bridged metadata")
    with monkeypatch.context() as patch:
        for cls in (Capture, ParseReceipt, Executed, k.Known, k.Unknown, b.stp.Row, b.stp.Result):
            patch.setattr(cls, "__init__", forbidden)
        for module, name in ((b, "_observed"), (b.stp, "parse_capture"), (b.stp, "run_rules"),
                             (b, "execute_parsers"), (b.p4_pipeline, "execute_p4_folder"), (b, "bind_writer"), (FactWriter, "write")):
            patch.setattr(module, name, forbidden)
        patch.setattr(Capture, "resolved_metadata", property(forbidden))
        result = b.reported_root_guard_proofs(item, output)
    assert [row is original for (row, _), original in zip(result, output.value.rows, strict=True)] == [True, True]
    assert all(len(claims) == 7 for _, claims in result) and len(facts.store.values) == 4


@pytest.mark.parametrize("plant", ["omitted", "duplicate", "unmodelled", "role_unknown", "state_unknown", "guard_unknown", "partial", "global", "row", "error", "truncated", "metadata_error", "empty"])
def test_unresolved_rows_stay_original_and_have_no_positive_claims(plant):
    item = target()
    raw = body(item, None, 1) + body(item, None, 2) if plant == "omitted" else b"" if plant == "empty" else None
    if plant == "duplicate":
        raw = (body(item, "enabled", 1) + body(item, "disabled", 2)) * 2
    if plant == "unmodelled":
        raw = body(item, "enabled", 1) + body(item, "disabled", 2) + b"unmodelled\n"
    item, output, _ = made(raw, role="mystery" if plant == "role_unknown" else "designated",
                           state="mystery" if plant == "state_unknown" else "forwarding")
    if plant == "guard_unknown":
        item, output, _ = made((body(item, "enabled", 1) + body(item, "disabled", 2)).replace(b"enabled", b"inherited"))
    if plant == "partial":
        output = rebound(output, parsed=replace(output.value.parse, quality="partial"), reason=None)
    if plant in ("global", "row"):
        output = rebound(output, reason=k.UnknownReason.PARSE_PARTIAL if plant == "global" else None,
            rows=tuple(replace(row, reason=k.UnknownReason.CONFLICTING_EVIDENCE) for row in output.value.rows) if plant == "row" else None)
    if plant in ("error", "truncated", "metadata_error"):
        cap = output.receipt.capture
        cap = replace(cap, metadata=replace(cap.resolved_metadata, error=ErrorKind.TIMEOUT)) if plant == "metadata_error" else replace(cap, integrity=k.IntegrityState.ERROR if plant == "error" else k.IntegrityState.TRUNCATED)
        output = replace(output, receipt=replace(output.receipt, capture=cap))
    if plant == "omitted":
        assert all(row.reason is None and "root_guard" not in dict(row.fields) for row in output.value.rows)
    result = b.reported_root_guard_proofs(item, output)
    assert all(row is original and claims == () for (row, claims), original in zip(result, output.value.rows, strict=True))


@pytest.mark.parametrize("name,word", [("root_guard", b"enabled"), ("role", b"designated"), ("state", b"forwarding")])
def test_unknown_mapped_tokens_cannot_be_laundered_by_clearing_all_reason_flags(name, word):
    item = target()
    raw = (body(item, "enabled", 1) + body(item, "disabled", 2)).replace(word, b"mystery")
    item, output, _ = made(raw)
    rows = tuple(replace(row, reason=None) for row in output.value.rows)
    output = rebound(output, rows=rows, parsed=replace(output.value.parse, quality="complete"), reason=None)
    result = b.reported_root_guard_proofs(item, output)
    assert all(row is original and claims == () for (row, claims), original in zip(result, rows, strict=True))


@pytest.mark.parametrize("name,plant", [(name, plant) for name in ("role", "state")
    for plant in ("row_plain", "row_enum", "record_plain", "record_enum", "coherent_enum", "raw", "offset", "neighbor")]
    + [("root_guard", "record_plain"), ("root_guard", "record_enum")])
def test_coherent_header_tokens_cannot_borrow_same_bytes_or_hide_wrong_enum_classes(name, plant):
    point = target()
    raw = body(point, "disabled", 1) + body(point, "disabled", 2) if name == "root_guard" else None
    item, output, facts = made(raw, role="disabled", state="disabled")
    old = dict(output.value.rows[0].fields)[name]
    if plant == "neighbor":
        token = dict(output.value.rows[1].fields)[name]
    elif plant == "raw":
        token = replace(old, raw=old.raw + "x")
    elif plant == "offset":
        token = replace(old, span=replace(old.span, start=old.span.start + 1, end=old.span.end + 1))
    else:
        value = "disabled" if plant.endswith("plain") else b.stp.State.DISABLED if name in ("role", "root_guard") else b.stp.Role.DISABLED
        token = replace(old, value=value)
    output = token_plant(output, name, token, row=not plant.startswith("record_"), record=not plant.startswith("row_"))
    if name in ("role", "state") and plant in ("neighbor", "coherent_enum"):
        assert b._observed(item, output.value.rows[0], output, item.node.declaration.evidence) == facts.rows[0].value
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.reported_root_guard_proofs(item, output)


@pytest.mark.parametrize("plant", ["target", "output", "receipt", "capture", "result", "parse_identity"])
def test_nominal_shapes_and_original_parse_association_refuse(plant):
    item, output, _ = made()
    if plant == "target":
        item = object()
    elif plant in ("output", "receipt", "result"):
        output = object() if plant == "output" else replace(output, **{plant if plant == "receipt" else "value": object()})
    elif plant == "capture":
        receipt = replace(output.receipt)
        object.__setattr__(receipt, "capture", object())
        output = replace(output, receipt=receipt)
    else:
        output = replace(output, receipt=replace(output.receipt, parse=replace(output.value.parse)))
    with pytest.raises(ValueError, match="^stp_proof_input$"):
        b.reported_root_guard_proofs(item, output)


@pytest.mark.parametrize("plant", ["owner", "context", "operation", "rendered", "source", "codec", "exec_scope"])
def test_exact_receipt_command_source_and_context_binding_refuses(plant):
    item, output, _ = made()
    if plant in ("owner", "context"):
        output = replace(output, receipt=replace(output.receipt, **{plant: "other"}))
    else:
        cap = output.receipt.capture
        changes = {"operation": {"operation": "other"}, "rendered": {"rendered": b.stp.command(Q)}, "source": {"source": B.key},
            "codec": {"codec": "latin-1"}, "exec_scope": {"metadata": replace(cap.resolved_metadata, scope=replace(cap.scope, vrf="other"))}}[plant]
        receipt = replace(output.receipt)
        object.__setattr__(receipt, "capture", replace(cap, **changes))
        output = replace(output, receipt=receipt)
    with pytest.raises(ValueError, match="^stp_proof_binding$"):
        b.reported_root_guard_proofs(item, output)


@pytest.mark.parametrize("plant", ["missing", "extra", "duplicate", "reordered", "port", "vlan"])
def test_declared_port_and_sorted_vlan_census_cannot_shrink_or_rebind(plant):
    item, output, _ = made()
    rows = output.value.rows
    changed = {"missing": rows[:1], "extra": rows + (replace(rows[0], vlan=3),), "duplicate": (rows[0], rows[0]),
        "reordered": tuple(reversed(rows)), "port": (replace(rows[0], port=Q), rows[1]), "vlan": (replace(rows[0], vlan=3), rows[1])}[plant]
    output = rebound(output, rows=changed)
    with pytest.raises(ValueError, match="^stp_proof_population$"):
        b.reported_root_guard_proofs(item, output)


@pytest.mark.parametrize("name", ["role", "state"])
def test_coherently_duplicated_header_fields_do_not_gain_positive_claims(name):
    item, output, _ = made()
    row, parsed = output.value.rows[0], output.value.parse
    token = dict(row.fields)[name]
    rows = (replace(row, fields=row.fields + ((name, token),)),) + output.value.rows[1:]
    records = tuple(replace(record, fields=record.fields + ((name, token),))
        if record.rule_id.startswith("header_") and record.span in row.spans else record for record in parsed.records)
    tokens = tuple(field for record in records for field in record.fields if field[0] in ("role", "state", "root_guard"))
    output = rebound(output, rows=rows, parsed=replace(parsed, records=records, tokens=tokens))
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.reported_root_guard_proofs(item, output)
