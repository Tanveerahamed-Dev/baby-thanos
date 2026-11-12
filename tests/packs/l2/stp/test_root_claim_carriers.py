"""Raw Root-ID carriers are reauthenticated as data, never producer or fact authority."""
from dataclasses import replace

import pytest
from test_build import request, target
from test_root_identity import MAC, block, oracle

from atlas_brain.evidence.capture import Capture
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l2.stp import root_identity as m
from atlas_brain.runner.pack_receipts import ParseReceipt
from atlas_brain.runner.pack_runtime import Executed


def prepared(raw=None, *, priority="32769", guard=False, ending=b"\n", indent=b"", integrity=k.IntegrityState.COMPLETE):
    point = target(vlans=(3, 2, 1))
    raw = block(1, priority, guard=guard) + block(2, priority, guard=guard) if raw is None else raw
    raw = ending.join(indent + line + b" \t" for line in raw.splitlines()) + ending if raw else raw
    supplied = request(point, raw, integrity=integrity)
    facts = b.build_root_guard((point,), (supplied,))
    output, = facts.executed
    return point, output, facts


def source_spans(output, row):
    fields = dict(row.fields)
    header, = [record for record in output.value.parse.records if record.rule_id.startswith("header_") and record.span in row.spans]
    root, = [record for record in output.value.parse.records if record.rule_id == "root" and record.span in row.spans]
    return header.span, fields["port"].span, fields["vlan"].span, root.span, fields["root_priority"].span, fields["root_mac"].span


@pytest.mark.parametrize("priority", ["0", "32769", "65535"])
@pytest.mark.parametrize("guard", [False, True])
@pytest.mark.parametrize("ending,indent", [(b"\n", b""), (b"\r\n", b" \t")])
def test_canonical_authenticated_values_and_original_six_spans_replace_valid_submitted_objects(priority, guard, ending, indent):
    point, output, facts = prepared(priority=priority, guard=guard, ending=ending, indent=indent)
    before = facts.rows, dict(facts.store.values), output.receipt.capture.raw, output.receipt.capture.metadata
    submitted = m.reported_root_identity_proofs(point, output)
    result = m.validate_root_identity_claims(point, output, submitted)
    assert type(result) is tuple and len(result) == 3
    for (row, value, spans), original, offered in zip(result, output.value.rows, submitted, strict=True):
        assert row is original
        if row.vlan == 3:
            assert value is None and spans == ()
            continue
        assert type(value) is m.DisplayedRoot and value is not offered[1]
        assert (value.priority, value.address) == (int(priority), MAC) and type(value.priority) is int
        assert tuple((span.start, span.end) for span in spans) == oracle(output.receipt.capture.raw, row.vlan)
        assert all(type(span) is k.ByteSpan and span is actual
            for span, actual in zip(spans, source_spans(output, row), strict=True))
    assert (facts.rows, facts.store.values, output.receipt.capture.raw, output.receipt.capture.metadata) == before


@pytest.mark.parametrize("case", ["omitted", "missing", "partial", "empty", "error", "truncated", "unknown_role"])
def test_genuine_unavailable_claims_preserve_every_original_row_and_none_without_defaults(case):
    raw = block(1, root=False) + block(2, root=False) if case == "omitted" else block(1) if case == "missing" else (
        b"" if case == "empty" else block(1) + block(2) + (b"unmodelled\n" if case == "partial" else b""))
    raw = raw.replace(b"designated forwarding", b"mystery forwarding") if case == "unknown_role" else raw
    point, output, _ = prepared(raw, integrity={"error": k.IntegrityState.ERROR,
        "truncated": k.IntegrityState.TRUNCATED}.get(case, k.IntegrityState.COMPLETE))
    submitted = m.reported_root_identity_proofs(point, output)
    result = m.validate_root_identity_claims(point, output, submitted)
    assert len(result) == 3 and all(row is original for (row, _, _), original in zip(result, output.value.rows, strict=True))
    for row, value, spans in result:
        if case == "missing" and row.vlan == 1:
            assert value == m.DisplayedRoot(priority=32769, address=MAC) and len(spans) == 6
        else:
            assert value is None and spans == ()


def test_private_reauthentication_never_calls_public_getter_parser_fact_or_writer(monkeypatch):
    point, output, facts = prepared()
    submitted = m.reported_root_identity_proofs(point, output)
    header, calls = b.reported_header_proofs, []
    def checked(actual_target, actual_output):
        calls.append((actual_target, actual_output))
        return header(actual_target, actual_output)
    def forbidden(*args, **kwargs):
        pytest.fail("carrier verifier replayed parsing, trusted public getter, created facts or wrote state")
    with monkeypatch.context() as patch:
        patch.setattr(m, "reported_root_identity_proofs", forbidden)
        patch.setattr(b, "reported_header_proofs", checked)
        for cls in (k.Known, k.Unknown):
            patch.setattr(cls, "__post_init__", forbidden)
        for cls in (Capture, ParseReceipt, Executed, b.stp.Row, b.stp.Result, b.stp.Record, b.stp.Captured, k.ByteSpan):
            patch.setattr(cls, "__init__", forbidden)
        for module, name in ((b.stp, "parse_capture"), (b.stp, "run_rules"), (b, "execute_parsers"),
                (b, "_observed"), (b, "bind_writer"), (FactWriter, "write")):
            patch.setattr(module, name, forbidden)
        patch.setattr(Capture, "resolved_metadata", property(forbidden))
        result = m.validate_root_identity_claims(point, output, submitted)
    assert len(calls) == 1 and calls[0][0] is point and calls[0][1] is output
    assert result[0][1] is not submitted[0][1] and len(facts.store.values) == 6


class Text(str):
    pass


@pytest.mark.parametrize("plant", ["clone_expr", "neighbor", "drop_claim", "short", "provenance_only", "withhold",
    "wrong_int", "bool_alias", "mac_case", "over_unknown", "list", "item_list", "arity", "span_list", "span_clone",
    "reordered", "duplicate", "high_priority", "negative_priority", "mac_domain", "mac_subclass", "value_shape", "missing_slots", "missing_address"])
def test_current_source_and_typed_domain_cannot_be_replaced_by_coherent_carriers(monkeypatch, plant):
    point, output, _ = prepared(priority="0" if plant == "bool_alias" else "32769")
    if plant == "over_unknown":
        point, output, _ = prepared(block(1) + block(2) + b"unmodelled\n")
    claims = m.reported_root_identity_proofs(point, output)
    rich, displayed, spans = claims[0]
    if plant == "list":
        submitted = list(claims)
    elif plant == "drop_claim":
        submitted = claims[1:]
    elif plant == "reordered":
        submitted = tuple(reversed(claims))
    elif plant == "duplicate":
        submitted = (claims[0], claims[0], claims[2])
    else:
        if plant == "clone_expr":
            rich = replace(rich, fields=tuple((name, replace(token, raw="32768", value="32768")) if name == "root_priority" else (name, token) for name, token in rich.fields))
            displayed = m.DisplayedRoot(priority=32768, address=MAC)
        elif plant == "neighbor":
            spans = claims[1][2]
        elif plant == "short":
            spans = spans[:-1]
        elif plant == "provenance_only":
            spans = ()
        elif plant == "withhold":
            displayed, spans = None, ()
        elif plant == "over_unknown":
            displayed, spans = m.DisplayedRoot(priority=32769, address=MAC), source_spans(output, rich)
        elif plant == "span_list":
            spans = list(spans)
        elif plant == "span_clone":
            spans = (replace(spans[0]),) + spans[1:]
        elif plant in ("value_shape", "missing_slots", "missing_address"):
            priority = displayed.priority
            displayed = object() if plant == "value_shape" else object.__new__(m.DisplayedRoot)
            if plant == "missing_address":
                object.__setattr__(displayed, "priority", priority)
        elif plant not in ("item_list", "arity"):
            displayed = replace(displayed)
            field, value = {"wrong_int": ("priority", 32768), "bool_alias": ("priority", False),
                "mac_case": ("address", MAC.lower()), "high_priority": ("priority", 65536),
                "negative_priority": ("priority", -1), "mac_domain": ("address", "abcd:ef01:2345"),
                "mac_subclass": ("address", Text(MAC))}[plant]
            object.__setattr__(displayed, field, value)
        offered = [rich, displayed, spans] if plant == "item_list" else (rich, displayed) if plant == "arity" else (rich, displayed, spans)
        submitted = (offered,) + claims[1:]
    monkeypatch.setattr(m, "reported_root_identity_proofs", lambda *args: submitted)
    code = "value" if plant in ("wrong_int", "bool_alias", "mac_case", "high_priority", "negative_priority", "mac_domain", "mac_subclass", "value_shape", "missing_slots", "missing_address") else "claims"
    with pytest.raises(ValueError, match="^stp_root_identity_" + code + "$"):
        m.validate_root_identity_claims(point, output, submitted)
