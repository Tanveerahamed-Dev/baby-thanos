"""Generated declared populations and real STP observations; no device qualification."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import admit_members
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest

P, Q = "GigabitEthernet1/0/1", "GigabitEthernet1/0/12"
DISCOVERY = b"Device ID: sw-b\n"
MANIFEST = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "fixture",
            "nodes": [{"id": name, "discovery_id": "sw-" + name, "ports": [P, Q]} for name in ("a", "b")],
            "captures": [{"path": "link.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(DISCOVERY).hexdigest()}]}
A, B = admit_members({"p2.json": canonical(MANIFEST), "link.txt": DISCOVERY}).nodes
U, COMPLETE = k.UnknownReason, k.IntegrityState.COMPLETE


def target(**changes):
    return replace(b.Target(context="first", node=A, port=P, vlans=(2, 1)), **changes)


def body(item, state="enabled", vlan=1):
    header = f"Port 1 ({item.port}) of VLAN{vlan:04d} is designated forwarding\n".encode()
    return header + (b"" if state is None else f"   Root guard is {state} on the port\n".encode())


def request(item, raw=None, identity="a", integrity=COMPLETE):
    raw = body(item) if raw is None else raw
    capture = Capture(id=k.CaptureId("cap:" + identity), source=item.node.key, operation=b.stp.OP,
        rendered=b.stp.command(item.port), codec="utf-8", raw=raw, integrity=integrity,
        lines=text_lines(raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)
    return CaptureRequest(capture=capture, context=item.context)


def watch(monkeypatch):
    calls, original = [], b.stp.parse_capture
    def spy(*args):
        calls.append(None)
        calls[-1] = original(*args)
        return calls[-1]
    monkeypatch.setattr(b.stp, "parse_capture", spy)
    return calls


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("state,expected", [("enabled", True), ("disabled", False)])
def test_real_owned_fact_receipt_identity_and_all_five_original_byte_proofs(monkeypatch, ending, state, expected):
    item, calls = target(), watch(monkeypatch)
    raw = body(item, state).replace(b"\n", ending)
    supplied = request(item, raw)
    result = b.build_root_guard((item,), (supplied,))
    row, absent = result.rows
    assert (row.vlan, absent.vlan, absent.value.reason) == (1, 2, U.SUBJECT_ABSENT_FROM_CAPTURE)
    assert row.value.value is expected and (row.value.raw, row.value.basis) == (state, k.Basis.OBSERVED)
    assert result.store.owners == {b.ROOT_GUARD: b.STEP.id} and len(result.store.values) == 2
    assert result.store.values[k.FactRef(fact=b.ROOT_GUARD, subject=row.subject)] is row.value
    fact, = b.DECLARATION.facts
    assert (fact.id, fact.step, fact.value_type) == (b.ROOT_GUARD, b.STEP.id, "boolean")
    output, = result.executed
    assert output.value is calls[0] and output.receipt.parse is output.value.parse
    assert output.receipt.capture is supplied.capture and output.receipt.context == item.context
    assert (output.receipt.owner, output.receipt.registration_sha256) == (b.STEP.id, compile_packs((b.DECLARATION,)).registration_sha256)
    assert tuple(ref for ref in row.value.evidence if type(ref) is k.RegistryRef) == A.declaration.evidence
    refs = [ref for ref in row.value.evidence if type(ref) is k.EvidenceRef]
    assert len(refs) == 5
    for ref in refs:
        assert ref.capture == supplied.capture.id and type(ref.locator) is k.ByteSpan
        excerpt = raw[ref.locator.start:ref.locator.end]
        assert sha256(excerpt).hexdigest() == ref.excerpt_sha256
    assert {raw[ref.locator.start:ref.locator.end] for ref in refs} == {state.encode(), raw.splitlines()[1], P.encode(), b"0001", raw.splitlines()[0]}


@pytest.mark.parametrize("raw,integrity,reason", [
    (body(target(), None), COMPLETE, U.FIELD_NOT_PRINTED),
    (body(target(), None) + b"   Bpdu guard is enabled\n   Loop guard is enabled on the port\n", COMPLETE, U.FIELD_NOT_PRINTED),
    (body(target()) + b"unmodeled\n", COMPLETE, U.PARSE_PARTIAL), (body(target()).replace(b"enabled", b"inherit"), COMPLETE, U.PARSE_PARTIAL),
    (body(target()) * 2, COMPLETE, U.CONFLICTING_EVIDENCE), (body(target()) + b"   Root guard is disabled on the port\n", COMPLETE, U.CONFLICTING_EVIDENCE),
    (body(target()), k.IntegrityState.ERROR, U.CAPTURE_ERROR), (body(target()), k.IntegrityState.TRUNCATED, U.CAPTURE_TRUNCATED),
    (body(target()), k.IntegrityState.PAGING_ARTIFACTS, U.CAPTURE_TRUNCATED), (b"", COMPLETE, U.EMPTY_UNREGISTERED),
    (body(target()).replace(b"VLAN0001", b"MST0"), COMPLETE, U.PARSE_UNSUPPORTED_VARIANT),
])
def test_stronger_unknowns_never_become_false_or_health(raw, integrity, reason):
    item = target(vlans=(1,))
    row, = b.build_root_guard((item,), (request(item, raw, integrity=integrity),)).rows
    assert type(row.value) is k.Unknown and row.value.reason is reason
    need, = row.value.next_evidence
    assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (A.key, b.stp.OP, (("port", P),), (b.ROOT_GUARD,), (b.STEP.id,))


def test_population_survives_disabled_omitted_deleted_capture_and_reordering():
    first = target()
    targets = (first, target(node=B), target(context="second"), target(port=Q))
    results = [b.build_root_guard(targets, () if state == "deleted" else (request(first, body(first, state)),))
               for state in ("enabled", "disabled", None, "deleted")]
    assert len({row.subject for row in results[0].rows}) == 8
    assert all([row.subject for row in result.rows] == [row.subject for row in results[0].rows] for result in results)
    assert [result.rows[0].value.value for result in results[:2]] == [True, False]
    assert results[2].rows[0].value.reason is U.FIELD_NOT_PRINTED
    assert all(type(row.value) is k.Unknown and row.value.reason is U.NOT_COLLECTED for row in results[3].rows)
    assert all(row.value.reason is U.NOT_COLLECTED for row in results[0].rows[2:])
    reordered = tuple(replace(item, vlans=tuple(reversed(item.vlans))) for item in reversed(targets))
    supplied = (request(first), request(target(node=B), identity="z"))
    once = b.build_root_guard(targets, supplied)
    same = b.build_root_guard(reordered, tuple(reversed(supplied)))
    assert (same.rows, same.store.values, same.executed) == (once.rows, once.store.values, once.executed)
    assert b.subject(target(vlans=(23,)), 23) != b.subject(target(port=Q, vlans=(3,)), 3)


@pytest.mark.parametrize("state,integrity", [("enabled", COMPLETE), ("disabled", COMPLETE), ("enabled", k.IntegrityState.ERROR)])
def test_duplicate_target_captures_refuse_before_any_parser_or_writer(monkeypatch, state, integrity):
    item, calls = target(), watch(monkeypatch)
    supplied = (request(item, identity="z", integrity=integrity),
                request(item, body(item, state), identity="a", integrity=integrity))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before validation"))
    with pytest.raises(ValueError, match="^stp_duplicate_target_capture$"):
        b.build_root_guard((item,), supplied)
    assert calls == []


@pytest.mark.parametrize("change,code", [
    ({"vlans": (True,)}, "invalid_stp_vlans"), ({"vlans": (1.0,)}, "invalid_stp_vlans"),
    ({"vlans": ()}, "invalid_stp_vlans"), ({"vlans": (0,)}, "invalid_stp_vlans"), ({"vlans": (4095,)}, "invalid_stp_vlans"),
    ({"vlans": (1, 1)}, "invalid_stp_vlans"), ({"vlans": [1]}, "invalid_stp_vlans"), ({"vlans": tuple(range(1, 18))}, "invalid_stp_vlans"),
    ({"port": "GigabitEthernet99"}, "synthetic_undeclared_port"), ({"context": ""}, "stp_target"),
    ({"node": object()}, "stp_target"), (None, "stp_duplicate_target"),
    ({"node": replace(A, declaration=replace(A.declaration, basis=k.Basis.OBSERVED))}, "stp_node_declaration"),
])
@pytest.mark.parametrize("empty", [False, True])
def test_late_bad_target_refuses_even_with_no_capture(monkeypatch, change, code, empty):
    item, calls = target(), watch(monkeypatch)
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_root_guard((item, target(vlans=(3,)) if change is None else target(**change)),
                           () if empty else (request(item),))
    assert calls == []


@pytest.mark.parametrize("plant", ["context", "source", "command", "operation", "scope"])
def test_whole_request_plan_precedes_first_parse(monkeypatch, plant):
    item, calls = target(), watch(monkeypatch)
    later = request(item, identity="z")
    if plant == "context":
        later = replace(later, context="unknown")
    else:
        capture = later.capture
        changes = {"source": {"source": B.key}, "command": {"rendered": b.stp.command(Q)},
                   "operation": {"operation": None}, "scope": {"metadata": replace(capture.resolved_metadata,
                       scope=replace(capture.scope, vrf="other"))}}[plant]
        later = replace(later, capture=replace(capture, **changes))
    with pytest.raises(ValueError, match="^stp_request_" + ("scope" if plant == "scope" else "target") + "$"):
        b.build_root_guard((item,), (request(item), later))
    assert calls == []
    assert b.build_root_guard((item,), (request(item),)).executed and len(calls) == 1


@pytest.mark.parametrize("plant,code", [("association", "stp_receipt_parse"), ("result", "stp_receipt_parse"),
    ("missing", "stp_parser_population"), ("extra", "stp_parser_population"), ("rowtype", "stp_parser_population"),
    ("duplicate", "stp_parser_population"), ("port", "stp_parser_population"), ("neighbor", "stp_guard_header")])
def test_late_rich_or_wrong_vlan_proof_refuses_before_writer(monkeypatch, plant, code):
    first, last = target(), target(node=B)
    actual = b.execute_parsers
    def forge(*args):
        outputs = actual(*args)
        item = outputs[-1]
        rows = item.value.rows
        if plant == "association":
            return outputs[:-1] + (replace(item, receipt=replace(item.receipt, parse=replace(item.receipt.parse))),)
        if plant == "result":
            return outputs[:-1] + (replace(item, value=object()),)
        if plant == "neighbor":
            fields = dict(rows[0].fields) | {"root_guard": dict(rows[1].fields)["root_guard"]}
            changed = replace(rows[0], fields=tuple(fields.items()), spans=(rows[0].spans[0], rows[1].spans[-1]))
            rows = (changed, rows[1])
        else:
            rows = {"missing": (), "rowtype": (object(),), "extra": rows + (replace(rows[0], vlan=3),), "duplicate": rows + rows[:1],
                    "port": (replace(rows[0], port=Q), rows[1])}[plant]
        return outputs[:-1] + (replace(item, value=replace(item.value, rows=rows)),)
    monkeypatch.setattr(b, "execute_parsers", forge)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before validation"))
    raw = body(last) + body(last, vlan=2)
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_root_guard((first, last), (request(first), request(last, raw, "z")))


def test_runtime_receipt_barrier_must_finish_before_any_writer(monkeypatch):
    def refuse(*args):
        raise ValueError("planted_receipt_barrier")
    monkeypatch.setattr(pack_runtime, "validate_receipts", refuse)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before validation"))
    item = target()
    with pytest.raises(ValueError, match="^planted_receipt_barrier$"):
        b.build_root_guard((item,), (request(item),))
