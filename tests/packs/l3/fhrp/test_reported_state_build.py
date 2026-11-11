"""Declared HSRP local census and original-capture state proofs; no peer or health inference."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_brief import ACTIVE, BODY, HEADER, INIT, LEGEND, capture

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.synthetic import admit_members
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.runner.pack_receipts import CaptureRequest

DISCOVERY = b"Device ID: fixture-b\n"
REGISTRY = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
    "nodes": [{"id": name, "discovery_id": "fixture-" + name, "ports": ["Gi1/0/1"]} for name in ("a", "b")],
    "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(DISCOVERY).hexdigest()}]}
A, B = admit_members({"p2.json": canonical(REGISTRY), "discovery.txt": DISCOVERY}).nodes
GROUPS = (("Vl20", "0"), ("Vl10", "1"), ("BD3329", "129"), ("Vl99", "2"))


def target(**changes):
    return replace(b.Target(context="round", node=A, groups=GROUPS), **changes)


def request(item, raw=BODY, identity="a", integrity=k.IntegrityState.COMPLETE):
    sample = replace(capture(raw, integrity), id=k.CaptureId("cap:" + identity), source=item.node.key)
    return CaptureRequest(context=item.context, capture=sample)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_actual_registered_state_uses_only_original_local_record_and_every_own_af_witness(monkeypatch, ending):
    item, raw = target(), BODY.replace(b"\n", ending)
    supplied = request(item, raw)
    calls, parse = [], b.hsrp.parse_capture
    def watched(sample):
        value = parse(sample)
        calls.append(value)
        return value
    monkeypatch.setattr(b.hsrp, "parse_capture", watched)
    out = b.build_reported_state((item,), (supplied,))
    output, = out.executed
    assert len(calls) == 1 and output.value is calls[0] and output.receipt.parse is calls[0].parse
    assert output.receipt.capture is supplied.capture and output.receipt.owner == b.STEP.id and output.receipt.context == item.context
    assert output.receipt.registration_sha256 == compile_packs((b.DECLARATION,)).registration_sha256
    assert b.REPORTED_STATE == "l3.fhrp.reported_state"
    spec, = b.DECLARATION.facts
    assert (spec.id, spec.subject, spec.value_type, spec.step) == (b.REPORTED_STATE, "fhrp_local", "text", b.STEP.id)
    rows = {(row.interface, row.group): row for row in out.rows}
    assert set(rows) == set(GROUPS) and out.store.owners == {b.REPORTED_STATE: b.STEP.id}
    for interface, group, state, printed in (("Vl20", "0", "init", "Init"), ("Vl10", "1", "active", "Active"), ("BD3329", "129", "standby", "Standby")):
        row = rows[(interface, group)]
        original = next(value for value in output.value.rows if value.interface.raw == interface and value.group.raw == group)
        value = row.value
        assert row.subject == b.subject(item, interface, group)
        assert (value.value, value.raw, value.basis) == (state, printed, k.Basis.OBSERVED)
        assert value.evidence[:1] == item.node.declaration.evidence
        refs = tuple(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
        expected = {original.interface.span, original.group.span, original.state.span, original.span, *original.af_spans}
        assert tuple(ref.locator for ref in refs) == tuple(sorted(expected, key=lambda span: (span.start, span.end)))
        assert all(ref.capture == supplied.capture.id and ref.role is k.EvidenceRole.SUBJECT and ref.excerpt_sha256 == sha256(raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
        assert out.store.values[k.FactRef(fact=b.REPORTED_STATE, subject=row.subject)] is value
    assert rows[("Vl99", "2")].value.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE


def test_exact_interface_node_context_and_group_are_independent_subject_axes():
    item = target(groups=(("Vl10", "0"), ("Vlan10", "0"), ("Vl10", "4095")))
    subjects = {b.subject(item, interface, group) for interface, group in item.groups}
    subjects.add(b.subject(replace(item, node=B), "Vl10", "0"))
    subjects.add(b.subject(replace(item, context="other"), "Vl10", "0"))
    assert len(subjects) == 5
    with pytest.raises(ValueError):
        b.subject(item, "Vl10", "1")


@pytest.mark.parametrize("raw,integrity,reason", [
    (None, k.IntegrityState.COMPLETE, k.UnknownReason.NOT_COLLECTED),
    (BODY + ACTIVE, k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + ACTIVE.replace(b"192.0.2.1", b"192.0.2.9"), k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + INIT.replace(b"203.0.113.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + b"unrecognised\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"Active", b"Listen"), k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (b"", k.IntegrityState.COMPLETE, k.UnknownReason.EMPTY_UNREGISTERED),
    (BODY, k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY, k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
])
def test_global_poison_and_missing_capture_preserve_declared_population_and_candidate_evidence(raw, integrity, reason):
    item = target()
    out = b.build_reported_state((item,), () if raw is None else (request(item, raw, integrity=integrity),))
    assert {(row.interface, row.group) for row in out.rows} == set(GROUPS)
    assert all(type(row.value) is k.Unknown and row.value.reason is reason for row in out.rows)
    row = next(row for row in out.rows if (row.interface, row.group) == (("Vl20", "0") if reason is k.UnknownReason.IDENTITY_UNRESOLVED else ("Vl10", "1")))
    need, = row.value.next_evidence
    assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (item.node.key, b.hsrp.OP, (("group", row.group), ("interface", row.interface)), (b.REPORTED_STATE,), (b.STEP.id,))
    if raw is not None:
        refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        assert type(refs[0].locator) is k.WholeCapture and refs[0].role is k.EvidenceRole.WITNESS
        spans = tuple(record.span for record in out.executed[0].receipt.parse.records if record.rule_id in ("row", "row_preempt") and dict(record.fields)["interface"].raw == row.interface and dict(record.fields)["group"].raw == row.group)
        assert tuple(ref.locator for ref in refs[1:]) == spans and all(ref.role is k.EvidenceRole.WITNESS for ref in refs)
        assert all(ref.capture == out.executed[0].receipt.capture.id for ref in refs)


def test_capture_loss_and_input_permutation_preserve_subjects_and_canonical_rows():
    first, second = target(), target(node=B, context="later")
    before = b.build_reported_state((second, first), (request(second, identity="b"), request(first)))
    after = b.build_reported_state((first, second), ())
    assert [row.subject for row in before.rows] == [row.subject for row in after.rows]
    assert all(row.value.reason is k.UnknownReason.NOT_COLLECTED for row in after.rows)
    changed = b.build_reported_state((replace(first, groups=tuple(reversed(GROUPS))), second), (request(first), request(second, identity="b")))
    assert before.rows == changed.rows and before.executed == changed.executed


@pytest.mark.parametrize("change", [
    {"context": ""}, {"node": object()}, {"groups": []}, {"groups": ()}, {"groups": (("Vl10", "01"),)},
    {"groups": (("Vl10", "4096"),)}, {"groups": (("Vl10", True),)}, {"groups": (("", "1"),)},
    {"groups": (("Vl10", "1"), ("Vl10", "1"))},
    {"node": replace(A, declaration=replace(A.declaration, evidence=(replace(A.declaration.evidence[0], citation="/group"),)))}, None,
])
@pytest.mark.parametrize("empty", [False, True])
def test_late_target_preflight_refuses_before_any_parser_or_writer(monkeypatch, change, empty):
    item = target()
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: pytest.fail("parser before full target preflight"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before full target preflight"))
    with pytest.raises(ValueError):
        b.build_reported_state((item, target(**change) if change is not None else target(groups=(("Vl50", "1"),))), () if empty else (request(item),))


@pytest.mark.parametrize("plant,code", [("context", "hsrp_request_target"), ("source", "hsrp_request_target"),
    ("operation", "hsrp_request_target"), ("rendered", "hsrp_request_target"), ("scope", "hsrp_request_scope"),
    ("duplicate", "hsrp_duplicate_capture"), ("codec", "hsrp_request_target")])
def test_late_request_fault_never_runs_an_earlier_parser(monkeypatch, plant, code):
    item = target()
    later = request(item, identity="z")
    if plant == "context":
        later = replace(later, context="wrong")
    else:
        changes = {"source": {"source": B.key}, "operation": {"operation": "iosxe.other"},
            "rendered": {"rendered": "show standby"}, "scope": {"metadata": replace(later.capture.resolved_metadata, scope=replace(later.capture.scope, vrf="other"))}, "duplicate": {}, "codec": {"codec": "latin-1"}}[plant]
        later = replace(later, capture=replace(later.capture, **changes))
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: pytest.fail("parser before request preflight"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before request preflight"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_reported_state((item,), (request(item), later))


@pytest.mark.parametrize("plant,code", [("coverage", "hsrp_receipt_coverage"), ("owner", "hsrp_receipt_owner"),
    ("context", "hsrp_receipt_owner"), ("registration", "hsrp_receipt_owner"), ("association", "hsrp_receipt_parse"),
    ("state", "hsrp_record"), ("af", "hsrp_af"), ("empty_af", "hsrp_af"),
    ("interface", "hsrp_record"), ("group", "hsrp_record"), ("span", "hsrp_record"), ("undeclared", "hsrp_undeclared_subject"), ("state_value", "hsrp_value")])
def test_late_original_record_or_receipt_substitution_refuses_before_writer(monkeypatch, plant, code):
    first, item = target(), target(node=B, groups=(("Vl10", "1"), ("Vl11", "2")))
    raw = LEGEND + HEADER + ACTIVE + ACTIVE.replace(b"Vl10", b"Vl11").replace(b"1    110", b"2    110")
    execute = b.execute_parsers
    def forged(*args):
        outputs = execute(*args)
        out = outputs[-1]
        if plant == "coverage":
            return outputs[:-1]
        if plant in ("owner", "context", "registration", "association"):
            changes = {"owner": {"owner": type(b.STEP.id)("test.other/parse")}, "context": {"context": "wrong"},
                "registration": {"registration_sha256": "0" * 64}, "association": {"parse": replace(out.receipt.parse)}}[plant]
            return outputs[:-1] + (replace(out, receipt=replace(out.receipt, **changes)),)
        left, right = out.value.rows
        if plant == "state_value":
            state = replace(left.state, value=b.hsrp.State.STANDBY)
            records = tuple(replace(record, fields=tuple((name, state if original is left.state else original) for name, original in record.fields)) for record in out.value.parse.records)
            parsed = replace(out.value.parse, records=records, tokens=tuple((name, state if original is left.state else original) for name, original in out.value.parse.tokens))
            value = replace(out.value, rows=(replace(left, state=state), right), parse=parsed)
            return outputs[:-1] + (replace(out, value=value, receipt=replace(out.receipt, parse=parsed)),)
        changes = {"state": {"state": right.state}, "af": {"af_spans": right.af_spans}, "empty_af": {"af_spans": ()},
            "interface": {"interface": right.interface}, "group": {"group": right.group}, "span": {"span": right.span}}
        rows = out.value.rows if plant == "undeclared" else (replace(left, **changes[plant]), right)
        return outputs[:-1] + (replace(out, value=replace(out.value, rows=rows)),)
    monkeypatch.setattr(b, "execute_parsers", forged)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before every receipt and raw proof"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_reported_state((first, target(node=B, groups=(("Vl10", "1"),)) if plant == "undeclared" else item), (request(first), request(item, raw, "z")))
