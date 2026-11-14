"""Owning VERSION proof closure and leaf grants; no Source or execution-origin seal."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_all import block
from test_peer_execution import forbidden, no_writers
from test_peer_version_proofs import actual as ordinary
from test_peer_version_proofs import close as close_base
from test_peer_version_proofs import inputs
from test_state_owner import LIMITS
from test_state_version_correspondence import DETAIL
from test_version_values import reader_for

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactStore, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import peer_execution as runtime
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner import p4_pipeline as pipeline
from atlas_brain.runner.p4_refs import FhrpVersionProofIndex

FACT = profile.REPORTED_PROTOCOL_VERSION


def closing(component, index, reader=None, result=None, owner=None):
    index.close_protocol_version(component.version if result is None else result,
        reader_for(component.version.store) if reader is None else reader,
        component.version_owner if owner is None else owner)


def actual(root, monkeypatch, mode="normal"):
    variants = {"partial": DETAIL + b"unrecognized\n", "duplicate": DETAIL + block(interface="Vl20"),
        "unsupported": DETAIL.replace(b"Virtual IP address is", b"Virtual IPv6 address is"),
        "no_version": DETAIL.replace(b" (version 2)", b""), "unknown_vip": DETAIL.replace(b"192.0.2.1", b"unknown"),
        "empty": b"", "error": b"% Invalid input\n"}
    if mode in variants:
        inputs(root, detail=variants[mode])
        component = runtime.build_peer_state_version_component(root, LIMITS)
        no_writers(monkeypatch)
        monkeypatch.setattr(FactWriter, "write", forbidden)
        monkeypatch.setattr(pipeline, "execute_parsers", forbidden)
        for module in (stp.stp, ec.parse_summary, fhrp.hsrp, runtime.all_hsrp):
            monkeypatch.setattr(module, "parse_capture", forbidden)
    else:
        component = ordinary(root, monkeypatch, mode)
    good = FhrpVersionProofIndex(component.execution, LIMITS)
    close_base(component, good)
    closing(component, good)
    assert len(good.scopes) == 4 + 2 * len(component.version.rows)
    index = FhrpVersionProofIndex(component.execution, LIMITS)
    close_base(component, index)
    return component, index, reader_for(component.version.store)


def refused(component, index, **kwargs):
    bound, ordered = index.bound, index.scopes
    with pytest.raises(ValueError):
        closing(component, index, **kwargs)
    assert index.bound is bound and index.scopes is ordered
    assert index.protocol_version_reader is index.protocol_version_result is index.protocol_version_owner is None
    assert all(scope.reference.fact != FACT for scope in index.scopes)
    with pytest.raises(ValueError):
        index.resolve_protocol_version_reference(k.FactRef(fact=FACT, subject=component.version.rows[0].subject))


@pytest.mark.parametrize("mode", ["normal", "no_all_target", "no_all_capture", "no_all", "no_brief_capture",
    "no_captures", "unselected_b", "zero", "partial", "duplicate", "unsupported", "no_version", "unknown_vip", "empty", "error"])
def test_actual_known_and_unknown_rows_keep_exact_declarations_scopes_and_all_leaf_points(tmp_path, monkeypatch, mode):
    component, index, reader = actual(tmp_path, monkeypatch, mode)
    original = index.scopes
    assert all(scope.whole_captures is None for scope in original)
    closing(component, index, reader=replace(reader))
    assert all(index.scope(scope.reference.fact, scope.reference.subject) is scope for scope in original)
    if mode in ("normal", "no_brief_capture"):
        assert {row.value.value for row in component.version.rows if type(row.value) is k.Known} == {"1", "2"}
    for row in component.version.rows:
        scope = index.scope(FACT, row.subject)
        state = index.scope(fhrp.REPORTED_STATE, row.subject)
        detailed = next((target for target in component.execution.envelope.targets
            if target.node is row.target.node and target.operation == runtime.all_hsrp.OP), None)
        declarations = row.target.node.declaration.evidence + component.execution.envelope.declaration.evidence + state.target.declaration.evidence
        assert scope.declarations == declarations + (() if detailed is None else detailed.declaration.evidence)
        assert scope.target is (state.target if detailed is None else detailed)
        outputs = tuple(out for out in component.execution.executed if index.members[out.receipt.capture.id].target is scope.target
            and out.receipt.capture.operation == runtime.all_hsrp.OP)
        assert scope.whole_captures == frozenset(out.receipt.capture.id for out in outputs)
        assert index.resolve_protocol_version_reference(scope.reference) == index.resolve(scope, row.value.evidence, positive=type(row.value) is k.Known)
        if type(row.value) is k.Unknown:
            assert scope.spans == scope.positive == scope.required == frozenset()
            assert all(ref.capture in scope.whole_captures for ref in row.value.evidence
                if type(ref) is k.EvidenceRef and type(ref.locator) is k.WholeCapture)
            assert not any(ref.role is k.EvidenceRole.SUBJECT for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            continue
        output, = outputs
        rich = next(rich for rich in output.value.rows if rich.interface.raw == row.interface and rich.group.raw == row.group)
        body = {record.rule_id: record for record in rich.body}
        points = (rich.header.span, rich.interface.span, rich.group.span, rich.version.span,
            body["virtual_ip"].span, rich.virtual_ip.span, body["group_name"].span)
        expected = frozenset((output.receipt.capture.id, point) for point in points)
        assert scope.spans == scope.required == expected
        assert scope.positive == frozenset(((output.receipt.capture.id, rich.version.span),))
        assert {(ref.capture, ref.locator) for ref in row.value.evidence if type(ref) is k.EvidenceRef} == expected
        assert all(ref.excerpt_sha256 == sha256(output.receipt.capture.raw[ref.locator.start:ref.locator.end]).hexdigest()
            for ref in row.value.evidence if type(ref) is k.EvidenceRef)


@pytest.mark.parametrize("plant", ["header", "interface", "group", "version", "ipv4_record", "ipv4", "footer",
    "digest", "role", "block", "node", "capture", "registry", "order", "whole", "recursive"])
def test_known_grants_need_every_own_point_and_refuse_donations(tmp_path, monkeypatch, plant):
    component, index, reader = actual(tmp_path, monkeypatch)
    closing(component, index, reader=reader)
    row = next(row for row in component.version.rows if type(row.value) is k.Known and row.interface == "Vl20")
    scope, evidence = index.scope(FACT, row.subject), row.value.evidence
    output = component.version.executed[0]
    rich = next(item for item in output.value.rows if item.interface.raw == row.interface and item.group.raw == row.group)
    body = {item.rule_id: item for item in rich.body}
    points = dict(zip(("header", "interface", "group", "version", "ipv4_record", "ipv4", "footer"),
        (rich.header.span, rich.interface.span, rich.group.span, rich.version.span, body["virtual_ip"].span, rich.virtual_ip.span, body["group_name"].span), strict=True))
    if plant in points:
        evidence = tuple(ref for ref in evidence if type(ref) is not k.EvidenceRef or ref.locator != points[plant])
    elif plant in ("digest", "role", "registry"):
        selected = next(ref for ref in evidence if type(ref) is (k.RegistryRef if plant == "registry" else k.EvidenceRef))
        changed = replace(selected, **({"table_digest": "0" * 64} if plant == "registry" else
            {"excerpt_sha256": "0" * 64} if plant == "digest" else {"role": k.EvidenceRole.WITNESS}))
        evidence = tuple(changed if ref is selected else ref for ref in evidence)
    elif plant == "order":
        evidence = tuple(reversed(scope.declarations)) + tuple(ref for ref in evidence if type(ref) is k.EvidenceRef)
    elif plant == "block":
        donor = next(other for other in component.version.rows if type(other.value) is k.Known and other.interface == "BD3329")
        assert donor.value.value == row.value.value
        evidence = scope.declarations + tuple(ref for ref in donor.value.evidence if type(ref) is k.EvidenceRef)
    elif plant == "recursive":
        evidence += (scope.reference,)
    else:
        capture = next(capture for capture in index.captures if capture.operation == (
            ec.parse_summary.OP if plant == "node" else fhrp.hsrp.OP if plant == "capture" else runtime.all_hsrp.OP))
        evidence += (k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS,
            excerpt_sha256=capture.bytes_sha256),)
    with pytest.raises(ValueError, match="^p4_projection_"):
        index.resolve(scope, evidence, positive=True)


@pytest.mark.parametrize("plant", ["value", "raw", "basis", "evidence", "reason", "detail", "candidates", "needs",
    "params", "resolves", "reruns", "unprintable", "deep_candidate", "deep_need"])
def test_in_place_row_store_payload_and_need_forgeries_cannot_survive_owner_recomputation(tmp_path, monkeypatch, plant):
    component, index, _ = actual(tmp_path, monkeypatch)
    known = plant in ("value", "raw", "basis", "evidence")
    row = next(row for row in component.version.rows if (type(row.value) is k.Known) is known)
    value = row.value
    if plant in ("params", "resolves", "reruns", "unprintable", "deep_need"):
        need, = value.next_evidence
        changes = {"params": (("group", "synthetic-other"), ("interface", row.interface)), "resolves": ("other.fact",),
            "reruns": ("l3.fhrp/other",), "unprintable": ("other",), "deep_need": ([],)}
        object.__setattr__(need, "resolves" if plant == "deep_need" else plant, changes[plant])
    else:
        changes = {"value": "1" if known and value.value == "2" else "2", "raw": "9", "basis": k.Basis.DECLARED,
            "evidence": tuple(reversed(value.evidence)), "reason": k.UnknownReason.PARSE_PARTIAL, "detail": "other",
            "candidates": ("synthetic:other",), "needs": (), "deep_candidate": ([],)}
        if plant == "value":
            object.__setattr__(value, "raw", changes[plant])
        object.__setattr__(value, {"needs": "next_evidence", "deep_candidate": "candidates"}.get(plant, plant), changes[plant])
    assert component.version.store.values[k.FactRef(fact=FACT, subject=row.subject)] is row.value
    refused(component, index)


@pytest.mark.parametrize("plant", ["owner", "envelope", "budgets", "production", "reader_store", "reader_grant", "reader_type", "reader_clone",
    "registration", "ledger_receipt", "ledger_value", "ledger_missing", "ledger_duplicate", "cell_missing", "cell_extra",
    "cell_clone", "row_missing", "row_duplicate", "row_extra", "row_node", "row_subject"])
def test_actual_owner_reader_ledger_and_population_substitutions_leave_no_partial_scopes(tmp_path, monkeypatch, plant):
    component, index, reader = actual(tmp_path, monkeypatch)
    result, owner = component.version, component.version_owner
    if plant == "owner":
        owner = object()
    elif plant in ("envelope", "budgets", "production"):
        setattr(owner, plant, replace(owner.envelope) if plant == "envelope" else replace(LIMITS) if plant == "budgets" else None)
    elif plant == "reader_store":
        foreign = FactStore()
        foreign.owners, foreign.values = dict(result.store.owners), dict(result.store.values)
        reader = reader_for(foreign)
    elif plant in ("reader_grant", "reader_type"):
        reader = object() if plant == "reader_type" else bind_reader(result.store, step=fhrp.STEP)
    elif plant == "reader_clone":
        read = FactReader.read
        monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)))
    elif plant == "registration":
        object.__setattr__(result, "registration_sha256", "0" * 64)
    elif plant.startswith("ledger_"):
        outputs = component.execution.executed
        output = next(out for out in outputs if out.receipt.capture.operation == runtime.all_hsrp.OP)
        changed = replace(output, **({"receipt": replace(output.receipt)} if plant == "ledger_receipt" else {"value": replace(output.value)}))
        object.__setattr__(component.execution, "executed", outputs + (output,) if plant == "ledger_duplicate" else
            tuple(out for out in outputs if out is not output) if plant == "ledger_missing" else tuple(changed if out is output else out for out in outputs))
    elif plant.startswith("cell_"):
        reference = next(iter(result.store.values))
        if plant == "cell_missing":
            result.store.values.pop(reference)
        else:
            result.store.values[reference if plant == "cell_clone" else k.FactRef(fact=FACT, subject="extra:subject")] = replace(result.store.values[reference])
    elif plant in ("row_missing", "row_duplicate", "row_extra"):
        rows = result.rows[:-1] if plant == "row_missing" else result.rows + (replace(result.rows[0], subject="extra:subject") if plant == "row_extra" else result.rows[0],)
        object.__setattr__(result, "rows", rows)
        object.__setattr__(owner.completed, "rows", rows)
    else:
        row = result.rows[0]
        object.__setattr__(row, "subject" if plant == "row_subject" else "target",
            "other:subject" if plant == "row_subject" else replace(row.target, node=next(node for node in component.execution.envelope.base.nodes if node is not row.target.node)))
    refused(component, index, reader=reader, owner=owner)


def test_late_reader_failure_does_not_publish_staged_version_scopes(tmp_path, monkeypatch):
    component, index, _ = actual(tmp_path, monkeypatch)
    read, calls = FactReader.read, []
    def reading(self, **kwargs):
        calls.append(kwargs["subject"])
        if len(calls) == len(component.version.rows) + 2:
            raise ValueError("planted_late_read")
        return read(self, **kwargs)
    monkeypatch.setattr(FactReader, "read", reading)
    refused(component, index)
    assert len(calls) == len(component.version.rows) + 2


def test_absent_all_anchor_refuses_brief_whole_witness_while_legacy_default_and_ordering_stay_explicit(tmp_path, monkeypatch):
    component, index, reader = actual(tmp_path, monkeypatch, "no_all")
    closing(component, index, reader=reader)
    row = next(row for row in component.version.rows if row.target.node.id == "a")
    scope, legacy = index.scope(FACT, row.subject), index.scope(fhrp.REPORTED_STATE, row.subject)
    capture = next(capture for capture in index.captures if capture.operation == fhrp.hsrp.OP)
    witness = k.EvidenceRef(capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS, excerpt_sha256=capture.bytes_sha256)
    assert scope.target is legacy.target and scope.whole_captures == frozenset() and legacy.whole_captures is None
    assert index.resolve(legacy, legacy.declarations + (witness,), positive=False)
    with pytest.raises(ValueError, match="^p4_projection_scope$"):
        index.resolve(scope, scope.declarations + (witness,), positive=False)
    early = FhrpVersionProofIndex(component.execution, LIMITS)
    closing(component, early, reader=reader)
    with pytest.raises(ValueError, match="^p4_observations_population$"):
        close_base(component, early)


@pytest.mark.parametrize("plant", ["before", "type", "foreign_fact", "foreign_subject", "fact_type", "subject_type", "recursive", "post_value"])
def test_reference_api_is_narrow_current_and_never_recursive(tmp_path, monkeypatch, plant):
    component, index, reader = actual(tmp_path, monkeypatch)
    row = next(row for row in component.version.rows if type(row.value) is k.Known)
    reference = object() if plant == "type" else k.FactRef(fact=FACT, subject=row.subject)
    if plant != "before":
        closing(component, index, reader=reader)
    if plant in ("foreign_fact", "foreign_subject"):
        reference = replace(reference, **({"fact": fhrp.REPORTED_STATE} if plant == "foreign_fact" else {"subject": "extra:subject"}))
    elif plant in ("fact_type", "subject_type"):
        object.__setattr__(reference, plant.removesuffix("_type"), [])
    elif plant == "recursive":
        object.__setattr__(row.value, "evidence", row.value.evidence + (reference,))
    elif plant == "post_value":
        object.__setattr__(row.value, "value", "9")
    with pytest.raises(ValueError):
        index.resolve_protocol_version_reference(reference)
