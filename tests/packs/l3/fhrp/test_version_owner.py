"""Actual local owning execution and candidate cells; no Store, GLOBAL or admission claim."""
from dataclasses import fields, replace
from hashlib import sha256

import pytest
from test_parse_hsrp_all import BODY, block, capture
from test_reported_state_build import B
from test_version_inputs import fixture, forbid_bad_snapshots

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import version_owner as owner
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner import pack_runtime

FACT, STEP = "l3.fhrp.reported_protocol_version", "l3.fhrp/parse_hsrp_all_version"


def forbid_writes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("owning execution or candidate closure wrote a fact")
    monkeypatch.setattr(FactWriter, "write", forbidden)


@pytest.mark.parametrize("literal", ["1", "2"])
def test_actual_local_factory_execution_closes_original_candidates_without_store_or_parser_replay(monkeypatch, literal):
    first, supplied = fixture()
    cold, _ = fixture(B, "b")
    sample = replace(capture(block(literal)), source=first.node.key, id=supplied.capture.id)
    supplied = replace(supplied, capture=sample)
    parse, verify = owner.parser.parse_capture, owner.parser.validate_claims
    parsed, checked = [], []
    def parsing(sample):
        value = parse(sample)
        parsed.append((sample, value))
        return value
    def verifying(sample, value):
        proof = verify(sample, value)
        checked.append((sample, value, proof))
        return proof
    monkeypatch.setattr(owner.parser, "parse_capture", parsing)
    monkeypatch.setattr(owner.parser, "validate_claims", verifying)
    forbid_writes(monkeypatch)
    execution = owner.execute_local_version_inputs((cold, first), (supplied,))
    assert type(execution) is owner.VersionExecution and type(execution.owner) is owner.LocalVersionOwner
    assert tuple(field.name for field in fields(execution)) == ("owner", "executed")
    output, = execution.executed
    assert len(parsed) == len(checked) == 1 and parsed[0][0] is supplied.capture and parsed[0][1] is output.value
    assert output.receipt.capture is supplied.capture and output.receipt.parse is output.value.parse
    def forbidden(*args, **kwargs):
        pytest.fail("canonical candidate closure replayed the parser or dispatcher")
    monkeypatch.setattr(owner.parser, "parse_capture", forbidden)
    monkeypatch.setattr(owner, "execute_parsers", forbidden)
    rows = execution.owner.canonical_rows(execution.executed)
    assert len(checked) == 2 and all(sample is supplied.capture and value is output.value for sample, value, _ in checked)
    assert len(rows) == 4 and {(row.target.node.key, row.interface, row.group) for row in rows} == {
        (target.node.key, interface, group) for target in (first, cold) for interface, group in target.groups}
    for row in rows:
        assert row.subject == build.subject(row.target, row.interface, row.group)
        if row.target is first and row.interface == "Vlan10":
            assert type(row.value) is k.Known and type(row.value.value) is str
            assert (row.value.value, row.value.raw, row.value.basis) == (literal, literal, k.Basis.OBSERVED)
            rich, points = checked[-1][2][0]
            assert rich is output.value.rows[0]
            refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            assert tuple(ref.locator for ref in refs) == points and all(ref.role is k.EvidenceRole.SUBJECT for ref in refs)
            assert all(ref.capture == supplied.capture.id and ref.excerpt_sha256 == sha256(
                supplied.capture.raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
        else:
            assert type(row.value) is k.Unknown and row.value.reason is (
                k.UnknownReason.NOT_COLLECTED if row.target is cold else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
    with pytest.raises(AttributeError):
        execution.owner = execution.owner


def test_named_local_constructor_parse_own_and_canonical_rows_share_actual_execution(monkeypatch):
    target, supplied = fixture()
    actual = owner.VersionOwner.for_local((target,), (supplied,))
    assert type(actual) is owner.LocalVersionOwner
    with pytest.raises(ValueError):
        actual.parse(replace(supplied, capture=replace(supplied.capture)))
    outputs = pack_runtime.execute_parsers((profile.DECLARATION,), (pack_runtime.Handler(binding=profile.BINDING, parser=actual),), (supplied,))
    bound = actual.own(outputs[0])
    assert bound.value is outputs[0].value and bound.receipt is outputs[0].receipt
    forbid_writes(monkeypatch)
    rows = actual.canonical_rows((bound,))
    assert len(rows) == len(target.groups) and rows[0].value.value == "2"


@pytest.mark.parametrize("raw,integrity,reason", [
    (None, k.IntegrityState.COMPLETE, k.UnknownReason.NOT_COLLECTED),
    (block(None), k.IntegrityState.COMPLETE, k.UnknownReason.NOT_OBSERVABLE),
    (BODY.replace(b"192.0.2.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + BODY, k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + b"unsupported\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY, k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY, k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
])
def test_missing_and_adverse_inputs_preserve_original_declared_cells_and_needs(raw, integrity, reason):
    target, supplied = fixture()
    if raw is not None:
        supplied = replace(supplied, capture=replace(capture(raw, integrity), source=target.node.key, id=supplied.capture.id))
    execution = owner.execute_local_version_inputs((target,), () if raw is None else (supplied,))
    rows = execution.owner.canonical_rows(execution.executed)
    assert {(row.interface, row.group) for row in rows} == set(target.groups)
    observed = next(row for row in rows if row.interface == "Vlan10")
    assert type(observed.value) is k.Unknown and observed.value.reason is reason
    for row in rows:
        need, = row.value.next_evidence
        assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (
            target.node.key, "iosxe.show_standby_all", (("group", row.group), ("interface", row.interface)), (FACT,), (STEP,))


@pytest.mark.parametrize("plant", ["capture_copy", "parse_copy", "value_copy", "owner", "context", "registration"])
def test_own_refuses_counterfeit_receipt_and_cache_carriers(monkeypatch, plant):
    target, supplied = fixture()
    execution = owner.execute_local_version_inputs((target,), (supplied,))
    output, = execution.executed
    if plant == "capture_copy":
        output = replace(output, receipt=replace(output.receipt, capture=replace(output.receipt.capture)))
    elif plant == "parse_copy":
        output = replace(output, receipt=replace(output.receipt, parse=replace(output.receipt.parse)))
    elif plant == "value_copy":
        output = replace(output, value=replace(output.value))
    else:
        name = "registration_sha256" if plant == "registration" else plant
        value = "0" * 64 if plant == "registration" else "l3.fhrp/other" if plant == "owner" else "other"
        output = replace(output, receipt=replace(output.receipt, **{name: value}))
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        execution.owner.own(output)


@pytest.mark.parametrize("plant", ["missing_output", "extra_output", "drop_cache", "drop_snapshot", "pop_cold", "expected_copy"])
def test_complete_execution_and_derived_population_census_close_before_candidate_rows(monkeypatch, plant):
    first, supplied = fixture()
    cold, _ = fixture(B, "b")
    execution = owner.execute_local_version_inputs((first, cold), (supplied,))
    outputs, state = execution.executed, execution.owner.inputs
    if plant == "missing_output":
        outputs = ()
    elif plant == "extra_output":
        outputs = outputs + outputs
    elif plant == "drop_cache":
        state.produced.pop(supplied.capture.id)
    elif plant == "drop_snapshot":
        state.produced_values.pop(supplied.capture.id)
    elif plant == "pop_cold":
        state.source.indexed.pop((cold.context, cold.node.key))
    else:
        state.source.expected[supplied.capture.id] = replace(supplied)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        execution.owner.canonical_rows(outputs)


@pytest.mark.parametrize("empty,corrupt_both", [(False, False), (True, False), (False, True)])
def test_first_profile_identity_is_bound_to_post_profile_and_real_receipts_even_when_empty(monkeypatch, empty, corrupt_both):
    compile_profile, calls = profile.compile_version_profile, []
    def compiling():
        result = compile_profile()
        calls.append(result)
        return replace(result, registration_sha256="0" * 64) if corrupt_both or len(calls) == 1 else result
    monkeypatch.setattr(profile, "compile_version_profile", compiling)
    forbid_writes(monkeypatch)
    target, supplied = fixture()
    with pytest.raises(ValueError):
        execution = owner.execute_local_version_inputs(() if empty else (target,), () if empty else (supplied,))
        execution.owner.canonical_rows(execution.executed)


@pytest.mark.parametrize("stage", ["parse", "post"])
def test_current_raw_graph_is_verified_before_snapshot_traversal(monkeypatch, stage):
    target, supplied = fixture()
    parse, snapshot = owner.parser.parse_capture, owner.asdict
    poisoned = []
    def parsing(sample):
        result = parse(sample)
        if stage == "parse":
            object.__setattr__(result, "rows", list(result.rows))
            poisoned.append(result)
        return result
    def snapshotting(value):
        if poisoned and value is poisoned[0]:
            pytest.fail("traversed a raw result graph before verification")
        return snapshot(value)
    monkeypatch.setattr(owner.parser, "parse_capture", parsing)
    monkeypatch.setattr(owner, "asdict", snapshotting)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        execution = owner.execute_local_version_inputs((target,), (supplied,))
        poisoned.append(execution.executed[0].value)
        object.__setattr__(execution.executed[0].value, "rows", list(execution.executed[0].value.rows))
        execution.owner.canonical_rows(execution.executed)


@pytest.mark.parametrize("stage", ["initial_ports", "late_ports", "late_span"])
def test_actual_owner_checks_current_input_graph_before_detached_retention(monkeypatch, stage):
    target, supplied = fixture()
    if stage == "initial_ports":
        object.__setattr__(target.node, "ports", list(target.node.ports))
        forbid_bad_snapshots(monkeypatch, target, supplied, True)
    forbid_writes(monkeypatch)
    if stage == "initial_ports":
        with pytest.raises(ValueError):
            owner.VersionOwner.for_local((target,), (supplied,))
        return
    execution = owner.execute_local_version_inputs((target,), (supplied,))
    if stage == "late_ports":
        object.__setattr__(target.node, "ports", list(target.node.ports))
    else:
        object.__setattr__(supplied.capture.lines[0].span, "start", [])
    forbid_bad_snapshots(monkeypatch, target, supplied, stage == "late_ports")
    with pytest.raises(ValueError):
        execution.owner.canonical_rows(execution.executed)


def test_later_actual_parse_failure_never_writes_or_returns_qualified_candidates(monkeypatch):
    first, left = fixture()
    second, right = fixture(B, "b")
    verify, seen = owner.parser.validate_claims, []
    def verifying(sample, value):
        seen.append(sample.id)
        if sample.id == right.capture.id:
            raise ValueError("synthetic_later_claim")
        return verify(sample, value)
    monkeypatch.setattr(owner.parser, "validate_claims", verifying)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError, match="synthetic_later_claim"):
        owner.execute_local_version_inputs((first, second), (left, right))
    assert seen == [left.capture.id, right.capture.id]
