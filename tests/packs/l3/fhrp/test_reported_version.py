"""Synthetic registered VERSION custody; no raw admission, global source or health claim."""
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_hsrp_all import BODY, block, capture
from test_reported_state_build import B, target

from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactWriter, bind_reader
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import reported_version as version
from atlas_brain.packs.l3.fhrp import version_owner as owning
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner.pack_receipts import CaptureRequest

FACT = "l3.fhrp.reported_protocol_version"
OWNER = "l3.fhrp/parse_hsrp_all_version"
GROUPS = (("Vlan10", "0"), ("Vl10", "0"), ("Vlan99", "2"))


class Text(StrEnum):
    VERSION = "2"


def item(**changes):
    declared = target(groups=GROUPS, **changes)
    return replace(declared, node=replace(declared.node))


def request(subject, raw=BODY, identity="a", integrity=k.IntegrityState.COMPLETE):
    sample = replace(capture(raw, integrity), source=subject.node.key, id=k.CaptureId("cap:" + identity))
    return CaptureRequest(context=subject.context, capture=sample)


def forbid_writes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("wrote before the complete custody batch was validated")
    monkeypatch.setattr(FactWriter, "write", forbidden)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_fixed_registered_version_only_profile_owns_original_cached_proofs_and_declared_readers(monkeypatch, ending):
    first, cold = item(), item(node=B)
    supplied = request(first, (BODY + block("1", "Vl10")).replace(b"\n", ending))
    parse, verify = owning.parser.parse_capture, owning.parser.validate_claims
    parsed, checked = [], []
    def parsing(sample):
        value = parse(sample)
        parsed.append((sample, value))
        return value
    def verifying(sample, value):
        result = verify(sample, value)
        checked.append((sample, value, result))
        return result
    monkeypatch.setattr(owning.parser, "parse_capture", parsing)
    monkeypatch.setattr(owning.parser, "validate_claims", verifying)
    result = version.build_reported_version((cold, first), (supplied,))
    output, = result.executed
    assert len(parsed) == 1 and parsed[0] == (supplied.capture, output.value)
    assert len(checked) == 2 and all(sample is supplied.capture and value is output.value for sample, value, _ in checked)
    assert output.receipt.capture is supplied.capture and output.receipt.parse is output.value.parse
    assert output.receipt.owner == OWNER and output.receipt.context == first.context
    assert result.registration_sha256 == output.receipt.registration_sha256 == registration.compile_packs((profile.DECLARATION,)).registration_sha256
    assert profile.STEP.reads == () and profile.STEP.produces == (FACT,) and profile.BINDING.operation == "iosxe.show_standby_all"
    spec, = profile.DECLARATION.facts
    assert (spec.id, spec.subject, spec.value_type, spec.step) == (FACT, "fhrp_local", "text", OWNER)
    assert result.store.owners == {FACT: OWNER} and len(result.store.values) == len(result.rows) == 6
    for row in result.rows:
        assert row.subject == build.subject(row.target, row.interface, row.group)
        assert result.store.values[k.FactRef(fact=FACT, subject=row.subject)] is row.value
        if row.target is first and row.interface in ("Vlan10", "Vl10"):
            literal = "2" if row.interface == "Vlan10" else "1"
            assert type(row.value) is k.Known and type(row.value.value) is str
            assert (row.value.value, row.value.raw, row.value.basis) == (literal, literal, k.Basis.OBSERVED)
            rich, points = next((rich, points) for rich, points in checked[-1][2] if rich.interface.raw == row.interface)
            assert any(rich is original for original in output.value.rows)
            refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            assert tuple(ref.locator for ref in refs) == points
            assert row.value.evidence[:1] == first.node.declaration.evidence
            assert all(ref.capture == supplied.capture.id and ref.role is k.EvidenceRole.SUBJECT
                and ref.excerpt_sha256 == sha256(supplied.capture.raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
        else:
            assert type(row.value) is k.Unknown
            assert row.value.reason is (k.UnknownReason.NOT_COLLECTED if row.target is cold else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
    consumer = StepSpec(id=StepId("l3.fhrp/test_version"), pack=build.PACK, kind="check", scope="device",
                        reads=(FACT,), produces=(), evaluator="l3.fhrp.test_version")
    assert all(bind_reader(result.store, step=consumer).read(fact=FACT, subject=row.subject) is row.value for row in result.rows)
    with pytest.raises(ValueError, match="undeclared_read"):
        bind_reader(result.store, step=build.SOURCE_STEP).read(fact=FACT, subject=result.rows[0].subject)


@pytest.mark.parametrize("raw,integrity,reason", [
    (None, k.IntegrityState.COMPLETE, k.UnknownReason.NOT_COLLECTED),
    (block(None), k.IntegrityState.COMPLETE, k.UnknownReason.NOT_OBSERVABLE),
    (BODY.replace(b"192.0.2.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + BODY, k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + b"unsupported\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (BODY, k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY, k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
])
def test_unknown_census_and_exact_next_evidence_survive_missing_and_adverse_inputs(raw, integrity, reason):
    subject = item()
    supplied = () if raw is None else (request(subject, raw, integrity=integrity),)
    result = version.build_reported_version((subject,), supplied)
    assert {(row.interface, row.group) for row in result.rows} == set(GROUPS)
    row = next(row for row in result.rows if row.interface == "Vlan10")
    assert type(row.value) is k.Unknown and row.value.reason is reason
    for row in result.rows:
        need, = row.value.next_evidence
        assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (
            subject.node.key, "iosxe.show_standby_all", (("group", row.group), ("interface", row.interface)), (FACT,), (OWNER,))
        assert need.unprintable == ("explicit_reported_protocol_version",)
        if supplied:
            witness, = (ref for ref in row.value.evidence if type(ref) is k.EvidenceRef and type(ref.locator) is k.WholeCapture)
            assert witness.role is k.EvidenceRole.WITNESS and witness.excerpt_sha256 == supplied[0].capture.bytes_sha256


def test_capture_loss_and_permutation_keep_independent_declared_subjects():
    first, second = item(), item(node=B, context="other")
    requests = (request(first), request(second, identity="b"))
    before = version.build_reported_version((second, first), tuple(reversed(requests)))
    after = version.build_reported_version((first, second), ())
    assert [row.subject for row in before.rows] == [row.subject for row in after.rows]
    assert all(type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED for row in after.rows)


@pytest.mark.parametrize("plant", ["capture_copy", "parse_copy", "value_copy", "owner", "context", "registration",
                                   "extra_output", "missing_output", "late_value", "late_rows"])
def test_receipt_cache_and_late_value_counterfeits_refuse_before_any_writer(monkeypatch, plant):
    subject, execute = item(), owning.execute_parsers
    def executing(*args):
        outputs = execute(*args)
        output, = outputs
        receipt = output.receipt
        if plant == "capture_copy":
            output = replace(output, receipt=replace(receipt, capture=replace(receipt.capture)))
        elif plant == "parse_copy":
            output = replace(output, receipt=replace(receipt, parse=replace(receipt.parse)))
        elif plant == "value_copy":
            output = replace(output, value=replace(output.value))
        elif plant in ("owner", "context", "registration"):
            field = "registration_sha256" if plant == "registration" else plant
            value = "0" * 64 if plant == "registration" else "l3.fhrp/other" if plant == "owner" else "other"
            output = replace(output, receipt=replace(receipt, **{field: value}))
        elif plant == "extra_output":
            return outputs + outputs
        elif plant == "missing_output":
            return ()
        elif plant == "late_value":
            object.__setattr__(output.value.rows[0].version, "value", Text.VERSION)
        else:
            object.__setattr__(output.value, "rows", list(output.value.rows))
        return (output,)
    monkeypatch.setattr(owning, "execute_parsers", executing)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        version.build_reported_version((subject,), (request(subject),))


@pytest.mark.parametrize("plant", ["request_context", "capture_bytes", "target_groups", "target_node", "node_declaration"])
def test_original_inputs_and_targets_cannot_change_during_parser_execution(monkeypatch, plant):
    subject, parse = item(), owning.parser.parse_capture
    supplied = request(subject)
    def parsing(sample):
        value = parse(sample)
        if plant == "request_context":
            object.__setattr__(supplied, "context", "other")
        elif plant == "capture_bytes":
            object.__setattr__(supplied.capture, "raw", supplied.capture.raw + b"\n")
        elif plant == "target_groups":
            object.__setattr__(subject, "groups", (("Vlan10", "0"),))
        elif plant == "target_node":
            object.__setattr__(subject, "node", replace(subject.node))
        else:
            object.__setattr__(subject.node, "declaration", replace(subject.node.declaration))
        return value
    monkeypatch.setattr(owning.parser, "parse_capture", parsing)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        version.build_reported_version((subject,), (supplied,))


@pytest.mark.parametrize("empty,corrupt_both", [(False, False), (True, False), (False, True)],
                         ids=("first_nonempty", "first_empty", "both_nonempty"))
def test_first_compiled_identity_must_equal_postbatch_and_receipt_identity_even_when_empty(monkeypatch, empty, corrupt_both):
    compile_profile, calls = profile.compile_version_profile, []
    def compiling():
        result = compile_profile()
        calls.append(result)
        return replace(result, registration_sha256="0" * 64) if corrupt_both or len(calls) == 1 else result
    monkeypatch.setattr(profile, "compile_version_profile", compiling)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        subject = item()
        inputs = ((), ()) if empty else ((subject,), (request(subject),))
        version.build_reported_version(*inputs)


def test_later_invalid_raw_claim_is_checked_before_any_writer(monkeypatch):
    first, second = item(), item(node=B)
    verify, calls = owning.parser.validate_claims, []
    def verifying(sample, result):
        calls.append(sample.id)
        if sample.id == "cap:b":
            raise ValueError("synthetic_later_claim")
        return verify(sample, result)
    monkeypatch.setattr(owning.parser, "validate_claims", verifying)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError, match="synthetic_later_claim"):
        version.build_reported_version((first, second), (request(first), request(second, identity="b")))
    assert "cap:a" in calls and "cap:b" in calls


@pytest.mark.parametrize("stage", ["parse", "dispatch"])
def test_closed_graph_validation_precedes_each_snapshot_serialization(monkeypatch, stage):
    subject, execute, parse, snapshot = item(), owning.execute_parsers, owning.parser.parse_capture, owning.asdict
    poisoned = []
    def executing(*args):
        outputs = execute(*args)
        poisoned.append(outputs[0].value)
        object.__setattr__(outputs[0].value, "rows", list(outputs[0].value.rows))
        return outputs
    def parsing(sample):
        result = parse(sample)
        poisoned.append(result)
        object.__setattr__(result, "rows", list(result.rows))
        return result
    def snapshotting(value):
        if poisoned and value is poisoned[0]:
            pytest.fail("serialized a late unvalidated result graph")
        return snapshot(value)
    if stage == "dispatch":
        monkeypatch.setattr(owning, "execute_parsers", executing)
    else:
        monkeypatch.setattr(owning.parser, "parse_capture", parsing)
    monkeypatch.setattr(owning, "asdict", snapshotting)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        version.build_reported_version((subject,), (request(subject),))


@pytest.mark.parametrize("change", ["operation", "rendered", "codec", "context", "scope", "extra_observed",
                                    "duplicate_target", "duplicate_request", "targets_list", "requests_list"])
def test_input_operation_scope_and_closed_declared_population_refuse_before_writer(monkeypatch, change):
    subject = item()
    supplied = request(subject, BODY + block(interface="Vlan20") if change == "extra_observed" else BODY)
    if change in ("operation", "rendered", "codec"):
        value = {"operation": "iosxe.other", "rendered": "show standby", "codec": "latin-1"}[change]
        supplied = replace(supplied, capture=replace(supplied.capture, **{change: value}))
    elif change == "context":
        supplied = replace(supplied, context="other")
    elif change == "scope":
        metadata = supplied.capture.resolved_metadata
        supplied = replace(supplied, capture=replace(supplied.capture,
            metadata=replace(metadata, scope=replace(metadata.scope, vrf="fixture"))))
    targets = (subject, subject) if change == "duplicate_target" else (subject,)
    requests = (supplied, supplied) if change == "duplicate_request" else (supplied,)
    if change == "targets_list":
        targets = list(targets)
    if change == "requests_list":
        requests = list(requests)
    forbid_writes(monkeypatch)
    with pytest.raises(ValueError):
        version.build_reported_version(targets, requests)




@pytest.mark.parametrize("empty", [False, True])
def test_facade_uses_one_execution_then_one_shot_completion_with_real_owned_outputs(monkeypatch, empty):
    execute, executions = version.execute_local_version_inputs, []
    def executing(targets, requests):
        actual = execute(targets, requests)
        executions.append(actual)
        return actual
    monkeypatch.setattr(version, "execute_local_version_inputs", executing)
    subject = item()
    result = version.build_reported_version((), ()) if empty else version.build_reported_version((subject,), (request(subject),))
    assert len(executions) == 1
    execution, = executions
    actual = execution.owner
    assert actual.production_attempted is True and actual.production is result
    assert type(result) is owning.VersionResult and result.store.owners == {FACT: OWNER}
    assert len(result.rows) == len(result.store.values) == (0 if empty else len(GROUPS))
    assert all(out is actual.inputs.owned[out.receipt.capture.id] for out in result.executed)
    assert all(out.receipt is execution.executed[index].receipt and out.value is execution.executed[index].value
               for index, out in enumerate(result.executed))
    def forbidden(*args, **kwargs):
        pytest.fail("completion replayed parser or dispatcher")
    monkeypatch.setattr(owning.parser, "parse_capture", forbidden)
    monkeypatch.setattr(owning, "execute_parsers", forbidden)
    assert actual.canonical_rows(execution.executed) == result.rows
    with pytest.raises(ValueError, match="production_once"):
        actual.finish(execution.executed)


