"""Current full-peer/FHRP closure controls; no Writer, readiness or source authority."""
from dataclasses import replace

import pytest
from test_peer_execution import forbidden, no_writers
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import peer_canonical as canonical
from atlas_brain.packs.l3.fhrp import peer_execution as runtime
from atlas_brain.runner import p4_pipeline as pipeline


def actual(root, mode="normal"):
    folder(root, mode=mode)
    result = runtime.execute_peer_state_version_inputs(root, LIMITS)
    closing(result)
    return result


def closing(result, **changes):
    arguments = {"execution": result.execution, "state": result.fhrp.state,
        "owner": result.fhrp.owner, "budgets": LIMITS}
    arguments.update(changes)
    return canonical.canonical_peer_state_version_outputs(**arguments)


def test_real_current_closure_keeps_original_cache_and_receipts_without_replay_or_writers(tmp_path, monkeypatch):
    no_writers(monkeypatch)
    parsed, dispatched = [], []
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, preparation.all_hsrp):
        original = module.parse_capture
        def parsing(capture, *args, original=original):
            value = original(capture, *args)
            parsed.append((capture, value))
            return value
        monkeypatch.setattr(module, "parse_capture", parsing)
    execute = pipeline.execute_parsers
    def executing(*args):
        outputs = execute(*args)
        dispatched.append(outputs)
        return outputs
    monkeypatch.setattr(pipeline, "execute_parsers", executing)
    result = actual(tmp_path)
    assert len(parsed) == 4 and len(dispatched) == 1
    assert result.execution.executed is dispatched[0]
    monkeypatch.setattr(pipeline, "execute_parsers", forbidden)
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, preparation.all_hsrp):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    first, second = closing(result), closing(result, execution=replace(result.execution))
    assert len(first[0]) == len(first[1]) == 1
    for pair in (first, second):
        assert tuple(output.receipt.capture.operation for output in pair[0]) == (fhrp.hsrp.OP,)
        assert tuple(output.receipt.capture.operation for output in pair[1]) == (preparation.all_hsrp.OP,)
        for output in pair[0] + pair[1]:
            original = next(out for out in dispatched[0] if out.receipt.capture.id == output.receipt.capture.id)
            assert output.receipt is original.receipt and output.value is original.value
            assert output.receipt.registration_sha256 == result.execution.envelope.registration_sha256
            assert any(output.receipt.capture is capture and output.value is value for capture, value in parsed)
    assert not result.fhrp.state.finished
    assert not result.fhrp.owner.production_attempted and result.fhrp.owner.production is None


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "no_captures", "unselected_b"])
def test_current_closure_preserves_original_brief_population_and_missing_all_cells(tmp_path, monkeypatch, mode):
    no_writers(monkeypatch)
    result = actual(tmp_path, mode)
    states, versions = closing(result)
    assert len(states) == (0 if mode in ("no_brief_capture", "no_captures") else 1)
    assert len(versions) == (0 if mode.startswith("no_all") or mode == "no_captures" else 1)
    rows = result.fhrp.owner.canonical_rows(versions)
    assert len(rows) == (4 if mode == "unselected_b" else 5)
    for row in rows:
        if mode.startswith("no_all") or mode == "no_captures" or row.target.node.id == "b":
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
            need, = row.value.next_evidence
            assert need.node == row.target.node.key and need.operation == preparation.all_hsrp.OP
    if mode in ("no_brief_capture", "unselected_b"):
        assert sum(type(row.value) is k.Known for row in rows) == 3


@pytest.mark.parametrize("plant", ["missing", "duplicate", "owner", "context", "registration",
    "foreign_raw_copy", "foreign_parse_copy", "foreign_value_type"])
def test_complete_original_ledger_refuses_foreign_and_global_substitution(tmp_path, monkeypatch, plant):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    outputs = result.execution.executed
    target = next(out for out in outputs if out.receipt.capture.operation == stp.stp.OP)
    if plant == "missing":
        changed = tuple(out for out in outputs if out is not target)
    elif plant == "duplicate":
        changed = (*outputs, target)
    elif plant == "foreign_raw_copy":
        object.__setattr__(target.receipt.capture, "raw", bytes(bytearray(target.receipt.capture.raw)))
        changed = outputs
    elif plant == "foreign_parse_copy":
        altered = replace(target, receipt=replace(target.receipt, parse=replace(target.receipt.parse)))
        changed = tuple(altered if out is target else out for out in outputs)
    elif plant == "foreign_value_type":
        changed = tuple(replace(out, value=[]) if out is target else out for out in outputs)
    else:
        field, value = {"owner": ("owner", "l3.fhrp/wrong_owner"), "context": ("context", "wrong"),
            "registration": ("registration_sha256", "0" * 64)}[plant]
        altered = replace(target, receipt=replace(target.receipt, **{field: value}))
        changed = tuple(altered if out is target else out for out in outputs)
    with pytest.raises(ValueError):
        closing(result, execution=replace(result.execution, executed=changed))


@pytest.mark.parametrize("operation", [stp.stp.OP, ec.parse_summary.OP, fhrp.hsrp.OP, preparation.all_hsrp.OP])
@pytest.mark.parametrize("field", ["id", "source", "raw", "lines"])
def test_every_actual_capture_graph_refuses_before_identifier_sets(tmp_path, monkeypatch, operation, field):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    output = next(out for out in result.execution.executed if out.receipt.capture.operation == operation)
    object.__setattr__(output.receipt.capture, field, [])
    with pytest.raises(ValueError):
        closing(result)


@pytest.mark.parametrize("field", ["owner", "context", "registration_sha256"])
def test_foreign_receipt_scalar_graph_refuses_before_capture_reconstruction(tmp_path, monkeypatch, field):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    output = next(out for out in result.execution.executed if out.receipt.capture.operation == ec.parse_summary.OP)
    object.__setattr__(output.receipt, field, [])
    with pytest.raises(ValueError):
        closing(result)


@pytest.mark.parametrize("operation", [fhrp.hsrp.OP, preparation.all_hsrp.OP])
@pytest.mark.parametrize("plant", ["capture", "value", "raw_claim"])
def test_both_fhrp_owners_close_actual_capture_value_and_raw_claims(tmp_path, monkeypatch, operation, plant):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    outputs = result.execution.executed
    target = next(out for out in outputs if out.receipt.capture.operation == operation)
    if plant == "raw_claim":
        object.__setattr__(target.value.rows[0].interface, "raw", "tampered")
        changed = outputs
    else:
        altered = (replace(target, receipt=replace(target.receipt, capture=replace(target.receipt.capture)))
            if plant == "capture" else replace(target, value=replace(target.value)))
        changed = tuple(altered if out is target else out for out in outputs)
    with pytest.raises(ValueError):
        closing(result, execution=replace(result.execution, executed=changed))


@pytest.mark.parametrize("plant", ["cold_index", "cold_proofs", "proof_value", "registration",
    "requests", "expected", "target_context", "target_groups", "target_node"])
def test_state_population_and_declaration_proofs_reclose_against_before_batch_version_census(tmp_path, monkeypatch, plant):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    state, plan = result.fhrp.state, result.fhrp.state.plan
    cold = next(key for key, target in plan.indexed.items() if target.node.id == "b")
    if plant == "cold_index":
        plan.indexed.pop(cold)
    elif plant == "cold_proofs":
        plan.proofs.pop(cold)
    elif plant == "proof_value":
        refs = plan.proofs[cold]
        plan.proofs[cold] = (replace(refs[0], citation="/wrong"), *refs[1:])
    elif plant == "registration":
        state.registration = "0" * 64
    elif plant == "requests":
        object.__setattr__(plan, "requests", (*plan.requests, *plan.requests))
    elif plant == "expected":
        plan.expected.clear()
    elif plant == "target_context":
        plan.indexed[cold] = replace(plan.indexed[cold], context="wrong")
    elif plant == "target_groups":
        target = plan.indexed[cold]
        plan.indexed[cold] = replace(target, groups=((target.groups[0][0], "4095"),))
    else:
        plan.indexed[cold] = replace(plan.indexed[cold], node=replace(plan.indexed[cold].node))
    with pytest.raises(ValueError):
        closing(result)


def test_normalized_state_target_values_are_compared_without_pointer_origin_authority(tmp_path, monkeypatch):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    indexed, source = result.fhrp.state.plan.indexed, result.fhrp.owner.inputs.source
    assert all(target == source.indexed[key] and target is not source.indexed[key]
               for key, target in indexed.items())
    before = dict(indexed)
    for key, target in before.items():
        indexed[key] = replace(target)
    states, versions = closing(result)
    assert len(states) == len(versions) == 1
    assert all(indexed[key] == target and indexed[key] is not target
               and indexed[key].node is source.indexed[key].node for key, target in before.items())


@pytest.mark.parametrize("plant", ["cold_index", "targets", "expected", "request_copy", "invocation"])
def test_version_retention_remains_original_instead_of_trusting_returned_preparation_data(tmp_path, monkeypatch, plant):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    owner = result.fhrp.owner
    source = owner.inputs.source
    if plant == "cold_index":
        source.indexed.pop(next(key for key, target in source.indexed.items() if target.node.id == "b"))
    elif plant == "targets":
        object.__setattr__(source, "targets", tuple(target for target in source.targets if target.node.id != "b"))
    elif plant == "expected":
        source.expected.clear()
    elif plant == "request_copy":
        object.__setattr__(source, "requests", tuple(replace(request) for request in source.requests))
    else:
        owner.inputs = None
    with pytest.raises(ValueError):
        closing(result)


@pytest.mark.parametrize("field", ["envelope", "budgets"])
def test_version_owner_context_must_match_the_current_original_execution(tmp_path, monkeypatch, field):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    owner = result.fhrp.owner
    object.__setattr__(owner, field, replace(getattr(owner, field)))
    with pytest.raises(ValueError):
        closing(result)


@pytest.mark.parametrize("field", ["execution", "state", "owner", "budgets"])
def test_typed_public_boundary_refuses_missing_carriers_without_writing(tmp_path, monkeypatch, field):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    with pytest.raises(ValueError):
        closing(result, **{field: None})


def test_current_canonical_data_does_not_assert_producer_readiness(tmp_path, monkeypatch):
    no_writers(monkeypatch)
    result = actual(tmp_path)
    state_before, version_before = closing(result)
    result.fhrp.state.finished = True
    result.fhrp.owner.production_attempted = True
    states, versions = closing(result)
    assert all(a.receipt is b.receipt and a.value is b.value
        for a, b in zip(state_before + version_before, states + versions, strict=True))
    assert result.fhrp.owner.production is None


@pytest.mark.parametrize("part", ["interface", "group"])
def test_complete_real_brief_candidates_must_belong_to_original_declared_groups(tmp_path, monkeypatch, part):
    no_writers(monkeypatch)
    actual(tmp_path / "valid")
    before, after = {"interface": (b"Vl20", b"Vl21"), "group": (b"Vl20        0", b"Vl20        9")}[part]
    def changed(_side, files):
        assert files["brief.txt"].count(before) == 1
        files["brief.txt"] = files["brief.txt"].replace(before, after, 1)
    root = tmp_path / "changed"
    folder(root, change=changed)
    result = runtime.execute_peer_state_version_inputs(root, LIMITS)
    output = next(out for out in result.execution.executed if out.receipt.capture.operation == fhrp.hsrp.OP)
    assert output.value.reason is None and output.value.parse.quality == "complete"
    target = result.fhrp.owner.inputs.source.indexed[output.receipt.context, output.receipt.capture.source]
    assert any((row.interface.raw, row.group.raw) not in target.groups for row in output.value.rows)
    with pytest.raises(ValueError, match="hsrp_undeclared_subject"):
        closing(result)


def test_partial_real_brief_candidates_remain_unresolved_comparison_data(tmp_path, monkeypatch):
    no_writers(monkeypatch)
    actual(tmp_path / "valid")
    def changed(_side, files):
        assert files["brief.txt"].count(b"Vl20") == 1
        files["brief.txt"] = files["brief.txt"].replace(b"Vl20", b"Vl21", 1) + b"unrecognised output\n"
    root = tmp_path / "changed"
    folder(root, change=changed)
    result = runtime.execute_peer_state_version_inputs(root, LIMITS)
    states, versions = closing(result)
    assert len(states) == len(versions) == 1
    value = states[0].value
    assert value.reason is k.UnknownReason.PARSE_PARTIAL and value.parse.quality == "partial"
    assert all(row.reason is k.UnknownReason.PARSE_PARTIAL for row in value.rows)
    target = result.fhrp.owner.inputs.source.indexed[states[0].receipt.context, states[0].receipt.capture.source]
    assert any((row.interface.raw, row.group.raw) not in target.groups for row in value.rows)
