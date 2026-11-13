"""Actual producing-boundary controls; no lower execution data supplies admission."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_all import block
from test_state_owner import LIMITS
from test_state_version_input_preparation import DETAIL, folder

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import state_version_execution as runtime
from atlas_brain.packs.l3.fhrp import state_version_production as production
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as profile

VERSION = profile.REPORTED_PROTOCOL_VERSION


def component(root, budgets):
    source = runtime.execute_state_version_inputs(root, budgets)
    return production.StateVersionProduction(source).finish()


def no_writers(monkeypatch):
    for module in (b, vo):
        monkeypatch.setattr(module, "bind_writer", lambda *args, **kwargs: pytest.fail("Writer before complete closure"))


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_declared_population_exact_values_and_original_same_block_byte_proofs(tmp_path, ending):
    files = folder(tmp_path, DETAIL.replace(b"\n", ending))
    result = component(tmp_path, LIMITS)
    assert len(result.state.rows) == len(result.version.rows) == 5
    expected = {("Vl20", "0"): "2", ("Vl10", "1"): "1", ("BD3329", "129"): "2"}
    output, = result.version.executed
    raw = output.receipt.capture.raw
    for row in result.version.rows:
        original = next(item for item in result.state.rows if item.subject == row.subject)
        assert result.state.store.values[k.FactRef(fact=b.REPORTED_STATE, subject=original.subject)] is original.value
        assert row.target.node is original.target.node
        assert (row.target.context, row.target.groups) == (original.target.context, original.target.groups)
        assert row.subject == b.subject(row.target, row.interface, row.group)
        assert result.version.store.values[k.FactRef(fact=VERSION, subject=row.subject)] is row.value
        refs = tuple(ref for ref in row.value.evidence if type(ref) is k.RegistryRef)
        targets = tuple(item for item in result.envelope.targets if item.node is row.target.node)
        assert refs == row.target.node.declaration.evidence + result.envelope.declaration.evidence + tuple(
            ref for target in sorted(targets, key=lambda item: item.operation == gp.all_hsrp.OP)
            for ref in target.declaration.evidence)
        assert all(ref.table_digest == sha256(files["p2.json"] if ref.table == "synthetic_p2.nodes" else files["p4.json"]).hexdigest() for ref in refs)
        printed = expected.get((row.interface, row.group)) if row.target.node.id == "a" else None
        if printed is None:
            assert type(row.value) is k.Unknown
            assert row.value.reason is (k.UnknownReason.NOT_COLLECTED if row.target.node.id == "b" else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
            need, = row.value.next_evidence
            assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.unprintable) == (
                row.target.node.key, gp.all_hsrp.OP, (("group", row.group), ("interface", row.interface)),
                (VERSION,), (profile.STEP.id,), ("explicit_reported_protocol_version",))
            continue
        assert type(row.value) is k.Known and type(row.value.value) is str
        assert (row.value.value, row.value.raw, row.value.basis) == (printed, printed, k.Basis.OBSERVED)
        rich, points = next((rich, points) for rich, points in gp.all_hsrp.validate_claims(output.receipt.capture, output.value)
            if rich.interface.raw == row.interface and rich.group.raw == row.group)
        assert any(rich is original for original in output.value.rows) and rich.address_family == "ipv4"
        witnesses = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        assert tuple(ref.locator for ref in witnesses) == points
        assert all(ref.capture == output.receipt.capture.id and ref.role is k.EvidenceRole.SUBJECT
            and ref.excerpt_sha256 == sha256(raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in witnesses)


@pytest.mark.parametrize("raw,reason", [
    (block(None, "Vl20"), k.UnknownReason.NOT_OBSERVABLE),
    (block(interface="Vl20").replace(b"192.0.2.1", b"unknown"), k.UnknownReason.IDENTITY_UNRESOLVED),
    (block(interface="Vl20").replace(b"Virtual IP address is 192.0.2.1", b"Virtual IPv6 address is 2001:db8::1"), k.UnknownReason.PARSE_PARTIAL),
    (DETAIL + b"unrecognised\n", k.UnknownReason.PARSE_PARTIAL),
    (DETAIL + block(interface="Vl20"), k.UnknownReason.CONFLICTING_EVIDENCE),
    (DETAIL + block("1", "Vl20"), k.UnknownReason.CONFLICTING_EVIDENCE),
    (DETAIL.replace(b"(version 2)", b"(version 3)", 1), k.UnknownReason.PARSE_PARTIAL),
    (DETAIL + b"[truncated]\n", k.UnknownReason.CAPTURE_TRUNCATED),
    (DETAIL + b"--More--\n", k.UnknownReason.CAPTURE_TRUNCATED),
    (DETAIL + b"% Invalid input detected\n", k.UnknownReason.CAPTURE_ERROR),
    (b"", k.UnknownReason.EMPTY_UNREGISTERED),
])
def test_body_unknowns_preserve_entire_declared_population_without_brief_inference(tmp_path, raw, reason):
    folder(tmp_path, detail=raw)
    result = component(tmp_path, LIMITS)
    assert len(result.state.rows) == len(result.version.rows) == 5
    assert sum(type(row.value) is k.Known for row in result.state.rows) == 3
    first = next(row for row in result.version.rows if row.target.node.id == "a" and row.interface == "Vl20")
    assert type(first.value) is k.Unknown and first.value.reason is reason
    assert all(type(row.value) is k.Unknown for row in result.version.rows)


@pytest.mark.parametrize("plant", [
    "missing", "duplicate", "capture", "value", "parse", "owner", "context", "registration", "source", "operation", "raw",
    "state_missing", "state_value", "state_owner", "state_line", "member_raw", "target_params", "state_census",
    "version_census", "target_graph", "request_context", "capture_line", "envelope", "base_raw", "context_ref",
    "target_ref", "member_hash", "member_id", "member_target",
])
def test_later_whole_ledger_input_graph_or_population_fault_precedes_either_writer(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    execute, batches = runtime.execute_parsers, []
    def recording(*args):
        result = execute(*args)
        batches.append((args, result))
        return result
    monkeypatch.setattr(runtime, "execute_parsers", recording)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    arguments, original_outputs = batches[0]
    def changed(declarations, handlers, requests):
        outputs = original_outputs
        operation = b.hsrp.OP if plant.startswith("state_") else gp.all_hsrp.OP
        item = next(out for out in outputs if out.receipt.capture.operation == operation)
        receipt, capture = item.receipt, item.receipt.capture
        if plant in ("missing", "state_missing"):
            return tuple(out for out in outputs if out is not item)
        if plant == "duplicate":
            return outputs + (item,)
        if plant in ("capture", "value", "state_value", "parse"):
            altered = replace(item, receipt=replace(receipt, capture=replace(capture))) if plant == "capture" else (
                replace(item, receipt=replace(receipt, parse=replace(receipt.parse))) if plant == "parse" else replace(item, value=replace(item.value)))
            return tuple(altered if out is item else out for out in outputs)
        if plant in ("owner", "state_owner", "context", "registration", "source", "operation", "raw"):
            changes = {"owner": {"owner": b.STEP.id}, "state_owner": {"owner": profile.STEP.id},
                "context": {"context": "other"}, "registration": {"registration_sha256": "0" * 64},
                "source": {"capture": replace(capture, source=k.EntityKey("node:wrong"))},
                "operation": {"capture": replace(capture, operation=b.hsrp.OP)},
                "raw": {"capture": replace(capture, raw=capture.raw + b"changed")}}[plant]
            altered = replace(item, receipt=replace(receipt, **changes))
            return tuple(altered if out is item else out for out in outputs)
        state, owner = (handler.parser for handler in handlers)
        if plant == "envelope":
            owner.envelope = replace(owner.envelope)
        elif plant == "base_raw":
            object.__setattr__(owner.envelope.base, "raw", b"{}")
        elif plant in ("context_ref", "target_ref"):
            declared = owner.envelope.declaration if plant == "context_ref" else owner.envelope.targets[0].declaration
            ref, = declared.evidence
            object.__setattr__(declared, "evidence", (replace(ref, citation="/wrong"),))
        elif plant in ("member_raw", "member_hash", "member_id", "member_target"):
            member = owner.envelope.captures[-1]
            field, value = {"member_raw": ("raw", b"changed"), "member_hash": ("sha256", "0" * 64),
                "member_id": ("id", "cap:wrong"), "member_target": ("target", replace(member.target))}[plant]
            object.__setattr__(member, field, value)
        elif plant == "target_params":
            object.__setattr__(next(target for target in owner.envelope.targets if target.id == "all-b"), "params", b"{}")
        elif plant == "state_census":
            state.plan.indexed.pop(next(key for key, target in state.plan.indexed.items() if target.node.id == "b"))
        elif plant == "version_census":
            owner.inputs.source.indexed.pop(next(key for key, target in owner.inputs.source.indexed.items() if target.node.id == "b"))
        elif plant == "target_graph":
            object.__setattr__(owner.inputs.source.targets[-1].node, "ports", [])
        elif plant == "request_context":
            object.__setattr__(requests[-1], "context", "other")
        else:
            object.__setattr__(capture.lines[0].span, "start", [])
        return outputs
    object.__setattr__(source.batch, "outputs", changed(*arguments))
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        production.StateVersionProduction(source).finish()


@pytest.mark.parametrize("phase", ["initial", "post_dispatch"])
def test_state_graph_refuses_before_generic_detached_retention_or_comparison(tmp_path, monkeypatch, phase):
    folder(tmp_path)
    scope = gp._scope
    retain, validate = runtime.custody.retain_requests, runtime.custody.validate_retained_requests
    def unsafe(requests):
        return any(type(line.span.start) is not int for request in requests for line in request.capture.lines)
    def retaining(requests):
        assert not unsafe(requests), "invalid state graph reached detached retention"
        return retain(requests)
    def validating(requests, retained):
        assert not unsafe(requests), "invalid state graph reached detached comparison"
        return validate(requests, retained)
    def initial(*args):
        targets, domains, requests = scope(*args)
        object.__setattr__(requests[0].capture.lines[0].span, "start", [])
        return targets, domains, requests
    monkeypatch.setattr(runtime.custody, "retain_requests", retaining)
    monkeypatch.setattr(runtime.custody, "validate_retained_requests", validating)
    if phase == "initial":
        monkeypatch.setattr(gp, "_scope", initial)
        def action():
            return component(tmp_path, LIMITS)
    else:
        source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
        object.__setattr__(source.batch.brief_requests[0].capture.lines[0].span, "start", [])
        action = production.StateVersionProduction(source).finish
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        action()


@pytest.mark.parametrize("forge", [False, True])
def test_brief_full_accounting_cannot_be_upgraded_by_coherent_cached_reason_mutation(tmp_path, monkeypatch, forge):
    def partial(side, files):
        files["brief.txt"] += b"unrecognised body\n"
    folder(tmp_path, change=partial)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    output = next(item for item in source.batch.outputs if item.receipt.capture.operation == b.hsrp.OP)
    value = output.value
    assert value.reason is k.UnknownReason.PARSE_PARTIAL
    assert output.receipt.capture.integrity is k.IntegrityState.COMPLETE
    assert any(line.status == "unrecognised" for line in value.parse.lines)
    if forge:
        object.__setattr__(value, "reason", None)
        object.__setattr__(value.parse, "quality", "complete")
        for row in value.rows:
            object.__setattr__(row, "reason", None)
        no_writers(monkeypatch)
        with pytest.raises(ValueError):
            production.StateVersionProduction(source).finish()
    else:
        result = production.StateVersionProduction(source).finish()
        assert all(type(row.value) is k.Unknown for row in result.state.rows)
        assert sum(type(row.value) is k.Known for row in result.version.rows) == 3


@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_independent_first_component_registration_tuple_survives_post_batch_carrier_mutation(tmp_path, monkeypatch, field):
    folder(tmp_path)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    object.__setattr__(source.batch.first, field, "0" * 64 if field == "registration_sha256" else b"corrupt")
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        production.StateVersionProduction(source).finish()


@pytest.mark.parametrize("field,value", [("production_attempted", True), ("production", object())])
def test_already_consumed_or_prepopulated_actual_version_owner_refuses_before_first_writer(tmp_path, monkeypatch, field, value):
    folder(tmp_path)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    producer = production.StateVersionProduction(source)
    object.__setattr__(source.batch.owner, field, value)
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        producer.finish()
    assert producer.attempted and producer.result is None
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        producer.finish()


def test_live_reported_state_scalar_drift_refuses_before_first_binder_and_consumes_run(tmp_path, monkeypatch):
    folder(tmp_path)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    producer = production.StateVersionProduction(source)
    monkeypatch.setattr(b, "REPORTED_STATE", "l3.fhrp.wrong_reported_state")
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        producer.finish()
    assert producer.attempted and producer.result is None
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        producer.finish()


@pytest.mark.parametrize("phase", ["closure", "state_writer", "version_writer"])
def test_actual_producer_attempt_is_consumed_after_closure_or_writer_failure(tmp_path, monkeypatch, phase):
    folder(tmp_path)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    producer = production.StateVersionProduction(source)
    if phase == "closure":
        item = source.batch.outputs[0]
        object.__setattr__(source.batch, "outputs", tuple(replace(out, value=replace(out.value)) if out is item else out for out in source.batch.outputs))
    write, seen = FactWriter.write, []
    def writing(self, **kwargs):
        seen.append((self.store, kwargs["fact"]))
        if (phase == "state_writer" and kwargs["fact"] == b.REPORTED_STATE) or (
                phase == "version_writer" and kwargs["fact"] == VERSION):
            raise ValueError("planted_writer")
        return write(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError):
        producer.finish()
    assert producer.attempted and producer.result is None
    if phase == "closure":
        assert seen == []
    elif phase == "version_writer":
        assert len(seen[0][0].values) == 5
    count = len(seen)
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        producer.finish()
    assert len(seen) == count and producer.result is None


def test_coherent_execution_and_owner_budget_copy_is_not_the_closed_original_budget(tmp_path, monkeypatch):
    folder(tmp_path)
    source = runtime.execute_state_version_inputs(tmp_path, LIMITS)
    original = source.batch.budgets
    copied = replace(original)
    assert copied == original and copied is not original
    source.budgets = copied
    source.batch.owner.budgets = copied
    producer = production.StateVersionProduction(source)
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        producer.finish()
    assert producer.attempted and producer.result is None
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        producer.finish()
