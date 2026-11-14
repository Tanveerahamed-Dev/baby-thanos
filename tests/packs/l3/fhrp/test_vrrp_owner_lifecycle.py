"""Supplement local VRRP lifecycle qualification; no admission or unforgeable origin claim."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_parse_vrrp import BODY, capture
from test_peer_execution import forbidden
from test_vrrp_owner import supplied

from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import vrrp_inputs as inputs
from atlas_brain.packs.l3.fhrp import vrrp_owner as owner
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.runner.pack_receipts import CaptureRequest


def no_writes(monkeypatch):
    for module, name in ((FactStore, "__init__"), (owner, "bind_writer"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


def recording(monkeypatch):
    constructor, held = owner.VRRPOwner, []
    def constructing(*args):
        actual = constructor(*args)
        held.append(actual)
        return actual
    monkeypatch.setattr(owner, "VRRPOwner", constructing)
    return held


@pytest.mark.parametrize("phase", ["before_batch", "after_batch"])
@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_all_captured_compiler_fields_reclose_before_parsing_or_finishing(monkeypatch, phase, field):
    targets, requests = supplied()
    owner.execute_local_vrrp_inputs(targets, requests)
    compiler, constructor, execute, held = profile.compile_vrrp_profile, owner.VRRPOwner, owner.execute_parsers, []
    def compiling():
        result = compiler()
        return replace(result, **{field: "0" * 64 if field.endswith("sha256") else b"changed"})
    def constructing(*args):
        actual = constructor(*args)
        held.append(actual)
        if phase == "before_batch":
            monkeypatch.setattr(profile, "compile_vrrp_profile", compiling)
        return actual
    def executing(*args):
        result = execute(*args)
        if phase == "after_batch":
            monkeypatch.setattr(profile, "compile_vrrp_profile", compiling)
        return result
    monkeypatch.setattr(owner, "VRRPOwner", constructing)
    monkeypatch.setattr(owner, "execute_parsers", executing)
    no_writes(monkeypatch)
    code = "vrrp_inputs_input" if field == "registration_sha256" else "vrrp_owner_registration"
    with pytest.raises(ValueError, match="^" + code + "$"):
        owner.execute_local_vrrp_inputs(targets, requests)
    actual = held[0]
    assert actual.attempted and not actual.running and not actual.production_attempted and actual.production is actual.executed is None
    assert len(actual.produced) == len(actual.parsed) == len(actual.snapshots) == (0 if phase == "before_batch" else 1)


@pytest.mark.parametrize("field", ["node", "declaration", "raw", "profile", "returned_claims", "context"])
def test_mutation_during_real_parser_callback_is_refused_before_caching_or_store(monkeypatch, field):
    targets, requests = supplied()
    owner.execute_local_vrrp_inputs(targets, requests)
    parse = owner.parser.parse_capture
    held = recording(monkeypatch)
    def parsing(sample):
        result = parse(sample)
        if field == "node":
            object.__setattr__(targets[0].node, "ports", targets[0].node.ports + ("Gi1/0/2",))
        elif field == "declaration":
            object.__setattr__(targets[0].node.declaration.evidence[0], "table_digest", "1" * 64)
        elif field == "raw":
            object.__setattr__(sample, "raw", sample.raw + b"\n")
            object.__setattr__(sample, "lines", text_lines(sample.raw, sample.codec))
        elif field == "profile":
            monkeypatch.setattr(profile, "REPORTED_VRRP_STATE", StrEnum("Alias", {"VALUE": profile.REPORTED_VRRP_STATE}).VALUE)
        elif field == "returned_claims":
            object.__setattr__(result.rows[0].state, "value", owner.parser.VRRPState.MASTER)
        else:
            object.__setattr__(requests[0], "context", "other")
        return result
    monkeypatch.setattr(owner.parser, "parse_capture", parsing)
    no_writes(monkeypatch)
    code = "vrrp_inputs_target" if field in ("node", "declaration") else "vrrp_claims_accounting" if field == "raw" else (
        "vrrp_profile" if field == "profile" else "vrrp_claims_state" if field == "returned_claims" else "vrrp_inputs_population")
    with pytest.raises(ValueError, match="^" + code + "$"):
        owner.execute_local_vrrp_inputs(targets, requests)
    actual = held[0]
    assert actual.attempted and not actual.running and not actual.production_attempted and actual.production is actual.executed is None
    assert actual.produced == actual.parsed == actual.snapshots == {}


@pytest.mark.parametrize("argument", ["finish_positional", "finish_keyword", "helper_positional", "helper_keyword", "constructor", "owner_execute"])
def test_no_supplied_outcomes_receipts_or_owner_execution_api(monkeypatch, argument):
    targets, requests = supplied()
    good = owner.execute_local_vrrp_inputs(targets, requests)
    no_writes(monkeypatch)
    monkeypatch.setattr(owner.parser, "parse_capture", forbidden)
    monkeypatch.setattr(owner, "execute_parsers", forbidden)
    with pytest.raises(AttributeError if argument == "owner_execute" else TypeError):
        if argument == "finish_positional":
            good.owner.finish(good.result.executed)
        elif argument == "finish_keyword":
            good.owner.finish(outputs=good.result.executed)
        elif argument == "helper_positional":
            owner.execute_local_vrrp_inputs(targets, requests, good.result.executed)
        elif argument == "helper_keyword":
            owner.execute_local_vrrp_inputs(targets, requests, outcomes=good.result.executed)
        elif argument == "constructor":
            owner.VRRPOwner(targets, requests, outcomes=good.result.executed)
        else:
            good.owner.execute()
    assert good.owner.production is good.result and good.owner.production_attempted
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        good.owner.finish()


def test_foreign_capture_and_repeat_parse_refuse_inside_live_real_batch_without_poisoning_good_inputs(monkeypatch):
    targets, requests = supplied()
    owner.execute_local_vrrp_inputs(targets, requests)
    execute, parses, held = owner.execute_parsers, [], []
    def executing(declarations, handlers, actual_requests):
        actual = handlers[0].parser
        held.append(actual)
        foreign = replace(requests[0], capture=replace(requests[0].capture))
        with pytest.raises(ValueError, match="^vrrp_owner_request$"):
            actual.parse(foreign)
        assert not actual.produced
        result = execute(declarations, handlers, actual_requests)
        parses.append(result)
        with pytest.raises(ValueError, match="^vrrp_owner_request$"):
            actual.parse(requests[0])
        return result
    monkeypatch.setattr(owner, "execute_parsers", executing)
    result = owner.execute_local_vrrp_inputs(targets, requests)
    assert len(parses) == len(held) == 1 and result.owner is held[0] and result.owner.production is result.result


@pytest.mark.parametrize("failure", [1, 2])
def test_actual_parser_failure_retains_completed_cache_and_resets_running_without_any_store(monkeypatch, failure):
    targets, requests = supplied()
    owner.execute_local_vrrp_inputs(targets, requests)
    requests += (CaptureRequest(context=targets[1].context, capture=replace(capture(BODY), id="cap:second", source=targets[1].node.key)),)
    parse, calls = owner.parser.parse_capture, []
    held = recording(monkeypatch)
    def parsing(sample):
        calls.append(sample)
        if len(calls) == failure:
            raise ValueError("planted_parser")
        return parse(sample)
    monkeypatch.setattr(owner.parser, "parse_capture", parsing)
    no_writes(monkeypatch)
    with pytest.raises(ValueError, match="^planted_parser$"):
        owner.execute_local_vrrp_inputs(targets, requests)
    actual = held[0]
    assert actual.attempted and not actual.running and not actual.production_attempted and actual.production is actual.executed is None
    assert len(actual.produced) == len(actual.parsed) == len(actual.snapshots) == failure - 1
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        actual.finish()


def test_declared_absent_subject_and_cold_node_remain_in_registered_population_without_fake_capture():
    targets, requests = supplied()
    execution = owner.execute_local_vrrp_inputs(targets, requests)
    result = execution.result
    expected = {inputs.subject(target, interface, group) for target in targets for interface, group in target.groups}
    assert {row.subject for row in result.rows} == expected
    assert set(result.store.values) == {k.FactRef(fact=profile.REPORTED_VRRP_STATE, subject=subject) for subject in expected}
    absent = next(row for row in result.rows if row.target is targets[0] and row.group == "101")
    assert absent.value.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert all(row.value.reason is k.UnknownReason.NOT_COLLECTED for row in result.rows if row.target is targets[1])
    assert len(result.executed) == 1 and result.registration_sha256 == profile.compile_vrrp_profile().registration_sha256


def test_equal_receipt_copies_inside_the_actual_registered_batch_are_data_not_origin_tokens(monkeypatch):
    targets, requests = supplied()
    owner.execute_local_vrrp_inputs(targets, requests)
    execute, batches = owner.execute_parsers, []
    def executing(*args):
        actual = execute(*args)
        copied = tuple(replace(output, receipt=replace(output.receipt)) for output in actual)
        assert all(copy.receipt is not original.receipt and copy.value is original.value
            and copy.receipt.capture is original.receipt.capture for copy, original in zip(copied, actual, strict=True))
        batches.append(copied)
        return copied
    monkeypatch.setattr(owner, "execute_parsers", executing)
    result = owner.execute_local_vrrp_inputs(targets, requests)
    assert result.result.executed is batches[0] and result.owner.production is result.result
