"""Real local VRRP production controls; no admission, Reader, global or origin seal."""
from copy import deepcopy
from dataclasses import asdict, replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_vrrp import BODY, block, capture
from test_peer_execution import forbidden
from test_reported_state_build import A, B

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import vrrp_inputs as inputs
from atlas_brain.packs.l3.fhrp import vrrp_owner as owner
from atlas_brain.packs.l3.fhrp import vrrp_profile as profile
from atlas_brain.runner.pack_receipts import CaptureRequest

FACT = profile.REPORTED_VRRP_STATE


def supplied(raw=BODY, integrity=k.IntegrityState.COMPLETE, missing=False):
    targets = tuple(inputs.VRRPTarget(context="round", node=deepcopy(node), groups=(("Vlan61", "100"), ("Vl61", "101"))) for node in (A, B))
    return targets, () if missing else (CaptureRequest(context="round", capture=replace(capture(raw, integrity), source=targets[0].node.key)),)


@pytest.fixture
def rejected(monkeypatch):
    targets, requests = supplied()
    assert len(owner.execute_local_vrrp_inputs(targets, requests).result.rows) == 4
    execute, held = owner.execute_parsers, []
    def run(change, code):
        def executing(declarations, handlers, supplied_requests):
            batch = execute(declarations, handlers, supplied_requests)
            actual = handlers[0].parser
            held.append(actual)
            changed = change(actual, batch)
            for module, name in ((FactStore, "__init__"), (owner, "bind_writer"), (FactWriter, "write")):
                monkeypatch.setattr(module, name, forbidden)
            return batch if changed is None else changed
        monkeypatch.setattr(owner, "execute_parsers", executing)
        with pytest.raises(ValueError, match="^" + code + "$"):
            owner.execute_local_vrrp_inputs(targets, requests)
        actual = held[0]
        assert actual.attempted and not actual.running and actual.production is None
        assert len(actual.parsed) == len(actual.snapshots) == 1
        with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
            actual.finish()
        return actual
    return run


@pytest.mark.parametrize("state", ["Init", "INIT", "Master", "MASTER", "Backup", "BACKUP"])
def test_one_registered_batch_creates_actual_cached_rows_exact_evidence_and_one_write_per_subject(monkeypatch, state):
    targets, requests = supplied(block(state=state))
    before, batches, writes, parses = deepcopy(requests[0].capture), [], [], []
    execute, write, parse = owner.execute_parsers, FactWriter.write, owner.parser.parse_capture
    def executing(declarations, handlers, supplied_requests):
        assert declarations == (profile.DECLARATION,) and supplied_requests is requests
        actual = handlers[0].parser
        assert actual.running and actual.attempted and len(actual.subjects) == 4 and actual.production is None
        result = execute(declarations, handlers, supplied_requests)
        batches.append(result)
        return result
    def parsing(sample):
        result = parse(sample)
        parses.append((sample, result))
        return result
    def writing(self, **kwargs):
        assert len(parses) == len(batches) and kwargs["fact"] == FACT
        writes.append((self.store, kwargs["subject"], kwargs["value"]))
        return write(self, **kwargs)
    monkeypatch.setattr(owner, "execute_parsers", executing)
    monkeypatch.setattr(owner.parser, "parse_capture", parsing)
    monkeypatch.setattr(FactWriter, "write", writing)
    first = owner.execute_local_vrrp_inputs(targets, requests)
    second = owner.execute_local_vrrp_inputs(targets, requests)
    assert len(parses) == len(batches) == 2 and len(writes) == 8 and first.owner is not second.owner
    assert first.result.store is not second.result.store and first.result.rows == second.result.rows
    for index, execution in enumerate((first, second)):
        actual, result = execution.owner, execution.result
        assert actual.production is result and actual.production_attempted and not actual.running
        assert result.executed is batches[index] and actual.executed is result.executed
        assert result.store.owners == {FACT: profile.STEP.id} and len(result.store.values) == len(result.rows) == 4
        output, = result.executed
        assert output.value is actual.produced[requests[0].capture.id] is parses[index][1]
        assert output.receipt.capture is parses[index][0] is requests[0].capture
        assert output.receipt.parse is actual.parsed[requests[0].capture.id] is output.value.parse
        assert (output.receipt.owner, output.receipt.context, output.receipt.registration_sha256) == (profile.STEP.id, "round", result.registration_sha256)
        row = next(row for row in result.rows if type(row.value) is k.Known)
        assert row.target is targets[0] and (row.interface, row.group, row.value.value, row.value.raw, row.value.basis) == (
            "Vlan61", "100", state.lower(), state, k.Basis.OBSERVED)
        points = owner.parser.validate_claims(output.receipt.capture, output.value)[0][1]
        assert row.value.evidence[:1] == targets[0].node.declaration.evidence
        assert {ref.locator for ref in row.value.evidence if type(ref) is k.EvidenceRef} == set(points)
        assert all(ref.role is k.EvidenceRole.SUBJECT and ref.excerpt_sha256 == sha256(requests[0].capture.raw[ref.locator.start:ref.locator.end]).hexdigest()
            for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        assert all(result.store.values[k.FactRef(fact=FACT, subject=row.subject)] is row.value for row in result.rows)
    assert all(row.subject == inputs.subject(row.target, row.interface, row.group) for row in first.result.rows)
    assert requests[0].capture == before and type(requests[0].capture.collected_utc) is k.Unknown


@pytest.mark.parametrize("mode", ["missing", "empty", "partial", "duplicate", "unsupported", "error", "truncated", "unknown_state"])
def test_actual_unknowns_keep_declared_denominator_and_real_witnesses_needs_without_fake_capture(mode):
    raw = b"" if mode == "empty" else BODY + b"unrecognized\n" if mode == "partial" else BODY + BODY if mode == "duplicate" else (
        block(group="10000") if mode == "unsupported" else BODY.replace(b"Backup", b"Unknown") if mode == "unknown_state" else BODY)
    targets, requests = supplied(raw, k.IntegrityState.ERROR if mode == "error" else k.IntegrityState.TRUNCATED if mode == "truncated" else k.IntegrityState.COMPLETE, mode == "missing")
    result = owner.execute_local_vrrp_inputs(targets, requests).result
    reasons = {"empty": k.UnknownReason.EMPTY_UNREGISTERED, "partial": k.UnknownReason.PARSE_PARTIAL,
        "duplicate": k.UnknownReason.CONFLICTING_EVIDENCE, "unsupported": k.UnknownReason.PARSE_PARTIAL,
        "error": k.UnknownReason.CAPTURE_ERROR, "truncated": k.UnknownReason.CAPTURE_TRUNCATED, "unknown_state": k.UnknownReason.PARSE_PARTIAL}
    assert len(result.rows) == 4 and len(result.executed) == (0 if mode == "missing" else 1)
    for row in result.rows:
        value = row.value
        assert type(value) is k.Unknown and not value.candidates and value.detail == "vrrp_state_unresolved"
        assert value.reason is (k.UnknownReason.NOT_COLLECTED if row.target is targets[1] or mode == "missing" else reasons[mode])
        need, = value.next_evidence
        assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s, need.unprintable) == (
            row.target.node.key, "iosxe.show_vrrp", (("group", row.group), ("interface", row.interface)), (FACT,), (profile.STEP.id,), None, ())
        refs = tuple(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
        assert not refs if row.target is targets[1] or mode == "missing" else any(type(ref.locator) is k.WholeCapture for ref in refs)
        assert all(ref.role is k.EvidenceRole.WITNESS for ref in refs)


@pytest.mark.parametrize("fault", ["value", "parse", "parsed_cache", "produced_cache", "drop_cache", "snapshots", "drop", "duplicate",
    "capture", "foreign", "owner", "context", "registration", "alias", "claims", "subjects", "input", "profile"])
def test_actual_batch_and_cache_falsifications_refuse_before_any_store_or_writer(rejected, fault, monkeypatch):
    def changing(actual, batch):
        output = batch[0]
        key = output.receipt.capture.id
        if fault in ("drop_cache", "produced_cache", "parsed_cache", "snapshots"):
            if fault == "drop_cache":
                actual.produced.pop(key)
            else:
                mapping = actual.produced if fault == "produced_cache" else actual.parsed if fault == "parsed_cache" else actual.snapshots
                mapping[key] = replace(mapping[key]) if fault != "snapshots" else {}
        elif fault == "subjects":
            actual.subjects = actual.subjects[:-1]
        elif fault == "input":
            object.__setattr__(actual.inputs.targets[0].node, "ports", ("Gi1/0/1", "Gi1/0/2"))
        elif fault == "profile":
            monkeypatch.setattr(profile, "REPORTED_VRRP_STATE", StrEnum("Alias", {"VALUE": FACT}).VALUE)
        elif fault == "claims":
            object.__setattr__(output.value.rows[0].state, "value", owner.parser.VRRPState.MASTER)
            actual.snapshots[key] = asdict(output.value)
        elif fault in ("drop", "duplicate"):
            return () if fault == "drop" else batch + batch
        elif fault == "value":
            return (replace(output, value=replace(output.value)),)
        else:
            receipt = output.receipt
            if fault in ("capture", "foreign"):
                sample = replace(receipt.capture)
                if fault == "foreign":
                    object.__setattr__(sample, "id", "cap:foreign")
                receipt = replace(receipt, capture=sample)
            else:
                fields = {"parse": {"parse": replace(receipt.parse)}, "owner": {"owner": "l3.fhrp/other"},
                    "context": {"context": "other"}, "registration": {"registration_sha256": "0" * 64}, "alias": {}}
                receipt = replace(receipt, **fields[fault])
                if fault == "alias":
                    object.__setattr__(receipt, "owner", StrEnum("Alias", {"VALUE": profile.STEP.id}).VALUE)
            return (replace(output, receipt=receipt),)
    code = "vrrp_inputs_target" if fault == "input" else "vrrp_profile" if fault == "profile" else "vrrp_claims_state" if fault == "claims" else (
        "vrrp_owner_subjects" if fault == "subjects" else "vrrp_owner_coverage" if fault == "drop" else "vrrp_owner_receipt"
        if fault in ("duplicate", "capture", "foreign", "owner", "context", "registration", "alias") else "vrrp_owner_cache")
    actual = rejected(changing, code)
    assert actual.production_attempted is (fault not in ("input", "profile", "subjects"))


def test_complete_undeclared_row_and_early_or_repeated_finish_do_not_write(monkeypatch):
    targets, requests = supplied()
    actual = owner.VRRPOwner(targets, requests)
    assert not hasattr(actual, "execute")
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        actual.finish()
    with pytest.raises(ValueError, match="^vrrp_owner_request$"):
        actual.parse(requests[0])
    original = owner.execute_parsers
    def executing(*args):
        batch = original(*args)
        for module, name in ((FactStore, "__init__"), (owner, "bind_writer"), (FactWriter, "write")):
            monkeypatch.setattr(module, name, forbidden)
        return batch
    targets, requests = supplied(BODY + block("Vl62", "101"))
    monkeypatch.setattr(owner, "execute_parsers", executing)
    with pytest.raises(ValueError, match="^vrrp_owner_population$"):
        owner.execute_local_vrrp_inputs(targets, requests)


def test_writer_exception_leaves_no_production_and_does_not_claim_rollback(monkeypatch):
    targets, requests = supplied()
    owner.execute_local_vrrp_inputs(targets, requests)
    constructor, write, held, stores = owner.VRRPOwner, FactWriter.write, [], []
    def constructing(*args):
        result = constructor(*args)
        held.append(result)
        return result
    def writing(self, **kwargs):
        stores.append(self.store)
        if len(stores) == 2:
            raise RuntimeError("planted_writer")
        write(self, **kwargs)
    monkeypatch.setattr(owner, "VRRPOwner", constructing)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(RuntimeError, match="^planted_writer$"):
        owner.execute_local_vrrp_inputs(targets, requests)
    assert held[0].production is None and held[0].production_attempted and len(stores[0].values) == 1
    with pytest.raises(ValueError, match="^vrrp_owner_production_once$"):
        held[0].finish()
