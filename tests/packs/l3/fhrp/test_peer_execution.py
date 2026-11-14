"""Real ordinary peer staging and fresh execution; returned data is not a Store/source seal."""
from dataclasses import replace

import pytest
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import peer_execution as fresh
from atlas_brain.packs.l3.fhrp import (
    peer_pack,
    peer_profile,
    version_owner,
    version_profile,
)
from atlas_brain.runner import p4_pipeline as pipeline


def forbidden(*args, **kwargs):
    pytest.fail("forbidden parser, preparation, admission, compilation or Writer")


def no_writers(monkeypatch):
    for module in (stp, ec, fhrp, version_owner):
        monkeypatch.setattr(module, "bind_writer", forbidden)


def test_real_public_packs_all_prepare_before_one_batch_and_four_original_parsers(tmp_path, monkeypatch):
    files = folder(tmp_path)
    no_writers(monkeypatch)
    prepared, parsed, calls = [], [], []
    for cls in (stp.RootGuardPack, SummaryPack, peer_pack.PeerStateVersionPack):
        original = cls.prepare
        def preparing(self, envelope, original=original):
            assert not parsed and not calls
            value = original(self, envelope)
            prepared.append((self, envelope, value))
            return value
        monkeypatch.setattr(cls, "prepare", preparing)
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, preparation.all_hsrp):
        original = module.parse_capture
        def parsing(capture, *args, original=original):
            assert len(prepared) == 3 and len(calls) == 1
            value = original(capture, *args)
            parsed.append((capture, value))
            return value
        monkeypatch.setattr(module, "parse_capture", parsing)
    execute = pipeline.execute_parsers
    def executing(declarations, handlers, requests):
        assert len(prepared) == 3 and not calls and not parsed
        calls.append((declarations, handlers, requests))
        return execute(declarations, handlers, requests)
    monkeypatch.setattr(pipeline, "execute_parsers", executing)
    result = fresh.execute_peer_state_version_inputs(tmp_path, LIMITS)
    declarations, handlers, requests = calls[0]
    envelope, ledger = result.execution.envelope, result.execution.executed
    assert type(result.tree) is stp.RootGuardPack and type(result.channel) is SummaryPack
    assert type(result.fhrp) is peer_pack.PeerStateVersionPack
    assert tuple(pack for pack, _, _ in prepared) == (result.tree, result.channel, result.fhrp)
    assert all(original is envelope for _, original, _ in prepared)
    assert declarations == peer_profile.DECLARATIONS
    compiled = compile_packs(declarations)
    assert compiled == peer_profile.compile_peer_state_version_profile()
    assert len(calls) == 1 and len(handlers) == len(requests) == len(ledger) == len(parsed) == 4
    assert {handler.binding for handler in handlers} == set(compiled.operations)
    assert all(any(target is original for original in envelope.targets)
               for _, _, batch in prepared for target in batch.targets)
    assert result.tree.envelope is result.channel.run.envelope is envelope
    assert result.fhrp.inputs.envelope is result.fhrp.owner.envelope is envelope
    assert result.fhrp.inputs.budgets is result.fhrp.owner.budgets is LIMITS
    assert all(pack.budgets is LIMITS for pack, _, _ in prepared)
    assert tuple(handler.parser for handler in prepared[-1][2].handlers) == (result.fhrp.state, result.fhrp.owner)
    assert result.fhrp.inputs.version.targets is result.fhrp.owner.inputs.source.targets
    for output in ledger:
        capture, receipt = output.receipt.capture, output.receipt
        member = next(member for member in envelope.captures if member.id == capture.id)
        request = next(request for request in requests if request.capture.id == capture.id)
        assert capture is request.capture and capture.raw is member.raw
        assert receipt.owner == member.target.owner and receipt.context == envelope.context
        assert receipt.registration_sha256 == envelope.registration_sha256 == compiled.registration_sha256
        assert receipt.parse is output.value.parse
        assert any(capture is original and output.value is value for original, value in parsed)
    assert result.fhrp.owner.production is None and not result.fhrp.owner.production_attempted
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "no_captures", "unselected_b"])
def test_actual_execution_preserves_original_brief_population_without_all_evidence(tmp_path, monkeypatch, mode):
    folder(tmp_path, mode=mode)
    no_writers(monkeypatch)
    result = fresh.execute_peer_state_version_inputs(tmp_path, LIMITS)
    pack = result.fhrp
    outputs = tuple(out for out in result.execution.executed if out.receipt.capture.operation == preparation.all_hsrp.OP)
    rows = pack.owner.canonical_rows(outputs)
    assert len(rows) == sum(len(target.groups) for target in pack.inputs.domains) == (4 if mode == "unselected_b" else 5)
    assert {out.receipt.capture.operation for out in result.execution.executed} >= {stp.stp.OP, ec.parse_summary.OP}
    for row in rows:
        if mode.startswith("no_all") or mode == "no_captures" or row.target.node.id == "b":
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
            need, = row.value.next_evidence
            assert need.node == row.target.node.key and need.operation == preparation.all_hsrp.OP
        assert any(type(ref) is k.RegistryRef for ref in row.value.evidence)
    if mode in ("no_brief_capture", "unselected_b"):
        assert sum(type(row.value) is k.Known for row in rows) == 3
    assert pack.owner.production is None and not pack.owner.production_attempted


def test_public_fhrp_pack_prepares_both_fixed_operations_once_without_parsing(tmp_path, monkeypatch):
    folder(tmp_path)
    envelope = pipeline.p4.admit_folder(tmp_path, LIMITS, declarations=peer_profile.DECLARATIONS)
    pack = peer_pack.PeerStateVersionPack(LIMITS)
    assert pack.declaration() is version_profile.STATE_VERSION_DECLARATION
    no_writers(monkeypatch)
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, preparation.all_hsrp):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    batch = pack.prepare(envelope)
    assert pack.attempted and pack.inputs.envelope is envelope
    assert {target.operation for target in batch.targets} == {fhrp.hsrp.OP, preparation.all_hsrp.OP}
    assert tuple(handler.parser for handler in batch.handlers) == (pack.state, pack.owner)
    assert batch.requests == pack.inputs.requests + pack.inputs.version.requests
    original = pack.inputs, pack.state, pack.owner
    monkeypatch.setattr(preparation, "prepare_peer_state_version_inputs", forbidden)
    with pytest.raises(ValueError, match="fhrp_peer_pack_once"):
        pack.prepare(envelope)
    assert (pack.inputs, pack.state, pack.owner) == original


@pytest.mark.parametrize("phase", ["preparation", "state", "version", "prepared"])
def test_failing_pack_prepare_is_consumed_without_publishing_partial_owners(tmp_path, monkeypatch, phase):
    folder(tmp_path)
    envelope = pipeline.p4.admit_folder(tmp_path, LIMITS, declarations=peer_profile.DECLARATIONS)
    pack = peer_pack.PeerStateVersionPack(LIMITS)
    def refusing(*args, **kwargs):
        raise ValueError("planted_" + phase)
    if phase == "prepared":
        class RefusingPrepared[T]:
            def __init__(self, **kwargs):
                raise ValueError("planted_prepared")
        monkeypatch.setattr(pipeline, "Prepared", RefusingPrepared)
    else:
        module, name = {"preparation": (preparation, "prepare_peer_state_version_inputs"),
            "state": (fhrp, "StateOwner"), "version": (version_owner, "PeerGlobalVersionOwner")}[phase]
        monkeypatch.setattr(module, name, refusing)
    with pytest.raises(ValueError, match="planted_" + phase):
        pack.prepare(envelope)
    assert pack.attempted and pack.inputs is pack.state is pack.owner is None
    monkeypatch.setattr(preparation, "prepare_peer_state_version_inputs", forbidden)
    with pytest.raises(ValueError, match="fhrp_peer_pack_once"):
        pack.prepare(envelope)
    assert pack.inputs is pack.state is pack.owner is None


@pytest.mark.parametrize("operand", ["root", "budgets"])
@pytest.mark.parametrize("value", ["not_a_path", None, 7])
def test_input_types_refuse_before_profile_compile_or_admission(tmp_path, monkeypatch, operand, value):
    monkeypatch.setattr(peer_profile, "compile_peer_state_version_profile", forbidden)
    monkeypatch.setattr(pipeline.p4, "admit_folder", forbidden)
    with pytest.raises(ValueError):
        fresh.execute_peer_state_version_inputs(value if operand == "root" else tmp_path,
            LIMITS if operand == "root" else value)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth",
    "numeric_digits", "compression_ratio", "archive_index_bytes"])
@pytest.mark.parametrize("value", [False, [], 0, -1])
def test_all_budget_leaves_refuse_before_profile_compile_or_admission(tmp_path, monkeypatch, field, value):
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, value)
    monkeypatch.setattr(peer_profile, "compile_peer_state_version_profile", forbidden)
    monkeypatch.setattr(pipeline.p4, "admit_folder", forbidden)
    with pytest.raises(ValueError):
        fresh.execute_peer_state_version_inputs(tmp_path, budgets)


@pytest.mark.parametrize("plant", ["missing", "unlisted", "hash", "bundle", "artifact"])
def test_fresh_runner_uses_actual_whole_folder_admission_before_any_parser(tmp_path, monkeypatch, plant):
    root, budgets = tmp_path, LIMITS
    if plant == "missing":
        root = tmp_path / "absent"
    else:
        folder(tmp_path)
        if plant == "unlisted":
            (tmp_path / "extra.txt").write_bytes(b"unclaimed")
        elif plant == "hash":
            (tmp_path / "all.txt").write_bytes(b"changed")
        else:
            budgets = replace(LIMITS, **{("bundle_bytes" if plant == "bundle" else "artifact_bytes"): 1})
    monkeypatch.setattr(pipeline, "execute_parsers", forbidden)
    no_writers(monkeypatch)
    expected = FileNotFoundError if plant == "missing" else (ValueError, BudgetExceeded)
    with pytest.raises(expected):
        fresh.execute_peer_state_version_inputs(root, budgets)


@pytest.mark.parametrize("field", ["node_id", "target_id", "target_owner", "member_id", "member_raw"])
def test_pack_finite_graph_refuses_before_retention_and_identifier_sets(tmp_path, monkeypatch, field):
    folder(tmp_path)
    envelope = pipeline.p4.admit_folder(tmp_path, LIMITS, declarations=peer_profile.DECLARATIONS)
    target = next(target for target in envelope.targets if target.operation == fhrp.hsrp.OP)
    member = next(member for member in envelope.captures if member.target is target)
    obj, attribute = {"node_id": (target.node, "id"), "target_id": (target, "id"),
        "target_owner": (target, "owner"), "member_id": (member, "id"), "member_raw": (member, "raw")}[field]
    object.__setattr__(obj, attribute, [])
    monkeypatch.setattr(preparation, "retain_version_inputs", forbidden)
    no_writers(monkeypatch)
    pack = peer_pack.PeerStateVersionPack(LIMITS)
    with pytest.raises(ValueError):
        pack.prepare(envelope)
    assert pack.attempted and pack.inputs is pack.state is pack.owner is None


@pytest.mark.parametrize("phase", ["first", "current"])
@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_fresh_runner_recloses_first_and_current_full_profile_after_the_real_batch(tmp_path, monkeypatch, phase, field):
    folder(tmp_path)
    no_writers(monkeypatch)
    compiler, execute = peer_profile.compile_peer_state_version_profile, pipeline.execute_parsers
    compilations, dispatched = [], []
    def compiling():
        result = compiler()
        if phase == "current" and dispatched:
            return replace(result, **{field: "0" * 64 if field.endswith("sha256") else b"changed"})
        compilations.append(result)
        return result
    def executing(*args):
        outputs = execute(*args)
        dispatched.append(outputs)
        if phase == "first":
            object.__setattr__(compilations[0], field, "0" * 64 if field.endswith("sha256") else b"changed")
        return outputs
    monkeypatch.setattr(peer_profile, "compile_peer_state_version_profile", compiling)
    monkeypatch.setattr(pipeline, "execute_parsers", executing)
    with pytest.raises(ValueError):
        fresh.execute_peer_state_version_inputs(tmp_path, LIMITS)
    assert len(dispatched) == 1 and len(dispatched[0]) == 4


def test_fresh_runner_requires_original_full_envelope_hash_after_the_real_batch(tmp_path, monkeypatch):
    folder(tmp_path)
    no_writers(monkeypatch)
    execute, calls = pipeline.execute_p4_folder, []
    def executing(*args, **kwargs):
        result = execute(*args, **kwargs)
        calls.append(result)
        object.__setattr__(result.envelope, "registration_sha256",
            version_profile.compile_state_version_profile().registration_sha256)
        return result
    monkeypatch.setattr(pipeline, "execute_p4_folder", executing)
    with pytest.raises(ValueError, match="fhrp_peer_registration"):
        fresh.execute_peer_state_version_inputs(tmp_path, LIMITS)
    assert len(calls) == 1 and len(calls[0].executed) == 4


def test_batch_failure_propagates_without_materializing_any_peer_store(tmp_path, monkeypatch):
    folder(tmp_path)
    no_writers(monkeypatch)
    def refusing(*args):
        raise ValueError("planted_batch")
    monkeypatch.setattr(pipeline, "execute_parsers", refusing)
    with pytest.raises(ValueError, match="planted_batch"):
        fresh.execute_peer_state_version_inputs(tmp_path, LIMITS)
