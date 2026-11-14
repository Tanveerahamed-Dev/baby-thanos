"""One fresh saved-evidence mixed batch; no Store, projection, global-proof or health qualification."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_mixed_context import admitted
from test_peer_execution import forbidden
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import mixed_execution as fresh


@pytest.fixture(autouse=True)
def no_stores(monkeypatch):
    monkeypatch.setattr(FactStore, "__init__", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)


@pytest.fixture
def case(tmp_path):
    files, result = admitted(tmp_path)[1], fresh.execute_mixed_inputs(tmp_path, LIMITS)
    assert len(result.execution.executed) == 5
    return tmp_path, files, result


@pytest.mark.parametrize("mode", ["normal", "none", "cold_vrrp", "only_vrrp", "zero_vrrp"])
def test_real_saved_folder_admits_once_prepares_all_then_runs_one_five_handler_batch(tmp_path, monkeypatch, mode):
    if mode == "zero_vrrp":
        files = folder(tmp_path)
    else:
        _, files = admitted(tmp_path, mode)
    admission, execute = fresh.pipeline.p4.admit_folder, fresh.pipeline.execute_parsers
    admissions, prepared, batches, parsed = [], [], [], []
    def admitting(*args, **kwargs):
        admissions.append(value := admission(*args, **kwargs))
        return value
    monkeypatch.setattr(fresh.pipeline.p4, "admit_folder", admitting)
    for cls in (fresh.stp.RootGuardPack, fresh.SummaryPack, fresh.MixedFhrpPack):
        original = cls.prepare
        def preparing(self, envelope, original=original):
            assert not batches and not parsed
            value = original(self, envelope)
            prepared.append((self, envelope, value))
            return value
        monkeypatch.setattr(cls, "prepare", preparing)
    for module in (fresh.stp.stp, fresh.ec.parse_summary, fresh.brief, fresh.all_hsrp, fresh.vrrp):
        original = module.parse_capture
        def parsing(capture, *args, original=original):
            assert len(prepared) == 3 and len(batches) == 1
            parsed.append((capture, value := original(capture, *args)))
            return value
        monkeypatch.setattr(module, "parse_capture", parsing)
    def executing(declarations, handlers, requests):
        assert len(prepared) == 3 and not batches
        batches.append((declarations, handlers, requests))
        return execute(declarations, handlers, requests)
    monkeypatch.setattr(fresh.pipeline, "execute_parsers", executing)
    result = fresh.execute_mixed_inputs(tmp_path, LIMITS)
    envelope, ledger, pack = result.execution.envelope, result.execution.executed, result.fhrp
    assert type(result) is fresh.MixedExecution and admissions == [envelope]
    assert tuple(row[0] for row in prepared) == (result.tree, result.channel, pack)
    assert all(row[1] is envelope for row in prepared)
    declarations, handlers, requests = batches[0]
    assert declarations == fresh.mixed_profile.DECLARATIONS and len(handlers) == 5
    assert {handler.binding for handler in handlers} == set(fresh.mixed_profile.compile_mixed_profile().operations)
    assert len(ledger) == len(requests) == len(parsed) == len(envelope.captures)
    assert pack.hsrp.envelope is pack.vrrp_inputs.envelope is pack.version.envelope is pack.vrrp_owner.envelope is envelope
    assert pack.hsrp.budgets is pack.vrrp_inputs.budgets is pack.version.budgets is pack.vrrp_owner.budgets is LIMITS
    for output in ledger:
        capture = output.receipt.capture
        request = next(request for request in requests if request.capture.id == capture.id)
        member = next(member for member in envelope.captures if member.id == capture.id)
        assert capture is request.capture and capture.raw is member.raw and capture.bytes_sha256 == member.sha256
        assert output.receipt.owner == member.target.owner and output.receipt.registration_sha256 == envelope.registration_sha256
        assert output.receipt.parse is output.value.parse
        assert any(capture is original and output.value is value for original, value in parsed)
    actual = tuple(out for out in ledger if out.receipt.capture.operation == fresh.vrrp.OP)
    assert len(pack.vrrp_owner.executed) == len(actual)
    assert all(a.receipt is b.receipt and a.value is b.value for a, b in zip(pack.vrrp_owner.executed, actual, strict=True))
    assert pack.vrrp_owner.attempted and not pack.vrrp_owner.running
    assert pack.vrrp_owner.production is pack.version.production is None
    assert not pack.vrrp_owner.production_attempted and not pack.version.production_attempted and not pack.state.finished
    assert sum(len(domain.groups) for domain in pack.hsrp.domains) == (0 if mode == "only_vrrp" else 5)
    assert len(pack.vrrp_inputs.subjects) == (0 if mode == "zero_vrrp" else 2)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("operand", ["root", "budgets"])
@pytest.mark.parametrize("value", [None, [], "invalid"])
def test_invalid_outer_inputs_refuse_before_compilation_or_admission(monkeypatch, tmp_path, operand, value):
    monkeypatch.setattr(fresh.mixed_profile, "compile_mixed_profile", forbidden)
    monkeypatch.setattr(fresh.pipeline.p4, "admit_folder", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_" + ("input" if operand == "root" else "budget") + "$"):
        fresh.execute_mixed_inputs(value if operand == "root" else tmp_path, LIMITS if operand == "root" else value)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
@pytest.mark.parametrize("value", [False, [], 0, -1])
def test_every_budget_leaf_is_finite_positive_before_compilation(monkeypatch, tmp_path, field, value):
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, value)
    monkeypatch.setattr(fresh.mixed_profile, "compile_mixed_profile", forbidden)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_budget$"):
        fresh.execute_mixed_inputs(tmp_path, budgets)


@pytest.mark.parametrize("plant,code", [("unlisted", "p4_unlisted_member"), ("hash", "p4_capture_hash"), ("missing", "p4_missing_member")])
def test_actual_folder_accounting_and_capture_hash_admission_precedes_any_batch(case, monkeypatch, plant, code):
    root, _, _ = case
    if plant == "unlisted":
        (root / "unlisted.txt").write_bytes(b"unclaimed")
    elif plant == "hash":
        (root / "all.txt").write_bytes(b"changed")
    else:
        (root / "all.txt").unlink()
    monkeypatch.setattr(fresh.pipeline, "execute_parsers", forbidden)
    with pytest.raises(ValueError, match="^" + code + "$"):
        fresh.execute_mixed_inputs(root, LIMITS)


@pytest.mark.parametrize("phase", ["hsrp", "vrrp_inputs", "state", "version", "vrrp", "prepared", "preflight", "parse"])
def test_failure_consumes_pack_and_finally_clears_any_armed_owner_without_execution_result(case, monkeypatch, phase):
    root, _, baseline = case
    prepared, original = [], fresh.MixedFhrpPack.prepare
    def preparing(self, envelope):
        prepared.append((self, envelope))
        if phase == "prepared":
            monkeypatch.setattr(fresh.pipeline, "Prepared", RefusingPrepared)
        value = original(self, envelope)
        return replace(value, targets=value.targets[:-1]) if phase == "preflight" else value
    monkeypatch.setattr(fresh.MixedFhrpPack, "prepare", preparing)
    def refusing(*args, **kwargs):
        raise ValueError("planted_" + phase)
    class RefusingPrepared[T]:
        def __init__(self, **kwargs):
            raise ValueError("planted_prepared")
    if phase == "parse":
        monkeypatch.setattr(fresh.vrrp, "parse_capture", refusing)
    elif phase not in ("prepared", "preflight"):
        module, name = {"hsrp": (fresh.global_parse, "prepare_mixed_hsrp_inputs"),
            "vrrp_inputs": (fresh.mixed_vrrp_inputs, "prepare_mixed_vrrp_inputs"), "state": (fresh.build, "StateOwner"),
            "version": (fresh, "MixedGlobalVersionOwner"), "vrrp": (fresh, "MixedVRRPOwner")}[phase]
        monkeypatch.setattr(module, name, refusing)
    with pytest.raises(ValueError, match="^" + ("p4_pipeline_target_claims" if phase == "preflight" else "planted_" + phase) + "$"):
        fresh.execute_mixed_inputs(root, LIMITS)
    pack, envelope = prepared[-1]
    assert pack.attempted and baseline.fhrp.vrrp_owner.production is None
    if phase in ("prepared", "preflight", "parse"):
        assert pack.vrrp_owner is not None and pack.vrrp_owner.attempted and not pack.vrrp_owner.running
        assert pack.vrrp_owner.executed is pack.vrrp_owner.production is None
    else:
        assert pack.hsrp is pack.vrrp_inputs is pack.state is pack.version is pack.vrrp_owner is None
    with pytest.raises(ValueError, match="^fhrp_mixed_pack_once$"):
        original(pack, envelope)


@pytest.mark.parametrize("operation,cache_code", [
    ("iosxe.show_spanning_tree_interface_detail", "fhrp_mixed_execution_cache"),
    ("iosxe.show_etherchannel_summary", "etherchannel_global_value"),
    ("iosxe.show_standby_brief", "hsrp_global_value"), ("iosxe.show_standby_all", "hsrp_version_cache"),
    ("iosxe.show_vrrp", "vrrp_owner_cache")])
@pytest.mark.parametrize("plant", ["value_copy", "parse_copy", "capture_copy", "raw_copy", "owner_alias"])
def test_every_concrete_result_capture_parse_and_owner_is_bound_to_actual_batch_cache(case, monkeypatch, operation, cache_code, plant):
    root, _, _ = case
    original = fresh.pipeline.execute_p4_folder
    def executing(*args, **kwargs):
        result = original(*args, **kwargs)
        output = next(out for out in result.executed if out.receipt.capture.operation == operation)
        if plant == "raw_copy":
            object.__setattr__(output.receipt.capture, "raw", bytes(bytearray(output.receipt.capture.raw)))
            return result
        receipt = replace(output.receipt)
        if plant == "owner_alias":
            object.__setattr__(receipt, "owner", StrEnum("Alias", {"VALUE": receipt.owner}).VALUE)
        changed = replace(output, value=replace(output.value)) if plant == "value_copy" else replace(output,
            receipt=replace(receipt, **({"parse": replace(receipt.parse)} if plant == "parse_copy" else
                {"capture": replace(receipt.capture)})) if plant != "owner_alias" else receipt)
        return replace(result, executed=tuple(changed if out is output else out for out in result.executed))
    monkeypatch.setattr(fresh.pipeline, "execute_p4_folder", executing)
    with pytest.raises(ValueError, match="^" + (cache_code if plant == "value_copy" else "fhrp_mixed_execution_output") + "$"):
        fresh.execute_mixed_inputs(root, LIMITS)


@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_first_retained_compiled_identity_is_rechecked_after_real_batch(case, monkeypatch, field):
    root, _, _ = case
    original_compile, original_execute, compiled = fresh.mixed_profile.compile_mixed_profile, fresh.pipeline.execute_p4_folder, []
    def compiling():
        value = original_compile()
        compiled.append(value)
        return value
    def executing(*args, **kwargs):
        result = original_execute(*args, **kwargs)
        object.__setattr__(compiled[0], field, "0" * 64 if field == "registration_sha256" else b"changed")
        return result
    monkeypatch.setattr(fresh.mixed_profile, "compile_mixed_profile", compiling)
    monkeypatch.setattr(fresh.pipeline, "execute_p4_folder", executing)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        fresh.execute_mixed_inputs(root, LIMITS)


@pytest.mark.parametrize("field", ["artifacts", "envelope", "pack_budgets"])
def test_late_budget_values_and_original_envelope_pack_binding_refuse(case, monkeypatch, field):
    root, _, _ = case
    budgets, original = replace(LIMITS), fresh.pipeline.execute_p4_folder
    def executing(*args, **kwargs):
        result = original(*args, **kwargs)
        if field == "artifacts":
            object.__setattr__(budgets, "artifacts", budgets.artifacts + 1)
        elif field == "envelope":
            result = replace(result, envelope=replace(result.envelope))
        else:
            kwargs["packs"][-1].budgets = replace(budgets)
        return result
    monkeypatch.setattr(fresh.pipeline, "execute_p4_folder", executing)
    with pytest.raises(ValueError, match="^fhrp_mixed_execution_current$"):
        fresh.execute_mixed_inputs(root, budgets)


@pytest.mark.parametrize("owner", ["vrrp", "version"])
def test_both_current_canonical_subsets_close_before_any_execution_carrier_is_accepted(case, monkeypatch, owner):
    root, _, _ = case
    original, calls = fresh.pipeline.execute_p4_folder, []
    def executing(*args, **kwargs):
        calls.append(value := original(*args, **kwargs))
        return value
    def refusing(*args):
        raise ValueError("planted_canonical")
    monkeypatch.setattr(fresh.pipeline, "execute_p4_folder", executing)
    monkeypatch.setattr(fresh.VRRPOwner if owner == "vrrp" else fresh.MixedGlobalVersionOwner, "canonical_rows", refusing)
    monkeypatch.setattr(fresh, "MixedExecution", forbidden)
    with pytest.raises(ValueError, match="^planted_canonical$"):
        fresh.execute_mixed_inputs(root, LIMITS)
    assert len(calls) == 1 and len(calls[0].executed) == 5


def test_repeated_fresh_runs_and_coherent_execution_wrappers_preserve_values_without_origin_tokens(case, monkeypatch):
    root, files, first = case
    original = fresh.pipeline.execute_p4_folder
    def executing(*args, **kwargs):
        result = original(*args, **kwargs)
        return replace(result, executed=tuple(replace(out) for out in result.executed))
    monkeypatch.setattr(fresh.pipeline, "execute_p4_folder", executing)
    second = fresh.execute_mixed_inputs(root, LIMITS)
    assert second.execution == first.execution and second.execution is not first.execution
    assert second.execution.envelope is not first.execution.envelope and second.fhrp is not first.fhrp
    with pytest.raises(ValueError, match="^fhrp_mixed_pack_once$"):
        first.fhrp.prepare(first.execution.envelope)
    assert all(a.value is not b.value and a.receipt.capture is not b.receipt.capture
        for a, b in zip(first.execution.executed, second.execution.executed, strict=True))
    assert {path.name: path.read_bytes() for path in root.iterdir()} == files


def test_metadata_valid_repeated_stp_command_does_not_bypass_existing_runtime_uniqueness(tmp_path):
    admitted(tmp_path, "multi_tree")
    with pytest.raises(ValueError, match="^stp_duplicate_target$"):
        fresh.execute_mixed_inputs(tmp_path, LIMITS)
