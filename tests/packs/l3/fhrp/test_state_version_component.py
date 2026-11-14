"""Actual producing-boundary controls; no lower execution data supplies admission."""
import json
from dataclasses import replace

import pytest
from test_state_owner import LIMITS
from test_state_version_input_preparation import DETAIL, folder

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import state_version_component as fresh
from atlas_brain.packs.l3.fhrp import state_version_execution as runtime
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.packs.l3.fhrp import version_profile as profile

VERSION = profile.REPORTED_PROTOCOL_VERSION


component = fresh.build_fhrp_state_version_component


def no_writers(monkeypatch):
    for module in (b, vo):
        monkeypatch.setattr(module, "bind_writer", lambda *args, **kwargs: pytest.fail("Writer before complete closure"))


def test_real_compound_profile_one_batch_original_owners_and_stores(tmp_path, monkeypatch):
    files = folder(tmp_path)
    execute, write = runtime.execute_parsers, FactWriter.write
    calls, parsed, closure = [], [], []
    for module in (b.hsrp, gp.all_hsrp):
        parse = module.parse_capture
        def parsing(capture, original=parse):
            value = original(capture)
            parsed.append((capture, value))
            return value
        monkeypatch.setattr(module, "parse_capture", parsing)
    def executing(declarations, handlers, requests):
        result = execute(declarations, handlers, requests)
        calls.append((declarations, handlers, requests, result))
        return result
    canonical_rows = vo.VersionOwner.canonical_rows
    def closing(self, outputs):
        result = canonical_rows(self, outputs)
        closure.append((self, outputs, result))
        return result
    def writing(self, **kwargs):
        assert len(calls) == 1 and len(parsed) == 2 and closure
        return write(self, **kwargs)
    monkeypatch.setattr(runtime, "execute_parsers", executing)
    monkeypatch.setattr(vo.VersionOwner, "canonical_rows", closing)
    monkeypatch.setattr(FactWriter, "write", writing)
    for module in (b, vo):
        monkeypatch.setattr(module, "execute_parsers", lambda *args: pytest.fail("local executor"))
    result = component(tmp_path, LIMITS)
    declarations, handlers, requests, outputs = calls[0]
    assert declarations == (profile.STATE_VERSION_DECLARATION,) and result.executed is outputs
    assert tuple(handler.parser for handler in handlers) == (result.state_owner, result.version_owner)
    assert type(result.version_owner) is vo.GlobalVersionOwner
    compound = compile_packs(declarations)
    catalogue = json.loads(compound.catalogue_bytes)
    assert {fact["fact"] for fact in catalogue["facts"]} == {b.REPORTED_STATE, VERSION}
    assert len(catalogue["entity_kinds"]) == 1 and catalogue["entity_kinds"][0]["entity_kind"] == "fhrp_local"
    assert result.envelope.registration_sha256 == result.version.registration_sha256 == compound.registration_sha256
    assert compound.registration_sha256 not in (profile.compile_version_profile().registration_sha256,
        compile_packs((b.DECLARATION,)).registration_sha256)
    assert result.state.store.owners == {b.REPORTED_STATE: b.STEP.id}
    assert result.version.store.owners == {VERSION: profile.STEP.id}
    for output in outputs:
        request = next(item for item in requests if item.capture.id == output.receipt.capture.id)
        assert output.receipt.capture is request.capture and output.receipt.context == "round"
        assert output.receipt.registration_sha256 == compound.registration_sha256
        assert any(output.value is value and output.receipt.capture is capture for capture, value in parsed)
        owned = result.state.executed if output.receipt.owner == b.STEP.id else result.version.executed
        assert any(item.receipt is output.receipt and item.value is output.value for item in owned)
    assert all(any(target is row.target for row in result.version.rows) for target in result.version_owner.inputs.source.targets)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "unselected_b"])
def test_original_brief_declarations_define_denominator_independent_of_observations(tmp_path, mode):
    folder(tmp_path, mode=mode)
    result = component(tmp_path, LIMITS)
    assert len(result.version.rows) == len(result.state.rows) == (4 if mode == "unselected_b" else 5)
    assert {row.subject for row in result.version.rows} == {row.subject for row in result.state.rows}
    for row in result.version.rows:
        if mode.startswith("no_all") or row.target.node.id == "b":
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
    state_a = [row for row in result.state.rows if row.target.node.id == "a"]
    assert sum(type(row.value) is k.Known for row in state_a) == (0 if mode == "no_brief_capture" else 3)


@pytest.mark.parametrize("raw", [
    b"fixture#show standby all\n" + DETAIL + b"fixture#\n",
    b"show standby all\n" + DETAIL,
    DETAIL,
])
def test_exact_frame_forms_remain_owned_by_real_body_parser(tmp_path, raw):
    folder(tmp_path, detail=raw)
    result = component(tmp_path, LIMITS)
    assert sum(type(row.value) is k.Known for row in result.version.rows) == 3


@pytest.mark.parametrize("raw", [
    b"fixture#show standby\n" + DETAIL + b"fixture#\n",
    b"fixture#show standby all\n" + DETAIL,
    b"fixture#show standby all\n" + DETAIL + b"other#\n",
    DETAIL + b"show clock\n", DETAIL + b"configure terminal\n", DETAIL + b"!\n",
    DETAIL + b"\x00", DETAIL.replace(b"\n", b"\r"), b"\xff",
])
def test_command_session_and_control_byte_refusals_precede_all_writers(tmp_path, monkeypatch, raw):
    folder(tmp_path, detail=raw)
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        component(tmp_path, LIMITS)


@pytest.mark.parametrize("plant", ["orphan", "mismatch", "duplicate_all", "duplicate_brief", "duplicate_capture", "unknown_operation", "foreign_pack"])
def test_target_operation_and_exact_original_brief_correspondence(tmp_path, monkeypatch, plant):
    def changed(side, files):
        selected = next(row for row in side["targets"] if row["id"] == "all-a")
        if plant == "orphan":
            side["targets"] = [row for row in side["targets"] if row["id"] != "brief-a"]
            side["captures"] = [row for row in side["captures"] if row["target"] != "brief-a"]
            files.pop("brief.txt")
        elif plant == "mismatch":
            selected["params"]["groups"][0][0] = "Vlan20"
        elif plant in ("duplicate_all", "duplicate_brief"):
            target = selected if plant == "duplicate_all" else side["targets"][0]
            side["targets"].append(dict(target, id="extra", params={"groups": [["Vl20", "3"]]}))
        elif plant == "duplicate_capture":
            files["second.txt"] = files["all.txt"]
            side["captures"].append({"target": "all-a", "path": "second.txt"})
        else:
            selected["operation"] = "iosxe.show_clock" if plant == "unknown_operation" else "iosxe.show_spanning_tree"
    folder(tmp_path, change=changed)
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        component(tmp_path, LIMITS)


@pytest.mark.parametrize("plant", ["unlisted", "hash", "budget", "registration_before", "registration_after"])
def test_whole_folder_and_compiled_profile_refusal_before_any_store(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    if plant == "unlisted":
        (tmp_path / "extra.txt").write_bytes(b"unclaimed")
    elif plant == "hash":
        (tmp_path / "all.txt").write_bytes(DETAIL + b"changed")
    elif plant.startswith("registration"):
        compile_profile, dispatched = profile.compile_state_version_profile, []
        execute = runtime.execute_parsers
        def executing(*args):
            result = execute(*args)
            dispatched.append(result)
            return result
        def changed():
            value = compile_profile()
            return replace(value, registration_sha256="0" * 64) if plant.endswith("before") or dispatched else value
        monkeypatch.setattr(profile, "compile_state_version_profile", changed)
        monkeypatch.setattr(runtime, "execute_parsers", executing)
    no_writers(monkeypatch)
    with pytest.raises((ValueError, BudgetExceeded)):
        component(tmp_path, replace(LIMITS, bundle_bytes=1) if plant == "budget" else LIMITS)


def test_successful_runner_publishes_both_canonical_stores_once_without_replay(tmp_path, monkeypatch):
    folder(tmp_path)
    run = fresh.StateVersionRun(tmp_path, LIMITS)
    result = run.build()
    assert run.attempted and run.result is result
    states = {("a", "Vl20"): "init", ("a", "Vl10"): "active", ("a", "BD3329"): "standby"}
    assert {row.subject for row in result.state.rows} == {row.subject for row in result.version.rows}
    for row in result.state.rows:
        assert result.state.store.values[k.FactRef(fact=b.REPORTED_STATE, subject=row.subject)] is row.value
        expected = states.get((row.target.node.id, row.interface))
        if expected is not None:
            assert type(row.value) is k.Known and row.value.value == expected and row.value.basis is k.Basis.OBSERVED
        else:
            assert type(row.value) is k.Unknown
    def forbidden(*args, **kwargs):
        pytest.fail("completed runner replayed parser, batch or Writer")
    monkeypatch.setattr(runtime, "execute_parsers", forbidden)
    monkeypatch.setattr(b.hsrp, "parse_capture", forbidden)
    monkeypatch.setattr(gp.all_hsrp, "parse_capture", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        run.build()


@pytest.mark.parametrize("phase", ["preparation", "batch", "closure", "state_writer", "version_writer"])
def test_failed_attempt_is_consumed_and_never_publishes_a_component(tmp_path, monkeypatch, phase):
    folder(tmp_path)
    run = fresh.StateVersionRun(tmp_path, LIMITS)
    writes, original_write = [], FactWriter.write
    def writing(self, **kwargs):
        writes.append((self.store, kwargs["fact"], kwargs["subject"]))
        if (phase == "state_writer" and kwargs["fact"] == b.REPORTED_STATE) or (
                phase == "version_writer" and kwargs["fact"] == VERSION):
            raise ValueError("planted_writer")
        return original_write(self, **kwargs)
    def refusing(*args, **kwargs):
        raise ValueError("planted_" + phase)
    execute = runtime.execute_parsers
    def corrupting(*args):
        outputs = execute(*args)
        item = next(out for out in outputs if out.receipt.capture.operation == gp.all_hsrp.OP)
        return tuple(replace(out, value=replace(out.value)) if out is item else out for out in outputs)
    monkeypatch.setattr(FactWriter, "write", writing)
    if phase == "preparation":
        monkeypatch.setattr(runtime.preparation, "prepare_state_version_inputs", refusing)
    elif phase == "batch":
        monkeypatch.setattr(runtime, "execute_parsers", refusing)
    elif phase == "closure":
        monkeypatch.setattr(runtime, "execute_parsers", corrupting)
    with pytest.raises(ValueError):
        run.build()
    assert run.attempted and run.result is None
    if phase in ("preparation", "batch", "closure"):
        assert writes == []
    elif phase == "version_writer":
        state_store = writes[0][0]
        assert len(state_store.values) == 5
        assert all(reference.fact == b.REPORTED_STATE for reference in state_store.values)
    count = len(writes)
    with pytest.raises(ValueError, match="hsrp_state_version_once"):
        run.build()
    assert len(writes) == count and run.result is None


@pytest.mark.parametrize("field", ["envelope", "budgets", "compiled", "targets", "domains", "requests", "version", "declarations"])
def test_inspectable_prepared_wrapper_substitutions_do_not_replace_held_original_inputs(tmp_path, monkeypatch, field):
    folder(tmp_path)
    prepare, execute = runtime.preparation.prepare_state_version_inputs, runtime.execute_parsers
    wrappers, originals = [], []
    def preparing(*args):
        value = prepare(*args)
        wrappers.append(value)
        originals.append((value.envelope, value.version, value.compiled))
        return value
    def executing(*args):
        result = execute(*args)
        object.__setattr__(wrappers[0], field, object())
        return result
    monkeypatch.setattr(runtime.preparation, "prepare_state_version_inputs", preparing)
    monkeypatch.setattr(runtime, "execute_parsers", executing)
    result = component(tmp_path, LIMITS)
    assert result.envelope is originals[0][0] and len(result.state.rows) == len(result.version.rows) == 5
    assert result.version.registration_sha256 == originals[0][2].registration_sha256
