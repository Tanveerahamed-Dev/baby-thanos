"""Fresh four-Store ownership and partial-failure controls; no Source/proof qualification."""
from dataclasses import replace
from enum import StrEnum

import pytest
from test_peer_execution import forbidden, no_writers
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import peer_canonical
from atlas_brain.packs.l3.fhrp import peer_execution as runtime
from atlas_brain.packs.l3.fhrp import version_owner as vo
from atlas_brain.runner import p4_pipeline as pipeline

component = runtime.build_peer_state_version_component
VERSION = "l3.fhrp.reported_protocol_version"


class IntAlias(int):
    pass


class FactAlias(StrEnum):
    STATE = "l3.fhrp.reported_state"


def reader(store, pack):
    return bind_reader(store, step=StepSpec(id=pack + "/inspect_component", pack=pack,
        kind="check", scope="estate", reads=tuple(sorted(store.owners)), produces=(), evaluator=pack + ".inspect_component"))


def checked_root(tmp_path, budgets=LIMITS):
    valid, changed = tmp_path / "valid", tmp_path / "changed"
    folder(valid)
    component(valid, budgets)
    folder(changed)
    return changed


def publication_spy(monkeypatch):
    original, calls = runtime.PeerStateVersionComponent, []
    def constructing(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)
    monkeypatch.setattr(runtime, "PeerStateVersionComponent", constructing)
    return calls


def after_phase(monkeypatch, phase, change):
    execute, prepared = runtime.execute_peer_state_version_inputs, []
    def executing(*args):
        result = execute(*args)
        prepared.append(result)
        if phase == "batch":
            change(result)
        return result
    monkeypatch.setattr(runtime, "execute_peer_state_version_inputs", executing)
    if phase != "batch":
        cls = {"tree": stp.RootGuardPack, "channel": SummaryPack, "state": fhrp.StateOwner,
            "version": vo.PeerGlobalVersionOwner}[phase]
        finish = cls.finish
        def finishing(self, *args):
            result = finish(self, *args)
            change(prepared[0])
            return result
        monkeypatch.setattr(cls, "finish", finishing)
    return prepared


def test_real_four_stores_keep_one_batch_caches_receipts_and_reader_cells_without_replay(tmp_path, monkeypatch):
    files, parsed, batches, prepared, closed, writes = folder(tmp_path), [], [], [], [], []
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, runtime.all_hsrp):
        original = module.parse_capture
        def parsing(capture, *args, original=original):
            value = original(capture, *args)
            parsed.append((capture, value))
            return value
        monkeypatch.setattr(module, "parse_capture", parsing)
    execute, prepare = pipeline.execute_parsers, runtime.execute_peer_state_version_inputs
    close, write = peer_canonical.canonical_peer_state_version_outputs, FactWriter.write
    def executing(*args):
        outputs = execute(*args)
        batches.append(outputs)
        return outputs
    def preparing(*args):
        result = prepare(*args)
        prepared.append(result)
        return result
    def closing(*args):
        result = close(*args)
        closed.append(result)
        return result
    def writing(self, **kwargs):
        assert len(parsed) == 4 and len(batches) == 1 and closed
        if kwargs["fact"] == fhrp.REPORTED_STATE:
            assert len(closed) >= 2
        write(self, **kwargs)
        writes.append((self.store, kwargs["fact"]))
    monkeypatch.setattr(pipeline, "execute_parsers", executing)
    monkeypatch.setattr(runtime, "execute_peer_state_version_inputs", preparing)
    monkeypatch.setattr(peer_canonical, "canonical_peer_state_version_outputs", closing)
    monkeypatch.setattr(FactWriter, "write", writing)
    result = component(tmp_path, LIMITS)
    assert len(prepared) == len(batches) == 1 and result.execution is prepared[0].execution
    assert result.execution.executed is batches[0] and result.tree_owner is prepared[0].tree
    assert result.channel_owner is prepared[0].channel.owner
    assert result.state_owner is prepared[0].fhrp.state and result.version_owner is prepared[0].fhrp.owner
    records = (result.tree, result.channel, result.state, result.version)
    assert len({id(record.store) for record in records}) == 4 and len(writes) == 14
    assert [len(record.store.values) for record in records] == [2, 2, 5, 5]
    assert len(set().union(*(set(record.store.owners) for record in records))) == 6
    for record, step in zip(records, (stp.STEP, ec.STEP, fhrp.STEP, vo.profile.STEP), strict=True):
        assert record.store.owners == {fact: step.id for fact in step.produces}
    caches = {stp.stp.OP: result.tree_owner.produced, ec.parse_summary.OP: result.channel_owner.produced,
        fhrp.hsrp.OP: result.state_owner.produced, runtime.all_hsrp.OP: result.version_owner.inputs.produced}
    for record in records:
        for output in record.executed:
            assert caches[output.receipt.capture.operation][output.receipt.capture.id] is output.value
            assert any(output.receipt is out.receipt and output.value is out.value for out in batches[0])
            assert output.receipt.registration_sha256 == result.execution.envelope.registration_sha256
    versions = {row.subject: row for row in result.version.rows}
    assert {row.subject for row in result.state.rows} == set(versions)
    for row in result.state.rows:
        other = versions[row.subject]
        assert row.target is not other.target and row.target.node is other.target.node
        assert row.target.groups == other.target.groups
        assert (row.target.context, row.interface, row.group) == (other.target.context, other.interface, other.group)
    monkeypatch.setattr(pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(runtime, "execute_peer_state_version_inputs", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    no_writers(monkeypatch)
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, runtime.all_hsrp):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    for record, pack, rows in ((result.tree, "l2.stp", stp.fact_rows(result.tree)),
            (result.channel, "l2.etherchannel", ec.fact_rows(result.channel)),
            (result.state, "l3.fhrp", fhrp.fact_rows(result.state))):
        view = reader(record.store, pack)
        for fact, row, value in rows:
            assert view.read(fact=fact, subject=row.subject) is value
    result.channel_owner.validate_reported_protocol_values(result.channel, reader(result.channel.store, "l2.etherchannel"), batches[0])
    result.state_owner.validate_gateway_source_values(result.state, reader(result.state.store, "l3.fhrp"), batches[0])
    result.version_owner.validate_values(result.version, reader(result.version.store, "l3.fhrp"))
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "no_captures", "unselected_b"])
def test_actual_stores_preserve_original_brief_denominator_when_observations_are_missing(tmp_path, mode):
    folder(tmp_path, mode=mode)
    result = component(tmp_path, LIMITS)
    assert len(result.state.rows) == len(result.version.rows) == (4 if mode == "unselected_b" else 5)
    assert {row.subject for row in result.state.rows} == {row.subject for row in result.version.rows}
    for row in result.version.rows:
        if mode.startswith("no_all") or mode == "no_captures" or row.target.node.id == "b":
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
    if mode in ("no_brief_capture", "no_captures"):
        assert all(type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED for row in result.state.rows)


@pytest.mark.parametrize("phase", ["batch", "tree", "channel", "state", "version"])
@pytest.mark.parametrize("plant", ["value", "boolean", "integer_alias", "tree_copy", "channel_copy", "fhrp_copy", "owner_copy", "coherent_copy"])
def test_original_caller_budget_values_types_and_all_owner_pointers_close_after_each_callback(tmp_path, monkeypatch, phase, plant):
    budgets = replace(LIMITS, compression_ratio=1)
    root = checked_root(tmp_path, budgets)
    calls, written = publication_spy(monkeypatch), []
    write = FactWriter.write
    def writing(self, **kwargs):
        write(self, **kwargs)
        written.append(kwargs["fact"])
    monkeypatch.setattr(FactWriter, "write", writing)
    def changing(prepared):
        if plant in ("value", "boolean", "integer_alias"):
            object.__setattr__(budgets, "compression_ratio", {"value": 2, "boolean": True, "integer_alias": IntAlias(1)}[plant])
        else:
            copied = replace(budgets)
            targets = {"tree_copy": (prepared.tree,), "channel_copy": (prepared.channel,), "fhrp_copy": (prepared.fhrp,),
                "owner_copy": (prepared.fhrp.owner,), "coherent_copy": (prepared.tree, prepared.channel, prepared.fhrp, prepared.fhrp.owner)}[plant]
            for target in targets:
                target.budgets = copied
    after_phase(monkeypatch, phase, changing)
    with pytest.raises(ValueError):
        component(root, budgets)
    assert len(written) == {"batch": 0, "tree": 2, "channel": 4, "state": 9, "version": 14}[phase]
    assert calls == []


@pytest.mark.parametrize("phase", ["batch", "channel"])
@pytest.mark.parametrize("plant", ["state_finished", "state_flag_alias", "version_attempted", "version_flag_alias",
    "version_production", "state_fact", "state_fact_alias", "context", "raw_claim"])
def test_joint_fhrp_candidates_readiness_and_live_fact_close_before_any_then_before_state_writer(tmp_path, monkeypatch, phase, plant):
    root = checked_root(tmp_path)
    calls, writes = publication_spy(monkeypatch), []
    write = FactWriter.write
    def writing(self, **kwargs):
        write(self, **kwargs)
        writes.append(kwargs["fact"])
    monkeypatch.setattr(FactWriter, "write", writing)
    def changing(prepared):
        if plant.startswith("state_fact"):
            monkeypatch.setattr(fhrp, "REPORTED_STATE", FactAlias.STATE if plant.endswith("alias") else "l3.fhrp.wrong_state")
        elif plant.startswith("state_"):
            prepared.fhrp.state.finished = 0 if plant.endswith("alias") else True
        elif plant == "version_production":
            prepared.fhrp.owner.production = object()
        elif plant.startswith("version_"):
            prepared.fhrp.owner.production_attempted = 0 if plant.endswith("alias") else True
        else:
            output = next(out for out in prepared.execution.executed if out.receipt.capture.operation == fhrp.hsrp.OP)
            if plant == "context":
                object.__setattr__(output.receipt, "context", "wrong")
            else:
                object.__setattr__(output.value.rows[0].interface, "raw", "tampered")
    after_phase(monkeypatch, phase, changing)
    with pytest.raises(ValueError):
        component(root, LIMITS)
    assert len(writes) == (0 if phase == "batch" else 4) and calls == []


@pytest.mark.parametrize("phase", ["tree", "channel", "state", "version"])
def test_actual_writer_failure_can_leave_earlier_stores_but_never_publishes_a_component(tmp_path, monkeypatch, phase):
    root = checked_root(tmp_path)
    calls, stores = publication_spy(monkeypatch), {}
    write = FactWriter.write
    def writing(self, **kwargs):
        fact = kwargs["fact"]
        group = ("tree" if fact.startswith("l2.stp.") else "channel" if fact.startswith("l2.etherchannel.")
            else "version" if fact == VERSION else "state")
        stores[group] = self.store
        if group == phase:
            raise ValueError("planted_writer")
        write(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="planted_writer"):
        component(root, LIMITS)
    order = ["tree", "channel", "state", "version"]
    assert list(stores) == order[:order.index(phase) + 1] and calls == []
    assert [len(stores[name].values) for name in order[:order.index(phase)]] == [2, 2, 5][:order.index(phase)]


@pytest.mark.parametrize("operation,phase", [(stp.stp.OP, "tree"), (ec.parse_summary.OP, "channel")])
@pytest.mark.parametrize("plant", ["cache", "raw_claim"])
def test_foreign_cached_values_and_raw_claims_close_before_their_own_writer(tmp_path, monkeypatch, operation, phase, plant):
    root = checked_root(tmp_path)
    calls, writes = publication_spy(monkeypatch), []
    write = FactWriter.write
    def writing(self, **kwargs):
        write(self, **kwargs)
        writes.append(kwargs["fact"])
    monkeypatch.setattr(FactWriter, "write", writing)
    def changing(prepared):
        outputs = prepared.execution.executed
        output = next(out for out in outputs if out.receipt.capture.operation == operation)
        if plant == "cache":
            object.__setattr__(prepared.execution, "executed", tuple(
                replace(out, value=replace(out.value)) if out is output else out for out in outputs))
        else:
            if phase == "tree":
                record = next(record for record in output.value.parse.records if record.rule_id.startswith("header_"))
            else:
                record = next(record for record in output.value.parse.records if record.rule_id == "group")
            object.__setattr__(record, "span", k.ByteSpan(start=0, end=1))
    after_phase(monkeypatch, "batch", changing)
    monkeypatch.setattr(stp if phase == "tree" else ec, "bind_writer", forbidden)
    with pytest.raises(ValueError):
        component(root, LIMITS)
    assert len(writes) == (0 if phase == "tree" else 2) and calls == []


@pytest.mark.parametrize("position", ["root", "budgets"])
def test_fresh_boundary_refuses_an_external_prepared_carrier_before_another_batch(tmp_path, monkeypatch, position):
    folder(tmp_path)
    prepared = runtime.execute_peer_state_version_inputs(tmp_path, LIMITS)
    monkeypatch.setattr(runtime, "execute_peer_state_version_inputs", forbidden)
    with pytest.raises(ValueError):
        component(prepared if position == "root" else tmp_path, LIMITS if position == "root" else prepared)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth",
    "numeric_digits", "compression_ratio", "archive_index_bytes"])
@pytest.mark.parametrize("value", [False, []])
def test_initial_budget_graph_refuses_before_preparation_or_store_work(tmp_path, monkeypatch, field, value):
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, value)
    monkeypatch.setattr(runtime, "execute_peer_state_version_inputs", forbidden)
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        component(tmp_path, budgets)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth",
    "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_all_seven_caller_budget_values_are_retained_before_the_actual_batch(tmp_path, monkeypatch, field):
    budgets = replace(LIMITS)
    root = checked_root(tmp_path, budgets)
    calls = publication_spy(monkeypatch)
    def changing(_prepared):
        object.__setattr__(budgets, field, getattr(budgets, field) + 1)
    after_phase(monkeypatch, "batch", changing)
    no_writers(monkeypatch)
    with pytest.raises(ValueError):
        component(root, budgets)
    assert calls == []
