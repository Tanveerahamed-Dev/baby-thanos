"""Actual STATE Writer next-use guards; final Source meaning remains caller-owned."""
from dataclasses import replace

import pytest
from test_trusted_finish import parsed

from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import reported_presence_graph as graph
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack


@pytest.mark.parametrize("vip", [False, True])
@pytest.mark.parametrize("missing", [None, "hsrp", "both"])
def test_real_state_writer_keeps_full_rows_stores_receipts_growth_and_vip_phases(tmp_path, monkeypatch, vip, missing):
    tree, channel, pack, execution, budgets, files = parsed(tmp_path / "inputs", vip, missing)
    owner, indexed = pack.owner, pack.owner.plan.indexed
    targets = graph.retain_targets(indexed)
    original = tuple(out for out in execution.executed if out.receipt.capture.operation == state.hsrp.OP)
    wanted = state.StateOwner.reclose_current_rows(owner, execution.envelope, budgets, original)
    expected = graph.source_rows_bytes(wanted, indexed, targets)
    captured, completed, preludes = [], [], []
    retain, write, prelude = handle_comparison.retain_handle, FactWriter.write, state.VirtualIpOwner.virtual_ip_originals
    def retaining(handle):
        result = retain(handle)
        if handle.step is state.STEP:
            captured.append((handle, result))
        return result
    def writing(self, **kw):
        if kw["fact"] == state.REPORTED_STATE:
            assert len(captured) == 1 and captured[0][0] is captured[0][1].handle is self
        result = write(self, **kw)
        if kw["fact"] == state.REPORTED_STATE:
            completed.append((kw["fact"], kw["subject"], kw["value"]))
        return result
    def originals(self, outputs):
        preludes.append(tuple(outputs))
        return prelude(self, outputs)
    monkeypatch.setattr(handle_comparison, "retain_handle", retaining)
    monkeypatch.setattr(FactWriter, "write", writing)
    monkeypatch.setattr(state.VirtualIpOwner, "virtual_ip_originals", originals)
    monkeypatch.setattr(state.hsrp, "parse_capture", lambda *_: pytest.fail("finish parsed again"))
    tree.finish(execution)
    channel.finish(execution)
    result = StandbyBriefPack.finish(pack, execution)
    assert graph.source_rows_bytes(result.rows, indexed, targets) == expected
    assert len(result.rows) == len(result.store.values) == len(completed) == 6
    assert result.store.owners == {state.REPORTED_STATE: state.STEP.id}
    assert captured[0][1].store is result.store and captured[0][1].values is result.store.values
    assert all(result.store.values[k.FactRef(fact=fact, subject=subject)] is value for fact, subject, value in completed)
    assert all(a.receipt is b.receipt and a.value is b.value for a, b in zip(result.executed, original, strict=True))
    assert pack.finished is owner.finished is True
    assert preludes == ([original] if vip else [])
    if vip:
        assert owner.source is result
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("vip", [False, True])
@pytest.mark.parametrize("fault", [
    "writer_get", "writer_set", "store_foreign", "store_clone", "store_get",
    "step_foreign", "step_clone", "step_tuple", "step_get",
    "owners_clone", "values_clone", "owners_dict", "values_dict", "owner_key", "owner_value",
    "reference_get", "reference_fact", "reference_subject",
])
def test_actual_first_state_writer_callback_refuses_before_second_write_or_hook(tmp_path, monkeypatch, vip, fault):
    tree, channel, pack, execution, _budgets, files = parsed(tmp_path / "inputs", vip)
    owner = pack.owner
    calls, completed, hit = [], [], []
    write = FactWriter.write
    def hook(*args, **kwargs):
        calls.append("hook")
        raise AssertionError("unsafe STATE next operation")
    class Foreign:
        __getattribute__ = hook
    class Dict(dict):
        __iter__ = __getitem__ = __contains__ = hook
    class Tuple(tuple):
        __iter__ = hook
    class Equal(str):
        __eq__ = hook
        __hash__ = str.__hash__
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"] != state.REPORTED_STATE:
            return result
        completed.append((kw["fact"], kw["subject"]))
        if len(completed) != 1:
            return result
        source, step = self.store, self.step
        owners, values = source.owners, source.values
        reference = next(iter(values))
        assert reference.fact == kw["fact"] and reference.subject == kw["subject"]
        hit.append(True)
        if fault in ("writer_get", "writer_set"):
            changed = type("ChangedWriter", (FactWriter,), {"__slots__": (),
                "__getattribute__" if fault == "writer_get" else "__setattr__": hook})
            object.__setattr__(self, "__class__", changed)
        elif fault == "store_foreign": object.__setattr__(self, "store", Foreign())
        elif fault == "store_clone":
            clone = FactStore()
            clone.owners, clone.values = owners, values
            object.__setattr__(self, "store", clone)
        elif fault == "store_get":
            changed = type("ChangedStore", (FactStore,), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(source, "__class__", changed)
        elif fault == "step_foreign": object.__setattr__(self, "step", Foreign())
        elif fault in ("step_clone", "step_tuple", "step_get"):
            clone = replace(step)
            if fault == "step_tuple":
                object.__setattr__(clone, "produces", Tuple(clone.produces))
            elif fault == "step_get":
                changed = type("ChangedStep", (type(clone),), {"__slots__": (), "__getattribute__": hook})
                object.__setattr__(clone, "__class__", changed)
            object.__setattr__(self, "step", clone)
        elif fault == "owners_clone": source.owners = dict(owners)
        elif fault == "values_clone": source.values = dict(values)
        elif fault == "owners_dict": source.owners = Dict(owners)
        elif fault == "values_dict": source.values = Dict(values)
        elif fault == "owner_key":
            owners.clear()
            owners[Equal(kw["fact"])] = step.id
        elif fault == "owner_value": owners[kw["fact"]] = Equal(step.id)
        elif fault == "reference_get":
            changed = type("ChangedRef", (k.FactRef,), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(reference, "__class__", changed)
        elif fault == "reference_fact": object.__setattr__(reference, "fact", Equal(reference.fact))
        else: object.__setattr__(reference, "subject", Equal(reference.subject))
        return result
    tree.finish(execution)
    channel.finish(execution)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        StandbyBriefPack.finish(pack, execution)
    assert len(completed) == 1 and hit == [True] and calls == []
    assert owner.finished is pack.finished is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("vip", [False, True])
def test_plain_owner_permission_failure_still_belongs_to_real_writer(tmp_path, monkeypatch, vip):
    tree, channel, pack, execution, _budgets, _files = parsed(tmp_path / "inputs", vip)
    write = FactWriter.write
    completed = []
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"] == state.REPORTED_STATE:
            completed.append(kw["subject"])
            if len(completed) == 1:
                self.store.owners[state.REPORTED_STATE] = "l3.fhrp/foreign_owner"
        return result
    tree.finish(execution)
    channel.finish(execution)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^unregistered_writer:"):
        StandbyBriefPack.finish(pack, execution)
    assert len(completed) == 1 and pack.finished is pack.owner.finished is False


@pytest.mark.parametrize("vip", [False, True])
@pytest.mark.parametrize("fault", ["row_class", "subject", "value"])
def test_flat_cells_avoid_later_row_lookup_and_qualified_graph_closure_rejects_damage(tmp_path, monkeypatch, vip, fault):
    tree, channel, pack, execution, _budgets, files = parsed(tmp_path / "inputs", vip)
    indexed = pack.owner.plan.indexed
    retained = graph.retain_targets(indexed)
    canonical_rows, write = state._canonical_rows, FactWriter.write
    seen, calls, completed = {}, [], []
    def rows(*args, **kwargs):
        actual = canonical_rows(*args, **kwargs)
        seen.setdefault("rows", actual)
        return actual
    def getting(self, name):
        calls.append("get")
        raise AssertionError("later Row access before next-use guard")
    class Equal(str):
        def __eq__(self, other):
            calls.append("equality")
            raise AssertionError("later subject use")
        __hash__ = str.__hash__
    class Foreign:
        def __getattribute__(self, name):
            calls.append(name)
            raise AssertionError("later value access")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"] == state.REPORTED_STATE:
            completed.append(kw["subject"])
            if len(completed) == 1:
                later = seen["rows"][1]
                if fault == "row_class":
                    changed = type("ChangedRow", (state.Row,), {"__slots__": (), "__getattribute__": getting})
                    object.__setattr__(later, "__class__", changed)
                elif fault == "subject": object.__setattr__(later, "subject", Equal(later.subject))
                else: object.__setattr__(later, "value", Foreign())
        return result
    tree.finish(execution)
    channel.finish(execution)
    monkeypatch.setattr(state, "_canonical_rows", rows)
    monkeypatch.setattr(FactWriter, "write", writing)
    result = StandbyBriefPack.finish(pack, execution)
    assert len(completed) == 6 and calls == []
    with pytest.raises(ValueError, match="^hsrp_(presence_graph|version_inputs_state)$"):
        graph.source_rows_bytes(result.rows, indexed, retained)
    assert calls == []
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files
