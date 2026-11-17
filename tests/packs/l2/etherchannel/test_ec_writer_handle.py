"""Actual EC Writer next-use guards, including the second fact of the same Row."""
from dataclasses import replace

import pytest
from test_global_protocol_finish import BODY, LIMITS, scenario

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model import handle_comparison
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactStore, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_pipeline


def parsed(root, mode="lacp"):
    root.mkdir()
    raw = BODY.replace(b"LACP", b"PAgP" if mode == "pagp" else b"-" if mode == "dash" else b"LACP")
    if mode == "wrapped":
        raw = raw.replace(b"Gi1/0/1(P)\n", b"Gi1/0/1(P)\n   Gi1/0/2(s)\n")
    side = scenario(root, raw)
    if mode in ("missing", "no_targets"):
        side["captures"] = [row for row in side["captures"] if row["target"] != "ec"]
        (root / "ec.txt").unlink()
        if mode == "no_targets":
            side["targets"] = [row for row in side["targets"] if row["operation"] != ec.parse_summary.OP]
        (root / "p4.json").write_bytes(canonical(side))
    files = {path.name: path.read_bytes() for path in root.iterdir()}
    tree, pack = stp.RootGuardPack(LIMITS), gp.SummaryPack(LIMITS)
    execution = p4_pipeline.execute_p4_folder(root, LIMITS, packs=(tree, pack))
    return tree, pack, execution, files


def reader(source):
    step = StepSpec(id=StepId("l2.etherchannel/inspect_source"), pack=ec.PACK, kind="derive",
        scope="estate", reads=ec.STEP.produces, produces=(), evaluator="l2.etherchannel.inspect_source")
    return bind_reader(source.store, step=step)


@pytest.mark.parametrize("mode", ["lacp", "pagp", "dash", "wrapped", "missing", "no_targets"])
def test_full_original_ec_facts_growth_order_receipts_and_bytes_without_reparse(tmp_path, monkeypatch, mode):
    tree, pack, execution, files = parsed(tmp_path / "inputs", mode)
    owner = pack.owner
    captured, completed = [], []
    retain, write = handle_comparison.retain_handle, FactWriter.write
    def retaining(handle):
        result = retain(handle)
        if handle.step is ec.STEP:
            captured.append((handle, result))
        return result
    def writing(self, **kw):
        if kw["fact"] in ec.STEP.produces:
            assert len(captured) == 1 and captured[0][0] is captured[0][1].handle is self
        result = write(self, **kw)
        if kw["fact"] in ec.STEP.produces:
            completed.append((kw["fact"], kw["subject"], kw["value"]))
        return result
    tree.finish(execution)
    monkeypatch.setattr(handle_comparison, "retain_handle", retaining)
    monkeypatch.setattr(FactWriter, "write", writing)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *_: pytest.fail("finish parsed again"))
    source = gp.SummaryPack.finish(pack, execution)
    count = 0 if mode == "no_targets" else 3
    assert len(source.rows) == count and len(source.store.values) == len(completed) == 2 * count
    assert len(captured) == 1 and captured[0][1].store is source.store and captured[0][1].values is source.store.values
    assert source.store.owners == {fact: ec.STEP.id for fact in ec.STEP.produces}
    assert [(fact, subject) for fact, subject, _ in completed] == [
        (fact, row.subject) for row in source.rows for fact in (ec.REPORTED_PROTOCOL, ec.REPORTED_MEMBER_TOKENS)]
    assert all(source.store.values[k.FactRef(fact=fact, subject=subject)] is value for fact, subject, value in completed)
    own = tuple(out for out in execution.executed if out.receipt.capture.operation == ec.parse_summary.OP)
    assert all(a.receipt is b.receipt and a.value is b.value for a, b in zip(source.executed, own, strict=True))
    ec.ProtocolOwner.validate_reported_protocol_values(owner, source, reader(source), execution.executed)
    assert pack.finished is owner.finished is True
    if mode in ("lacp", "pagp", "dash", "wrapped"):
        row = next(row for row in source.rows if row.group == "1")
        assert row.value.value == {"lacp": "lacp", "pagp": "pagp", "dash": "none_reported", "wrapped": "lacp"}[mode]
        assert row.member_tokens.value == ("Gi1/0/1(P) Gi1/0/2(s)" if mode == "wrapped" else "Gi1/0/1(P)")
    elif mode == "missing":
        assert all(row.value.reason is row.member_tokens.reason is k.UnknownReason.NOT_COLLECTED for row in source.rows)
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("fault", [
    "writer_get", "writer_set", "store_foreign", "store_clone", "store_get",
    "step_foreign", "step_clone", "step_tuple", "step_get",
    "owners_clone", "values_clone", "owners_dict", "values_dict", "owner_key", "owner_value",
    "reference_get", "reference_fact", "reference_subject",
])
def test_first_actual_protocol_write_refuses_before_same_row_member_write(tmp_path, monkeypatch, fault):
    tree, pack, execution, files = parsed(tmp_path / "inputs")
    owner = pack.owner
    calls, completed, hit = [], [], []
    write = FactWriter.write
    def hook(*args, **kwargs):
        calls.append("hook")
        raise AssertionError("unsafe next EC write")
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
        if kw["fact"] not in ec.STEP.produces:
            return result
        completed.append((kw["fact"], kw["subject"]))
        if len(completed) != 1:
            return result
        assert kw["fact"] == ec.REPORTED_PROTOCOL
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
            owners[Equal(ec.REPORTED_PROTOCOL)] = step.id
        elif fault == "owner_value": owners[ec.REPORTED_MEMBER_TOKENS] = Equal(step.id)
        elif fault == "reference_get":
            changed = type("ChangedRef", (k.FactRef,), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(reference, "__class__", changed)
        elif fault == "reference_fact": object.__setattr__(reference, "fact", Equal(reference.fact))
        else: object.__setattr__(reference, "subject", Equal(reference.subject))
        return result
    tree.finish(execution)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^store_handle_comparison$"):
        gp.SummaryPack.finish(pack, execution)
    assert len(completed) == 1 and completed[0][0] == ec.REPORTED_PROTOCOL and hit == [True] and calls == []
    assert owner.finished is pack.finished is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


def test_plain_member_owner_permission_still_belongs_to_existing_writer(tmp_path, monkeypatch):
    tree, pack, execution, _files = parsed(tmp_path / "inputs")
    completed = []
    write = FactWriter.write
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"] in ec.STEP.produces:
            completed.append(kw["fact"])
            if len(completed) == 1:
                self.store.owners[ec.REPORTED_MEMBER_TOKENS] = "l2.etherchannel/foreign_owner"
        return result
    tree.finish(execution)
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^unregistered_writer:"):
        gp.SummaryPack.finish(pack, execution)
    assert completed == [ec.REPORTED_PROTOCOL] and owner_unfinished(pack)


def owner_unfinished(pack):
    return pack.finished is pack.owner.finished is False


@pytest.mark.parametrize("fault", ["same_row_class", "protocol_cell", "member_cell"])
def test_flat_pairs_avoid_row_getters_and_actual_owner_closure_refuses_changed_rows(tmp_path, monkeypatch, fault):
    tree, pack, execution, files = parsed(tmp_path / "inputs")
    owner = pack.owner
    original_rows, write = ec._rows, FactWriter.write
    seen, completed, calls = [], [], []
    def observing(*args, **kwargs):
        rows = original_rows(*args, **kwargs)
        if not seen:
            seen.append([])
        seen[0].extend(rows)
        return rows
    def getting(self, name):
        calls.append("get")
        raise AssertionError("same Row member argument read after callback")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"] in ec.STEP.produces:
            completed.append((kw["fact"], kw["subject"]))
            if len(completed) == 1:
                assert kw["fact"] == ec.REPORTED_PROTOCOL
                if fault == "same_row_class":
                    changed = type("ChangedRow", (ec.Row,), {"__slots__": (), "__getattribute__": getting})
                    object.__setattr__(seen[0][0], "__class__", changed)
                else:
                    row = next(row for row in seen[0] if row.group == "1")
                    value = row.value if fault == "protocol_cell" else row.member_tokens
                    object.__setattr__(value, "value", "forged")
        return result
    tree.finish(execution)
    monkeypatch.setattr(ec, "_rows", observing)
    monkeypatch.setattr(FactWriter, "write", writing)
    source = gp.SummaryPack.finish(pack, execution)
    assert len(completed) == 6 and calls == []
    with pytest.raises(ValueError, match="^etherchannel_protocol_source_(population|value)$"):
        ec.ProtocolOwner.validate_reported_protocol_values(owner, source, reader(source), execution.executed)
    assert calls == []
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files
