"""Exact ordinary EC completion at actual earlier/final Writer boundaries."""
import pytest
from test_global_protocol_finish import BODY, LIMITS, scenario

from atlas_brain.contract.canonical import canonical
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_pipeline as pipeline


def inputs(root, mode="lacp"):
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
    return {path.name: path.read_bytes() for path in root.iterdir()}


def parsed(root, mode="lacp", pack=None):
    files = inputs(root, mode)
    tree = stp.RootGuardPack(LIMITS)
    channel = gp.SummaryPack(LIMITS) if pack is None else pack
    execution = pipeline.execute_p4_folder(root, LIMITS, packs=(tree, channel))
    tree.finish(execution)
    return channel, execution, files


@pytest.mark.parametrize("mode", ["lacp", "pagp", "dash", "wrapped", "missing", "no_targets"])
def test_current_route_preserves_entire_legacy_result_without_parser_replay(tmp_path, monkeypatch, mode):
    calls = []
    parse = ec.parse_summary.parse_capture
    def parsing(*args, **kwargs):
        calls.append(args[0])
        return parse(*args, **kwargs)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", parsing)
    legacy, first, original = parsed(tmp_path / "legacy", mode)
    current, second, files = parsed(tmp_path / "current", mode)
    assert len(calls) == (0 if mode in ("missing", "no_targets") else 2)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *_: pytest.fail("finish replayed parser"))
    expected = legacy.finish(first)
    actual = gp.SummaryPack.finish_current(current, second)
    assert (actual.rows, actual.store.owners, actual.store.values, actual.executed) == (
        expected.rows, expected.store.owners, expected.store.values, expected.executed)
    owned = tuple(out for out in second.executed if out.receipt.capture.operation == ec.parse_summary.OP)
    assert all(a.receipt is b.receipt and a.value is b.value for a, b in zip(actual.executed, owned, strict=True))
    assert current.finished is current.owner.finished is True
    assert len(actual.rows) == (0 if mode == "no_targets" else 3)
    if mode == "wrapped":
        assert next(row.member_tokens.value for row in actual.rows if row.group == "1") == "Gi1/0/1(P) Gi1/0/2(s)"
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        gp.SummaryPack.finish_current(current, second)
    assert {p.name: p.read_bytes() for p in (tmp_path / "current").iterdir()} == files
    assert {p.name: p.read_bytes() for p in (tmp_path / "legacy").iterdir()} == original


def observe(monkeypatch):
    seen = {}
    execute = pipeline.execute_p4_folder
    def observing(root, budgets, *, packs):
        assert type(packs) is tuple and type(packs[1]) is gp.SummaryPack
        seen["pack"] = packs[1]
        result = execute(root, budgets, packs=packs)
        seen.update(owner=packs[1].owner, run=packs[1].run, execution=result)
        return result
    monkeypatch.setattr(pipeline, "execute_p4_folder", observing)
    return seen


@pytest.mark.parametrize("target", ["owner_own", "owner_finish", "owner_current", "pack_finish", "pack_current"])
def test_real_earlier_stp_writer_cannot_dispatch_instance_shadows(tmp_path, monkeypatch, target):
    seen = observe(monkeypatch)
    calls, hit = [], []
    write = FactWriter.write
    def shadow(*args, **kwargs):
        calls.append("shadow")
        raise AssertionError("instance completion dispatch")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"].startswith("l2.stp.") and not hit:
            hit.append(True)
            receiver = seen["owner"] if target.startswith("owner") else seen["pack"]
            name = "own" if target == "owner_own" else "finish_current" if target.endswith("current") else "finish"
            monkeypatch.setattr(receiver, name, shadow)
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    pack, execution, files = parsed(tmp_path / "inputs")
    result = gp.SummaryPack.finish_current(pack, execution)
    assert hit == [True] and calls == [] and len(result.rows) == 3
    assert pack.finished is seen["owner"].finished is True
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("target", ["pack", "owner", "run", "execution"])
@pytest.mark.parametrize("hook", ["__getattribute__", "__setattr__"])
def test_real_earlier_stp_writer_class_drift_refuses_before_current_fields(tmp_path, monkeypatch, target, hook):
    seen = observe(monkeypatch)
    calls, hit = [], []
    write = FactWriter.write
    def getting(self, name):
        calls.append(("get", name))
        raise AssertionError("changed receiver read")
    def setting(self, name, value):
        calls.append(("set", name))
        raise AssertionError("changed receiver assignment")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"].startswith("l2.stp.") and not hit:
            receiver = seen[target]
            changed = type("ChangedEarly", (type(receiver),), {"__slots__": (),
                hook: getting if hook == "__getattribute__" else setting})
            hit.append(True)
            object.__setattr__(receiver, "__class__", changed)
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    pack, execution, files = parsed(tmp_path / "inputs")
    with pytest.raises(ValueError, match="^etherchannel_global_(run|owner)$"):
        gp.SummaryPack.finish_current(pack, execution)
    assert hit == [True] and calls == []
    assert object.__getattribute__(pack, "finished") is False
    assert object.__getattribute__(seen["owner"], "finished") is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("target", ["owner", "pack"])
@pytest.mark.parametrize("hook", ["__getattribute__", "__setattr__"])
def test_actual_final_ec_writer_class_drift_refuses_before_tail_setters(tmp_path, monkeypatch, target, hook):
    pack, execution, files = parsed(tmp_path / "inputs")
    receiver = pack.owner if target == "owner" else pack
    calls, hit, cells = [], [], set()
    write = FactWriter.write
    def getting(self, name):
        calls.append(("get", name))
        raise AssertionError("changed finish receiver read")
    def setting(self, name, value):
        calls.append(("set", name))
        raise AssertionError("changed finish receiver assignment")
    changed = type("ChangedFinal", (type(receiver),), {"__slots__": (),
        hook: getting if hook == "__getattribute__" else setting})
    def writing(self, **kw):
        result = write(self, **kw)
        if self.step is ec.STEP:
            cells.add((kw["fact"], kw["subject"]))
            if len(cells) == 6 and not hit:
                hit.append(True)
                object.__setattr__(receiver, "__class__", changed)
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    with pytest.raises(ValueError, match="^etherchannel_global_(run|owner)$"):
        gp.SummaryPack.finish_current(pack, execution)
    assert hit == [True] and len(cells) == 6 and calls == []
    assert object.__getattribute__(receiver, "finished") is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


def test_legacy_subclass_phase_is_not_replaced_by_the_exact_current_route(tmp_path):
    calls = []
    class Extended(gp.SummaryPack):
        def finish(self, execution):
            calls.append("extended")
            return super().finish(execution)
    pack, execution, _ = parsed(tmp_path / "inputs", pack=Extended(LIMITS))
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        gp.SummaryPack.finish_current(pack, execution)
    result = pack.finish(execution)
    assert calls == ["extended"] and len(result.rows) == 3


@pytest.mark.parametrize("hook", ["__getattribute__", "__setattr__"])
def test_direct_owner_current_route_rejects_real_early_class_drift_before_fields(tmp_path, monkeypatch, hook):
    seen = observe(monkeypatch)
    calls, hit = [], []
    write = FactWriter.write
    def getting(self, name):
        calls.append(("get", name))
        raise AssertionError("changed owner read")
    def setting(self, name, value):
        calls.append(("set", name))
        raise AssertionError("changed owner assignment")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"].startswith("l2.stp.") and not hit:
            owner = seen["owner"]
            seen["owned"] = tuple(out for out in seen["execution"].executed
                if out.receipt.capture.operation == ec.parse_summary.OP)
            changed = type("ChangedOwner", (type(owner),), {"__slots__": (),
                hook: getting if hook == "__getattribute__" else setting})
            hit.append(True)
            object.__setattr__(owner, "__class__", changed)
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    _pack, _execution, files = parsed(tmp_path / "inputs")
    with pytest.raises(ValueError, match="^etherchannel_global_owner$"):
        ec.ProtocolOwner.finish_current(seen["owner"], seen["owned"])
    assert hit == [True] and calls == []
    assert object.__getattribute__(seen["owner"], "finished") is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("route", ["pack", "owner"])
@pytest.mark.parametrize("fault", [
    "plan_class", "requests", "indexed", "by_capture", "proofs", "produced",
    "request", "capture", "target", "target_groups", "node_ports", "declaration_value",
    "proof_refs", "result", "parse", "records", "record_fields", "row_fields",
    "members", "spans", "token_value", "span_end", "registration",
    "capture_id", "capture_source", "capture_operation",
])
def test_actual_stp_writer_current_footprint_refuses_before_hooks(tmp_path, monkeypatch, route, fault):
    seen = observe(monkeypatch)
    calls, hit = [], []
    write = FactWriter.write
    def hook(*args, **kwargs):
        calls.append("hook")
        raise AssertionError("opaque current finishing field")
    class Opaque:
        __getattribute__ = hook
    class OpaqueTuple(tuple):
        __iter__ = hook
    class OpaqueDict(dict):
        __iter__ = __getitem__ = __contains__ = hook
    class Equal(str):
        __eq__ = __hash__ = hook
    def writing(self, **kw):
        result = write(self, **kw)
        if not kw["fact"].startswith("l2.stp.") or hit:
            return result
        owner = seen["owner"]
        plan = owner.plan
        request = plan.requests[0]
        value = next(iter(owner.produced.values()))
        row = value.rows[0]
        token = row.fields[0][1]
        target = next(iter(plan.indexed.values()))
        seen["owned"] = tuple(out for out in seen["execution"].executed
            if out.receipt.capture.operation == ec.parse_summary.OP)
        hit.append(True)
        if fault in ("capture_id", "capture_source", "capture_operation"):
            capture = request.capture
            original = next(out for out in seen["owned"] if out.receipt.capture is capture)
            assert original.receipt.capture is capture
            if fault == "capture_id": object.__setattr__(capture, "id", Equal(capture.id))
            elif fault == "capture_source": object.__setattr__(capture, "source", Equal(capture.source))
            else: object.__setattr__(capture, "operation", Equal(capture.operation))
            return result
        if fault == "plan_class":
            changed = type("ChangedPlan", (type(plan),), {"__slots__": (), "__getattribute__": hook})
            object.__setattr__(plan, "__class__", changed)
        elif fault == "requests": object.__setattr__(plan, "requests", OpaqueTuple(plan.requests))
        elif fault == "indexed": object.__setattr__(plan, "indexed", OpaqueDict(plan.indexed))
        elif fault == "by_capture": object.__setattr__(plan, "by_capture", OpaqueDict(plan.by_capture))
        elif fault == "proofs": object.__setattr__(plan, "proofs", OpaqueDict(plan.proofs))
        elif fault == "produced": owner.produced = OpaqueDict(owner.produced)
        elif fault == "request": object.__setattr__(plan, "requests", (Opaque(),))
        elif fault == "capture": object.__setattr__(request, "capture", Opaque())
        elif fault == "target": plan.indexed[next(iter(plan.indexed))] = Opaque()
        elif fault == "target_groups": object.__setattr__(target, "groups", OpaqueTuple(target.groups))
        elif fault == "node_ports": object.__setattr__(target.node, "ports", OpaqueTuple(target.node.ports))
        elif fault == "declaration_value": object.__setattr__(target.node.declaration, "value", Equal(target.node.id))
        elif fault == "proof_refs": plan.proofs[next(iter(plan.proofs))] = OpaqueTuple(next(iter(plan.proofs.values())))
        elif fault == "result": owner.produced[request.capture.id] = Opaque()
        elif fault == "parse": object.__setattr__(value, "parse", Opaque())
        elif fault == "records": object.__setattr__(value.parse, "records", OpaqueTuple(value.parse.records))
        elif fault == "record_fields": object.__setattr__(value.parse.records[0], "fields", OpaqueTuple(value.parse.records[0].fields))
        elif fault == "row_fields": object.__setattr__(row, "fields", OpaqueTuple(row.fields))
        elif fault == "members": object.__setattr__(row, "members", OpaqueTuple(row.members))
        elif fault == "spans": object.__setattr__(row, "spans", OpaqueTuple(row.spans))
        elif fault == "token_value": object.__setattr__(token, "value", Equal(token.raw))
        elif fault == "span_end": object.__setattr__(token.span, "end", Equal("1"))
        else: owner.registration = Equal(owner.registration)
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    pack, execution, files = parsed(tmp_path / "inputs")
    with pytest.raises(ValueError, match="^etherchannel_current_shape$"):
        if route == "pack":
            gp.SummaryPack.finish_current(pack, execution)
        else:
            ec.ProtocolOwner.finish_current(seen["owner"], seen["owned"])
    assert hit == [True] and calls == []
    assert object.__getattribute__(seen["owner"], "finished") is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("field", ["missing_ports", "lines", "tokens"])
def test_unused_peer_metadata_is_not_promoted_to_finishing_authority(tmp_path, monkeypatch, field):
    seen = observe(monkeypatch)
    hit, calls = [], []
    write = FactWriter.write
    class Opaque:
        def __iter__(self):
            calls.append("iteration")
            raise AssertionError("unused metadata read")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"].startswith("l2.stp.") and not hit:
            value = next(iter(seen["owner"].produced.values()))
            hit.append(True)
            object.__setattr__(value if field == "missing_ports" else value.parse, field, Opaque())
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    pack, execution, _ = parsed(tmp_path / "inputs")
    result = gp.SummaryPack.finish_current(pack, execution)
    assert len(result.rows) == 3 and hit == [True] and calls == []
