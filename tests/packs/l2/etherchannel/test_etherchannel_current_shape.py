"""Finite EC finishing fields from actual qualified pipeline objects, never origin seals."""
import pytest
from test_global_protocol_finish import BODY, LIMITS, scenario

from atlas_brain.contract.canonical import canonical
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_pipeline as pipeline


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
    execution = pipeline.execute_p4_folder(root, LIMITS, packs=(tree, pack))
    return tree, pack, execution, files


@pytest.mark.parametrize("mode", ["lacp", "pagp", "dash", "wrapped", "missing", "no_targets"])
def test_original_current_fields_validate_without_replay_or_changing_legacy_facts(tmp_path, monkeypatch, mode):
    tree, pack, execution, files = parsed(tmp_path / "inputs", mode)
    owner = pack.owner
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *_: pytest.fail("shape guard replayed parser"))
    tree.finish(execution)
    assert ec.ProtocolOwner.validate_current(owner) is None
    result = pack.finish(execution)
    assert len(result.rows) == (0 if mode == "no_targets" else 3)
    assert pack.finished is owner.finished is True
    own = tuple(out for out in execution.executed if out.receipt.capture.operation == ec.parse_summary.OP)
    assert all(a.receipt is b.receipt and a.value is b.value for a, b in zip(result.executed, own, strict=True))
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("fault", [
    "plan_class", "requests", "indexed", "by_capture", "proofs", "produced",
    "request", "capture", "target", "target_groups", "node_ports", "declaration_value",
    "proof_refs", "result", "parse", "records", "record_fields", "row_fields",
    "members", "spans", "token_value", "span_end", "registration",
])
def test_actual_stp_writer_current_footprint_refuses_before_hooks(tmp_path, monkeypatch, fault):
    tree, pack, execution, files = parsed(tmp_path / "inputs")
    owner, plan = pack.owner, pack.owner.plan
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
        request = plan.requests[0]
        value = next(iter(owner.produced.values()))
        row = value.rows[0]
        token = row.fields[0][1]
        target = next(iter(plan.indexed.values()))
        hit.append(True)
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
    tree.finish(execution)
    with pytest.raises(ValueError, match="^etherchannel_current_shape$"):
        ec.ProtocolOwner.validate_current(owner)
    assert hit == [True] and calls == [] and owner.finished is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("field", ["missing_ports", "lines", "tokens"])
def test_unused_peer_metadata_is_outside_this_current_read_footprint(tmp_path, monkeypatch, field):
    tree, pack, execution, _files = parsed(tmp_path / "inputs")
    owner = pack.owner
    hit, calls = [], []
    write = FactWriter.write
    class Opaque:
        def __iter__(self):
            calls.append("iteration")
            raise AssertionError("unused metadata read")
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"].startswith("l2.stp.") and not hit:
            value = next(iter(owner.produced.values()))
            hit.append(True)
            object.__setattr__(value if field == "missing_ports" else value.parse, field, Opaque())
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    tree.finish(execution)
    assert ec.ProtocolOwner.validate_current(owner) is None
    assert len(pack.finish(execution).rows) == 3 and hit == [True] and calls == []
