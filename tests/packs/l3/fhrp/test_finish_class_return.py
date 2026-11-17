"""Actual final HSRP Writer class drift must refuse before finish tail hooks."""
import pytest
from test_trusted_finish import parsed

from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack


@pytest.mark.parametrize("vip", [False, True])
@pytest.mark.parametrize("missing", [None, "hsrp", "both"])
def test_unchanged_finish_keeps_original_outputs_and_vip_source(tmp_path, monkeypatch, vip, missing):
    tree, channel, pack, execution, _budgets, files = parsed(tmp_path / "inputs", vip, missing)
    owner = pack.owner
    original = tuple(out for out in execution.executed if out.receipt.capture.operation == state.hsrp.OP)
    monkeypatch.setattr(state.hsrp, "parse_capture", lambda *_: pytest.fail("finish replayed parser"))
    tree.finish(execution)
    channel.finish(execution)
    result = StandbyBriefPack.finish(pack, execution)
    assert pack.finished is owner.finished is True
    assert len(result.rows) == len(result.store.values) == 6
    assert all(a.receipt is b.receipt and a.value is b.value
               for a, b in zip(result.executed, original, strict=True))
    if vip:
        assert owner.source is result
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("vip", [False, True])
@pytest.mark.parametrize("target", ["owner", "pack"])
@pytest.mark.parametrize("hook", ["__getattribute__", "__setattr__"])
def test_final_actual_writer_class_drift_refuses_before_tail_lookup_or_assignment(
    tmp_path, monkeypatch, vip, target, hook,
):
    tree, channel, pack, execution, _budgets, files = parsed(tmp_path / "inputs", vip)
    owner = pack.owner
    receiver = owner if target == "owner" else pack
    calls, hit, subjects = [], [], set()
    def getting(self, name):
        calls.append(("get", name))
        raise AssertionError("changed finish receiver read")
    def setting(self, name, value):
        calls.append(("set", name))
        raise AssertionError("changed finish receiver write")
    changed = type("ChangedFinish", (type(receiver),),
                   {"__slots__": (), hook: getting if hook == "__getattribute__" else setting})
    write = FactWriter.write
    def writing(self, **kw):
        result = write(self, **kw)
        if kw["fact"] == state.REPORTED_STATE:
            subjects.add(kw["subject"])
            if len(subjects) == 6 and not hit:
                hit.append(True)
                object.__setattr__(receiver, "__class__", changed)
        return result
    monkeypatch.setattr(FactWriter, "write", writing)
    tree.finish(execution)
    channel.finish(execution)
    with pytest.raises(ValueError, match="^hsrp_(global_run|global_owner)$"):
        StandbyBriefPack.finish(pack, execution)
    assert hit == [True] and len(subjects) == 6 and calls == []
    assert object.__getattribute__(receiver, "finished") is False
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files
