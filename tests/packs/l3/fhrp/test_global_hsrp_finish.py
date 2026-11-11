"""Production three-pack HSRP handoff, framing and owned-store publication boundaries."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_brief import BODY
from test_state_owner import LIMITS, estate

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp


def folder(root, raw=None, mode="normal"):
    estate(root, mode)
    if raw is not None:
        (root / "hsrp.txt").write_bytes(raw)
        side = json.loads((root / "p4.json").read_bytes())
        next(row for row in side["captures"] if row["target"] == "hsrp")["sha256"] = sha256(raw).hexdigest()
        (root / "p4.json").write_bytes(canonical(side))


def run(root):
    peer = gp.StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](LIMITS)
    channel = SummaryPack[stp.stp.Result | b.hsrp.Result](LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(channel, peer))
    return peer, tree


@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
def test_real_three_pack_run_preserves_original_global_leaves_and_guarded_owner(tmp_path, monkeypatch, frame):
    raw = BODY if frame == "body" else b"show standby brief\n" + BODY if frame == "command" else b"fixture#show standby brief\n" + BODY + b"fixture#\n"
    folder(tmp_path, raw)
    fresh = gp.StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](LIMITS)
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        _ = fresh.owner
    peer, tree = run(tmp_path)
    owner = peer.owner
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: pytest.fail("HSRP replay"))
    original = next(out for out in tree.execution.executed if out.receipt.capture.operation == b.hsrp.OP)
    result = peer.finish(replace(tree.execution, executed=tuple(replace(out) for out in reversed(tree.execution.executed))))
    assert peer.owner is owner and len(tree.execution.executed) == 3 and len(result.rows) == 5
    assert result.executed[0].receipt is original.receipt and result.executed[0].value is original.value
    assert result.executed[0].receipt.registration_sha256 == tree.execution.envelope.registration_sha256
    assert all(len(tuple(ref for ref in row.value.evidence if type(ref) is k.RegistryRef)) == 3 for row in result.rows)
    with pytest.raises(AttributeError):
        peer.owner = owner
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        peer.finish(tree.execution)


@pytest.mark.parametrize("plant", [
    "envelope", "missing", "duplicate", "shape", "capture", "value", "parse", "foreign_missing", "foreign_duplicate", "foreign_shape", "foreign_id",
    *[side + "_" + field for side in ("own", "foreign") for field in ("owner", "context", "registration", "source", "operation", "raw")],
])
def test_whole_ledger_and_cached_leaves_refuse_before_hsrp_writer_then_retry(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    peer, tree = run(tmp_path)
    execution, outputs = tree.execution, tree.execution.executed
    item = next(out for out in outputs if (out.receipt.capture.operation == b.hsrp.OP) == (not plant.startswith("foreign_")))
    selected = item
    if plant == "envelope":
        execution = replace(execution, envelope=replace(execution.envelope))
    elif plant in ("missing", "duplicate", "foreign_missing", "foreign_duplicate"):
        execution = replace(execution, executed=tuple(out for out in outputs if out is not item) if plant.endswith("missing") else outputs + (item,))
    else:
        if plant.endswith("shape"):
            item = replace(item, receipt=object())
        elif plant == "capture":
            item = replace(item, receipt=replace(item.receipt, capture=replace(item.receipt.capture)))
        elif plant == "value":
            item = replace(item, value=replace(item.value))
        elif plant == "parse":
            item = replace(item, receipt=replace(item.receipt, parse=replace(item.receipt.parse)))
        else:
            field = plant.split("_", 1)[1]
            changes = {"owner": {"owner": stp.STEP.id if item.receipt.owner == b.STEP.id else b.STEP.id},
                "context": {"context": "wrong"}, "registration": {"registration_sha256": "0" * 64},
                "source": {"capture": replace(item.receipt.capture, source=k.EntityKey("node:wrong"))},
                "operation": {"capture": replace(item.receipt.capture, operation=stp.stp.OP if item.receipt.capture.operation == b.hsrp.OP else b.hsrp.OP)},
                "raw": {"capture": replace(item.receipt.capture, raw=item.receipt.capture.raw + b"changed")},
                "id": {"capture": replace(item.receipt.capture, id=k.CaptureId("cap:extra"))}}[field]
            item = replace(item, receipt=replace(item.receipt, **changes))
        execution = replace(execution, executed=tuple(item if out is selected else out for out in outputs))
    code = ("run" if plant == "envelope" else "coverage" if plant in ("missing", "duplicate", "foreign_missing", "foreign_duplicate", "foreign_id") else
            "capture" if plant == "capture" else "value" if plant in ("value", "parse") else "receipt")
    with monkeypatch.context() as guard:
        guard.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before full global ledger"))
        with pytest.raises(ValueError, match="^hsrp_global_" + code + "$"):
            peer.finish(execution)
    assert len(peer.finish(tree.execution).rows) == 5


def test_foreign_value_that_looks_like_hsrp_stays_opaque(tmp_path):
    folder(tmp_path)
    peer, tree = run(tmp_path)
    own = next(out for out in tree.execution.executed if out.receipt.capture.operation == b.hsrp.OP)
    outputs = tuple(replace(out, value=own.value, receipt=replace(out.receipt, capture=replace(out.receipt.capture))) if out.receipt.capture.operation != b.hsrp.OP else out for out in tree.execution.executed)
    assert len(peer.finish(replace(tree.execution, executed=outputs)).rows) == 5


@pytest.mark.parametrize("plant", ["member_id", "member_raw", "target_params", "context_ref"])
def test_prepare_failure_publishes_no_owner_and_consumes_the_single_attempt(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    _, tree = run(tmp_path)
    envelope = tree.execution.envelope
    if plant.startswith("member_"):
        member = next(member for member in envelope.captures if member.target.operation == b.hsrp.OP)
        changed = replace(member, **({"id": k.CaptureId("cap:wrong")} if plant == "member_id" else {"raw": member.raw + b"X"}))
        envelope = replace(envelope, captures=tuple(changed if item is member else item for item in envelope.captures))
    elif plant == "target_params":
        target = next(target for target in envelope.targets if target.operation == b.hsrp.OP)
        changed = replace(target, params=canonical({"groups": [["Vl10", "2"]]}))
        envelope = replace(envelope, targets=tuple(changed if item is target else item for item in envelope.targets))
    else:
        ref, = envelope.declaration.evidence
        envelope = replace(envelope, declaration=replace(envelope.declaration, evidence=(replace(ref, citation="/wrong"),)))
    peer = gp.StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](LIMITS)
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: pytest.fail("prepare parsed HSRP"))
    with pytest.raises(ValueError, match="^hsrp_folder_"):
        peer.prepare(envelope)
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        _ = peer.owner
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        peer.prepare(tree.execution.envelope)


def test_late_prepared_constructor_failure_does_not_publish_constructed_owner(tmp_path, monkeypatch):
    folder(tmp_path)
    _, tree = run(tmp_path)
    peer = gp.StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](LIMITS)
    made, constructor = [], b.StateOwner
    def traced(*args):
        result = constructor(*args)
        made.append(result)
        return result
    monkeypatch.setattr(b, "StateOwner", traced)
    monkeypatch.setattr(gp.p4_pipeline.Prepared, "__init__", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("late_prepared")))
    with pytest.raises(RuntimeError, match="^late_prepared$"):
        peer.prepare(tree.execution.envelope)
    assert len(made) == 1
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        _ = peer.owner


@pytest.mark.parametrize("raw,reason", [
    (b"", k.UnknownReason.EMPTY_UNREGISTERED), (b"show standby brief\n", k.UnknownReason.EMPTY_UNREGISTERED),
    *[(b"fixture#show standby brief\n" + BODY + marker, reason)
      for marker, reason in ((b"% Invalid input\n", k.UnknownReason.CAPTURE_ERROR),
                             (b"--More--\n", k.UnknownReason.CAPTURE_TRUNCATED), (b"[truncated]\n", k.UnknownReason.CAPTURE_TRUNCATED))],
])
def test_real_transport_damage_preserves_unknown_rows_and_declared_population(tmp_path, raw, reason):
    folder(tmp_path, raw)
    peer, tree = run(tmp_path)
    result = peer.finish(tree.execution)
    assert len(result.rows) == 5 and all(row.value.reason is reason for row in result.rows if row.target.node.id == "a")


@pytest.mark.parametrize("raw,code", [(b"interface Vlan10\n", "frame"), (b"fixture#show version\n", "frame"),
    (b"\xff", "text"), (b"bad\rline", "text"), (b"bad\x00line", "text")])
def test_late_raw_transport_fault_precedes_all_three_parsers(tmp_path, monkeypatch, raw, code):
    folder(tmp_path, raw)
    for module in (b.hsrp, stp.stp, ec.parse_summary):
        monkeypatch.setattr(module, "parse_capture", lambda *args: pytest.fail("parser before transport closure"))
    with pytest.raises(ValueError, match="^hsrp_folder_" + code + "$"):
        run(tmp_path)


@pytest.mark.parametrize("mode", ["no_targets", "no_captures"])
def test_zero_own_scope_and_capture_loss_keep_honest_denominators(tmp_path, mode):
    folder(tmp_path, mode=mode)
    peer, tree = run(tmp_path)
    result = peer.finish(tree.execution)
    assert len(result.rows) == (0 if mode == "no_targets" else 5) and result.executed == ()
    assert all(row.value.reason is k.UnknownReason.NOT_COLLECTED for row in result.rows)
