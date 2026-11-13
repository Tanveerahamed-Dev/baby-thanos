"""Owning GLOBAL VIP producer controls; no whole-source admission or gateway claim."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_gateway_source import LIMITS, folder, subject
from test_reported_virtual_ip import token_plant

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactReader, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.runner import p4_pipeline as pipe

VIP, STATE = "l3.fhrp.reported_virtual_ip", "l3.fhrp.reported_state"
READ = StepSpec(id=StepId("l3.fhrp/test_virtual_ip_owner"), pack=b.PACK, kind="check", scope="estate",
    reads=(VIP,), produces=(), evaluator="l3.fhrp.test_virtual_ip_owner")


def inputs(root, mode="normal"):
    files = folder(root, "both" if mode == "zero" else None)
    side = json.loads(files["p4.json"])
    if mode == "zero":
        side["targets"] = [row for row in side["targets"] if row["operation"] != b.hsrp.OP]
    elif mode == "unknown":
        files["hsrp.txt"] = files["hsrp.txt"].replace(b"192.0.2.1\n", b"unknown\n")
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (root / name).write_bytes(raw)


def run(root):
    channel, standby = SummaryPack(LIMITS), gp.VirtualIpPack(LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(channel, standby))
    channel.finish(tree.execution)
    state = standby.finish(tree.execution)
    domains = standby.owner.validate_gateway_source_values(state, bind_reader(state.store, step=b.SOURCE_STEP), tree.execution.executed)
    result = standby.virtual_ip_owner.build_virtual_ip()
    standby.virtual_ip_owner.validate_virtual_ip_values(result, bind_reader(result.store, step=READ))
    return standby, tree, result, domains


@pytest.mark.parametrize("mode", ["normal", "unknown", "zero"])
def test_real_registered_batch_original_cache_state_reader_and_literal_vip_population(tmp_path, monkeypatch, mode):
    inputs(tmp_path / "inputs", mode)
    compile_packs, execute, parse, read, write = pipe.compile_packs, pipe.execute_parsers, b.hsrp.parse_capture, FactReader.read, FactWriter.write
    compiled, batches, parsed, reads = [], [], [], []
    fixed = (stp.DECLARATION, ec.DECLARATION, b.VIP_DECLARATION)
    def compiling(declarations):
        result = compile_packs(declarations)
        compiled.append((declarations, result.registration_sha256))
        return result
    def executing(declarations, *args):
        assert compiled and compiled[0][0] == declarations == fixed
        result = execute(declarations, *args)
        batches.append(result)
        return result
    def parsing(capture):
        result = parse(capture)
        parsed.append((capture, result))
        return result
    def reading(self, **kwargs):
        value = read(self, **kwargs)
        if self.step is b.VIP_STEP:
            assert kwargs["fact"] == STATE
            reads.append((self.store, kwargs["subject"], value))
        return value
    def writing(self, **kwargs):
        if kwargs["fact"] == VIP:
            assert len({subject for _, subject, _ in reads}) == 6 and len(parsed) == 2
        return write(self, **kwargs)
    monkeypatch.setattr(pipe, "compile_packs", compiling)
    monkeypatch.setattr(pipe, "execute_parsers", executing)
    monkeypatch.setattr(b.hsrp, "parse_capture", parsing)
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(FactWriter, "write", writing)
    peer, tree, result, domains = run(tmp_path / "inputs")
    source = result.source
    assert len(batches) == 1 and batches[0] is tree.execution.executed and len(parsed) == (0 if mode == "zero" else 2)
    assert len(result.rows) == len(result.store.values) == len(source.rows) == len(source.store.values) == (0 if mode == "zero" else 6)
    assert result.registration_sha256 == tree.execution.envelope.registration_sha256 == compiled[0][1]
    assert source.store.owners == {STATE: b.STEP.id} and result.store.owners == {VIP: b.VIP_STEP.id}
    assert {domain.node.id for domain in domains} == (set() if mode == "zero" else {"a", "b"})
    assert all(peer.owner.produced[capture.id] is value and any(out.receipt.capture is capture and out.value is value
        and out.receipt.parse is value.parse for out in source.executed) for capture, value in parsed)
    assert all(store is source.store and value is source.store.values[k.FactRef(fact=STATE, subject=subject)] for store, subject, value in reads)
    expected = {("a", "Vl20"): "203.0.113.1", ("a", "Vl10"): "192.0.2.1", ("a", "BD3329"): "198.51.100.1", ("b", "BD10"): "192.0.2.99"}
    for row in result.rows:
        original = next(item for item in source.rows if item.subject == row.subject)
        assert row.target is original.target and row.target is next(domain for domain in domains if domain.node is row.target.node)
        assert row.subject == subject(row.target.node.id, row.interface, row.group)
        assert result.store.values[k.FactRef(fact=VIP, subject=row.subject)] is row.value
        key = row.target.node.id, row.interface
        if key not in expected or mode == "unknown" and key == ("a", "Vl10"):
            assert type(row.value) is k.Unknown and row.value.reason is (
                k.UnknownReason.NOT_OBSERVABLE if key in expected else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE)
            need, = row.value.next_evidence
            assert (need.resolves, need.reruns, need.unprintable) == ((VIP,), (b.VIP_STEP.id,), ("reported_virtual_ip",))
        else:
            assert type(row.value) is k.Known and type(row.value.value) is str
            assert (row.value.value, row.value.raw, row.value.basis) == (expected[key], expected[key], k.Basis.OBSERVED)


@pytest.mark.parametrize("plant,code", [("cache", "hsrp_global_value"), ("token", "hsrp_vip_value"), ("bool", "hsrp_vip_value"),
    ("raw", "hsrp_witness"), ("column", "hsrp_witness"), ("association", "hsrp_record"), ("kind", "hsrp_value"),
    ("append", "stp_global_receipt"), ("retarget", "stp_global_receipt"),
    ("original_request", "pack_receipts_retention_mismatch"), ("original_capture", "pack_receipts_retention_mismatch")])
def test_late_second_hsrp_fault_refuses_before_both_fhrp_writers(tmp_path, monkeypatch, plant, code):
    inputs(tmp_path / "inputs")
    execute = pipe.execute_parsers
    def changed(declarations, handlers, requests):
        outputs = execute(declarations, handlers, requests)
        own = tuple(out for out in outputs if out.receipt.capture.operation == b.hsrp.OP)
        assert len(own) == 2
        output = own[-1]
        owner = next(handler.parser for handler in handlers if handler.binding.operation == b.hsrp.OP)
        if plant == "cache":
            owner.produced[output.receipt.capture.id] = replace(output.value)
        elif plant in ("append", "retarget"):
            field, value = ("raw", output.receipt.capture.raw + b"not parsed\n") if plant == "append" else (
                "source", own[0].receipt.capture.source)
            object.__setattr__(output.receipt.capture, field, value)
        elif plant.startswith("original_"):
            request = next(item for item in owner.plan.requests if item.capture.id == output.receipt.capture.id)
            object.__setattr__(request, "context" if plant == "original_request" else "capture",
                "changed" if plant == "original_request" else replace(request.capture))
        else:
            row = output.value.rows[-1]
            if plant == "kind":
                object.__setattr__(row.virtual_ip, "kind", "unknown")
            else:
                token = replace(row.virtual_ip.token, **({"value": False if plant == "bool" else "192.0.2.254"} if plant in ("token", "bool")
                    else {"raw": "192.0.2.254"} if plant == "raw" else {"span": row.state.span}))
                if plant == "association":
                    object.__setattr__(row.virtual_ip, "token", token)
                else:
                    forged = token_plant(output, row, token)
                    outputs = tuple(forged if item is output else item for item in outputs)
        return outputs
    monkeypatch.setattr(pipe, "execute_parsers", changed)
    monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("FHRP writer before all original inputs closed"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        run(tmp_path / "inputs")


def test_actual_state_reader_identity_refuses_before_vip_writer(tmp_path, monkeypatch):
    inputs(tmp_path / "inputs")
    read, writer = FactReader.read, b.bind_writer
    monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)) if self.step is b.VIP_STEP else read(self, **kwargs))
    monkeypatch.setattr(b, "bind_writer", lambda store, *, step: writer(store, step=step) if step is b.STEP else pytest.fail("VIP writer before actual STATE identity"))
    with pytest.raises(ValueError, match="^hsrp_vip_source$"):
        run(tmp_path / "inputs")


@pytest.mark.parametrize("plant", ["reads", "produces", "evaluator", "type", "missing"])
@pytest.mark.parametrize("mode", ["normal", "zero"])
def test_fixed_literal_profile_drift_refuses_before_any_parser_or_fhrp_writer(tmp_path, monkeypatch, plant, mode):
    inputs(tmp_path / "inputs", mode)
    declaration, step = b.VIP_DECLARATION, b.VIP_STEP
    if plant in ("type", "missing"):
        facts = tuple(replace(fact, value_type="boolean") if fact.id == VIP else fact for fact in declaration.facts)
        declaration = replace(declaration, facts=declaration.facts[:1] if plant == "missing" else facts)
    else:
        step = replace(step, **{"reads": {"reads": ()}, "produces": {"produces": ()}, "evaluator": {"evaluator": "l3.fhrp.other"}}[plant])
        declaration = replace(declaration, steps=(b.STEP, step))
    monkeypatch.setattr(b, "VIP_DECLARATION", declaration)
    monkeypatch.setattr(b, "VIP_STEP", step)
    for module in (b.hsrp, stp.stp, ec.parse_summary):
        monkeypatch.setattr(module, "parse_capture", lambda *_: pytest.fail("parser before fixed full profile"))
    monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("writer before fixed full profile"))
    with pytest.raises(ValueError):
        run(tmp_path / "inputs")


@pytest.mark.parametrize("side,plant", [(side, plant) for side in ("state", "vip") for plant in (
    "rows", "duplicate", "missing_cell", "store_identity", "value", "raw", "basis", "false_unknown", "reason", "need", "reader")]
    + [("vip", "registration"), ("vip", "source")])
def test_state_and_vip_canonical_store_population_and_every_value_close_in_owning_validator(tmp_path, monkeypatch, side, plant):
    inputs(tmp_path / "inputs")
    build, finish, read = b.VirtualIpOwner.build_virtual_ip, gp.VirtualIpPack.finish, FactReader.read
    fact = STATE if side == "state" else VIP
    def changed(result):
        row = next(row for row in reversed(result.rows) if (type(row.value) is k.Unknown) == (plant in ("reason", "need")))
        reference = k.FactRef(fact=fact, subject=row.subject)
        if plant == "reader":
            monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)) if kwargs["fact"] == fact else read(self, **kwargs))
            return result
        if plant == "rows":
            return replace(result, rows=result.rows[:-1])
        if plant == "duplicate":
            return replace(result, rows=result.rows + (result.rows[-1],))
        if plant in ("registration", "source"):
            return replace(result, **({"registration_sha256": "0" * 64} if plant == "registration" else {"source": replace(result.source)}))
        if plant == "missing_cell":
            result.store.values.pop(reference)
        elif plant == "store_identity":
            result.store.values[reference] = replace(row.value)
        else:
            if plant == "false_unknown":
                forged = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="forged", evidence=row.value.evidence, candidates=(), next_evidence=())
            else:
                changes = {"value": {"value": "192.0.2.254"}, "raw": {"raw": "192.0.2.254"}, "basis": {"basis": k.Basis.DECLARED},
                    "reason": {"reason": k.UnknownReason.NOT_COLLECTED}, "need": {"next_evidence": ()}}[plant]
                forged = replace(row.value, **changes)
            result.store.values[reference] = forged
            return replace(result, rows=tuple(replace(item, value=forged) if item is row else item for item in result.rows))
        return result
    if side == "vip":
        monkeypatch.setattr(b.VirtualIpOwner, "build_virtual_ip", lambda self: changed(build(self)))
    else:
        monkeypatch.setattr(gp.VirtualIpPack, "finish", lambda self, execution: changed(finish(self, execution)))
    with pytest.raises(ValueError):
        run(tmp_path / "inputs")


@pytest.mark.parametrize("plant", ["raw_append", "cold_retarget", "request_context", "capture_clone",
    "request_clone", "line_text", "codec", "integrity"])
def test_inner_owner_original_snapshot_refuses_after_outer_ledgers_before_both_fhrp_writers(tmp_path, monkeypatch, plant):
    inputs(tmp_path / "inputs")
    finish = b.VirtualIpOwner.finish
    entered = []
    def changed(self, executed):
        request = next(item for item in self.plan.requests if item.capture.source == k.EntityKey("node:demo:b"))
        capture = request.capture
        entered.append(capture.id)
        if plant == "raw_append":
            object.__setattr__(capture, "raw", capture.raw + b"unparsed appendix\n")
        elif plant == "cold_retarget":
            object.__setattr__(capture, "source", k.EntityKey("node:demo:a"))
        elif plant == "request_context":
            object.__setattr__(request, "context", "changed")
        elif plant == "capture_clone":
            object.__setattr__(request, "capture", replace(capture))
        elif plant == "request_clone":
            self.plan = replace(self.plan, requests=tuple(replace(item) if item is request else item for item in self.plan.requests))
        elif plant == "line_text":
            object.__setattr__(capture.lines[0], "text", "changed")
        elif plant == "codec":
            object.__setattr__(capture, "codec", "ascii")
        else:
            object.__setattr__(capture, "integrity", k.IntegrityState.UNKNOWN_FORMAT)
        return finish(self, executed)
    monkeypatch.setattr(b.VirtualIpOwner, "finish", changed)
    monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("FHRP writer before inner-owner snapshot closure"))
    with pytest.raises(ValueError, match="^pack_receipts_retention_mismatch$"):
        run(tmp_path / "inputs")
    assert len(entered) == 1


def test_failed_prepared_construction_never_publishes_global_vip_owner(tmp_path, monkeypatch):
    inputs(tmp_path / "inputs")
    envelope = run(tmp_path / "inputs")[1].execution.envelope
    peer = gp.VirtualIpPack(LIMITS)
    def refused(*_a, **_k):
        raise RuntimeError("late_prepared")
    monkeypatch.setattr(pipe.Prepared, "__init__", refused)
    with pytest.raises(RuntimeError, match="^late_prepared$"):
        peer.prepare(envelope)
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        _ = peer.owner
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        _ = peer.virtual_ip_owner
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        peer.prepare(envelope)
