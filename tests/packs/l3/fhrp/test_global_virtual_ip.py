"""Fresh fixed GLOBAL VIP source controls; no gateway policy, health or acceptance."""
import json
from dataclasses import replace
from hashlib import sha256
from ipaddress import IPv4Address

import pytest
from test_gateway_source import LIMITS, folder, subject

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.runner import p4_fhrp_policy as runner

VIP, STATE = "l3.fhrp.reported_virtual_ip", "l3.fhrp.reported_state"
prepare = runner.prepare_fhrp_virtual_ip_source


def inputs(root, mode="normal"):
    files = folder(root, "both" if mode == "zero" else mode if mode in ("hsrp", "hsrp-cold", "both") else None)
    side = json.loads(files["p4.json"])
    if mode == "zero":
        side["targets"] = [row for row in side["targets"] if row["operation"] != b.hsrp.OP]
    elif mode in ("partial", "duplicate", "unknown", "zero_address"):
        raw = files["hsrp.txt"]
        if mode == "partial":
            raw += b"unrecognised\n"
        elif mode == "duplicate":
            raw += next(line for line in raw.splitlines(keepends=True) if line.startswith(b"Vl10 "))
        else:
            raw = raw.replace(b"192.0.2.1\n", ("unknown" if mode == "unknown" else str(IPv4Address(0))).encode() + b"\n")
        files["hsrp.txt"] = raw
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


@pytest.mark.parametrize("mode", ["normal", "hsrp", "hsrp-cold", "both", "zero", "partial", "duplicate", "unknown", "zero_address"])
def test_canonical_populations_values_and_exact_vip_column_proofs(tmp_path, mode):
    files = inputs(tmp_path / "inputs", mode)
    result = prepare(tmp_path / "inputs", LIMITS)
    vip, state, index = result.source, result.source.source, result.proofs
    assert len(vip.rows) == len(vip.store.values) == len(state.rows) == len(state.store.values) == (0 if mode == "zero" else 6)
    assert vip.store.owners == {VIP: b.VIP_STEP.id} and state.store.owners == {STATE: b.STEP.id}
    assert vip.registration_sha256 == result.execution.envelope.registration_sha256
    assert index.execution is result.execution and index.virtual_ip_reader.store is vip.store
    assert len([scope for scope in index.scopes if scope.reference.fact == VIP]) == len(vip.rows)
    assert len(index.scopes) == (14 if mode == "zero" else 26) and len(result.domains) == (0 if mode == "zero" else 2)
    expected = {("a", "Vl20"): "203.0.113.1", ("a", "Vl10"): "192.0.2.1", ("a", "BD3329"): "198.51.100.1", ("b", "BD10"): "192.0.2.99"}
    missing = {"a", "b"} if mode == "both" else {"a"} if mode == "hsrp" else {"b"} if mode == "hsrp-cold" else set()
    for row in vip.rows:
        key = row.target.node.id, row.interface
        original = next(item for item in state.rows if item.subject == row.subject)
        assert row.subject == subject(row.target.node.id, row.interface, row.group) and row.target is original.target
        assert row.target is next(domain for domain in result.domains if domain.node is row.target.node)
        assert vip.store.values[k.FactRef(fact=VIP, subject=row.subject)] is row.value
        assert state.store.values[k.FactRef(fact=STATE, subject=row.subject)] is original.value
        leaves = index.resolve_virtual_ip_reference(k.FactRef(fact=VIP, subject=row.subject))
        assert len(leaves) == len(row.value.evidence)
        reason = (k.UnknownReason.NOT_COLLECTED if key[0] in missing else
            k.UnknownReason.PARSE_PARTIAL if mode == "partial" and key[0] == "a" else
            k.UnknownReason.CONFLICTING_EVIDENCE if mode == "duplicate" and key[0] == "a" else
            k.UnknownReason.NOT_OBSERVABLE if mode == "unknown" and key == ("a", "Vl10") else
            k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE if key not in expected else None)
        if reason is not None:
            assert type(row.value) is k.Unknown and row.value.reason is reason and row.value.detail == "hsrp_virtual_ip_unresolved"
            need, = row.value.next_evidence
            assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.unprintable) == (
                row.target.node.key, b.hsrp.OP, (("group", row.group), ("interface", row.interface)), (VIP,), (b.VIP_STEP.id,), ("reported_virtual_ip",))
            if reason is k.UnknownReason.NOT_OBSERVABLE:
                raw = files["hsrp.txt"]
                line = next(line for line in raw.splitlines(keepends=True) if line.startswith(b"Vl10 "))
                refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
                start, anchor = raw.index(line), raw.index(line) + line.rindex(b"unknown")
                assert {(ref.locator.start, ref.locator.end) for ref in refs} == {(start, start + len(line.rstrip(b"\r\n"))), (anchor, anchor + 7)}
                assert all(ref.role is k.EvidenceRole.WITNESS for ref in refs)
            continue
        printed = str(IPv4Address(0)) if mode == "zero_address" and key == ("a", "Vl10") else expected[key]
        assert type(row.value) is k.Known and type(row.value.value) is str
        assert (row.value.value, row.value.raw, row.value.basis) == (printed, printed, k.Basis.OBSERVED)
        capture = next(out.receipt.capture for out in state.executed if out.receipt.capture.source == row.target.node.key)
        raw = capture.raw
        line = next(line for line in raw.splitlines(keepends=True) if line.startswith(row.interface.encode() + b" "))
        start, group, anchor = raw.index(line), line.index(row.group.encode(), len(row.interface)), line.rindex(printed.encode())
        points = {(start, start + len(row.interface)), (start + group, start + group + len(row.group)),
            (start, start + len(line.rstrip(b"\r\n"))), (start + anchor, start + anchor + len(printed))}
        refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        assert {(ref.locator.start, ref.locator.end) for ref in refs} == points
        assert all(ref.capture == capture.id and ref.role is k.EvidenceRole.SUBJECT
            and ref.excerpt_sha256 == sha256(raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
        scope = index.scope(VIP, row.subject)
        assert scope.required == scope.spans == frozenset((capture.id, k.ByteSpan(start=a, end=z)) for a, z in points)
        assert scope.positive == frozenset(((capture.id, k.ByteSpan(start=start + anchor, end=start + anchor + len(printed))),))
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("mode", ["normal", "zero"])
def test_full_registration_before_any_parser_one_fresh_run_and_actual_state_reader(tmp_path, monkeypatch, mode):
    inputs(tmp_path / "inputs", mode)
    pipe, fixed = runner.p4_pipeline, (runner.stp.DECLARATION, runner.ec.DECLARATION, b.VIP_DECLARATION)
    compile_packs, execute, read, write = pipe.compile_packs, pipe.execute_p4_folder, FactReader.read, FactWriter.write
    compiled, runs, parsed, reads, finishes = [], [], [], [], []
    def compiling(declarations):
        result = compile_packs(declarations)
        compiled.append((declarations, result.registration_sha256))
        return result
    def executing(*args, **kwargs):
        result = execute(*args, **kwargs)
        runs.append(result)
        return result
    def reading(self, **kwargs):
        value = read(self, **kwargs)
        if self.step is b.VIP_STEP:
            assert kwargs["fact"] == STATE
            reads.append((self.store, kwargs["subject"], value))
        return value
    def writing(self, **kwargs):
        if kwargs["fact"] in (STATE, VIP):
            assert len([capture for capture, _ in parsed if capture.operation == b.hsrp.OP]) == 2
        if kwargs["fact"] == VIP:
            assert len({subject for _, subject, _ in reads}) == 6
        return write(self, **kwargs)
    for module in (b.hsrp, runner.stp.stp, runner.ec.parse_summary):
        parse = module.parse_capture
        def parsing(capture, *args, original=parse, **kwargs):
            assert compiled and compiled[0][0] == fixed
            result = original(capture, *args, **kwargs)
            parsed.append((capture, result))
            return result
        monkeypatch.setattr(module, "parse_capture", parsing)
    for capsule in (runner.stp._GlobalSTP, runner.SummaryPack, runner.VirtualIpPack):
        finish = capsule.finish
        def finishing(self, execution, original=finish):
            finishes.append(execution)
            return original(self, execution)
        monkeypatch.setattr(capsule, "finish", finishing)
    monkeypatch.setattr(pipe, "compile_packs", compiling)
    monkeypatch.setattr(pipe, "execute_p4_folder", executing)
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(FactWriter, "write", writing)
    first = prepare(tmp_path / "inputs", LIMITS)
    assert len(runs) == 1 and first.execution is runs[0]
    assert len(parsed) == len(first.execution.executed) == len({capture.id for capture, _ in parsed})
    assert len(finishes) == 3 and all(execution is first.execution for execution in finishes)
    assert all(any(output.receipt.capture is capture and output.value is value and output.receipt.parse is value.parse
        for output in first.execution.executed) for capture, value in parsed)
    assert first.source.registration_sha256 == compiled[0][1]
    assert all(store is first.source.source.store and value is first.source.source.store.values[k.FactRef(fact=STATE, subject=subject)]
        for store, subject, value in reads)
    monkeypatch.setattr(FactWriter, "write", write)
    second = prepare(tmp_path / "inputs", LIMITS)
    assert len(runs) == 2 and second.execution is not first.execution and second.source is not first.source
    assert b.VIP_STEP.reads == (STATE,) and b.VIP_STEP.produces == (VIP,)


@pytest.mark.parametrize("plant", ["owner", "context", "registration", "raw", "missing", "duplicate", "clone_value", "clone_parse"])
@pytest.mark.parametrize("operation", ["stp", "ec", "hsrp"])
def test_every_peer_receipt_and_original_payload_closes_before_return(tmp_path, monkeypatch, plant, operation):
    inputs(tmp_path / "inputs")
    execute = runner.p4_pipeline.execute_parsers
    selected = {"stp": runner.stp.stp.OP, "ec": runner.ec.parse_summary.OP, "hsrp": b.hsrp.OP}[operation]
    def changed(*args):
        outputs = execute(*args)
        out = next(item for item in outputs if item.receipt.capture.operation == selected)
        if plant == "missing":
            return tuple(item for item in outputs if item is not out)
        if plant == "duplicate":
            return outputs + (out,)
        if plant == "clone_value":
            forged = replace(out, value=replace(out.value))
        else:
            changes = {"owner": {"owner": "planted/owner"}, "context": {"context": "planted"},
                "registration": {"registration_sha256": "0" * 64}, "raw": {"capture": replace(out.receipt.capture, raw=out.receipt.capture.raw + b"changed")},
                "clone_parse": {"parse": replace(out.receipt.parse)}}[plant]
            forged = replace(out, receipt=replace(out.receipt, **changes))
        return tuple(forged if item is out else item for item in outputs)
    monkeypatch.setattr(runner.p4_pipeline, "execute_parsers", changed)
    monkeypatch.setattr(runner.FhrpVirtualIpSource, "__init__", lambda *_a, **_k: pytest.fail("carrier before every peer receipt"))
    with pytest.raises(ValueError):
        prepare(tmp_path / "inputs", LIMITS)


@pytest.mark.parametrize("owner", ["stp", "ec", "hsrp"])
@pytest.mark.parametrize("fault", ["completion", "store", "reader", "proof"])
def test_all_peer_completion_store_reader_and_leaf_proofs_precede_carrier(tmp_path, monkeypatch, owner, fault):
    inputs(tmp_path / "inputs")
    original_read = FactReader.read
    def changed(result):
        if fault == "completion":
            raise ValueError("planted_peer_failure")
        if fault == "store":
            result.store.owners.clear()
        elif fault == "reader":
            def reading(self, **kwargs):
                value = original_read(self, **kwargs)
                return replace(value) if self.store is result.store else value
            monkeypatch.setattr(FactReader, "read", reading)
        else:
            row = next(row for row in result.rows if type(row.value) is k.Known)
            point = next(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            forged = replace(row.value, evidence=tuple(replace(ref, excerpt_sha256="0" * 64) if ref is point else ref for ref in row.value.evidence))
            reference = next(ref for ref, value in result.store.values.items() if value is row.value)
            result.store.values[reference] = forged
            result = replace(result, rows=tuple(replace(item, value=forged) if item is row else item for item in result.rows))
        return result
    if fault == "completion":
        if owner == "stp":
            finish = runner.stp.build_root_guard_global
            def finishing(*args, **kwargs):
                tree = finish(*args, **kwargs)
                return replace(tree, result=changed(tree.result))
            monkeypatch.setattr(runner.stp, "build_root_guard_global", finishing)
        else:
            capsule = runner.SummaryPack if owner == "ec" else runner.VirtualIpPack
            finish = capsule.finish
            monkeypatch.setattr(capsule, "finish", lambda self, execution: changed(finish(self, execution)))
    else:
        close = runner.observations.close_owned_facts
        def closing(index, tree, channel, state):
            results = [tree, channel, state]
            results[("stp", "ec", "hsrp").index(owner)] = changed(results[("stp", "ec", "hsrp").index(owner)])
            return close(index, *results)
        monkeypatch.setattr(runner.observations, "close_owned_facts", closing)
    monkeypatch.setattr(runner.FhrpVirtualIpSource, "__init__", lambda *_a, **_k: pytest.fail("carrier before peer closure"))
    code = "planted_peer_failure" if fault == "completion" else "p4_projection_span" if fault == "proof" else "p4_observations_store"
    with pytest.raises(ValueError, match="^" + code + "$"):
        prepare(tmp_path / "inputs", LIMITS)


@pytest.mark.parametrize("side", ["state", "vip"])
@pytest.mark.parametrize("plant", ["rows", "duplicate", "owners", "missing_cell", "extra_cell", "store_identity",
    "value", "raw", "basis", "false_unknown", "reason", "need", "reader"])
def test_state_and_vip_canonical_store_population_and_every_value_close_before_carrier(tmp_path, monkeypatch, side, plant):
    inputs(tmp_path / "inputs")
    build, finish, read = b.VirtualIpOwner.build_virtual_ip, runner.VirtualIpPack.finish, FactReader.read
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
        if plant == "owners":
            result.store.owners.clear()
        elif plant == "missing_cell":
            result.store.values.pop(reference)
        elif plant == "extra_cell":
            result.store.values[k.FactRef(fact=fact, subject=k.EntityKey("fhrp_local:extra"))] = row.value
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
        monkeypatch.setattr(runner.VirtualIpPack, "finish", lambda self, execution: changed(finish(self, execution)))
    monkeypatch.setattr(runner.FhrpVirtualIpSource, "__init__", lambda *_a, **_k: pytest.fail("carrier before full STATE/VIP closure"))
    with pytest.raises(ValueError):
        prepare(tmp_path / "inputs", LIMITS)


@pytest.mark.parametrize("carrier", ["prepared", "source", "state", "store", "execution", "domains", "proofs", "text", "budget"])
def test_opaque_carriers_and_non_nominal_budgets_refuse_before_io(tmp_path, monkeypatch, carrier):
    inputs(tmp_path / "inputs")
    result = prepare(tmp_path / "inputs", LIMITS)
    roots = {"prepared": result, "source": result.source, "state": result.source.source, "store": result.source.store,
        "execution": result.execution, "domains": result.domains, "proofs": result.proofs, "text": str(tmp_path / "inputs"), "budget": tmp_path / "inputs"}
    monkeypatch.setattr(runner.stp, "build_root_guard_global", lambda *_a, **_k: pytest.fail("invalid input reached IO"))
    with pytest.raises(ValueError, match="^fhrp_source_input$"):
        prepare(roots[carrier], object() if carrier == "budget" else LIMITS)


def test_exact_original_file_budgets_and_failures_precede_all_parsers(tmp_path, monkeypatch):
    files = inputs(tmp_path / "inputs")
    total, count, largest = sum(map(len, files.values())), len(files), max(files, key=lambda name: len(files[name]))
    budgets = type(LIMITS)
    assert len(prepare(tmp_path / "inputs", budgets(total, len(files[largest]), count)).source.rows) == 6
    for module in (b.hsrp, runner.stp.stp, runner.ec.parse_summary):
        monkeypatch.setattr(module, "parse_capture", lambda *_: pytest.fail("budget failure reached parser"))
    for limits, member in ((budgets(total - 1, 1000000, count), "bundle"),
        (budgets(total, len(files[largest]) - 1, count), largest), (budgets(total, 1000000, count - 1), "bundle")):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as error:
            prepare(tmp_path / "inputs", limits)
        assert error.value.member == member
