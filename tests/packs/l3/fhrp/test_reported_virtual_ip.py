"""Registered local IPv4 observations; no intended gateway, peer, version or health claim."""
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256
from ipaddress import IPv4Address

import pytest
from test_gateway_source import subject
from test_parse_hsrp_brief import ACTIVE, BODY, HEADER, INIT, LEGEND
from test_reported_state_build import GROUPS, B, request, target

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactReader, FactWriter, bind_reader
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.runner import p4
from tools import p4_estate_cases as estate

VIP, STATE = "l3.fhrp.reported_virtual_ip", "l3.fhrp.reported_state"
OWNER, DERIVE = "l3.fhrp/parse_hsrp_brief", "l3.fhrp/derive_virtual_ip"


class Address(StrEnum):
    PRINTED = "198.51.100.1"


def token_plant(output, row, token):
    value = output.value
    changed = replace(row, virtual_ip=replace(row.virtual_ip, token=token))
    records = tuple(replace(record, fields=tuple((name, token if old is row.virtual_ip.token else old)
        for name, old in record.fields)) for record in value.parse.records)
    parsed = replace(value.parse, records=records, tokens=tuple((name, token if old is row.virtual_ip.token else old)
        for name, old in value.parse.tokens))
    object.__setattr__(value, "rows", tuple(changed if old is row else old for old in value.rows))
    object.__setattr__(value, "parse", parsed)
    return replace(output, receipt=replace(output.receipt, parse=parsed))


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
def test_registered_profile_original_parse_and_literal_ipv4_span_custody(monkeypatch, ending, frame):
    item, cold = target(), target(node=B, groups=(("Vlan10", "1"),))
    raw = BODY if frame == "body" else b"show standby brief\n" + BODY
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    supplied = request(item, raw.replace(b"\n", ending))
    execute, compile_packs, parse = b.execute_parsers, b.compile_packs, b.hsrp.parse_capture
    compiled, parsed, runs = [], [], []
    def compiling(declarations):
        result = compile_packs(declarations)
        compiled.append((declarations, result.registration_sha256))
        return result
    def executing(declarations, handlers, requests):
        assert compiled and compiled[0][0] == (b.VIP_DECLARATION,)
        assert declarations == (b.VIP_DECLARATION,) and len(handlers) == 1
        result = execute(declarations, handlers, requests)
        runs.append(result)
        return result
    def parsing(capture):
        result = parse(capture)
        parsed.append(result)
        return result
    monkeypatch.setattr(b, "compile_packs", compiling)
    monkeypatch.setattr(b, "execute_parsers", executing)
    monkeypatch.setattr(b.hsrp, "parse_capture", parsing)
    result = b.build_reported_virtual_ip((cold, item), (supplied,))
    output, = result.source.executed
    assert len(runs) == len(parsed) == 1 and output.value is parsed[0] and output.receipt.parse is parsed[0].parse
    assert output.receipt.capture is supplied.capture and output.receipt.owner == OWNER
    assert result.registration_sha256 == output.receipt.registration_sha256 == compiled[0][1]
    assert result.registration_sha256 != registration.compile_packs((b.DECLARATION,)).registration_sha256
    assert {(f.id, f.subject, f.value_type, str(f.step)) for f in b.VIP_DECLARATION.facts} == {
        (STATE, "fhrp_local", "text", OWNER), (VIP, "fhrp_local", "text", DERIVE)}
    assert b.VIP_STEP.reads == (STATE,) and b.VIP_STEP.produces == (VIP,)
    assert result.source.store.owners == {STATE: OWNER} and result.store.owners == {VIP: DERIVE}
    assert len(result.rows) == len(result.source.rows) == len(result.store.values) == 5
    expected = {("Vl20", "0"): "203.0.113.1", ("Vl10", "1"): "192.0.2.1", ("BD3329", "129"): "198.51.100.1"}
    for row in result.rows:
        source = next(original for original in result.source.rows if original.subject == row.subject)
        assert row.target is source.target and row.subject == subject(row.target.node.id, row.interface, row.group)
        assert result.store.values[k.FactRef(fact=VIP, subject=row.subject)] is row.value
        assert result.source.store.values[k.FactRef(fact=STATE, subject=row.subject)] is source.value
        if row.target.node is item.node and (row.interface, row.group) in expected:
            address = expected[row.interface, row.group]
            assert type(row.value) is k.Known and type(row.value.value) is str
            assert (row.value.value, row.value.raw, row.value.basis) == (address, address, k.Basis.OBSERVED)
            assert row.value.evidence is source.value.evidence
            line = next(line for line in supplied.capture.raw.splitlines(keepends=True) if line.startswith(row.interface.encode() + b" "))
            start = supplied.capture.raw.index(line) + line.rindex(address.encode())
            refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            assert any((ref.locator.start, ref.locator.end) == (start, start + len(address)) for ref in refs)
            assert all(ref.capture == supplied.capture.id and ref.role is k.EvidenceRole.SUBJECT
                and ref.excerpt_sha256 == sha256(supplied.capture.raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
        else:
            reason = k.UnknownReason.NOT_COLLECTED if row.target.node is cold.node else k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
            assert type(row.value) is k.Unknown and row.value.reason is reason
    consumer = StepSpec(id=StepId("l3.fhrp/test_vip"), pack=b.PACK, kind="check", scope="device",
        reads=(VIP,), produces=(), evaluator="l3.fhrp.test_vip")
    assert all(bind_reader(result.store, step=consumer).read(fact=VIP, subject=row.subject) is row.value for row in result.rows)
    with pytest.raises(ValueError, match="^undeclared_read:" + VIP + "$"):
        bind_reader(result.store, step=b.SOURCE_STEP).read(fact=VIP, subject=result.rows[0].subject)


@pytest.mark.parametrize("raw,integrity,reason", [
    (None, k.IntegrityState.COMPLETE, k.UnknownReason.NOT_COLLECTED),
    (BODY + ACTIVE, k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + INIT.replace(b"203.0.113.1", b"unknown"), k.IntegrityState.COMPLETE, k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + b"unrecognised\n", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    (b"", k.IntegrityState.COMPLETE, k.UnknownReason.EMPTY_UNREGISTERED),
    (BODY, k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY, k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED)])
def test_source_unknowns_keep_full_local_population_and_vip_specific_needs(raw, integrity, reason):
    item = target()
    result = b.build_reported_virtual_ip((item,), () if raw is None else (request(item, raw, integrity=integrity),))
    assert {(row.interface, row.group) for row in result.rows} == set(GROUPS)
    for row in result.rows:
        assert type(row.value) is k.Unknown and row.value.reason is reason
        assert row.value.detail == "hsrp_virtual_ip_unresolved"
        assert row.value.evidence == next(original.value.evidence for original in result.source.rows if original.subject == row.subject)
        need, = row.value.next_evidence
        assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s, need.unprintable) == (
            item.node.key, "iosxe.show_standby_brief", (("group", row.group), ("interface", row.interface)),
            (VIP,), (DERIVE,), None, ("reported_virtual_ip",))


@pytest.mark.parametrize("printed", ["unknown", str(IPv4Address(0))])
def test_printed_unknown_is_not_an_address_and_printed_zero_is_not_an_invented_default(printed):
    item = target(groups=(("Vl10", "1"),))
    raw = LEGEND + HEADER + ACTIVE.replace(b"192.0.2.1", printed.encode())
    result = b.build_reported_virtual_ip((item,), (request(item, raw),))
    row, = result.rows
    state, = result.source.rows
    assert (state.value.value, state.value.raw) == ("active", "Active")
    if printed == "unknown":
        assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_OBSERVABLE
        assert row.value.evidence[:-1] == state.value.evidence
        witness = row.value.evidence[-1]
        start = raw.rindex(b"unknown")
        assert (witness.locator.start, witness.locator.end, witness.role) == (start, start + 7, k.EvidenceRole.WITNESS)
        assert witness.excerpt_sha256 == sha256(b"unknown").hexdigest()
    else:
        assert (row.value.value, row.value.raw, row.value.basis) == (printed, printed, k.Basis.OBSERVED)


@pytest.mark.parametrize("plant", ["vip_type", "state_type", "missing", "reads", "produces", "vip_evaluator", "state_evaluator", "binding"])
def test_fixed_literal_catalogue_refuses_coherent_drift_before_any_parser_or_writer(monkeypatch, plant):
    declaration, step, state, binding = b.VIP_DECLARATION, b.VIP_STEP, b.STEP, b.BINDING
    if plant in ("vip_type", "state_type"):
        facts = tuple(replace(fact, value_type="boolean") if fact.id == (VIP if plant == "vip_type" else STATE) else fact for fact in declaration.facts)
        declaration = replace(declaration, facts=facts)
    elif plant == "missing":
        declaration = replace(declaration, facts=declaration.facts[:1])
    elif plant == "binding":
        binding = replace(binding, operation="iosxe.show_etherchannel_summary")
        declaration = replace(declaration, operations=(binding,))
    else:
        changes = {"reads": {"reads": ()}, "produces": {"produces": ()}, "vip_evaluator": {"evaluator": "l3.fhrp.other"}}
        if plant == "state_evaluator":
            state = replace(state, evaluator="l3.fhrp.other")
        else:
            step = replace(step, **changes[plant])
        declaration = replace(declaration, steps=(state, step))
    monkeypatch.setattr(b, "VIP_DECLARATION", declaration)
    monkeypatch.setattr(b, "VIP_STEP", step)
    monkeypatch.setattr(b, "STEP", state)
    monkeypatch.setattr(b, "BINDING", binding)
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *_: pytest.fail("parser before fixed catalogue"))
    monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("writer before fixed catalogue"))
    with pytest.raises(ValueError, match="^hsrp_vip_profile$"):
        b.build_reported_virtual_ip((target(),), (request(target()),))


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("plant,code", [("value", "hsrp_vip_value"), ("bool", "hsrp_vip_value"), ("enum", "hsrp_vip_value"),
    ("raw", "hsrp_witness"), ("column", "hsrp_witness"), ("association", "hsrp_record"), ("kind", "hsrp_value"), ("rows", "hsrp_record"),
    ("clone_value", "hsrp_vip_source"), ("parse", "hsrp_vip_source"), ("capture", "hsrp_receipt_owner"),
    ("registration", "hsrp_receipt_owner"), ("legacy", "hsrp_receipt_owner"), ("missing", "hsrp_vip_source"),
    ("duplicate", "hsrp_receipt_coverage"), ("cache", "hsrp_vip_source"), ("append", "pack_receipts_retention_mismatch"), ("retarget", "pack_receipts_retention_mismatch")])
def test_actual_runtime_late_source_column_and_cache_faults_refuse_before_both_writers(monkeypatch, plant, code, reverse):
    first, later = target(), target(node=B)
    execute = b.execute_parsers
    def changed(declarations, handlers, requests):
        outputs = execute((b.DECLARATION,) if plant == "legacy" else declarations, handlers, requests)
        outputs = tuple(reversed(outputs)) if reverse else outputs
        out = outputs[-1]
        if plant in ("append", "retarget"):
            field, value = ("raw", out.receipt.capture.raw + b"not parsed\n") if plant == "append" else ("source", later.node.key)
            object.__setattr__(out.receipt.capture, field, value)
            return outputs
        if plant == "legacy":
            return outputs
        if plant == "missing":
            return outputs[:-1]
        if plant == "duplicate":
            return (out, out)
        if plant == "cache":
            handlers[0].parser.produced["cap:extra"] = out.value
            return outputs
        if plant in ("clone_value", "parse", "capture", "registration"):
            if plant == "clone_value":
                replacement = replace(out, value=replace(out.value))
            else:
                changes = {"parse": {"parse": replace(out.receipt.parse)}, "capture": {"capture": replace(out.receipt.capture)},
                    "registration": {"registration_sha256": "0" * 64}}[plant]
                replacement = replace(out, receipt=replace(out.receipt, **changes))
        else:
            row = out.value.rows[-1]
            if plant == "rows":
                object.__setattr__(out.value, "rows", out.value.rows + (row,))
                return outputs
            if plant == "kind":
                object.__setattr__(row.virtual_ip, "kind", "unknown")
                return outputs
            token = replace(row.virtual_ip.token, **({"value": False if plant == "bool" else Address.PRINTED if plant == "enum" else "192.0.2.99"} if plant in ("bool", "value", "enum")
                else {"raw": "192.0.2.99"} if plant == "raw" else {"span": row.state.span}))
            if plant == "association":
                object.__setattr__(row.virtual_ip, "token", token)
                return outputs
            replacement = token_plant(out, row, token)
        return outputs[:-1] + (replacement,)
    monkeypatch.setattr(b, "execute_parsers", changed)
    monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("writer before complete late validation"))
    supplied = (request(first),) if plant == "retarget" else (request(first), request(later, identity="b"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_reported_virtual_ip((first, later), supplied)


def test_real_state_reader_dependency_precedes_every_vip_write_and_preserves_state_store(monkeypatch):
    item = target()
    read, write = FactReader.read, FactWriter.write
    reads, states = [], {}
    def reading(self, **kwargs):
        assert self.step is b.VIP_STEP and kwargs["fact"] == STATE
        result = read(self, **kwargs)
        reads.append((self.store, kwargs["subject"], result))
        return result
    def writing(self, **kwargs):
        if kwargs["fact"] == STATE:
            states[kwargs["subject"]] = kwargs["value"]
        else:
            assert len(reads) == len(GROUPS) and self.step is b.VIP_STEP
        return write(self, **kwargs)
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(FactWriter, "write", writing)
    result = b.build_reported_virtual_ip((item,), (request(item),))
    assert all(store is result.source.store and value is states[subject] for store, subject, value in reads)
    assert result.source.store.values == {k.FactRef(fact=STATE, subject=subject): value for subject, value in states.items()}
    writer = b.bind_writer
    monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)))
    monkeypatch.setattr(b, "bind_writer", lambda store, *, step: writer(store, step=step) if step is b.STEP else pytest.fail("VIP writer before STATE identity"))
    with pytest.raises(ValueError, match="^hsrp_vip_source$"):
        b.build_reported_virtual_ip((item,), (request(item),))


@pytest.mark.parametrize("case", ["baseline", "pagp", "missing"])
def test_opt_in_local_profile_leaves_default_five_report_bytes_and_catalogue_unchanged(tmp_path, case):
    inputs = estate.members(canonical, case)
    for name, raw in inputs.items():
        (tmp_path / name).write_bytes(raw)
    limits = p4.Budgets(1000000, 1000000, 1000)
    before = p4.analyse_folder(tmp_path, limits)
    declaration, profile = b.DECLARATION, registration.compile_packs((b.DECLARATION,)).registration_sha256
    b.build_reported_virtual_ip((target(),), (request(target()),))
    after = p4.analyse_folder(tmp_path, limits)
    assert after == before and b.DECLARATION is declaration
    assert registration.compile_packs((b.DECLARATION,)).registration_sha256 == profile
    assert len(estate.validate(after, inputs, case, canonical)["reports"]) == 5
