"""Global Root4 owning source and adapters; generic Root report integration is deferred."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l2.stp import root_identity
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4
from atlas_brain.runner.p4_refs import ProofIndex
from tools import p4_estate_cases as estate

LIMITS = Budgets(1000000, 1000000, 1000)
ROOT, ROLE = "l2.stp.root_guard", "l2.stp.reported_role"
PRIORITY, ADDRESS, MAC = "l2.stp.reported_root_priority", "l2.stp.reported_root_mac", "aBcD.EF01.2345"
IDS = tuple(sorted((ROOT, ROLE, PRIORITY, ADDRESS)))
READER = replace(p4.PROJECT, id=StepId("l2.stp/test_global_root_reader"), reads=IDS)


def fixture(root, case="baseline", *, roots=True):
    inputs = estate.members(canonical, case)
    if roots:
        inputs["tree.txt"] = inputs["tree.txt"].replace(b"   Root guard is disabled on the port\n",
            b"   Root guard is disabled on the port\n   Designated root has priority 0, address aBcD.EF01.2345\n")
        side = json.loads(inputs["p4.json"])
        next(member for member in side["captures"] if member["target"] == "tree")["sha256"] = sha256(inputs["tree.txt"]).hexdigest()
        inputs["p4.json"] = canonical(side)
    for name, raw in inputs.items():
        (root / name).write_bytes(raw)
    return inputs


def executed(root):
    channel, standby = SummaryPack(LIMITS), StandbyBriefPack(LIMITS)
    source = b.build_root_observations_global(root, LIMITS, peers=(channel, standby))
    return source, channel.finish(source.execution), standby.finish(source.execution)


def reader(source):
    return bind_reader(source.result.store, step=READER)


def coordinates(raw, vlan):
    header = raw.index(f"VLAN{vlan:04}".encode())
    start, end = raw.rfind(b"\n", 0, header) + 1, raw.index(b"\n", header)
    port = raw.index(estate.PORT.encode(), start)
    root = raw.index(b"   Designated root has priority 0, address ", end)
    priority, address = root + len(b"   Designated root has priority "), root + len(b"   Designated root has priority 0, address ")
    return ((start, end), (port, port + len(estate.PORT)), (header + 4, header + 8),
            (root, raw.index(b"\n", root)), (priority, priority + 1), (address, address + 14))


@pytest.mark.parametrize("case,known", [("baseline", 15), ("pagp", 15), ("missing", 8)])
def test_real_root_global_closes_original_execution_profile_cells_readers_and_literal_source(tmp_path, monkeypatch, case, known):
    inputs, calls, finishes, parses = fixture(tmp_path, case), [], [], []
    parser = b.stp.parse_capture
    expected = registration.compile_packs((b.ROOT_DECLARATION, p4.ec.DECLARATION, p4.fhrp.DECLARATION)).registration_sha256
    def parsed(*args, **kwargs):
        result = parser(*args, **kwargs)
        parses.append(result)
        return result
    execute, cfinish, sfinish = b.p4_pipeline.execute_p4_folder, SummaryPack.finish, StandbyBriefPack.finish
    def run(*args, **kwargs):
        result = execute(*args, **kwargs)
        calls.append(result)
        return result
    def finished(self, execution):
        assert len(calls) == 1 and execution is calls[0]
        result = (cfinish if type(self) is SummaryPack else sfinish)(self, execution)
        finishes.append(result)
        return result
    monkeypatch.setattr(b.p4_pipeline, "execute_p4_folder", run)
    monkeypatch.setattr(b.stp, "parse_capture", parsed)
    monkeypatch.setattr(SummaryPack, "finish", finished)
    monkeypatch.setattr(StandbyBriefPack, "finish", finished)
    source, channel, standby = executed(tmp_path)
    assert source.execution is calls[0] and len(finishes) == 2
    assert len(source.result.rows) == 3 and len(channel.rows) == 4 and len(standby.rows) == 5
    assert [len(owner.store.values) for owner in (source.result, channel, standby)] == [12, 8, 5]
    states = [state for owner in (source.result, channel, standby) for state in owner.store.values.values()]
    assert sum(type(state) is k.Known for state in states) == known and len(states) == 25
    assert source.result.store.owners == {fact: StepId("l2.stp/parse_root_guard") for fact in IDS}
    selected = reader(source)
    b.validate_root_observation_values(source, LIMITS, selected)
    assert source.execution.envelope.registration_sha256 == expected and len(parses) == 1
    owned, = source.result.executed
    original = next(out for out in source.execution.executed if out.receipt.capture.operation == b.stp.OP)
    assert owned.receipt is original.receipt and owned.value is original.value is parses[0]
    assert owned.receipt.capture is original.receipt.capture and owned.receipt.parse is original.value.parse
    for fact, row, state in b.root_fact_rows(source.result):
        assert any(row is original for original in source.result.rows) and b.root_original_state(fact, row) is state
        assert selected.read(fact=fact, subject=row.subject) is source.result.store.values[k.FactRef(fact=fact, subject=row.subject)] is state
        if row.vlan == 3:
            assert type(state) is k.Unknown and state.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
        elif fact in (PRIORITY, ADDRESS):
            value, raw = (0, "0") if fact == PRIORITY else (MAC, MAC)
            assert type(state.value) is type(value) and (state.value, state.raw, state.basis) == (value, raw, k.Basis.OBSERVED)
            refs = state.evidence[3:]
            assert tuple((ref.locator.start, ref.locator.end) for ref in refs) == coordinates(inputs["tree.txt"], row.vlan)
            assert all(ref.role is k.EvidenceRole.SUBJECT and ref.excerpt_sha256 ==
                sha256(inputs["tree.txt"][ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
    assert {name: (tmp_path / name).read_bytes() for name in inputs} == inputs
    with pytest.raises(ValueError, match="^p4_projection_profile$"):
        ProofIndex(source.execution, LIMITS)


def test_owning_projection_contract_and_six_leaf_grants_have_literal_types_and_specific_anchors(tmp_path):
    inputs = fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    step, pack = StepId("l2.stp/parse_root_guard"), k.PackId("l2.stp")
    assert b.root_projection_contract() == ((ROLE, pack, step, "stp_port_vlan", str), (ADDRESS, pack, step, "stp_port_vlan", str),
        (PRIORITY, pack, step, "stp_port_vlan", int), (ROOT, pack, step, "stp_port_vlan", bool))
    output, = tuple(output for output in source.execution.executed if output.receipt.capture.operation == "iosxe.show_spanning_tree_interface_detail")
    for row in source.result.rows:
        for fact, position in ((PRIORITY, 4), (ADDRESS, 5)):
            spans, positive, required = b.root_projection_leaves(k.FactId(fact), row.target, row.vlan, output)
            assert b.root_requires_all(k.FactId(fact)) is True and type(spans) is type(positive) is type(required) is frozenset
            expected = set(coordinates(inputs["tree.txt"], row.vlan)) if row.vlan < 3 else set()
            assert {(s.start, s.end) for s in spans} == expected and required == spans
            assert {(s.start, s.end) for s in positive} == ({coordinates(inputs["tree.txt"], row.vlan)[position]} if row.vlan < 3 else set())
    assert b.root_requires_all(k.FactId(ROOT)) is False and b.root_requires_all(k.FactId(ROLE)) is True


class Text(str):
    pass


@pytest.mark.parametrize("fact", ["l2.stp.unregistered", Text(PRIORITY), True])
@pytest.mark.parametrize("api", ["state", "leaves", "required"])
def test_new_owning_adapters_cannot_accept_alien_or_non_nominal_fact_ids(tmp_path, fact, api):
    fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    row = source.result.rows[0]
    output = next(output for output in source.execution.executed if output.receipt.capture.operation == "iosxe.show_spanning_tree_interface_detail")
    with pytest.raises(ValueError, match="^stp_projection_fact$"):
        if api == "state":
            b.root_original_state(fact, row)
        elif api == "required":
            b.root_requires_all(fact)
        else:
            b.root_projection_leaves(fact, row.target, 1, output)


@pytest.mark.parametrize("vlan", [True, 0, 4])
def test_leaf_adapter_refuses_boolean_or_outside_census_selectors(tmp_path, vlan):
    fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    output = next(output for output in source.execution.executed if output.receipt.capture.operation == "iosxe.show_spanning_tree_interface_detail")
    with pytest.raises(ValueError, match="^stp_projection_scope$"):
        b.root_projection_leaves(k.FactId(PRIORITY), source.result.rows[0].target, vlan, output)


def test_adapter_cannot_borrow_same_bytes_from_neighbor_vlan_even_with_real_getter(monkeypatch, tmp_path):
    fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    output = next(output for output in source.execution.executed if output.receipt.capture.operation == "iosxe.show_spanning_tree_interface_detail")
    actual = root_identity.reported_root_identity_proofs
    def borrowed(target, original):
        claims = actual(target, original)
        row, value, _spans = claims[0]
        return ((row, value, claims[1][2]),) + claims[1:]
    monkeypatch.setattr(root_identity, "reported_root_identity_proofs", borrowed)
    with pytest.raises(ValueError, match="^stp_root_identity_claims$"):
        b.root_projection_leaves(k.FactId(PRIORITY), source.result.rows[0].target, 1, output)


@pytest.mark.parametrize("plant", ["priority", "bool", "mac", "role", "guard", "basis", "raw", "false_unknown", "need", "target", "duplicate", "missing"])
def test_owning_semantic_validator_uses_original_execution_not_coherently_poisoned_store_and_rows(tmp_path, plant):
    fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    row = next(row for row in source.result.rows if row.vlan == (3 if plant == "need" else 1))
    field = "root_mac" if plant == "mac" else "role" if plant == "role" else "value" if plant == "guard" else "root_priority"
    fact = ADDRESS if field == "root_mac" else ROLE if field == "role" else ROOT if field == "value" else PRIORITY
    state = getattr(row, field)
    if plant == "false_unknown":
        changed = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="forged", evidence=state.evidence, candidates=(), next_evidence=())
    elif plant == "need":
        changed = replace(state, next_evidence=(replace(state.next_evidence[0], reruns=()),))
    elif plant in ("target", "duplicate", "missing"):
        changed = state
    else:
        changed = replace(state, **({"value": False if plant == "bool" else MAC.lower() if plant == "mac" else "root" if plant == "role" else True if plant == "guard" else 1}
            if plant in ("priority", "bool", "mac", "role", "guard") else {"basis": k.Basis.DECLARED} if plant == "basis" else {"raw": "normalized"}))
    altered = replace(row, target=replace(row.target, port="Gi1/0/1")) if plant == "target" else replace(row, **{field: changed})
    source.result.store.values[k.FactRef(fact=k.FactId(fact), subject=row.subject)] = changed
    rows = source.result.rows + (source.result.rows[0],) if plant == "duplicate" else source.result.rows[:-1] if plant == "missing" else tuple(altered if item is row else item for item in source.result.rows)
    source = replace(source, result=replace(source.result, rows=rows))
    code = "population" if plant in ("duplicate", "missing") else "source" if plant == "target" else "value"
    with pytest.raises(ValueError, match="^stp_root_observation_" + code + "$"):
        b.validate_root_observation_values(source, LIMITS, reader(source))


@pytest.mark.parametrize("plant", ["value", "parse", "capture", "coverage", "registration", "owner", "execution_clone", "ec_owner", "hsrp_owner"])
def test_real_global_runtime_cannot_substitute_owned_values_receipts_or_execution_before_writer(tmp_path, monkeypatch, plant):
    fixture(tmp_path)
    execute = b.p4_pipeline.execute_p4_folder
    def changed(*args, **kwargs):
        execution = execute(*args, **kwargs)
        outputs = execution.executed
        operation = p4.ec.parse_summary.OP if plant == "ec_owner" else p4.fhrp.hsrp.OP if plant == "hsrp_owner" else b.stp.OP
        owned = next(out for out in outputs if out.receipt.capture.operation == operation)
        if plant == "coverage":
            return replace(execution, executed=tuple(out for out in outputs if out is not owned))
        if plant == "execution_clone":
            return replace(execution, envelope=replace(execution.envelope))
        receipt = owned.receipt
        altered = replace(owned, value=replace(owned.value)) if plant == "value" else replace(owned, receipt=replace(receipt,
            **({"parse": replace(receipt.parse)} if plant == "parse" else {"capture": replace(receipt.capture)} if plant == "capture" else
               {"registration_sha256": "0" * 64} if plant == "registration" else {"owner": StepId("l2.stp/foreign")})))
        return replace(execution, executed=tuple(altered if out is owned else out for out in outputs))
    monkeypatch.setattr(b.p4_pipeline, "execute_p4_folder", changed)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before original global-run closure"))
    code = "coverage" if plant == "coverage" else "run" if plant == "execution_clone" else "capture" if plant == "capture" else "receipt" if plant in ("registration", "owner", "ec_owner", "hsrp_owner") else "value"
    with pytest.raises(ValueError, match="^stp_global_" + code + "$"):
        executed(tmp_path)


@pytest.mark.parametrize("parser", [p4.ec.ProtocolOwner, p4.fhrp.StateOwner])
def test_real_peer_parser_exception_prevents_root_writer(tmp_path, monkeypatch, parser):
    fixture(tmp_path)
    calls = []
    def failed(*args, **kwargs):
        calls.append(args)
        raise ValueError("planted_peer_parser_failure")
    monkeypatch.setattr(parser, "parse", failed)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before all parsers returned"))
    with pytest.raises(ValueError, match="^planted_peer_parser_failure$"):
        executed(tmp_path)
    assert len(calls) == 1


@pytest.mark.parametrize("case", ["baseline", "pagp", "missing"])
def test_existing_legacy_five_files_remain_qualified_byte_for_byte(tmp_path, case):
    inputs = fixture(tmp_path, case, roots=False)
    estate.validate(p4.analyse_folder(tmp_path, LIMITS), inputs, case, canonical)
