"""Genuine owning Root4 pack seam; no whole Root9 admission, source seal or health claim."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_folder import HEADER, LIMITS, scenario, write
from test_global_root_observations import fixture as peer_folder

from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactStore, FactWriter, bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack

MAC = "aBcD.EF01.2345"
IDS = tuple(sorted((b.ROOT_GUARD, b.REPORTED_ROLE, b.REPORTED_ROOT_PRIORITY, b.REPORTED_ROOT_MAC)))


def forbidden(*args, **kwargs):
    pytest.fail("Root4 current validation parsed, dispatched, constructed a Store or wrote")


def raw(priority="32769", mac=MAC, guard="disabled"):
    return HEADER + (b"" if guard is None else f"   Root guard is {guard} on the port\n".encode()) + (
        f"   Designated root has priority {priority}, address {mac}\n".encode())


def supplied(root, mode="normal", priority="32769", mac=MAC):
    root.mkdir(parents=True, exist_ok=True)
    body = raw(priority, mac, None if mode == "omitted_guard" else "disabled")
    body = HEADER + b"   Root guard is disabled on the port\n" if mode == "omitted_root" else body
    body = body + b"unmodelled\n" if mode == "partial" else b"" if mode == "empty" else b"% Invalid input\n" if mode == "error" else body
    files, side = scenario(body)
    if mode == "missing":
        side["captures"] = []
        files.pop("stp.txt")
    write(root, files, side)
    pack = b.RootObservationPack(LIMITS)
    execution = b.p4_pipeline.execute_p4_folder(root, LIMITS, packs=(pack,))
    assert len(pack.own_execution(execution)) == len(execution.executed)
    return pack, execution, body


def reader(result):
    return bind_reader(result.store, step=StepSpec(id="l2.stp/test_root4_values", pack="l2.stp", kind="derive",
        scope="estate", reads=IDS, produces=(), evaluator="l2.stp.test_root4_values"))


def freeze(monkeypatch):
    for module, name in ((b.stp, "parse_capture"), (b, "execute_parsers"), (b.p4_pipeline, "execute_p4_folder"),
            (b.p4_pipeline, "execute_parsers"), (b, "bind_writer"), (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


@pytest.mark.parametrize("priority", ["0", "32769", "65535"])
@pytest.mark.parametrize("mac", [MAC, "0000.0000.0000"])
def test_named_fixed_pack_owns_real_root_integer_mac_role_guard_and_exact_original_byte_leaves(tmp_path, monkeypatch, priority, mac):
    pack, execution, body = supplied(tmp_path, priority=priority, mac=mac)
    assert pack.declaration() is b.root_declaration() is b.ROOT_DECLARATION
    assert pack.producer.roots is True and pack.producer.step is b.ROOT_STEP
    assert len(execution.executed) == len(pack.produced) == 1
    output, = execution.executed
    assert pack.produced[output.receipt.capture.id] is output.value and output.receipt.parse is output.value.parse
    with monkeypatch.context() as patch:
        freeze(patch)
        before = pack.own_execution(execution)
    result = pack.finish(execution)
    assert len(result.rows) == 3 and len(result.store.values) == 12 and result.store.owners == {fact: b.ROOT_STEP.id for fact in IDS}
    freeze(monkeypatch)
    after = pack.own_execution(execution)
    assert before[0].receipt is after[0].receipt is output.receipt and before[0].value is after[0].value is output.value
    assert pack.validate_root_values(result, reader(result), execution) is None
    row = next(row for row in result.rows if row.vlan == 1 and row.target.node.id == "a")
    assert row.value.value is False and row.role.value == "designated"
    assert type(row.root_priority.value) is int and row.root_priority.value == int(priority) and row.root_priority.raw == priority
    assert row.root_mac.value == row.root_mac.raw == mac
    for fact, original, value in b.root_fact_rows(result):
        assert original in result.rows and reader(result).read(fact=fact, subject=original.subject) is value
        if original is row:
            assert len(tuple(ref for ref in value.evidence if type(ref) is k.RegistryRef)) == 3
            if fact in (b.REPORTED_ROOT_PRIORITY, b.REPORTED_ROOT_MAC):
                refs = tuple(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
                assert len(refs) == 6 and all(type(ref.locator) is k.ByteSpan and ref.role is k.EvidenceRole.SUBJECT for ref in refs)
                assert all(ref.excerpt_sha256 == sha256(body[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
    domain = row.target
    spans, positive, required = b.root_projection_leaves(b.REPORTED_ROOT_PRIORITY, domain, 1, output)
    assert spans == required and len(spans) == 6
    assert {body[span.start:span.end] for span in positive} == {priority.encode()}


@pytest.mark.parametrize("mode", ["missing", "omitted_root", "omitted_guard", "partial", "empty", "error"])
def test_absent_partial_and_unprinted_inputs_keep_independent_root4_population_and_actual_unknowns(tmp_path, monkeypatch, mode):
    pack, execution, _ = supplied(tmp_path, mode)
    result = pack.finish(execution)
    freeze(monkeypatch)
    assert pack.validate_root_values(result, reader(result), execution) is None
    assert len(result.rows) == 3 and len(result.store.values) == 12
    for row in result.rows:
        assert all(result.store.values[k.FactRef(fact=fact, subject=row.subject)] is b.root_original_state(fact, row) for fact in IDS)
        if row.target.node.id == "b" or mode == "missing":
            assert type(row.root_priority) is k.Unknown and row.root_priority.reason is k.UnknownReason.NOT_COLLECTED
        elif mode in ("partial", "empty", "error"):
            expected = {"partial": k.UnknownReason.PARSE_PARTIAL, "empty": k.UnknownReason.EMPTY_UNREGISTERED,
                "error": k.UnknownReason.CAPTURE_ERROR}[mode]
            assert row.root_priority.reason is expected and row.root_priority is row.root_mac
        elif row.vlan == 2:
            assert row.root_priority.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
        elif mode == "omitted_root":
            assert row.root_priority.reason is k.UnknownReason.FIELD_NOT_PRINTED
        elif mode == "omitted_guard":
            assert row.value.reason is k.UnknownReason.FIELD_NOT_PRINTED and type(row.root_priority) is k.Known
        if type(row.root_priority) is k.Unknown:
            need, = row.root_priority.next_evidence
            assert need.resolves == (b.REPORTED_ROOT_MAC, b.REPORTED_ROOT_PRIORITY) and need.operation == b.stp.OP


@pytest.mark.parametrize("root", [False, True])
def test_repeat_finishing_preserves_legacy_and_named_pack_lifecycle_but_allocates_fresh_stores(tmp_path, root):
    files, side = scenario(raw())
    write(tmp_path, files, side)
    pack = b.RootObservationPack(LIMITS) if root else b.RootGuardPack(LIMITS)
    execution = b.p4_pipeline.execute_p4_folder(tmp_path, LIMITS, packs=(pack,))
    first, second = pack.finish(execution), pack.finish(execution)
    assert first.store is not second.store and first.rows == second.rows and first.store.values == second.store.values
    assert first.executed[0].receipt is second.executed[0].receipt is execution.executed[0].receipt
    assert first.executed[0].value is second.executed[0].value is execution.executed[0].value
    assert len(first.store.owners) == (4 if root else 2)


@pytest.mark.parametrize("plant,code", [("execution", "stp_global_run"), ("list", "stp_global_receipt"),
    ("drop", "stp_global_coverage"), ("duplicate", "stp_global_coverage"), ("value", "stp_global_value"),
    ("parse", "stp_global_value"), ("capture", "stp_global_capture"), ("owner", "stp_global_receipt"),
    ("registration", "stp_global_receipt"), ("context", "stp_global_receipt"), ("extra_cache", "stp_global_value")])
def test_public_ledger_refuses_forged_runtime_parts_without_writing_and_failure_does_not_consume_pack(tmp_path, monkeypatch, plant, code):
    pack, execution, _ = supplied(tmp_path)
    output, = execution.executed
    bad = execution
    if plant == "execution":
        bad = replace(execution, envelope=replace(execution.envelope))
    elif plant in ("list", "drop", "duplicate"):
        bad = replace(execution, executed=list(execution.executed) if plant == "list" else () if plant == "drop" else execution.executed * 2)
    elif plant == "extra_cache":
        pack.produced["cap:extra"] = output.value
    else:
        changed = replace(output, value=replace(output.value)) if plant == "value" else replace(output, receipt=replace(output.receipt, **(
            {"parse": replace(output.receipt.parse)} if plant == "parse" else {"capture": replace(output.receipt.capture)} if plant == "capture" else
            {"owner": "l2.stp/other"} if plant == "owner" else {"registration_sha256": "0" * 64} if plant == "registration" else {"context": "other"})))
        bad = replace(execution, executed=(changed,))
    with monkeypatch.context() as patch:
        freeze(patch)
        with pytest.raises(ValueError, match="^" + code + "$"):
            pack.own_execution(bad)
        with pytest.raises(ValueError, match="^" + code + "$"):
            pack.finish(bad)
    if plant == "extra_cache":
        pack.produced.pop("cap:extra")
    assert pack.finish(execution).rows


@pytest.mark.parametrize("field,fact,code", [("value", b.ROOT_GUARD, "stp_root_observation_value"),
    ("role", b.REPORTED_ROLE, "stp_root_observation_value"), ("root_priority", b.REPORTED_ROOT_PRIORITY, "stp_root_observation_value"),
    ("root_mac", b.REPORTED_ROOT_MAC, "stp_root_observation_value")])
def test_each_root4_store_value_uses_actual_canonical_bytes_instead_of_row_store_agreement(tmp_path, monkeypatch, field, fact, code):
    pack, execution, _ = supplied(tmp_path)
    result = pack.finish(execution)
    freeze(monkeypatch)
    handle = reader(result)
    assert pack.validate_root_values(result, handle, execution) is None
    row = next(row for row in result.rows if row.target.node.id == "a" and row.vlan == 1)
    value = getattr(row, field)
    replacement = replace(value, value=True if field == "value" else 1 if field == "root_priority" else "root" if field == "role" else MAC.lower())
    result.store.values[k.FactRef(fact=fact, subject=row.subject)] = replacement
    object.__setattr__(row, field, replacement)
    with pytest.raises(ValueError, match="^" + code + "$"):
        pack.validate_root_values(result, handle, execution)


@pytest.mark.parametrize("plant", ["reader", "rows", "duplicate", "executed", "producer"])
def test_current_root_value_validation_refuses_foreign_binding_population_and_cache(tmp_path, monkeypatch, plant):
    pack, execution, _ = supplied(tmp_path)
    result = pack.finish(execution)
    other = FactStore()
    handle = reader(result)
    assert pack.validate_root_values(result, handle, execution) is None
    freeze(monkeypatch)
    code = "stp_root_observation_source"
    if plant == "reader":
        handle = replace(handle, store=other)
        code = "stp_root_observation_population"
    elif plant in ("rows", "duplicate"):
        result = replace(result, rows=result.rows[:-1] if plant == "rows" else result.rows + result.rows[:1])
        code = "stp_root_observation_population"
    elif plant == "executed":
        output, = result.executed
        result = replace(result, executed=(replace(output, value=replace(output.value)),))
    else:
        pack.producer = replace(pack.producer, roots=False, declaration=b.DECLARATION, step=b.STEP)
    with pytest.raises(ValueError, match="^" + code + "$"):
        pack.validate_root_values(result, handle, execution)


def test_whole_ordinary_peer_ledger_is_checked_and_only_original_stp_outputs_are_returned(tmp_path, monkeypatch):
    peer_folder(tmp_path)
    pack, channel, standby = b.RootObservationPack(LIMITS), SummaryPack(LIMITS), StandbyBriefPack(LIMITS)
    execution = b.p4_pipeline.execute_p4_folder(tmp_path, LIMITS, packs=(pack, channel, standby))
    actual = tuple(out for out in execution.executed if out.receipt.capture.operation == b.stp.OP)
    freeze(monkeypatch)
    owned = pack.own_execution(execution)
    assert len(owned) == len(actual) == 1 and all(a.receipt is c.receipt and a.value is c.value for a, c in zip(owned, actual, strict=True))
    peer = next(out for out in execution.executed if out.receipt.capture.operation != b.stp.OP)
    bad = replace(execution, executed=tuple(replace(out, receipt=replace(out.receipt, owner="l2.stp/other")) if out is peer else out for out in execution.executed))
    with pytest.raises(ValueError, match="^stp_global_receipt$"):
        pack.own_execution(bad)


@pytest.mark.parametrize("extra", [{"roots": False}, {"profile": object()}, {"producer": object()}])
def test_named_constructor_and_declaration_have_no_caller_selected_profiles(extra):
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        b.RootObservationPack(LIMITS, **extra)
    with pytest.raises(TypeError, match="positional"):
        b.root_declaration(b.ROOT_DECLARATION)


def test_writer_failure_allows_retry_from_same_actual_cache_without_claiming_rollback(tmp_path, monkeypatch):
    pack, execution, _ = supplied(tmp_path)
    write_cell, stores = FactWriter.write, []
    def writing(self, **kwargs):
        stores.append(self.store)
        if len(stores) == 2:
            raise ValueError("planted_root_writer")
        return write_cell(self, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(FactWriter, "write", writing)
        with pytest.raises(ValueError, match="^planted_root_writer$"):
            pack.finish(execution)
    assert len(stores[0].values) == 1 and stores[0] is stores[1]
    result = pack.finish(execution)
    assert result.store is not stores[0] and len(result.store.values) == 12


@pytest.mark.parametrize("field", ["ROOT_STEP", "ROOT_DECLARATION", "BINDING"])
def test_public_root_declaration_rechecks_live_fixed_literal_metadata_before_use(monkeypatch, field):
    assert b.root_declaration() is b.ROOT_DECLARATION
    value = replace(b.ROOT_STEP, evaluator="l2.stp.other") if field == "ROOT_STEP" else (
        replace(b.ROOT_DECLARATION, steps=()) if field == "ROOT_DECLARATION" else replace(b.BINDING, step="l2.stp/other"))
    monkeypatch.setattr(b, field, value)
    with pytest.raises(ValueError, match="^stp_root_observation_metadata$"):
        b.root_declaration()


@pytest.mark.parametrize("field", ["root_priority", "root_mac"])
def test_owning_raw_root_proof_precedes_writer_even_for_in_place_actual_cache_mutation(tmp_path, monkeypatch, field):
    pack, execution, _ = supplied(tmp_path)
    output, = execution.executed
    token = dict(output.value.rows[0].fields)[field]
    original = token.value
    object.__setattr__(token, "value", 1 if field == "root_priority" else MAC.lower())
    with monkeypatch.context() as patch:
        freeze(patch)
        assert pack.own_execution(execution)[0].value is output.value
        with pytest.raises(ValueError, match="^stp_root_identity_witness$"):
            pack.finish(execution)
    object.__setattr__(token, "value", original)
    assert pack.finish(execution).rows
