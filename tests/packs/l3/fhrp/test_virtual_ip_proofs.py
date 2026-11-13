"""GLOBAL VIP proof metadata over the real producer; no admission or value seal."""
import json
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest
from test_gateway_source import LIMITS, folder
from test_global_virtual_ip_owner import READ
from test_global_virtual_ip_owner import inputs as producer_inputs

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactStore, bind_reader
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.runner import p4 as observations
from atlas_brain.runner import p4_fhrp_policy as legacy
from atlas_brain.runner.p4_refs import FhrpVipProofIndex, ProofIndex, RootProofIndex

VIP, STATE = "l3.fhrp.reported_virtual_ip", "l3.fhrp.reported_state"


def inputs(root, mode="normal"):
    if mode == "missing":
        folder(root, "both")
    else:
        producer_inputs(root, mode)
    if mode not in ("partial", "duplicate", "same_bytes"):
        return
    raw = (root / "hsrp.txt").read_bytes()
    if mode == "partial":
        raw += b"unrecognised\n"
    elif mode == "duplicate":
        raw += next(line for line in raw.splitlines(keepends=True) if line.startswith(b"Vl10 "))
    else:
        raw = raw.replace(b"192.0.2.1\n", b"198.51.100.1\n")
        cold = root / "cold-gateway.txt"
        cold.write_bytes(cold.read_bytes().replace(b"192.0.2.99", b"198.51.100.1"))
    (root / "hsrp.txt").write_bytes(raw)
    side = json.loads((root / "p4.json").read_bytes())
    for row in side["captures"]:
        row["sha256"] = sha256((root / row["path"]).read_bytes()).hexdigest()
    (root / "p4.json").write_bytes(canonical(side))


def compose(root, mode="normal", *, close=True):
    inputs(root, mode)
    channel, standby = SummaryPack(LIMITS), gp.VirtualIpPack(LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(channel, standby))
    bundle, state = channel.finish(tree.execution), standby.finish(tree.execution)
    standby.owner.validate_gateway_source_values(state, bind_reader(state.store, step=b.SOURCE_STEP), tree.execution.executed)
    source = standby.virtual_ip_owner.build_virtual_ip()
    reader = bind_reader(source.store, step=READ)
    standby.virtual_ip_owner.validate_virtual_ip_values(source, reader)
    index = FhrpVipProofIndex(tree.execution, LIMITS)
    observations.close_owned_facts(index, tree.result, bundle, state)
    if close:
        index.close_virtual_ip(source, reader)
    return SimpleNamespace(source=source, execution=tree.execution, proofs=index, reader=reader)


@pytest.mark.parametrize("mode", ["normal", "unknown", "partial", "duplicate", "missing", "zero"])
def test_actual_producer_scopes_and_exact_leaf_grants_close_without_parser_or_writer_replay(tmp_path, monkeypatch, mode):
    case = compose(tmp_path / "inputs", mode, close=False)
    index, source, reads, read = case.proofs, case.source, [], FactReader.read
    def reading(self, **kwargs):
        value = read(self, **kwargs)
        reads.append((self, kwargs["fact"], kwargs["subject"], value))
        return value
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *_: pytest.fail("proof closure reparsed"))
    monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("proof closure wrote"))
    index.close_virtual_ip(source, case.reader)
    assert index.virtual_ip_reader is case.reader and index.execution is case.execution
    assert len(index.scopes) == (14 if mode == "zero" else 26)
    assert len(reads) == len(source.rows) == (0 if mode == "zero" else 6)
    assert source.store.owners == {VIP: b.VIP_STEP.id}
    assert set(source.store.values) == {k.FactRef(fact=VIP, subject=row.subject) for row in source.rows}
    assert all(reader is case.reader and fact == VIP and value is source.store.values[k.FactRef(fact=VIP, subject=subject)]
        for reader, fact, subject, value in reads)
    for row in source.rows:
        scope = index.scope(VIP, row.subject)
        assert scope.reference == k.FactRef(fact=VIP, subject=row.subject)
        assert scope.target.node is row.target.node and len(scope.declarations) == 3
        assert index.resolve_virtual_ip_reference(scope.reference) == index.resolve(scope, row.value.evidence, positive=type(row.value) is k.Known)
        if type(row.value) is k.Unknown:
            assert scope.spans == scope.required == scope.positive == frozenset()
            with pytest.raises(ValueError, match="^p4_projection_"):
                index.resolve(scope, row.value.evidence, positive=True)
            if row.value.reason is k.UnknownReason.NOT_OBSERVABLE:
                refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
                assert len(refs) == 2 and all(ref.role is k.EvidenceRole.WITNESS for ref in refs)
                assert scope.witnesses == frozenset((ref.capture, ref.locator) for ref in refs)
            continue
        capture = next(out.receipt.capture for out in source.source.executed if out.receipt.capture.source == row.target.node.key)
        raw = capture.raw
        line = next(line for line in raw.splitlines(keepends=True) if line.startswith(row.interface.encode() + b" "))
        start, group, printed = raw.index(line), line.index(row.group.encode(), len(row.interface)), line.split()[-1]
        anchor = start + line.rindex(printed)
        pairs = {(start, start + len(row.interface)), (start + group, start + group + len(row.group)),
            (start, start + len(line.rstrip(b"\r\n"))), (anchor, anchor + len(printed))}
        assert scope.required == scope.spans == frozenset((capture.id, k.ByteSpan(start=a, end=z)) for a, z in pairs)
        assert scope.positive == frozenset(((capture.id, k.ByteSpan(start=anchor, end=anchor + len(printed))),))
        refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        assert {(ref.locator.start, ref.locator.end) for ref in refs} == pairs
        assert all(ref.role is k.EvidenceRole.SUBJECT and ref.capture == capture.id
            and ref.excerpt_sha256 == sha256(raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
    if source.rows:
        with pytest.raises(ValueError, match="^p4_projection_profile$"):
            index.close_virtual_ip(source, case.reader)


@pytest.mark.parametrize("plant", ["interface", "group", "row", "vip", "witness", "active", "standby", "same_capture", "foreign_capture", "state", "whole", "factref"])
def test_vip_grants_require_every_own_column_span_and_reject_endpoint_or_neighbor_donation(tmp_path, plant):
    result = compose(tmp_path / "inputs", "same_bytes")
    row = next(row for row in result.source.rows if row.interface == "BD3329")
    scope = result.proofs.scope(VIP, row.subject)
    output = next(out for out in result.source.source.executed if out.receipt.capture.source == row.target.node.key)
    parsed = next(item for item in output.value.rows if item.interface.raw == row.interface)
    points = {"interface": parsed.interface.span, "group": parsed.group.span, "row": parsed.span, "vip": parsed.virtual_ip.token.span}
    evidence = row.value.evidence
    if plant in points:
        evidence = tuple(ref for ref in evidence if type(ref) is not k.EvidenceRef or ref.locator != points[plant])
    elif plant == "witness":
        evidence = tuple(replace(ref, role=k.EvidenceRole.WITNESS) if type(ref) is k.EvidenceRef and ref.locator == points["vip"] else ref for ref in evidence)
    elif plant in ("active", "standby"):
        donor = getattr(parsed, plant).token.span
        evidence += (k.EvidenceRef(capture=output.receipt.capture.id, locator=donor, role=k.EvidenceRole.SUBJECT,
            excerpt_sha256=sha256(output.receipt.capture.raw[donor.start:donor.end]).hexdigest()),)
    elif plant in ("same_capture", "foreign_capture"):
        donor = next(item for item in result.source.rows if item.interface == ("Vl10" if plant == "same_capture" else "BD10"))
        assert donor.value.value == row.value.value
        declarations = tuple(ref for ref in row.value.evidence if type(ref) is k.RegistryRef)
        evidence = declarations + tuple(ref for ref in donor.value.evidence if type(ref) is k.EvidenceRef)
    elif plant == "state":
        evidence = next(item.value.evidence for item in result.source.source.rows if item.subject == row.subject)
    elif plant == "whole":
        evidence += (k.EvidenceRef(capture=output.receipt.capture.id, locator=k.WholeCapture(),
            role=k.EvidenceRole.WITNESS, excerpt_sha256=output.receipt.capture.bytes_sha256),)
    else:
        evidence += (k.FactRef(fact=VIP, subject=row.subject),)
    with pytest.raises(ValueError, match="^p4_projection_"):
        result.proofs.resolve(scope, evidence, positive=True)


def test_vip_reference_is_narrow_leaf_expansion_with_retained_reader_and_no_admission_or_value_seal(tmp_path):
    result = compose(tmp_path / "inputs")
    row = next(row for row in result.source.rows if type(row.value) is k.Known)
    reference = k.FactRef(fact=VIP, subject=row.subject)
    leaves = result.proofs.resolve_virtual_ip_reference(reference)
    for fact in (STATE, stp.ROOT_GUARD, "unregistered.fact"):
        with pytest.raises(ValueError, match="^p4_projection_reference$"):
            result.proofs.resolve_virtual_ip_reference(k.FactRef(fact=fact, subject=row.subject))
    for value in (result.source, result.source.store, result.proofs.virtual_ip_reader, object()):
        with pytest.raises(ValueError, match="^p4_projection_reference$"):
            result.proofs.resolve_virtual_ip_reference(value)
    for key, value in (("store", result.source.store), ("reader", result.proofs.virtual_ip_reader)):
        with pytest.raises(TypeError):
            result.proofs.resolve_virtual_ip_reference(reference, **{key: value})
    with pytest.raises(ValueError, match="^p4_projection_reference$"):
        FhrpVipProofIndex(result.execution, LIMITS).resolve_virtual_ip_reference(reference)
    for kind in (ProofIndex, RootProofIndex):
        with pytest.raises(ValueError, match="^p4_projection_profile$"):
            kind(result.execution, LIMITS)
    with pytest.raises(ValueError, match="^missing_fact:" + VIP + ":"):
        result.proofs.resolve_virtual_ip_reference(k.FactRef(fact=VIP, subject=k.EntityKey("fhrp_local:extra")))
    previous = legacy.prepare_fhrp_source(tmp_path / "inputs", LIMITS)
    with pytest.raises(ValueError, match="^p4_projection_profile$"):
        FhrpVipProofIndex(previous.execution, LIMITS)
    result.source.store.values[reference] = replace(row.value, value="192.0.2.254")
    assert result.proofs.resolve_virtual_ip_reference(reference) == leaves



@pytest.mark.parametrize("fault", ["rows", "duplicate", "owners", "extra_owner", "missing_cell", "extra_cell",
    "value_clone", "reader_clone", "foreign_reader", "undeclared_reader", "store_type", "rows_type", "row_type", "result_type", "reader_type"])
def test_component_store_population_and_actual_reader_close_after_good_owner_validation(tmp_path, monkeypatch, fault):
    case = compose(tmp_path / "inputs", close=False)
    result, reader, index = case.source, case.reader, case.proofs
    row = result.rows[-1]
    reference = k.FactRef(fact=VIP, subject=row.subject)
    if fault in ("rows", "duplicate", "rows_type", "row_type"):
        rows = result.rows[:-1] if fault == "rows" else result.rows + (row,) if fault == "duplicate" else (
            list(result.rows) if fault == "rows_type" else (object(), *result.rows[1:]))
        result = replace(result, rows=rows)
    elif fault == "owners":
        result.store.owners[VIP] = "l3.fhrp/forged"
    elif fault == "extra_owner":
        result.store.owners[STATE] = b.STEP.id
    elif fault == "missing_cell":
        result.store.values.pop(reference)
    elif fault == "extra_cell":
        result.store.values[k.FactRef(fact=VIP, subject=k.EntityKey("fhrp_local:extra"))] = row.value
    elif fault == "value_clone":
        result.store.values[reference] = replace(row.value)
    elif fault == "reader_clone":
        read = FactReader.read
        monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)))
    elif fault == "foreign_reader":
        foreign = FactStore()
        foreign.owners, foreign.values = dict(result.store.owners), dict(result.store.values)
        reader = bind_reader(foreign, step=READ)
    elif fault == "undeclared_reader":
        reader = bind_reader(result.store, step=b.SOURCE_STEP)
    elif fault == "store_type":
        store = SimpleNamespace(owners=dict(result.store.owners), values=dict(result.store.values))
        result, reader = replace(result, store=store), bind_reader(store, step=READ)
    elif fault == "result_type":
        result = SimpleNamespace(store=result.store, rows=result.rows)
    else:
        reader = object()
    code = "undeclared_read:" + VIP if fault == "undeclared_reader" else "p4_projection_store"
    with pytest.raises(ValueError, match="^" + code + "$"):
        index.close_virtual_ip(result, reader)
    assert index.virtual_ip_reader is None
    with pytest.raises(ValueError, match="^p4_projection_reference$"):
        index.resolve_virtual_ip_reference(reference)


@pytest.mark.parametrize("fault", ["execution_type", "profile", "schema", "base_schema", "coverage",
    "owner", "context", "registration", "raw", "parse", "value_type", "member_type"])
def test_fixed_profile_registry_and_complete_capture_metadata_stay_closed(tmp_path, fault):
    case = compose(tmp_path / "inputs", close=False)
    execution = case.execution
    if fault == "execution_type":
        execution = SimpleNamespace(envelope=execution.envelope, executed=execution.executed)
    elif fault == "profile":
        execution = replace(execution, envelope=replace(execution.envelope, registration_sha256="0" * 64))
    elif fault in ("schema", "base_schema"):
        envelope = execution.envelope
        raw = json.loads(envelope.raw if fault == "schema" else envelope.base.raw)
        raw["schema"] = "unregistered.schema"
        envelope = replace(envelope, raw=canonical(raw)) if fault == "schema" else replace(envelope, base=replace(envelope.base, raw=canonical(raw)))
        execution = replace(execution, envelope=envelope)
    elif fault == "coverage":
        execution = replace(execution, executed=execution.executed[:-1])
    elif fault == "member_type":
        execution = replace(execution, envelope=replace(execution.envelope, captures=(object(), *execution.envelope.captures[1:])))
    else:
        output = next(item for item in execution.executed if item.receipt.capture.operation == b.hsrp.OP)
        if fault == "value_type":
            changed = replace(output, value=object())
        else:
            changes = {"owner": {"owner": "unregistered/owner"}, "context": {"context": "changed"},
                "registration": {"registration_sha256": "0" * 64}, "raw": {"capture": replace(output.receipt.capture, raw=output.receipt.capture.raw + b"changed")},
                "parse": {"parse": replace(output.receipt.parse)}}[fault]
            changed = replace(output, receipt=replace(output.receipt, **changes))
        execution = replace(execution, executed=tuple(changed if item is output else item for item in execution.executed))
    code = "profile" if fault == "profile" else "registry" if fault in ("schema", "base_schema") else "capture"
    with pytest.raises(ValueError, match="^p4_projection_" + code + "$"):
        FhrpVipProofIndex(execution, LIMITS)


@pytest.mark.parametrize("fault", ["digest", "registry", "slice", "unknown_role"])
def test_vip_byte_and_registry_leaves_authenticate_exact_authorized_points(tmp_path, fault):
    case = compose(tmp_path / "inputs", "unknown" if fault == "unknown_role" else "normal")
    row = next(row for row in case.source.rows if type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_OBSERVABLE) if fault == "unknown_role" else next(
        row for row in case.source.rows if type(row.value) is k.Known)
    evidence = row.value.evidence
    if fault == "registry":
        selected = next(ref for ref in evidence if type(ref) is k.RegistryRef)
        changed = replace(selected, table_digest="0" * 64)
    else:
        selected = tuple(ref for ref in evidence if type(ref) is k.EvidenceRef)[-1]
        capture = next(capture for capture in case.proofs.captures if capture.id == selected.capture)
        if fault == "digest":
            changed = replace(selected, excerpt_sha256="0" * 64)
        elif fault == "unknown_role":
            changed = replace(selected, role=k.EvidenceRole.SUBJECT)
        else:
            span = k.ByteSpan(start=selected.locator.start + 1, end=selected.locator.end)
            changed = replace(selected, locator=span, excerpt_sha256=sha256(capture.raw[span.start:span.end]).hexdigest())
    evidence = tuple(changed if ref is selected else ref for ref in evidence)
    code = "span" if fault == "digest" else "registry" if fault == "registry" else "scope"
    with pytest.raises(ValueError, match="^p4_projection_" + code + "$"):
        case.proofs.resolve(case.proofs.scope(VIP, row.subject), evidence, positive=type(row.value) is k.Known)
