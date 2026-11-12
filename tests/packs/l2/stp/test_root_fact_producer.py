"""Local registered Root4 facts bind literal values and evidence to this invocation only."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_build import P, request, target
from test_root_identity import MAC, block, oracle

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId
from atlas_brain.model.store import bind_reader
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l2.stp import root_identity
from atlas_brain.runner import p4
from atlas_brain.runner.p4_refs import ProofIndex
from tools import p4_estate_cases as estate

PRIORITY, ADDRESS = "l2.stp.reported_root_priority", "l2.stp.reported_root_mac"
ROOT, ROLE, STEP = "l2.stp.root_guard", "l2.stp.reported_role", "l2.stp/parse_root_guard"
IDS = tuple(sorted((ROOT, ROLE, PRIORITY, ADDRESS)))
LIMITS = Budgets(1000000, 1000000, 1000)


def inputs(raw=None, *, priority="32769", guard=True, integrity=k.IntegrityState.COMPLETE):
    point = target(vlans=(3, 2, 1))
    raw = block(1, priority, guard=guard) + block(2, priority, guard=guard) if raw is None else raw
    supplied = request(point, raw, integrity=integrity)
    return point, supplied


def run(point, supplied):
    return b.build_root_observations((point,), () if supplied is None else (supplied,))


def cells(row):
    return ((ROOT, row.value), (ROLE, row.role), (PRIORITY, row.root_priority), (ADDRESS, row.root_mac))


def original_spans(output, row):
    fields = dict(row.fields)
    header, = [record for record in output.value.parse.records if record.rule_id.startswith("header_") and record.span in row.spans]
    root, = [record for record in output.value.parse.records if record.rule_id == "root" and record.span in row.spans]
    return header.span, fields["port"].span, fields["vlan"].span, root.span, fields["root_priority"].span, fields["root_mac"].span


@pytest.mark.parametrize("priority", ["0", "32769", "65535"])
@pytest.mark.parametrize("guard", [False, True])
@pytest.mark.parametrize("ending,indent", [(b"\n", b""), (b"\r\n", b" \t")])
def test_root4_is_registered_before_one_parse_and_writes_exact_source_values_and_six_refs(monkeypatch, priority, guard, ending, indent):
    raw = block(1, priority, guard=guard) + block(2, priority, guard=guard)
    raw = ending.join(indent + line + b" \t" for line in raw.splitlines()) + ending
    point, supplied = inputs(raw)
    before, calls, checked = supplied.capture.raw, [], []
    execute, parse, validate = b.execute_parsers, b.stp.parse_capture, root_identity.validate_root_identity_claims
    def registered(declarations, handlers, requests):
        assert declarations == (b.ROOT_DECLARATION,) and declarations[0] is b.ROOT_DECLARATION
        specs = sorted((str(f.id), f.value_type, str(f.pack), f.subject, str(f.step)) for f in declarations[0].facts)
        assert specs == [(ROLE, "text", "l2.stp", "stp_port_vlan", STEP), (ADDRESS, "text", "l2.stp", "stp_port_vlan", STEP),
            (PRIORITY, "integer", "l2.stp", "stp_port_vlan", STEP), (ROOT, "boolean", "l2.stp", "stp_port_vlan", STEP)]
        assert b.ROOT_STEP.produces == IDS and handlers[0].binding.operation == "iosxe.show_spanning_tree_interface_detail"
        assert registration.compile_packs(declarations).registration_sha256 != registration.compile_packs((b.DECLARATION,)).registration_sha256
        return execute(declarations, handlers, requests)
    def parsed(*args):
        calls.append(args)
        return parse(*args)
    def canonical_source(domain, output, claims):
        canonical_claims = validate(domain, output, claims)
        checked.append(canonical_claims)
        object.__setattr__(claims[0][1], "priority", int(priority) + 1)
        return canonical_claims
    monkeypatch.setattr(root_identity, "validate_root_identity_claims", canonical_source)
    monkeypatch.setattr(b, "execute_parsers", registered)
    monkeypatch.setattr(b.stp, "parse_capture", parsed)
    result = run(point, supplied)
    assert len(calls) == len(checked) == 1 and supplied.capture.raw == before and len(result.rows) == 3
    assert result.store.owners == {fact: StepId(STEP) for fact in IDS} and len(result.store.values) == 12
    reader = bind_reader(result.store, step=replace(p4.PROJECT, id=StepId("l2.stp/test_root_reader"), reads=IDS))
    old_reader = bind_reader(result.store, step=p4.PROJECT)
    output, = result.executed
    assert output.receipt.capture is supplied.capture and output.receipt.parse is output.value.parse
    assert output.receipt.registration_sha256 == registration.compile_packs((b.ROOT_DECLARATION,)).registration_sha256
    for row in result.rows:
        for fact, state in cells(row):
            assert reader.read(fact=k.FactId(fact), subject=row.subject) is state
        for fact in (PRIORITY, ADDRESS):
            with pytest.raises(ValueError, match="^undeclared_read:" + fact + "$"):
                old_reader.read(fact=k.FactId(fact), subject=row.subject)
        if row.vlan == 3:
            assert row.root_priority is row.root_mac and row.root_priority.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
            continue
        for state, value, raw_value in ((row.root_priority, int(priority), priority), (row.root_mac, MAC, MAC)):
            assert type(state) is k.Known and type(state.value) is type(value)
            assert (state.value, state.raw, state.basis) == (value, raw_value, k.Basis.OBSERVED)
            assert state.evidence[:1] == point.node.declaration.evidence
            refs = state.evidence[1:]
            assert len(refs) == 6 and tuple((r.locator.start, r.locator.end) for r in refs) == oracle(raw, row.vlan)
            assert all(type(r) is k.EvidenceRef and r.capture == supplied.capture.id and r.role is k.EvidenceRole.SUBJECT
                and r.excerpt_sha256 == sha256(raw[r.locator.start:r.locator.end]).hexdigest() for r in refs)
            assert all(r.locator is span for r, span in zip(refs, original_spans(output, output.value.rows[row.vlan - 1]), strict=True))
        assert row.role.value == "designated"
        assert row.value.value is False if guard else row.value.reason is k.UnknownReason.FIELD_NOT_PRINTED


@pytest.mark.parametrize("case,reason", [("omitted", "field_not_printed"), ("missing", "subject_absent_from_capture"),
    ("nocapture", "not_collected"), ("partial", "parse_partial"), ("empty", "empty_unregistered"),
    ("error", "capture_error"), ("truncated", "capture_truncated"), ("unknown_role", "parse_partial")])
def test_unknown_roots_keep_all_four_cells_and_truthful_original_scope_and_needs(case, reason):
    raw = block(1, root=False) + block(2, root=False) if case == "omitted" else block(1) if case == "missing" else (
        b"" if case == "empty" else block(1) + block(2) + (b"unmodelled\n" if case == "partial" else b""))
    raw = raw.replace(b"designated forwarding", b"mystery forwarding") if case == "unknown_role" else raw
    point, supplied = inputs(raw, integrity={"error": k.IntegrityState.ERROR, "truncated": k.IntegrityState.TRUNCATED}.get(case, k.IntegrityState.COMPLETE))
    result = run(point, None if case == "nocapture" else supplied)
    assert len(result.rows) == 3 and len(result.store.values) == 12 and set(result.store.owners) == set(IDS)
    for row in result.rows:
        if case == "missing" and row.vlan == 1:
            assert type(row.root_priority) is k.Known
            continue
        wanted = "subject_absent_from_capture" if row.vlan == 3 and case in ("omitted", "missing") else reason
        priority, mac = row.root_priority, row.root_mac
        assert type(priority) is k.Unknown and priority is mac and str(priority.reason) == wanted
        assert priority.detail == "stp_reported_root_unresolved" and priority.evidence[:1] == point.node.declaration.evidence
        need, = priority.next_evidence
        assert (need.operation, need.params, need.resolves, need.reruns) == (
            "iosxe.show_spanning_tree_interface_detail", (("port", P),), (ADDRESS, PRIORITY), (STEP,))
        refs = priority.evidence[1:]
        assert len(refs) == (0 if case == "nocapture" else 1)
        assert all(type(r.locator) is k.WholeCapture and r.role is k.EvidenceRole.WITNESS
            and r.capture == supplied.capture.id and r.excerpt_sha256 == sha256(raw).hexdigest() for r in refs)


@pytest.mark.parametrize("plant", ["type", "owner", "produces", "binding"])
def test_malformed_root_metadata_is_refused_before_parser_or_writer(monkeypatch, plant):
    point, supplied = inputs()
    if plant == "type":
        monkeypatch.setattr(b, "ROOT_DECLARATION", replace(b.ROOT_DECLARATION,
            facts=tuple(replace(f, value_type="boolean") if f.id == PRIORITY else f for f in b.ROOT_DECLARATION.facts)))
    elif plant == "binding":
        monkeypatch.setattr(b, "BINDING", replace(b.BINDING, step=StepId("l2.stp/foreign")))
    else:
        monkeypatch.setattr(b, "ROOT_STEP", replace(b.ROOT_STEP, **({"id": StepId("l2.stp/foreign")} if plant == "owner" else {"produces": IDS[:-1]})))
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("parser before metadata gate"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before metadata gate"))
    with pytest.raises(ValueError, match="^stp_root_observation_metadata$"):
        run(point, supplied)


@pytest.mark.parametrize("plant", ["list", "missing", "duplicate", "value", "capture", "context", "source", "operation", "rendered", "parse", "owner", "legacy_profile", "extra_produced"])
def test_real_runtime_outputs_cannot_substitute_coverage_profiles_or_original_sources(monkeypatch, plant):
    point, supplied = inputs()
    execute = b.execute_parsers
    def forged(declarations, handlers, requests):
        outputs = execute((b.DECLARATION,) if plant == "legacy_profile" else declarations, handlers, requests)
        output, = outputs
        if plant == "list":
            return list(outputs)
        if plant == "missing":
            return ()
        if plant == "duplicate":
            return outputs + outputs
        if plant == "extra_produced":
            handlers[0].parser.produced[k.CaptureId("cap:unrequested")] = output.value
            return outputs
        if plant == "value":
            return (replace(output, value=replace(output.value)),)
        receipt = output.receipt
        if plant == "capture":
            receipt = replace(receipt, capture=replace(receipt.capture))
        elif plant == "parse":
            receipt = replace(receipt, parse=replace(receipt.parse))
        elif plant in ("source", "operation", "rendered"):
            object.__setattr__(receipt.capture, plant, "other")
        elif plant != "legacy_profile":
            receipt = replace(receipt, **{plant: "other"})
        return (replace(output, receipt=receipt),)
    monkeypatch.setattr(b, "execute_parsers", forged)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before source gate"))
    with pytest.raises(ValueError, match="^stp_root_observation_" + ("profile" if plant in ("owner", "legacy_profile") else "source") + "$"):
        run(point, supplied)


@pytest.mark.parametrize("case", ["baseline", "pagp", "missing"])
def test_legacy_two_fact_and_all_five_output_bytes_stay_unchanged(tmp_path, case):
    point, supplied = inputs()
    legacy = b.build_root_guard((point,), (supplied,))
    assert len(legacy.store.owners) == 2 and len(legacy.store.values) == 6
    assert all(row.root_priority is None and row.root_mac is None for row in legacy.rows)
    files = estate.members(canonical, case)
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    estate.validate(p4.analyse_folder(tmp_path, LIMITS), files, case, canonical)


def test_root_profile_is_not_implicitly_composable_or_an_old_projection(tmp_path):
    with pytest.raises(ValueError, match="^duplicate_pack$"):
        registration.compile_packs((b.DECLARATION, b.ROOT_DECLARATION))
    other_step = replace(b.ROOT_STEP, id=StepId("l2.other/parse"), pack=k.PackId("l2.other"), produces=(), evaluator="l2.other.parse")
    other = registration.PackDeclaration(pack=k.PackId("l2.other"), entity_kinds=(), facts=(), relations=(), steps=(other_step,),
        operations=(registration.OperationBinding(operation="iosxe.show_spanning_tree_interface_detail", step=other_step.id),))
    with pytest.raises(ValueError, match="^duplicate_operation$"):
        registration.compile_packs((b.ROOT_DECLARATION, other))
    files = estate.members(canonical, "missing")
    side = json.loads(files["p4.json"])
    side["captures"] = []
    files = {name: raw for name, raw in files.items() if name in ("p2.json", "p4.json", "discovery.txt")}
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    envelope = b.p4_admission.admit_folder(tmp_path, LIMITS, declarations=(b.ROOT_DECLARATION, p4.ec.DECLARATION, p4.fhrp.DECLARATION))
    with pytest.raises(ValueError, match="^p4_projection_profile$"):
        ProofIndex(b.p4_pipeline.Result(envelope=envelope, executed=()), LIMITS)


@pytest.mark.parametrize("missing", [0, 1])
def test_root_profile_never_writes_a_row_with_an_unfilled_new_state(monkeypatch, missing):
    point, supplied = inputs()
    generated = b._root_states
    def incomplete(*args, **kwargs):
        states = generated(*args, **kwargs)
        pair = list(states[0])
        pair[missing] = None
        return (tuple(pair),) + states[1:]
    monkeypatch.setattr(b, "_root_states", incomplete)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before population gate"))
    with pytest.raises(ValueError, match="^stp_root_observation_population$"):
        run(point, supplied)


def test_real_public_getter_carrier_fault_reaches_unpatched_verifier_before_writer(monkeypatch):
    point, supplied = inputs()
    actual = root_identity.reported_root_identity_proofs
    def forged(domain, output):
        claims = actual(domain, output)
        return ((replace(claims[0][0]), *claims[0][1:]),) + claims[1:]
    monkeypatch.setattr(root_identity, "reported_root_identity_proofs", forged)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before qualified carrier gate"))
    with pytest.raises(ValueError, match="^stp_root_identity_claims$"):
        run(point, supplied)
