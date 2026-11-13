"""Trusted conditional VIP checks; the caller owns complete source and plan closure."""
import json
from dataclasses import asdict, replace
from enum import StrEnum
from hashlib import sha256
from types import SimpleNamespace

import pytest
from test_gateway_policy import PAIR, gateway
from test_gateway_source import LIMITS
from test_gateway_source import folder as source_folder

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import virtual_ip_check as check
from atlas_brain.runner import p4_fhrp_policy as runner

VIP, STATE = "l3.fhrp.reported_virtual_ip", "l3.fhrp.reported_state"


class Address(StrEnum):
    PRINTED = "192.0.2.1"


def extra_points(count):
    return tuple(("hsrp" if index < 124 else "hsrp-cold", f"Vl{1000 + index}") for index in range(count))


def folder(root, right="192.0.2.99", missing=None, extra=0):
    files = source_folder(root, missing)
    side = json.loads(files["p4.json"])
    for target in side["targets"]:
        if target["operation"] == b.hsrp.OP:
            target["params"]["groups"].extend([[interface, "1"] for identity, interface in extra_points(extra) if identity == target["id"]])
    if "cold-gateway.txt" in files:
        files["cold-gateway.txt"] = files["cold-gateway.txt"].replace(b"192.0.2.99", right.encode())
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


def prepared(root, policies):
    source = runner.prepare_fhrp_virtual_ip_source(root, LIMITS)
    plan = policy.plan_for_declared_scope(source.execution.envelope, LIMITS, policies, source.domains)
    return source, plan, tuple(sorted(row.subject for row in source.source.rows))


def evaluated(root, policies):
    source, plan, subjects = prepared(root, policies)
    return SimpleNamespace(preparation=source, plan=plan, result=check.evaluate_declared(plan, source.source.store, subjects))


@pytest.mark.parametrize("right,missing,domain,count,state,reason", [
    ("192.0.2.99", None, "blue", 2, "problem", None),
    ("192.0.2.1", None, "blue", 2, "unknown", k.UnknownReason.AS_OF_MISSING),
    ("192.0.2.99", None, None, 2, "unknown", k.UnknownReason.JOIN_UNPROVEN),
    ("192.0.2.99", None, "blue", 1, "unknown", k.UnknownReason.NOT_OBSERVABLE),
    ("unknown", None, "blue", 2, "unknown", k.UnknownReason.NOT_OBSERVABLE),
    ("192.0.2.99", "hsrp-cold", "blue", 2, "unknown", k.UnknownReason.NOT_COLLECTED),
    ("192.0.2.99", "both", "blue", 2, "unknown", k.UnknownReason.NOT_COLLECTED),
    ("192.0.2.99", None, "blue", 3, "problem", None),
    ("192.0.2.1", None, "blue", 3, "unknown", k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE),
    ("192.0.2.99", None, "blue", 128, "problem", None)])
def test_trusted_report_twins_keep_every_operand_and_conditional_scope(tmp_path, right, missing, domain, count, state, reason):
    files = folder(tmp_path / "inputs", right, missing, max(0, count - 2))
    points = PAIR[:1] if count == 1 else PAIR + extra_points(count - 2)
    out = evaluated(tmp_path / "inputs", (gateway(domain=domain, participants=points),))
    finding, = out.result.rows
    row, = out.plan.rows
    assert (finding.check, finding.policy_id, finding.state, finding.reason, finding.conditional) == (
        "l3.fhrp.reported_virtual_ip_disagreement", "gateway", state, reason, True)
    assert len(finding.operands) == len(row.participants) == count
    assert all(operand.participant is point and operand.state is out.preparation.source.store.values[k.FactRef(fact=VIP, subject=point.subject)]
        for operand, point in zip(finding.operands, row.participants, strict=True))
    refs = tuple(k.FactRef(fact=VIP, subject=point.subject) for point in row.participants)
    assert finding.evidence == row.binding.evidence + refs
    assert all(out.preparation.proofs.resolve_virtual_ip_reference(ref) for ref in refs)
    with pytest.raises(ValueError, match="^p4_projection_reference$"):
        out.preparation.proofs.resolve_virtual_ip_reference(k.FactRef(fact=STATE, subject=row.participants[0].subject))
    assert out.result.denominator is out.plan.denominator and out.result.coverage is out.plan.coverage
    assert out.result.denominator == (("declared_gateways", 1), ("declared_participant_occurrences", count))
    assert out.result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    gaps = tuple(operand.state for operand in finding.operands if type(operand.state) is k.Unknown)
    if state == "problem":
        assert finding.detail == "conditional_reported_virtual_ip_difference"
        needs = tuple(need for gap in gaps for need in gap.next_evidence)
        assert finding.next_evidence[:len(needs)] == needs
        assert len(finding.next_evidence) == len(needs) + count
    elif domain is None:
        assert (finding.reason, finding.detail, finding.next_evidence) == (row.binding.reason, row.binding.detail, row.binding.next_evidence)
    elif gaps:
        assert (finding.reason, finding.detail, finding.next_evidence) == (gaps[0].reason, gaps[0].detail, gaps[0].next_evidence)
    else:
        assert finding.detail == ("comparison_operand_missing" if count == 1 else "untimed_equal_virtual_ip_reports")
    comparison = finding.next_evidence[-count:] if state == "problem" or not gaps and domain is not None else ()
    for point, need in zip(row.participants, comparison, strict=bool(comparison)):
        assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s, need.unprintable) == (
            point.node, b.hsrp.OP, (("group", point.group), ("interface", point.interface)), (VIP,), (str(check.STEP.id),), None,
            ("additional_declared_comparison_operand",) if count == 1 else ("collector_recorded_time", "declared_gateway_policy"))
    assert {path.name: path.read_bytes() for path in (tmp_path / "inputs").iterdir()} == files


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("fault", ["bool", "enum", "raw", "basis", "printed_unknown", "not_applicable", "object"])
def test_trusted_checker_rejects_unselected_last_cell_before_any_finding_even_empty(tmp_path, monkeypatch, empty, fault):
    folder(tmp_path / "inputs")
    source = runner.prepare_fhrp_virtual_ip_source(tmp_path / "inputs", LIMITS)
    last = sorted(row.subject for row in source.source.rows)[-1]
    selected = PAIR[1:] if last == next(row.subject for row in source.source.rows if row.interface == "Vl10") else PAIR[:1]
    plan = policy.plan_for_declared_scope(source.execution.envelope, LIMITS, () if empty else (gateway(participants=selected),), source.domains)
    value = next(row.value for row in source.source.rows if row.interface == "Vl10")
    forged = object() if fault == "object" else k.NotApplicable(reason=k.NAReason.FEATURE_NOT_ENABLED, evidence=value.evidence) if fault == "not_applicable" else replace(
        value, **({"value": False if fault == "bool" else Address.PRINTED} if fault in ("bool", "enum") else {"raw": "198.51.100.1"} if fault == "raw"
        else {"basis": k.Basis.DECLARED} if fault == "basis" else {"value": "unknown", "raw": "unknown"}))
    source.source.store.values[k.FactRef(fact=VIP, subject=last)] = forged
    assert all(point.subject != last for row in plan.rows for point in row.participants)
    monkeypatch.setattr(check.Finding, "__init__", lambda *_a, **_k: pytest.fail("finding before complete matrix"))
    with pytest.raises(ValueError, match="^fhrp_virtual_ip_check_value$"):
        check.evaluate_declared(plan, source.source.store, tuple(sorted(row.subject for row in source.source.rows)))


@pytest.mark.parametrize("fault", ["plan", "store", "list", "duplicate", "bool", "missing_selected", "late_selector", "late_key"])
def test_trusted_input_and_all_policy_prepass_close_before_first_finding(tmp_path, monkeypatch, fault):
    folder(tmp_path / "inputs")
    source, plan, subjects = prepared(tmp_path / "inputs", (gateway(),))
    store, code = source.source.store, "input"
    if fault == "plan":
        plan = object()
    elif fault == "store":
        store = object()
    elif fault == "list":
        subjects = list(subjects)
    elif fault == "duplicate":
        subjects = subjects + subjects[:1]
    elif fault == "bool":
        subjects = (True,)
    elif fault == "missing_selected":
        subjects = tuple(subject for subject in subjects if subject != plan.rows[0].participants[0].subject)
        code = "selector"
    else:
        row = plan.rows[0]
        foreign = replace(row.participants[0], subject=k.EntityKey("fhrp_local:outside"))
        late = replace(row, policy_id="late", participants=(foreign,)) if fault == "late_selector" else replace(row, policy_id="late", key=None)
        plan, code = replace(plan, rows=(row, late)), "selector"
    monkeypatch.setattr(check.Finding, "__init__", lambda *_a, **_k: pytest.fail("finding before every selector closed"))
    with pytest.raises(ValueError, match="^fhrp_virtual_ip_check_" + code + "$"):
        check.evaluate_declared(plan, store, subjects)


@pytest.mark.parametrize("multiple", [False, True])
@pytest.mark.parametrize("has_need", [False, True])
@pytest.mark.parametrize("detail", [None, "source_gap"])
def test_trusted_unknowns_preserve_original_objects_candidates_details_and_empty_needs(tmp_path, multiple, has_need, detail):
    folder(tmp_path / "inputs")
    source, plan, subjects = prepared(tmp_path / "inputs", (gateway(),))
    row = plan.rows[0]
    original = tuple(source.source.store.values[k.FactRef(fact=VIP, subject=point.subject)] for point in row.participants)
    gaps = []
    for index, point in enumerate(row.participants[:2 if multiple else 1]):
        need = k.EvidenceNeed(node=point.node, operation=b.hsrp.OP, params=(("group", point.group), ("interface", point.interface)),
            resolves=(VIP,), reruns=(str(b.VIP_STEP.id),), after_s=None, unprintable=("reported_virtual_ip",))
        gap = k.Unknown(reason=k.UnknownReason.CAPTURE_TRUNCATED if index == 0 else k.UnknownReason.CAPTURE_ERROR,
            detail=detail if index == 0 else "secondary_gap", evidence=original[index].evidence,
            candidates=(k.EntityKey("candidate:" + str(index)),), next_evidence=(need,) if has_need or index else ())
        source.source.store.values[k.FactRef(fact=VIP, subject=point.subject)] = gap
        gaps.append(gap)
    finding, = check.evaluate_declared(plan, source.source.store, subjects).rows
    assert finding.state == "unknown" and (finding.reason, finding.detail, finding.next_evidence) == (gaps[0].reason, detail, gaps[0].next_evidence)
    assert all(operand.state is source.source.store.values[k.FactRef(fact=VIP, subject=operand.participant.subject)] for operand in finding.operands)
    assert all(finding.operands[index].state is gap and finding.operands[index].state.candidates == (k.EntityKey("candidate:" + str(index)),)
        for index, gap in enumerate(gaps))
    assert finding.evidence == row.binding.evidence + tuple(k.FactRef(fact=VIP, subject=point.subject) for point in row.participants)


@pytest.mark.parametrize("mode", ["domain", "vlan", "missing_domain"])
def test_explicit_scope_separates_repeated_vlan_group_and_vip_operands(tmp_path, mode):
    folder(tmp_path / "inputs")
    declarations = (gateway(id="left", participants=PAIR[:1], domain=None if mode == "missing_domain" else "blue"),
        gateway(id="right", participants=PAIR[1:], domain=None if mode == "missing_domain" else "red" if mode == "domain" else "blue",
            vlan=20 if mode == "vlan" else 10))
    out = evaluated(tmp_path / "inputs", declarations)
    assert len(out.result.rows) == 2 and all(finding.state == "unknown" for finding in out.result.rows)
    assert [finding.reason for finding in out.result.rows] == [
        k.UnknownReason.JOIN_UNPROVEN if mode == "missing_domain" else k.UnknownReason.NOT_OBSERVABLE] * 2
    if mode == "missing_domain":
        assert all(row.key is None for row in out.plan.rows)
    else:
        keys = tuple(row.key for row in out.plan.rows)
        assert keys[0] != keys[1] and all(set(asdict(key)) == {"envelope_sha256", "domain", "vlan", "address_family", "protocol", "group"} for key in keys)
        assert [key.vlan for key in keys] == ([10, 20] if mode == "vlan" else [10, 10])
        assert all(key.group == "1" for key in keys)


@pytest.mark.parametrize("group,interface", [("0", "Vl20"), ("129", "BD3329")])
def test_singleton_nondefault_groups_keep_declared_vlan_without_health_inference(tmp_path, group, interface):
    folder(tmp_path / "inputs")
    out = evaluated(tmp_path / "inputs", (gateway(group=group, vlan=4094, participants=(("hsrp", interface),)),))
    finding, = out.result.rows
    assert (out.plan.rows[0].key.group, out.plan.rows[0].key.vlan) == (group, 4094)
    assert finding.operands[0].participant.interface == interface and type(finding.operands[0].state) is k.Known
    assert (finding.state, finding.reason, finding.detail, finding.conditional) == ("unknown", k.UnknownReason.NOT_OBSERVABLE, "comparison_operand_missing", True)


@pytest.mark.parametrize("empty", [False, True])
def test_trusted_complete_vip_reader_preserves_stores_profile_and_never_replays(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    source, plan, subjects = prepared(tmp_path / "inputs", () if empty else (gateway(),))
    read, init, reads = FactReader.read, check.Finding.__init__, []
    stores = (source.source.source.store, source.source.store)
    snapshots = tuple((dict(store.owners), dict(store.values)) for store in stores)
    registration, declaration = source.execution.envelope.registration_sha256, b.VIP_DECLARATION
    def reading(self, **kwargs):
        assert self.step is check.STEP and kwargs["fact"] == VIP
        reads.append((kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    def finding(self, **kwargs):
        assert reads == [(VIP, subject) for subject in subjects]
        return init(self, **kwargs)
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(check.Finding, "__init__", finding)
    for target, name in ((b.hsrp, "parse_capture"), (b, "reported_state_proofs"), (FactWriter, "write")):
        monkeypatch.setattr(target, name, lambda *_a, **_k: pytest.fail("trusted checker replayed parser/raw lookup/Writer"))
    result = check.evaluate_declared(plan, source.source.store, subjects)
    assert reads == [(VIP, subject) for subject in subjects] and len(result.rows) == (0 if empty else 1)
    assert result.coverage is plan.coverage and result.denominator is plan.denominator
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    for store, snapshot in zip(stores, snapshots, strict=True):
        assert (store.owners, store.values) == snapshot and all(store.values[ref] is value for ref, value in snapshot[1].items())
    assert source.execution.envelope.registration_sha256 == registration and b.VIP_DECLARATION is declaration
    assert (check.STEP.pack, check.STEP.kind, check.STEP.scope, check.STEP.reads, check.STEP.produces) == (b.PACK, "check", "estate", (VIP,), ())
    assert check.STEP.id not in {step.id for step in b.VIP_DECLARATION.steps}
