"""Conditional VIP checks over fresh sources and trusted complete Store matrices."""
import json
from dataclasses import asdict, replace
from hashlib import sha256

import pytest
from test_gateway_policy import PAIR, gateway
from test_gateway_source import LIMITS
from test_gateway_source import folder as source_folder

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded, Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import virtual_ip_check as check
from atlas_brain.runner import p4_fhrp_policy as runner

VIP, STATE = "l3.fhrp.reported_virtual_ip", "l3.fhrp.reported_state"


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
def test_public_report_twins_keep_every_operand_and_conditional_scope(tmp_path, right, missing, domain, count, state, reason):
    files = folder(tmp_path / "inputs", right, missing, max(0, count - 2))
    points = PAIR[:1] if count == 1 else PAIR + extra_points(count - 2)
    out = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, (gateway(domain=domain, participants=points),))
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
def test_public_wrapper_owns_one_fresh_source_original_binding_and_complete_vip_reader(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    factory, bind, read, init = runner.prepare_fhrp_virtual_ip_source, policy.plan_for_declared_scope, FactReader.read, check.Finding.__init__
    sources, reads, snapshots = [], [], []
    def preparing(*args):
        source = factory(*args)
        sources.append(source)
        snapshots.append(((dict(source.source.source.store.owners), dict(source.source.source.store.values)),
            (dict(source.source.store.owners), dict(source.source.store.values)), source.execution.envelope.registration_sha256, b.VIP_DECLARATION))
        monkeypatch.setattr(b.hsrp, "parse_capture", lambda *_: pytest.fail("checker reparsed"))
        monkeypatch.setattr(b, "reported_state_proofs", lambda *_: pytest.fail("checker looked up raw rows"))
        monkeypatch.setattr(FactWriter, "write", lambda *_a, **_k: pytest.fail("checker wrote facts"))
        return source
    def binding(envelope, budgets, policies, domains):
        assert len(sources) == 1 and envelope is sources[0].execution.envelope and domains is sources[0].domains and budgets is LIMITS
        return bind(envelope, budgets, policies, domains)
    def reading(self, **kwargs):
        if sources:
            assert self.step is check.STEP and kwargs["fact"] == VIP
            reads.append((kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    def finding(self, **kwargs):
        assert reads == [(VIP, subject) for subject in sorted(row.subject for row in sources[0].source.rows)]
        return init(self, **kwargs)
    monkeypatch.setattr(runner, "prepare_fhrp_virtual_ip_source", preparing)
    monkeypatch.setattr(policy, "plan_for_declared_scope", binding)
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(check.Finding, "__init__", finding)
    out = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, () if empty else (gateway(),))
    source, = sources
    assert out.preparation is source and out.plan.envelope is source.execution.envelope
    assert reads == [(VIP, subject) for subject in sorted(row.subject for row in source.source.rows)]
    for store, snapshot in zip((source.source.source.store, source.source.store), snapshots[0][:2], strict=True):
        assert (store.owners, store.values) == snapshot
        assert all(store.values[ref] is value for ref, value in snapshot[1].items())
    assert source.execution.envelope.registration_sha256 == snapshots[0][2] and b.VIP_DECLARATION is snapshots[0][3]
    assert (check.STEP.pack, check.STEP.kind, check.STEP.scope, check.STEP.reads, check.STEP.produces) == (b.PACK, "check", "estate", (VIP,), ())
    assert check.STEP.id not in {step.id for step in b.VIP_DECLARATION.steps}
    assert len(out.result.rows) == (0 if empty else 1) and out.result.coverage is out.plan.coverage
    assert out.result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN


@pytest.mark.parametrize("mode", ["domain", "vlan", "missing_domain"])
def test_explicit_scope_separates_repeated_vlan_group_and_vip_operands(tmp_path, mode):
    folder(tmp_path / "inputs")
    declarations = (gateway(id="left", participants=PAIR[:1], domain=None if mode == "missing_domain" else "blue"),
        gateway(id="right", participants=PAIR[1:], domain=None if mode == "missing_domain" else "red" if mode == "domain" else "blue",
            vlan=20 if mode == "vlan" else 10))
    out = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, declarations)
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
    out = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, (gateway(group=group, vlan=4094, participants=(("hsrp", interface),)),))
    finding, = out.result.rows
    assert (out.plan.rows[0].key.group, out.plan.rows[0].key.vlan) == (group, 4094)
    assert finding.operands[0].participant.interface == interface and type(finding.operands[0].state) is k.Known
    assert (finding.state, finding.reason, finding.detail, finding.conditional) == ("unknown", k.UnknownReason.NOT_OBSERVABLE, "comparison_operand_missing", True)


@pytest.mark.parametrize("fault", ["list", "member", "count", "too_many_participants", "later_policy"])
def test_public_policy_shapes_and_later_selectors_refuse_before_checker(tmp_path, monkeypatch, fault):
    folder(tmp_path / "inputs")
    declarations = [gateway()] if fault == "list" else (object(),) if fault == "member" else (gateway(),) * 65 if fault == "count" else (
        (gateway(participants=(PAIR[0],) * 129),) if fault == "too_many_participants" else (
            gateway(id="aaa"), gateway(id="zzz", participants=(("hsrp", "not_declared"),))))
    if fault in ("list", "member", "count"):
        monkeypatch.setattr(runner, "prepare_fhrp_virtual_ip_source", lambda *_: pytest.fail("invalid outer policies executed source"))
    monkeypatch.setattr(check, "evaluate_declared", lambda *_: pytest.fail("checker before all policies bound"))
    code = "fhrp_virtual_ip_check_input" if fault in ("list", "member", "count") else "fhrp_gateway_policy_selector"
    with pytest.raises(ValueError, match="^" + code + "$"):
        runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, declarations)


@pytest.mark.parametrize("carrier", ["preparation", "plan", "store", "execution", "evaluation", "domains", "proofs", "reader", "text", "budget"])
def test_public_api_refuses_opaque_carriers_and_non_nominal_budget_before_factory(tmp_path, monkeypatch, carrier):
    folder(tmp_path / "inputs")
    out = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, (gateway(),))
    roots = {"preparation": out.preparation, "plan": out.plan, "store": out.preparation.source.store,
        "execution": out.preparation.execution, "evaluation": out, "domains": out.preparation.domains,
        "proofs": out.preparation.proofs, "reader": out.preparation.proofs.virtual_ip_reader,
        "text": str(tmp_path / "inputs"), "budget": tmp_path / "inputs"}
    monkeypatch.setattr(runner, "prepare_fhrp_virtual_ip_source", lambda *_: pytest.fail("opaque input executed factory"))
    with pytest.raises(ValueError, match="^fhrp_source_input$"):
        runner.evaluate_virtual_ip_comparisons(roots[carrier], object() if carrier == "budget" else LIMITS, (gateway(),))


@pytest.mark.parametrize("empty", [False, True])
def test_public_factory_refuses_coherent_unselected_late_vip_lie_before_checker(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    build = b.VirtualIpOwner.build_virtual_ip
    def changed(self):
        source = build(self)
        row = next(row for row in source.rows if row.interface == "BD3329")
        forged = replace(row.value, value="192.0.2.254", raw="192.0.2.254")
        source.store.values[k.FactRef(fact=VIP, subject=row.subject)] = forged
        return replace(source, rows=tuple(replace(item, value=forged) if item is row else item for item in source.rows))
    monkeypatch.setattr(b.VirtualIpOwner, "build_virtual_ip", changed)
    monkeypatch.setattr(check, "evaluate_declared", lambda *_: pytest.fail("checker before canonical source closure"))
    with pytest.raises(ValueError, match="^hsrp_vip_value$"):
        runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, () if empty else (gateway(),))


def test_public_budget_covers_original_inputs_and_policy_registry_before_finding(tmp_path, monkeypatch):
    files = folder(tmp_path / "inputs")
    out = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, (gateway(),))
    raw, count = out.plan.raw, len(files) + 1
    total, largest = sum(map(len, files.values())) + len(raw), max(files, key=lambda name: len(files[name]))
    artifact = max(len(raw), len(files[largest]))
    exact = Budgets(total, artifact, count)
    assert runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", exact, (gateway(),)).plan.raw == raw
    monkeypatch.setattr(check.Finding, "__init__", lambda *_a, **_k: pytest.fail("finding before budget closure"))
    cases = ((Budgets(sum(map(len, files.values())) - 1, 1000000, count), "bundle"),
        (Budgets(total - 1, 1000000, count), "fhrp_gateway_policy"),
        (Budgets(total, artifact - 1, count), largest if len(files[largest]) >= len(raw) else "fhrp_gateway_policy"),
        (Budgets(total, 1000000, count - 1), "fhrp_gateway_policy"))
    for limits, member in cases:
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as error:
            runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", limits, (gateway(),))
        assert error.value.member == member


def test_each_public_evaluation_gets_a_distinct_factory_execution_once(tmp_path, monkeypatch):
    folder(tmp_path / "inputs")
    factory, sources = runner.prepare_fhrp_virtual_ip_source, []
    def preparing(*args):
        source = factory(*args)
        sources.append(source)
        return source
    monkeypatch.setattr(runner, "prepare_fhrp_virtual_ip_source", preparing)
    first = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, (gateway(),))
    second = runner.evaluate_virtual_ip_comparisons(tmp_path / "inputs", LIMITS, (gateway(),))
    assert len(sources) == 2 and first.preparation is sources[0] and second.preparation is sources[1]
    assert first.preparation is not second.preparation and first.preparation.execution is not second.preparation.execution
    assert first.preparation.source.store is not second.preparation.source.store
