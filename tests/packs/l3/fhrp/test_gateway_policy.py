"""Explicit declared gateway scope from fresh qualified facts; no peer, VIP or health inference."""
import json
from dataclasses import asdict, replace
from hashlib import sha256

import pytest
from test_gateway_source import LIMITS, folder, subject

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.runner import p4
from atlas_brain.runner import p4_fhrp_policy as runner

PAIR = (("hsrp", "Vl10"), ("hsrp-cold", "BD10"))


def gateway(**changes):
    return replace(policy.GatewayPolicy(id="gateway", domain="blue", vlan=10, address_family="ipv4",
        protocol="hsrp", group="1", participants=PAIR), **changes)


@pytest.mark.parametrize("missing", [None, "hsrp", "hsrp-cold", "both"])
def test_explicit_gateway_key_and_original_participants_ignore_capture_availability_and_vip(tmp_path, missing):
    inputs = folder(tmp_path / "inputs", missing)
    prepared = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, (gateway(),))
    row, = prepared.plan.rows
    namespace = sha256(canonical(("atlas-brain.synthetic-p4/1", prepared.execution.envelope.registration_sha256,
        sha256(inputs["p4.json"]).hexdigest(), sha256(inputs["p2.json"]).hexdigest(), "round"))).hexdigest()
    assert asdict(row.key) == {"envelope_sha256": namespace, "domain": "blue", "vlan": 10,
        "address_family": "ipv4", "protocol": "hsrp", "group": "1"}
    assert tuple((p.target_id, p.interface, p.group, p.subject) for p in row.participants) == (
        ("hsrp", "Vl10", "1", subject("a", "Vl10", "1")), ("hsrp-cold", "BD10", "1", subject("b", "BD10", "1")))
    ref, = row.binding.evidence
    assert row.binding.basis is k.Basis.DECLARED and row.binding.raw == row.binding.value == "gateway"
    assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == (
        "declared_fhrp_gateways", "gateway", sha256(prepared.plan.raw).hexdigest(), "/gateways/0")
    assert prepared.plan.envelope is prepared.execution.envelope and prepared.plan.sha256 == ref.table_digest
    domains = tuple({item.target.node.key: item.target for item in prepared.source.rows}.values())
    assert prepared.plan.raw == policy.plan_for_declared_scope(prepared.execution.envelope, LIMITS,
        (gateway(participants=tuple(reversed(PAIR))),), tuple(reversed(domains))).raw
    assert prepared.plan.denominator == (("declared_gateways", 1), ("declared_participant_occurrences", 2))
    assert prepared.plan.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN and len(prepared.source.rows) == 6
    assert b"192.0.2.1" in inputs.get("hsrp.txt", b"") or missing in ("hsrp", "both")
    assert b"192.0.2.99" in inputs.get("cold-gateway.txt", b"") or missing in ("hsrp-cold", "both")
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == inputs


@pytest.mark.parametrize("vlan", [1, 4094])
def test_group_zero_and_single_local_are_supported_without_vlan_or_role_inference(tmp_path, vlan):
    folder(tmp_path / "inputs")
    result = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, (
        gateway(vlan=vlan, group="0", participants=(("hsrp", "Vl20"),)),))
    row, = result.plan.rows
    assert row.key.vlan == vlan and row.key.group == "0" and len(row.participants) == 1
    assert row.participants[0].subject == subject("a", "Vl20", "0") and row.binding.basis is k.Basis.DECLARED
    assert next(item.value.value for item in result.source.rows if item.subject == row.participants[0].subject) == "init"


def test_multiple_missing_domains_remain_unjoined_and_raw_vlan_declarations_are_retained(tmp_path):
    folder(tmp_path / "inputs")
    declarations = (gateway(id="left", domain=None, participants=(PAIR[0],)),
        gateway(id="right", domain=None, vlan=20, participants=(PAIR[1],)))
    result = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, declarations)
    assert len(result.plan.rows) == 2 and all(row.key is None for row in result.plan.rows)
    assert [(row.policy_id, len(row.participants)) for row in result.plan.rows] == [("left", 1), ("right", 1)]
    raw = json.loads(result.plan.raw)
    assert [(item["id"], item["domain"], item["vlan"]) for item in raw["gateways"]] == [("left", None, 10), ("right", None, 20)]
    for index, row in enumerate(result.plan.rows):
        ref, = row.binding.evidence
        assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == (
            "declared_fhrp_gateways", row.policy_id, result.plan.sha256, f"/gateways/{index}")
        assert type(row.binding) is k.Unknown and row.binding.reason is k.UnknownReason.JOIN_UNPROVEN
        assert row.binding.detail == "declared_gateway_domain_missing"
        need, = row.binding.next_evidence
        point, = row.participants
        assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s, need.unprintable) == (
            point.node, "iosxe.show_standby_brief", (("group", "1"), ("interface", point.interface)), (),
            ("l3.fhrp/prepare_gateway_source",), None, ("declared_l2_domain",))
    domains = tuple({row.target.node.key: row.target for row in result.source.rows}.values())
    distinct = (replace(declarations[0], domain="blue"), replace(declarations[1], domain="red", vlan=10))
    plan = policy.plan_for_declared_scope(result.execution.envelope, LIMITS, distinct, domains)
    assert [row.key.domain for row in plan.rows] == ["blue", "red"] and plan.rows[0].key != plan.rows[1].key
    assert plan.raw == policy.plan_for_declared_scope(result.execution.envelope, LIMITS,
        tuple(reversed(distinct)), tuple(reversed(domains))).raw


@pytest.mark.parametrize("plant", ["id", "domain", "vlan_bool", "vlan_zero", "vlan_large", "af", "protocol",
    "group", "group_bool", "large_group", "local_group", "empty", "many", "inner", "target_op", "interface", "duplicate_local",
    "duplicate_inside", "duplicate_id", "duplicate_key", "foreign_node", "context"])
def test_exact_metadata_original_local_selectors_and_collisions(tmp_path, plant):
    folder(tmp_path / "inputs")
    result = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, (gateway(),))
    domains = tuple({row.target.node.key: row.target for row in result.source.rows}.values())
    changes = {"id": {"id": "BAD"}, "domain": {"domain": ""}, "vlan_bool": {"vlan": True},
        "vlan_zero": {"vlan": 0}, "vlan_large": {"vlan": 4095}, "af": {"address_family": "ipv6"},
        "protocol": {"protocol": "vrrp"}, "group": {"group": "01"}, "group_bool": {"group": True},
        "large_group": {"group": "4096"}, "local_group": {"group": "4"}, "many": {"participants": (PAIR[0],) * 129},
        "empty": {"participants": ()}, "inner": {"participants": (["hsrp", "Vl10"],)},
        "target_op": {"participants": (("ec", "Vl10"),)}, "interface": {"participants": (("hsrp", "Vl11"),)}}
    selected = (gateway(**changes[plant]),) if plant in changes else (gateway(), gateway(id="other", domain="red"))
    if plant == "duplicate_inside":
        selected = (gateway(participants=(PAIR[0], PAIR[0])),)
    elif plant == "duplicate_id":
        selected = (gateway(participants=(PAIR[0],)), gateway(participants=(PAIR[1],), domain="red"))
    elif plant == "duplicate_key":
        selected = (gateway(participants=(PAIR[0],)), gateway(id="other", participants=(PAIR[1],)))
    elif plant in ("foreign_node", "context"):
        selected = (gateway(),)
        domains = (replace(domains[0], node=replace(domains[0].node)) if plant == "foreign_node" else
            replace(domains[0], context="other"), *domains[1:])
    code = "duplicate" if plant.startswith("duplicate") else "selector" if plant in (
        "local_group", "empty", "many", "inner", "target_op", "interface", "foreign_node", "context") else "value"
    with pytest.raises(ValueError, match="^fhrp_gateway_policy_" + code + "$"):
        policy.plan_for_declared_scope(result.execution.envelope, LIMITS, selected, domains)


@pytest.mark.parametrize("empty", [False, True])
def test_public_binding_uses_one_fresh_source_and_its_original_objects_without_semantic_replay(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    prepare, bind = runner.prepare_fhrp_source, policy.plan_for_declared_scope
    sources = []
    def qualified(*args, **kwargs):
        result = prepare(*args, **kwargs)
        sources.append(result)
        monkeypatch.setattr(b.hsrp, "parse_capture", lambda *_: pytest.fail("binding reparsed"))
        monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("binding wrote facts"))
        monkeypatch.setattr(FactReader, "read", lambda *_a, **_k: pytest.fail("binding read observed state"))
        return result
    def binding(envelope, budgets, declarations, domains):
        assert len(sources) == 1 and envelope is sources[0].execution.envelope and domains is sources[0].domains
        return bind(envelope, budgets, declarations, domains)
    monkeypatch.setattr(runner, "prepare_fhrp_source", qualified)
    monkeypatch.setattr(policy, "plan_for_declared_scope", binding)
    result = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, () if empty else (gateway(),))
    assert len(sources) == 1 and result.source is sources[0].source and result.execution is sources[0].execution
    assert result.plan.envelope is sources[0].execution.envelope and len(result.plan.rows) == (0 if empty else 1)
    assert result.plan.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    if empty:
        assert result.plan.coverage.evidence == result.execution.envelope.declaration.evidence


@pytest.mark.parametrize("empty", [False, True])
def test_real_source_semantic_failure_precedes_even_empty_gateway_binding(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    finish = runner.StandbyBriefPack.finish
    def changed(self, execution):
        result = finish(self, execution)
        row = next(row for row in result.rows if row.interface == "BD3329")
        forged = replace(row.value, value="active", raw="Active")
        result.store.values[k.FactRef(fact=b.REPORTED_STATE, subject=row.subject)] = forged
        return replace(result, rows=tuple(replace(item, value=forged) if item is row else item for item in result.rows))
    monkeypatch.setattr(runner.StandbyBriefPack, "finish", changed)
    monkeypatch.setattr(policy, "plan_for_declared_scope", lambda *_: pytest.fail("binding before source closure"))
    with pytest.raises(ValueError, match="^hsrp_gateway_source_value$"):
        runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, () if empty else (gateway(),))


@pytest.mark.parametrize("plant", ["list", "member", "count"])
def test_outer_policy_input_refuses_before_the_source_factory(tmp_path, monkeypatch, plant):
    declarations = [gateway()] if plant == "list" else (object(),) if plant == "member" else (gateway(),) * 65
    monkeypatch.setattr(runner, "prepare_fhrp_source", lambda *_: pytest.fail("invalid policies executed source"))
    with pytest.raises(ValueError, match="^fhrp_gateway_policy_input$"):
        runner.prepare_gateway_bindings(tmp_path, LIMITS, declarations)


@pytest.mark.parametrize("carrier", ["prepared", "plan", "store", "execution", "budget"])
def test_opaque_public_carriers_retain_the_accepted_source_input_boundary(tmp_path, monkeypatch, carrier):
    folder(tmp_path / "inputs")
    result = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, (gateway(),))
    roots = {"prepared": result, "plan": result.plan, "store": result.source.store,
        "execution": result.execution, "budget": tmp_path / "inputs"}
    monkeypatch.setattr(runner.stp, "build_root_guard_global", lambda *_a, **_k: pytest.fail("invalid input executed"))
    with pytest.raises(ValueError, match="^fhrp_source_input$"):
        runner.prepare_gateway_bindings(roots[carrier], object() if carrier == "budget" else LIMITS, (gateway(),))


def test_policy_registry_is_canonical_and_budgeted_once_above_all_original_inputs(tmp_path):
    inputs = folder(tmp_path / "inputs")
    result = runner.prepare_gateway_bindings(tmp_path / "inputs", LIMITS, (gateway(),))
    domains = tuple({row.target.node.key: row.target for row in result.source.rows}.values())
    raw = result.plan.raw
    wire = json.loads(raw)
    assert raw == canonical(wire) and wire["schema"] == "atlas-brain.declared-fhrp-gateway-policy/1"
    assert wire["semantic_group"] == "declared_synthetic" and wire["context"] == "round"
    total, count = sum(map(len, inputs.values())) + len(raw), len(inputs) + 1
    limits = p4.Budgets(total, max(len(raw), max(map(len, inputs.values()))), count)
    assert policy.plan_for_declared_scope(result.execution.envelope, limits, (gateway(),), domains).raw == raw
    for limits in (p4.Budgets(total - 1, 1000000, count), p4.Budgets(total, len(raw) - 1, count), p4.Budgets(total, 1000000, count - 1)):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as error:
            policy.plan_for_declared_scope(result.execution.envelope, limits, (gateway(),), domains)
        assert error.value.member == "fhrp_gateway_policy"
