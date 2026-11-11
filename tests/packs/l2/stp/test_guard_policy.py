"""Trusted declared guard intent: no capture interpretation, peer or health conclusion."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_declared_root_guard_scope import LIMITS, admitted, declared_oracle

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l3.fhrp import build as h
from atlas_brain.runner import p4_guard_policy as m


def participant(target="t0", vlan=1, mode="pvst", position="designated_downstream"):
    return m.policy.GuardParticipant(target_id=target, vlan=vlan, declared_mode=mode, position=position)


def intent(identity="one", *, vlan=1, domain="fabric", mode="pvst", participants=None):
    return m.policy.GuardPolicy(id=identity, domain=domain, expectation="same_reported_root_guard",
        participants=(participant(vlan=vlan, mode=mode), participant("t1", vlan, mode)) if participants is None else participants)


def expected_participant(envelope, supplied):
    domain, refs = declared_oracle(envelope, supplied.target_id)
    record = {"target_id": supplied.target_id, "vlan": supplied.vlan, "declared_mode": supplied.declared_mode, "position": supplied.position,
        "node": domain.node.id, "port": domain.port, "subject": b.subject(domain, supplied.vlan),
        "declarations": [{"table": ref.table, "row_id": ref.row_id, "table_digest": ref.table_digest, "citation": ref.citation} for ref in refs]}
    return record, refs


def semantic_pairs(plan):
    return [(row.policy_id, row.status, row.gaps, tuple((part.target.id, part.port, part.vlan, part.subject) for part in row.participants)) for row in plan.rows]


def test_canonical_owned_policy_table_and_source_custody_never_parse_or_claim_observed_state(tmp_path, monkeypatch):
    envelope, _ = admitted(tmp_path)
    policies = (intent("z", domain="fabric-z"), intent("a", vlan=2, domain="fabric-a", mode="rpvst"))
    with monkeypatch.context() as patch:
        for module, names in ((b, ("Capture", "_integrity", "execute_parsers", "bind_writer")),
                              (b.stp, ("parse_capture",)), (b.p4_pipeline, ("execute_p4_folder",))):
            for name in names:
                patch.setattr(module, name, lambda *args, **kwargs: pytest.fail("planner crossed declared-only boundary"))
        plan = m.plan_guard_comparisons(envelope, LIMITS, policies)
        reversed_input = tuple(replace(policy, participants=tuple(reversed(policy.participants))) for policy in reversed(policies))
        assert m.plan_guard_comparisons(envelope, LIMITS, reversed_input) == plan
    expected = {"schema": "atlas-brain.declared-stp-guard-policy/1", "semantic_group": "declared_synthetic",
        "context": envelope.context, "registration_sha256": envelope.registration_sha256,
        "registry_sha256": sha256(envelope.raw).hexdigest(), "base_registry_sha256": sha256(envelope.base.raw).hexdigest(), "policies": []}
    assert plan.envelope is envelope and plan.context == envelope.context and plan.registration_sha256 == envelope.registration_sha256
    assert (plan.registry_sha256, plan.base_registry_sha256) == (expected["registry_sha256"], expected["base_registry_sha256"])
    for index, (row, policy) in enumerate(zip(plan.rows, sorted(policies, key=lambda item: item.id), strict=True)):
        source = sorted(policy.participants, key=lambda part: (part.target_id, part.vlan))
        records = [expected_participant(envelope, part) for part in source]
        expected["policies"].append({"id": policy.id, "domain": policy.domain, "expectation": policy.expectation, "participants": [record for record, _ in records]})
        assert row.policy_id == policy.id and row.domain == policy.domain and row.status == "conditional" and row.gaps == ()
        for bound, supplied, (record, refs) in zip(row.participants, source, records, strict=True):
            assert bound.target is next(target for target in envelope.targets if target.id == supplied.target_id)
            assert (bound.port, bound.vlan, bound.subject, bound.declared_mode, bound.position, bound.evidence) == (
                record["port"], supplied.vlan, record["subject"], supplied.declared_mode, supplied.position, refs)
        ref, = row.declaration.evidence
        assert (row.declaration.basis, row.declaration.value, row.declaration.raw) == (k.Basis.DECLARED, policy.id, policy.id)
        assert ref == k.RegistryRef(table="declared_stp_guard_policies", row_id=policy.id, table_digest=plan.sha256, citation=f"/policies/{index}")
    assert plan.raw == canonical(expected) and plan.sha256 == sha256(plan.raw).hexdigest()
    assert plan.denominator == (("declared_policies", 2), ("declared_participant_occurrences", 4))
    assert plan.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN and plan.coverage.detail == "caller_declared_guard_policy_only"
    assert plan.coverage.evidence == tuple(row.declaration.evidence[0] for row in plan.rows)
    assert plan.coverage.candidates == plan.coverage.next_evidence == ()


@pytest.mark.parametrize("field,gap", [("domain", "domain_missing"), ("missing_mode", "mode_missing"), ("mst", "mode_unsupported"),
    ("mixed", "mode_mismatch"), ("missing_position", "position_missing"), ("upstream", "position_ineligible"),
    ("opposed", "position_ineligible"), ("vlan", "vlan_mismatch"), ("same_node", "same_node")])
def test_well_formed_ineligible_intent_is_retained_unknown_not_rejected_or_inferred(tmp_path, field, gap):
    envelope, _ = admitted(tmp_path)
    left, right = participant(), participant("t1")
    if field in ("missing_mode", "mst", "mixed"):
        left = replace(left, declared_mode=None if field == "missing_mode" else "mst" if field == "mst" else "rpvst")
        right = replace(right, declared_mode="mst") if field == "mst" else right
    if field in ("missing_position", "upstream", "opposed"):
        left = replace(left, position=None if field == "missing_position" else "upstream")
        right = replace(right, position="upstream") if field == "upstream" else right
    right = replace(right, vlan=2) if field == "vlan" else replace(right, target_id="alt") if field == "same_node" else right
    plan = m.plan_guard_comparisons(envelope, LIMITS, (intent(domain=None if field == "domain" else "fabric", participants=(left, right)),))
    row, = plan.rows
    assert row.status == "unknown" and row.gaps == (gap,)
    assert plan.denominator == (("declared_policies", 1), ("declared_participant_occurrences", 2))


@pytest.mark.parametrize("plant", ["list", "element", "identifier", "domain", "expectation", "participant_list", "arity", "member_type",
    "mode", "position", "vlan_bool", "vlan_zero", "vlan_bound", "vlan_absent", "dangling", "self", "physical_alias", "duplicate_id", "duplicate_pair", "reverse_pair"])
def test_malformed_or_aliased_intent_refuses_the_whole_batch(tmp_path, plant):
    envelope, _ = admitted(tmp_path)
    with pytest.raises(ValueError, match="^stp_guard_policy_"):
        item, left, right = intent(), participant(), participant("t1")
        changes = {"identifier": {"id": "x" * 33}, "domain": {"domain": "x" * 65}, "expectation": {"expectation": "same_guard"},
            "participant_list": {"participants": [left, right]}, "arity": {"participants": (left,)}, "member_type": {"participants": (left, object())}}
        if plant in changes:
            item = replace(item, **changes[plant])
        elif plant in ("mode", "position", "vlan_bool", "vlan_zero", "vlan_bound", "vlan_absent", "dangling"):
            kwargs = {"mode": {"declared_mode": "PVST"}, "position": {"position": "downstream"}, "vlan_bool": {"vlan": True},
                "vlan_zero": {"vlan": 0}, "vlan_bound": {"vlan": 4095}, "vlan_absent": {"vlan": 3}, "dangling": {"target_id": "missing"}}[plant]
            item = replace(item, participants=(replace(left, **kwargs), right))
        elif plant in ("self", "physical_alias"):
            item = replace(item, participants=(left, left if plant == "self" else replace(left, vlan=2)))
        policies = (item,)
        if plant == "duplicate_id":
            policies += (intent(vlan=2),)
        elif plant in ("duplicate_pair", "reverse_pair"):
            policies += (intent("second", domain="other", participants=(right, left) if plant == "reverse_pair" else (left, right)),)
        supplied = list(policies) if plant == "list" else (object(),) if plant == "element" else policies
        m.plan_guard_comparisons(envelope, LIMITS, supplied)


@pytest.mark.parametrize("plant", ["type", "legacy", "digest", "unknown_operation", "foreign_owner"])
def test_application_profile_refuses_before_the_trusted_owning_hook(tmp_path, monkeypatch, plant):
    envelope, _ = admitted(tmp_path, declarations=(b.DECLARATION, ec.DECLARATION) if plant == "legacy" else None)
    changed = object() if plant == "type" else replace(envelope, registration_sha256="0" * 64) if plant == "digest" else envelope
    if plant in ("unknown_operation", "foreign_owner"):
        side = json.loads(envelope.raw)
        operation = "synthetic.unknown" if plant == "unknown_operation" else ec.parse_summary.OP
        next(target for target in side["targets"] if target["id"] == "ec")["operation"] = operation
        raw, digest = canonical(side), sha256(canonical(side)).hexdigest()
        def declared(state):
            return replace(state, evidence=tuple(replace(ref, table_digest=digest) for ref in state.evidence))
        targets = tuple(replace(target, operation=operation if target.id == "ec" else target.operation,
            owner=h.STEP.id if target.id == "ec" and plant == "foreign_owner" else target.owner,
            declaration=declared(target.declaration)) for target in envelope.targets)
        members = tuple(replace(member, target=next(target for target in targets if target.id == member.target.id),
            id=k.CaptureId("cap:" + sha256(canonical((p4.SCHEMA, digest, sha256(envelope.base.raw).hexdigest(), envelope.context,
                member.target.id, member.path, member.sha256, envelope.registration_sha256))).hexdigest())) for member in envelope.captures)
        changed = replace(envelope, raw=raw, declaration=declared(envelope.declaration), targets=targets, captures=members)
    monkeypatch.setattr(m.policy, "plan_for_declared_scope", lambda *args: pytest.fail("profile admitted before hook"))
    with pytest.raises(ValueError, match="^stp_guard_policy_(envelope|profile)$"):
        m.plan_guard_comparisons(changed, LIMITS, (intent(),))


def test_capture_removal_changes_raw_provenance_but_not_policy_pair_census(tmp_path):
    envelope, _ = admitted(tmp_path)
    before = m.plan_guard_comparisons(envelope, LIMITS, (intent(),))
    empty = tmp_path / "empty"
    empty.mkdir()
    uncaptured, _ = admitted(empty, captures=False)
    after = m.plan_guard_comparisons(uncaptured, LIMITS, (intent(),))
    assert semantic_pairs(before) == semantic_pairs(after) and before.denominator == after.denominator
    assert before.registry_sha256 != after.registry_sha256 and before.sha256 != after.sha256 and before.raw != after.raw


def test_empty_intent_has_zero_census_and_explicitly_unknown_policy_coverage(tmp_path):
    envelope, _ = admitted(tmp_path)
    plan = m.plan_guard_comparisons(envelope, LIMITS, ())
    assert plan.rows == () and plan.denominator == (("declared_policies", 0), ("declared_participant_occurrences", 0))
    assert json.loads(plan.raw)["policies"] == []
    assert plan.coverage.evidence == (k.RegistryRef(table="synthetic_p4.context", row_id=envelope.context,
        table_digest=sha256(envelope.raw).hexdigest(), citation="/context"),)
    assert plan.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN and plan.coverage.detail == "caller_declared_guard_policy_only"
    with pytest.raises(ValueError):
        m.plan_guard_comparisons(replace(envelope, raw=envelope.raw + b" "), LIMITS, ())


@pytest.mark.parametrize("budget", ["artifact_bytes", "bundle_bytes", "artifacts"])
def test_policy_memory_registry_obeys_exact_byte_and_aggregate_budgets(tmp_path, budget):
    envelope, files = admitted(tmp_path)
    plan = m.plan_guard_comparisons(envelope, LIMITS, (intent(),))
    cap = {"artifact_bytes": len(plan.raw), "bundle_bytes": sum(map(len, files.values())) + len(plan.raw), "artifacts": len(files) + 1}[budget]
    assert m.plan_guard_comparisons(envelope, replace(LIMITS, **{budget: cap}), (intent(),)) == plan
    with pytest.raises(BudgetExceeded):
        m.plan_guard_comparisons(envelope, replace(LIMITS, **{budget: cap - 1}), (intent(),))


def test_policy_count_limit_is_not_masked_by_duplicate_or_invalid_selectors(tmp_path):
    envelope, _ = admitted(tmp_path, vlans=tuple(range(1, 17)))
    policies = tuple(intent(f"p{i:02d}", participants=(participant(vlan=i // 16 + 1), participant("t1", i % 16 + 1))) for i in range(65))
    assert len(m.plan_guard_comparisons(envelope, LIMITS, policies[:64]).rows) == 64
    with pytest.raises(ValueError, match="^stp_guard_policy_count$"):
        m.plan_guard_comparisons(envelope, LIMITS, policies)
    with pytest.raises(ValueError, match="^stp_guard_policy_count$"):
        m.plan_guard_comparisons(envelope, LIMITS, (object(),) * 65)
