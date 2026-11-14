"""Trusted VERSION comparisons on real closed synthetic sources; no admission or temporal verdict."""
from dataclasses import asdict, replace
from enum import StrEnum

import pytest
from test_parse_hsrp_all import block
from test_peer_execution import forbidden
from test_peer_version_proofs import inputs
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.packs.l3.fhrp import gateway_policy as policy
from atlas_brain.packs.l3.fhrp import protocol_version_check as check
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.runner import p4_fhrp_version_source as factory
from atlas_brain.runner import p4_pipeline as pipeline

FACT = profile.REPORTED_PROTOCOL_VERSION
PAIR = (("brief-a", "Vl10"), ("brief-b", "Vl30"))


def gateway(**changes):
    return replace(policy.GatewayPolicy(id="gateway", domain="blue", vlan=10, address_family="ipv4",
        protocol="hsrp", group="1", participants=PAIR), **changes)


def prepared(root, *, right="2", mode="normal", count=2, domain="blue", policies=None):
    def changing(side, files):
        for target in side["targets"]:
            if target["node"] == "b" and target["operation"] in (hsrp.hsrp.OP, profile.parser.OP):
                target["params"]["groups"] = [["Vl30", "1"]]
            if count == 3 and target["node"] == "a" and target["operation"] in (hsrp.hsrp.OP, profile.parser.OP):
                target["params"]["groups"].append(["Vl41", "1"])
        body = block(right, "Vl30", "1")
        body = body + body if mode == "duplicate" else body + b"unrecognized\n" if mode == "partial" else (
            body.replace(b"Virtual IP address", b"Virtual IPv6 address") if mode == "unsupported" else body)
        if mode not in ("missing_right", "missing_both"):
            files["right-all.txt"] = body
            side["captures"].append({"target": "all-b", "path": "right-all.txt"})
        if mode == "missing_both":
            side["captures"] = [row for row in side["captures"] if row["target"] != "all-a"]
            files.pop("all.txt")
    inputs(root, change=changing)
    source = factory.prepare_fhrp_version_source(root, LIMITS)
    points = PAIR[:1] if count == 1 else PAIR + (("brief-a", "Vl41"),) if count == 3 else PAIR
    plan = policy.plan_for_declared_scope(source.execution.envelope, LIMITS,
        (gateway(domain=domain, participants=points),) if policies is None else policies, source.domains)
    subjects = tuple(sorted(row.subject for row in source.source.rows))
    assert len(check.evaluate_declared(plan, source.source.store, subjects).rows) == len(plan.rows)
    return source, plan, subjects


def freeze(monkeypatch):
    for module, name in ((hsrp.hsrp, "parse_capture"), (profile.parser, "parse_capture"),
            (pipeline, "execute_parsers"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


@pytest.mark.parametrize("right,mode,domain,count,state,reason", [
    ("2", "normal", "blue", 2, "problem", None), ("2", "normal", "blue", 3, "problem", None),
    ("1", "normal", "blue", 2, "unknown", k.UnknownReason.AS_OF_MISSING),
    ("2", "normal", None, 2, "unknown", k.UnknownReason.JOIN_UNPROVEN),
    ("2", "normal", "blue", 1, "unknown", k.UnknownReason.NOT_OBSERVABLE),
    ("1", "normal", "blue", 3, "unknown", k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE),
    ("2", "missing_right", "blue", 2, "unknown", k.UnknownReason.NOT_COLLECTED),
    ("2", "missing_both", "blue", 2, "unknown", k.UnknownReason.NOT_COLLECTED),
    ("2", "duplicate", "blue", 2, "unknown", k.UnknownReason.CONFLICTING_EVIDENCE),
    ("2", "partial", "blue", 2, "unknown", k.UnknownReason.PARSE_PARTIAL),
    ("2", "unsupported", "blue", 2, "unknown", k.UnknownReason.PARSE_PARTIAL)])
def test_conditional_twins_preserve_every_operand_gap_policy_scope_and_actual_all_need(tmp_path, monkeypatch, right, mode, domain, count, state, reason):
    source, plan, subjects = prepared(tmp_path, right=right, mode=mode, domain=domain, count=count)
    freeze(monkeypatch)
    result = check.evaluate_declared(plan, source.source.store, subjects)
    finding, = result.rows
    row, = plan.rows
    assert (finding.check, finding.policy_id, finding.state, finding.reason, finding.conditional) == (
        "l3.fhrp.reported_protocol_version_disagreement", "gateway", state, reason, True)
    assert result.denominator is plan.denominator and result.coverage is plan.coverage
    assert result.denominator == (("declared_gateways", 1), ("declared_participant_occurrences", count))
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN and len(finding.operands) == count
    assert all(operand.participant is point and operand.state is source.source.store.values[k.FactRef(fact=FACT, subject=point.subject)]
        for operand, point in zip(finding.operands, row.participants, strict=True))
    assert finding.evidence == row.binding.evidence + tuple(k.FactRef(fact=FACT, subject=point.subject) for point in row.participants)
    assert all(source.proofs.resolve_protocol_version_reference(ref) for ref in finding.evidence if type(ref) is k.FactRef)
    gaps = tuple(operand.state for operand in finding.operands if type(operand.state) is k.Unknown)
    if state == "problem":
        prefix = tuple(need for gap in gaps for need in gap.next_evidence)
        assert finding.next_evidence[:len(prefix)] == prefix and finding.detail == "conditional_reported_protocol_version_difference"
        assert len(finding.next_evidence) == len(prefix) + count
    elif domain is None:
        assert finding.next_evidence is row.binding.next_evidence and all(not need.resolves and need.operation == hsrp.hsrp.OP for need in finding.next_evidence)
    elif gaps:
        assert (finding.reason, finding.detail, finding.next_evidence) == (gaps[0].reason, gaps[0].detail, gaps[0].next_evidence)
    comparison = finding.next_evidence[-count:] if state == "problem" or domain is not None and not gaps else ()
    for point, need in zip(row.participants, comparison, strict=bool(comparison)):
        assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s) == (
            point.node, "iosxe.show_standby_all", (("group", point.group), ("interface", point.interface)), (FACT,), (check.STEP.id,), None)
        assert need.unprintable == (("additional_declared_comparison_operand",) if count == 1 else ("collector_recorded_time", "declared_gateway_policy"))


@pytest.mark.parametrize("separation", ["domain", "vlan", "group", "protocol"])
def test_original_logical_key_never_includes_version_or_vip_and_unjoined_policies_stay_separate(tmp_path, separation):
    source, _, _ = prepared(tmp_path)
    declarations = (gateway(id="left", participants=PAIR[:1]),
        gateway(id="right", participants=PAIR[1:], domain="red" if separation == "domain" else "blue", vlan=20 if separation == "vlan" else 10))
    if separation == "protocol":
        with pytest.raises(ValueError, match="^fhrp_gateway_policy_value$"):
            policy.plan_for_declared_scope(source.execution.envelope, LIMITS, (gateway(protocol="vrrp"),), source.domains)
        return
    if separation == "group":
        declarations = (declarations[0], gateway(id="right", group="129", participants=(("brief-a", "BD3329"),)))
    plan = policy.plan_for_declared_scope(source.execution.envelope, LIMITS, declarations, source.domains)
    result = check.evaluate_declared(plan, source.source.store, tuple(sorted(row.subject for row in source.source.rows)))
    assert len(result.rows) == 2 and all(row.state == "unknown" and row.reason is k.UnknownReason.NOT_OBSERVABLE for row in result.rows)
    keys = tuple(row.key for row in plan.rows)
    assert keys[0] != keys[1] and all(set(asdict(key)) == {"envelope_sha256", "domain", "vlan", "address_family", "protocol", "group"} for key in keys)


@pytest.mark.parametrize("binding", [False, True])
@pytest.mark.parametrize("has_need", [False, True])
@pytest.mark.parametrize("detail", [None, "source_gap"])
def test_finite_unknown_values_and_binding_take_precedence_without_relabelling_gap_needs(tmp_path, binding, has_need, detail):
    source, plan, subjects = prepared(tmp_path)
    row = plan.rows[0]
    point = row.participants[0]
    old = source.source.store.values[k.FactRef(fact=FACT, subject=point.subject)]
    need = k.EvidenceNeed(node=point.node, operation=profile.parser.OP, params=(("group", point.group), ("interface", point.interface)),
        resolves=(FACT,), reruns=(check.STEP.id,), after_s=None, unprintable=("synthetic_gap",))
    gap = k.Unknown(reason=k.UnknownReason.CAPTURE_TRUNCATED, detail=detail, evidence=old.evidence,
        candidates=("synthetic:other",), next_evidence=(need,) if has_need else ())
    if binding:
        plan = replace(plan, rows=(replace(row, binding=gap),))
    else:
        source.source.store.values[k.FactRef(fact=FACT, subject=point.subject)] = gap
    finding, = check.evaluate_declared(plan, source.source.store, subjects).rows
    assert (finding.state, finding.reason, finding.detail, finding.next_evidence) == ("unknown", gap.reason, detail, gap.next_evidence)
    assert finding.operands[0].state is (old if binding else gap) and gap.candidates == ("synthetic:other",)


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("fault", ["bool", "alias", "raw", "raw_alias", "basis", "basis_alias", "unsupported", "object", "na", "unknown_candidates", "unknown_need", "deep_need"])
def test_every_unselected_cell_is_validated_even_for_empty_policies_before_findings(tmp_path, monkeypatch, empty, fault):
    source, plan, subjects = prepared(tmp_path)
    selected = {point.subject for row in plan.rows for point in row.participants}
    subject = next(subject for subject in reversed(subjects) if subject not in selected)
    known = next(row.value for row in source.source.rows if type(row.value) is k.Known)
    value = object() if fault == "object" else k.NotApplicable(reason=k.NAReason.FEATURE_NOT_ENABLED, evidence=known.evidence) if fault == "na" else replace(known)
    if fault in ("unknown_candidates", "unknown_need", "deep_need"):
        value = next(row.value for row in source.source.rows if type(row.value) is k.Unknown)
        obj, field = (value.next_evidence[0], "resolves") if fault == "deep_need" else (value, "candidates" if fault == "unknown_candidates" else "next_evidence")
        object.__setattr__(obj, field, ([],))
    elif fault not in ("object", "na"):
        changes = {"bool": {"value": False}, "alias": {"value": StrEnum("Alias", {"VALUE": known.value}).VALUE},
            "raw": {"raw": "9"}, "raw_alias": {"raw": StrEnum("Alias", {"VALUE": known.raw}).VALUE},
            "basis": {"basis": k.Basis.DECLARED}, "basis_alias": {"basis": StrEnum("Alias", {"VALUE": "observed"}).VALUE}, "unsupported": {"value": "3", "raw": "3"}}[fault]
        for field, item in changes.items():
            object.__setattr__(value, field, item)
    source.source.store.values[k.FactRef(fact=FACT, subject=subject)] = value
    plan = replace(plan, rows=()) if empty else plan
    monkeypatch.setattr(check.Finding, "__init__", forbidden)
    code = "hsrp_version_inputs_state" if fault in ("bool", "alias") else "hsrp_version_inputs_need" if fault == "deep_need" else "hsrp_version_inputs_unknown" if fault in ("unknown_candidates", "unknown_need") else (
        "invalid_raw" if fault == "raw_alias" else "invalid_basis" if fault == "basis_alias" else "fhrp_protocol_version_check_value")
    with pytest.raises(ValueError, match="^" + code + "$"):
        check.evaluate_declared(plan, source.source.store, subjects)


@pytest.mark.parametrize("fault", ["plan", "store", "subjects", "duplicate", "unsorted", "subject_deep", "subject_alias", "owner", "owner_alias",
    "key_alias", "fact_alias", "key_deep", "cell_missing", "cell_extra", "late_subject", "participant_target_id", "participant_node", "participant_interface", "participant_group", "participant_subject", "binding", "coverage", "domain",
    "vlan", "af", "protocol", "group", "digest", "unbound", "producer", "graph"])
def test_all_metadata_stores_selectors_keys_and_bindings_prepass_before_first_finding(tmp_path, monkeypatch, fault):
    source, plan, subjects = prepared(tmp_path)
    store = source.source.store
    row = plan.rows[0]
    code = "input"
    if fault in ("plan", "store"):
        plan, store = (object(), store) if fault == "plan" else (plan, object())
    elif fault in ("subjects", "duplicate", "unsorted", "subject_deep", "subject_alias"):
        subjects = list(subjects) if fault == "subjects" else subjects + subjects[:1] if fault == "duplicate" else (
            tuple(reversed(subjects)) if fault == "unsorted" else (StrEnum("Alias", {"VALUE": subjects[0]}).VALUE, *subjects[1:])
            if fault == "subject_alias" else ([],))
    elif fault in ("owner", "owner_alias", "key_alias", "fact_alias", "key_deep", "cell_missing", "cell_extra"):
        code = "store"
        ref = next(iter(store.values))
        if fault in ("owner", "owner_alias"):
            store.owners[FACT] = "wrong/owner" if fault == "owner" else StrEnum("Alias", {"VALUE": profile.STEP.id}).VALUE
        elif fault in ("key_alias", "fact_alias", "key_deep"):
            field = "fact" if fault == "fact_alias" else "subject"
            object.__setattr__(ref, field, [] if fault == "key_deep" else StrEnum("Alias", {"VALUE": getattr(ref, field)}).VALUE)
            store.values = {key: value for key, value in store.values.items()} if fault != "key_deep" else store.values
        elif fault == "cell_missing":
            store.values.pop(ref)
        else:
            store.values[k.FactRef(fact=FACT, subject="extra:subject")] = store.values[ref]
    elif fault in ("producer", "graph"):
        if fault == "producer":
            monkeypatch.setattr(profile, "REPORTED_PROTOCOL_VERSION", StrEnum("Alias", {"VALUE": FACT}).VALUE)
        else:
            monkeypatch.setattr(check, "STEP", replace(check.STEP, reads=tuple(sorted((FACT, "l3.fhrp.other")))))
    else:
        code = "selector"
        if fault == "late_subject":
            late = replace(row, policy_id="late", binding=replace(row.binding, value="late", raw="late"), participants=(replace(row.participants[0], subject="outside:subject"),))
            plan = replace(plan, rows=(row, late))
        elif fault.startswith("participant_"):
            object.__setattr__(row.participants[0], fault.removeprefix("participant_"), [])
        elif fault in ("binding", "coverage"):
            gap = plan.coverage if fault == "coverage" else row.binding
            object.__setattr__(gap, "candidates" if fault == "coverage" else "value", [])
        elif fault == "unbound":
            plan = replace(plan, rows=(replace(row, key=None),))
        else:
            name, value = {"domain": ("domain", []), "vlan": ("vlan", True), "af": ("address_family", "ipv6"),
                "protocol": ("protocol", "vrrp"), "group": ("group", "9"), "digest": ("envelope_sha256", "bad")}[fault]
            object.__setattr__(row.key, name, value)
    monkeypatch.setattr(check.Finding, "__init__", forbidden)
    expected = {"binding": "hsrp_version_inputs_state", "coverage": "hsrp_version_inputs_unknown", "digest": "invalid_digest",
        "producer": "hsrp_version_profile", "graph": "missing_producer:l3.fhrp.other"}.get(fault, "fhrp_protocol_version_check_" + code)
    with pytest.raises(ValueError, match="^" + expected + "$"):
        check.evaluate_declared(plan, store, subjects)


@pytest.mark.parametrize("empty", [False, True])
def test_entire_reader_matrix_is_consumed_once_without_side_effects_and_fixed_step_reads_only_version(tmp_path, monkeypatch, empty):
    source, plan, subjects = prepared(tmp_path, policies=() if empty else None)
    store = source.source.store
    snapshots = dict(store.owners), dict(store.values)
    original, construct, reads = FactReader.read, check.Finding.__init__, []
    def reading(self, **kwargs):
        assert self.store is store and self.step is check.STEP and kwargs["fact"] == FACT
        reads.append(kwargs["subject"])
        return original(self, **kwargs)
    def finding(self, **kwargs):
        assert reads == list(subjects)
        construct(self, **kwargs)
    monkeypatch.setattr(FactReader, "read", reading)
    monkeypatch.setattr(check.Finding, "__init__", finding)
    freeze(monkeypatch)
    result = check.evaluate_declared(plan, store, subjects)
    assert reads == list(subjects) and len(result.rows) == (0 if empty else 1)
    assert (store.owners, store.values) == snapshots and all(store.values[ref] is value for ref, value in snapshots[1].items())
    assert (check.STEP.kind, check.STEP.scope, check.STEP.reads, check.STEP.produces) == ("check", "estate", (FACT,), ())
    assert result.denominator is plan.denominator and result.coverage is plan.coverage
