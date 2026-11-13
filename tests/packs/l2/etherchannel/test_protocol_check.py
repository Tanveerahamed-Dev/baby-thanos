"""Conditional check regressions over raw synthetic reports and authoritative stored states."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l2.etherchannel import build as b
from atlas_brain.packs.l2.etherchannel import protocol_check as check
from atlas_brain.packs.l2.etherchannel import protocol_policy as policy_module
from atlas_brain.runner import p4
from atlas_brain.runner import p4_etherchannel_policy as runner
from tools import p4_estate_cases as estate

LIMITS = p4.Budgets(1000000, 1000000, 1000)
FACT = b.REPORTED_PROTOCOL
PAIR = (("ec", "1"), ("cold", "4"))


def folder(root, left="LACP", right="PAgP", missing=None):
    files = estate.members(canonical, "baseline")
    files["ec.txt"] = files["ec.txt"].replace(b"1 Po1(SU) LACP", b"1 Po1(SU) " + left.encode())
    files["cold.txt"] = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
        b"--+--+--+--\n4 Po4(SU) " + right.encode() + b" Gi1/0/1(P)\n")
    side = json.loads(files["p4.json"])
    next(row for row in side["targets"] if row["id"] == "cold")["params"]["ports"] = ["Gi1/0/1"]
    side["captures"].append({"target": "cold", "path": "cold.txt", "sha256": sha256(files["cold.txt"]).hexdigest()})
    if missing:
        absent = ("ec", "cold") if missing == "both" else (missing,)
        for name in absent:
            files.pop(name + ".txt")
        side["captures"] = [row for row in side["captures"] if row["target"] not in absent]
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


def policy():
    return policy_module.ProtocolPolicy(id="same", expectation="same_reported_protocol", participants=PAIR)


def subject(node, group):
    return k.EntityKey("etherchannel_group:" + sha256(canonical(
        ("atlas-brain.etherchannel-group/1", "round", "node:demo:" + node, group))).hexdigest())


@pytest.mark.parametrize("left,right,missing,state,reason", [
    ("LACP", "PAgP", None, "problem", None), ("PAgP", "LACP", None, "problem", None),
    ("LACP", "LACP", None, "unknown", k.UnknownReason.AS_OF_MISSING),
    ("PAgP", "PAgP", None, "unknown", k.UnknownReason.AS_OF_MISSING),
    ("-", "PAgP", None, "unknown", k.UnknownReason.NOT_OBSERVABLE),
    ("LACP", "-", None, "unknown", k.UnknownReason.NOT_OBSERVABLE),
    ("LACP", "PAgP", "cold", "unknown", k.UnknownReason.NOT_COLLECTED),
    ("LACP", "PAgP", "ec", "unknown", k.UnknownReason.NOT_COLLECTED),
    ("-", "PAgP", "cold", "unknown", k.UnknownReason.NOT_COLLECTED),
    ("LACP", "PAgP", "both", "unknown", k.UnknownReason.NOT_COLLECTED)])
def test_report_twins_preserve_conditional_scope_evidence_and_unknowns(tmp_path, left, right, missing, state, reason):
    inputs = folder(tmp_path / "inputs", left, right, missing)
    out = runner.evaluate_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    finding, = out.result.rows
    pair, = out.plan.rows
    assert (finding.check, finding.policy_id, finding.state, finding.reason, finding.conditional) == (
        "l2.etherchannel.reported_protocol_mismatch", "same", state, reason, True)
    assert (finding.left, finding.right) == (subject("a", "4"), subject("b", "1"))
    assert finding.evidence == pair.declaration.evidence + tuple(
        k.FactRef(fact=FACT, subject=point) for point in (finding.left, finding.right))
    ref, = pair.declaration.evidence
    assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == (
        "declared_etherchannel_protocol_policies", "same", sha256(out.plan.raw).hexdigest(), "/policies/0")
    assert out.result.denominator is out.plan.denominator and out.result.coverage is out.plan.coverage
    assert out.result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == inputs
    if missing:
        gap = next(out.source.store.values[k.FactRef(fact=FACT, subject=point.subject)]
            for point in pair.participants if type(out.source.store.values[k.FactRef(fact=FACT, subject=point.subject)]) is k.Unknown)
        assert (finding.reason, finding.detail, finding.next_evidence) == (gap.reason, gap.detail, gap.next_evidence)
    else:
        unprintable = ("explicit_negotiation_protocol",) if reason is k.UnknownReason.NOT_OBSERVABLE else (
            "collector_recorded_time", "declared_protocol_policy")
        assert len(finding.next_evidence) == 2
        for point, need in zip(pair.participants, finding.next_evidence, strict=True):
            assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s, need.unprintable) == (
                point.node, "iosxe.show_etherchannel_summary", (), (FACT,),
                ("l2.etherchannel/check_reported_protocol",), None, unprintable)


@pytest.mark.parametrize("empty", [False, True])
def test_public_evaluation_owns_one_fresh_preparation_and_reads_complete_declared_matrix(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    prepare, read = runner.prepare_protocol_comparisons, FactReader.read
    prepared, reads, snapshots = [], [], []
    def preparing(*args, **kwargs):
        value = prepare(*args, **kwargs)
        prepared.append(value)
        snapshots.append((dict(value.source.store.values), dict(value.source.store.owners)))
        return value
    def reading(self, **kwargs):
        if self.step.id == check.STEP.id:
            reads.append((kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    monkeypatch.setattr(runner, "prepare_protocol_comparisons", preparing)
    monkeypatch.setattr(FactReader, "read", reading)
    out = runner.evaluate_protocol_comparisons(tmp_path / "inputs", LIMITS, () if empty else (policy(),))
    original, = prepared
    assert out.source is original.source and out.execution is original.execution and out.plan is original.plan
    assert (out.source.store.values, out.source.store.owners) == snapshots[0]
    assert all(out.source.store.values[ref] is state for ref, state in snapshots[0][0].items())
    assert reads == [(FACT, point) for point in sorted((subject("a", "4"), *(subject("b", str(i)) for i in (1, 2, 3))))]
    assert (check.STEP.pack, check.STEP.kind, check.STEP.scope, check.STEP.reads, check.STEP.produces) == (
        b.PACK, "check", "estate", (FACT,), ())
    assert check.STEP.id not in {step.id for step in b.DECLARATION.steps}
    assert len(out.result.rows) == (0 if empty else 1) and out.result.coverage is original.plan.coverage


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("plant", ["bool", "enum", "basis", "raw", "not_applicable", "object"])
def test_trusted_consumer_closes_unselected_cells_before_any_finding(tmp_path, monkeypatch, plant, empty):
    folder(tmp_path / "inputs")
    prepared = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, () if empty else (policy(),))
    row = next(row for row in prepared.source.rows if row.group == "2")
    value = row.value
    forged = (object() if plant == "object" else k.NotApplicable(reason=k.NAReason.FEATURE_NOT_ENABLED, evidence=value.evidence)
        if plant == "not_applicable" else replace(value, value=False if plant == "bool" else b.parse_summary.Protocol.LACP)
        if plant in ("bool", "enum") else replace(value, basis=k.Basis.DECLARED) if plant == "basis" else replace(value, raw="normalized"))
    prepared.source.store.values[k.FactRef(fact=FACT, subject=row.subject)] = forged
    monkeypatch.setattr(check.Finding, "__init__", lambda *_a, **_k: pytest.fail("finding before complete matrix"))
    with pytest.raises(ValueError, match="^etherchannel_protocol_check_value$"):
        check.evaluate_declared(prepared.plan, prepared.source.store, tuple(sorted(item.subject for item in prepared.source.rows)))


@pytest.mark.parametrize("has_need", [False, True])
@pytest.mark.parametrize("detail", [None, "original_unknown_detail"])
def test_trusted_source_unknown_preserves_reason_detail_and_even_empty_needs(tmp_path, has_need, detail):
    folder(tmp_path / "inputs")
    prepared = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    pair, = prepared.plan.rows
    point = pair.participants[0]
    ref = k.FactRef(fact=FACT, subject=point.subject)
    original = prepared.source.store.values[ref]
    need = k.EvidenceNeed(node=point.node, operation="iosxe.show_etherchannel_summary", params=(),
        resolves=(FACT,), reruns=("l2.etherchannel/parse_protocol",), after_s=None, unprintable=())
    gap = k.Unknown(reason=k.UnknownReason.CAPTURE_TRUNCATED, detail=detail, evidence=original.evidence,
        candidates=(), next_evidence=(need,) if has_need else ())
    prepared.source.store.values[ref] = gap
    result = check.evaluate_declared(prepared.plan, prepared.source.store, tuple(sorted(row.subject for row in prepared.source.rows)))
    finding, = result.rows
    assert finding.state == "unknown" and finding.evidence[1:] == tuple(
        k.FactRef(fact=FACT, subject=p.subject) for p in pair.participants)
    assert (finding.reason, finding.detail, finding.next_evidence) == (gap.reason, detail, gap.next_evidence)


@pytest.mark.parametrize("carrier", ["plan", "store", "execution", "evaluation"])
def test_public_evaluation_never_admits_prior_carriers(tmp_path, monkeypatch, carrier):
    folder(tmp_path / "inputs")
    out = runner.evaluate_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    root = out.plan if carrier == "plan" else out.source.store if carrier == "store" else out.execution if carrier == "execution" else out
    monkeypatch.setattr(runner.stp, "build_root_guard_global", lambda *_a, **_k: pytest.fail("opaque input executed"))
    with pytest.raises(ValueError, match="^etherchannel_protocol_policy_input$"):
        runner.evaluate_protocol_comparisons(root, LIMITS, (policy(),))


@pytest.mark.parametrize("empty", [False, True])
def test_public_source_binding_refuses_coherent_late_lie_before_checker(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    finish = runner.SummaryPack.finish
    def changed(self, execution):
        result = finish(self, execution)
        row = next(row for row in result.rows if row.group == "2")
        value = replace(row.value, value="pagp", raw="PAgP")
        result.store.values[k.FactRef(fact=FACT, subject=row.subject)] = value
        return replace(result, rows=tuple(replace(item, value=value) if item is row else item for item in result.rows))
    monkeypatch.setattr(runner.SummaryPack, "finish", changed)
    monkeypatch.setattr(check, "evaluate_declared", lambda *_: pytest.fail("checker before original source closure"))
    with pytest.raises(ValueError, match="^etherchannel_protocol_source_value$"):
        runner.evaluate_protocol_comparisons(tmp_path / "inputs", LIMITS, () if empty else (policy(),))


def test_trusted_store_is_fact_authority_and_checker_never_replays_parser(tmp_path, monkeypatch):
    folder(tmp_path / "inputs")
    prepared = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    point = prepared.plan.rows[0].participants[0]
    ref = k.FactRef(fact=FACT, subject=point.subject)
    original = prepared.source.store.values[ref]
    prepared.source.store.values[ref] = replace(original, value="lacp", raw="LACP")
    monkeypatch.setattr(b.parse_summary, "parse_capture", lambda *_: pytest.fail("trusted consumer replayed parser"))
    finding, = check.evaluate_declared(prepared.plan, prepared.source.store,
        tuple(sorted(row.subject for row in prepared.source.rows))).rows
    assert (finding.state, finding.reason) == ("unknown", k.UnknownReason.AS_OF_MISSING)


@pytest.mark.parametrize("plant", ["plan", "store", "list", "duplicate", "bool", "missing_selected", "late_policy"])
def test_trusted_inputs_and_all_policy_subjects_close_before_any_finding(tmp_path, monkeypatch, plant):
    folder(tmp_path / "inputs")
    prepared = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    plan, store = prepared.plan, prepared.source.store
    subjects = tuple(sorted(row.subject for row in prepared.source.rows))
    code = "input"
    if plant == "plan":
        plan = object()
    elif plant == "store":
        store = object()
    elif plant == "list":
        subjects = list(subjects)
    elif plant == "duplicate":
        subjects = subjects + subjects[:1]
    elif plant == "bool":
        subjects = (True,)
    elif plant == "missing_selected":
        subjects = tuple(s for s in subjects if s != plan.rows[0].participants[0].subject)
        code = "selector"
    else:
        pair = plan.rows[0]
        foreign = replace(pair.participants[0], subject=k.EntityKey("etherchannel_group:" + "0" * 64))
        plan = replace(plan, rows=(pair, replace(pair, policy_id="late", participants=(foreign, pair.participants[1]))))
        code = "selector"
    monkeypatch.setattr(check.Finding, "__init__", lambda *_a, **_k: pytest.fail("finding before complete input/policy closure"))
    with pytest.raises(ValueError, match="^etherchannel_protocol_check_" + code + "$"):
        check.evaluate_declared(plan, store, subjects)


def test_two_unknowns_choose_canonical_primary_without_losing_either_fact_reference(tmp_path):
    folder(tmp_path / "inputs")
    prepared = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    pair = prepared.plan.rows[0]
    for index, point in enumerate(pair.participants):
        ref = k.FactRef(fact=FACT, subject=point.subject)
        original = prepared.source.store.values[ref]
        prepared.source.store.values[ref] = k.Unknown(
            reason=k.UnknownReason.CAPTURE_ERROR if index == 0 else k.UnknownReason.CAPTURE_TRUNCATED,
            detail="canonical_first" if index == 0 else "second_retained", evidence=original.evidence,
            candidates=(), next_evidence=())
    finding, = check.evaluate_declared(prepared.plan, prepared.source.store,
        tuple(sorted(row.subject for row in prepared.source.rows))).rows
    assert (finding.reason, finding.detail, finding.next_evidence) == (k.UnknownReason.CAPTURE_ERROR, "canonical_first", ())
    assert finding.evidence[1:] == tuple(k.FactRef(fact=FACT, subject=p.subject) for p in pair.participants)
    assert prepared.source.store.values[finding.evidence[2]].detail == "second_retained"
