"""Guard reports retain original input pins, policy bytes and pair-specific fact evidence."""
import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256

import pytest
from test_guard_check import ROLE, ROOT, estate
from test_guard_policy import intent, participant

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import p4_guard_policy as m

LIMITS = b.Budgets(1000000, 1000000, 1000)
POLICY = "declared_guard_policy.json"
FACTS, CHECKS = "facts/stp_port_vlan.jsonl", "checks/l2.stp.jsonl"
FILES = {"result.json", FACTS, CHECKS, POLICY, "MANIFEST.sha256"}


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def lines(raw):
    return [json.loads(line) for line in raw.splitlines() if line]


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def manifest_oracle(files):
    return b"".join(f"{sha256(files[name]).hexdigest()}  {name}\n".encode() for name in sorted(files) if name != "MANIFEST.sha256")


def verify(value, inputs, files, captures, facts):
    if isinstance(value, dict):
        if value.get("kind") == "capture":
            content = inputs[value["path"]]
            meta = captures[value["capture"]]
            assert meta["path"] == value["path"] and meta["source"] == value["source"]
            assert meta["sha256"] == value["capture_sha256"] == sha256(content).hexdigest()
            excerpt = content
            if value["locator"] == "bytes":
                assert 0 <= value["start"] < value["end"] <= len(content)
                excerpt = content[value["start"]:value["end"]]
            else:
                assert value["locator"] == "whole_capture"
            assert value["sha256"] == sha256(excerpt).hexdigest()
        elif value.get("kind") == "registry":
            name = POLICY if value["table"] == "declared_stp_guard_policies" else "p2.json" if value["table"].startswith("synthetic_p2.") else "p4.json"
            content = files[name] if name == POLICY else inputs[name]
            expected = json.loads(content)
            for token in value["citation"].split("/")[1:]:
                token = token.replace("~1", "/").replace("~0", "~")
                expected = expected[int(token)] if isinstance(expected, list) else expected[token]
            assert value["table_digest"] == sha256(content).hexdigest() and value["value"] == expected
        elif value.get("kind") == "fact":
            assert value["value"] == facts[(value["subject"], value["fact"])]
        for item in value.values():
            verify(item, inputs, files, captures, facts)
    elif isinstance(value, list):
        for item in value:
            verify(item, inputs, files, captures, facts)


@pytest.mark.parametrize("mode,state,reason,prefix", [
    ("problem", "problem", None, 3), ("equal", "unknown", "as_of_missing", 3),
    ("na", "not_applicable", "role_excludes", 2), ("guard", "unknown", "field_not_printed", 3),
    ("role", "unknown", "not_collected", 2), ("gap", "unknown", "analysis_gap", 1)])
def test_five_canonical_files_pin_every_source_policy_and_conditional_prefix(tmp_path, monkeypatch, mode, state, reason, prefix):
    estate(tmp_path, left=None if mode == "guard" else "enabled", right="enabled" if mode == "equal" else "disabled",
        roles=("root", "designated") if mode == "na" else ("designated", "designated"), missing=mode == "role")
    inputs, evaluations, indexes, runs = snapshot(tmp_path), [], [], []
    ordinary = m.observations.analyse_folder(tmp_path, LIMITS)
    evaluate, initialize, execute = m.evaluate_guard_comparisons, m.ProofIndex.__init__, b.p4_pipeline.execute_p4_folder
    def evaluated(*args, **kwargs):
        result = evaluate(*args, **kwargs)
        evaluations.append(result)
        return result
    def indexed(self, execution, budgets):
        indexes.append(execution)
        initialize(self, execution, budgets)
    def executed(*args, **kwargs):
        result = execute(*args, **kwargs)
        runs.append(result)
        return result
    with monkeypatch.context() as patch:
        patch.setattr(m, "evaluate_guard_comparisons", evaluated)
        patch.setattr(m.ProofIndex, "__init__", indexed)
        patch.setattr(b.p4_pipeline, "execute_p4_folder", executed)
        files = m.report_guard_comparisons(tmp_path, LIMITS, (intent(domain=None if mode == "gap" else "fabric"),))
    evaluation, = evaluations
    assert len(runs) == 1 and len(indexes) == 2 and all(index is runs[0] is evaluation.source.execution for index in indexes)
    assert evaluation.plan.envelope is runs[0].envelope and snapshot(tmp_path) == inputs
    assert set(files) == FILES and list(files) == sorted(files) and files["MANIFEST.sha256"] == manifest_oracle(files)
    assert files[POLICY] == evaluation.plan.raw and files[FACTS] == ordinary[FACTS]
    head, facts, checks = json.loads(files["result.json"]), lines(files[FACTS]), lines(files[CHECKS])
    assert files["result.json"] == encoded(head)
    for name, rows in ((FACTS, facts), (CHECKS, checks)):
        assert files[name] == b"".join(encoded(row) + b"\n" for row in rows)
    assert head["schema"] == "atlas-brain.p4-guard-report/1" and head["semantic_group"] == "declared_synthetic"
    assert (head["scope"], head["fact_scope"], head["capture_scope"], head["source_required"], head["variant_support"]) == (
        "conditional_reported_guard_comparisons", "stp_operands_only", "p4_members_only", "original_pinned_evidence_folder", "allowlisted")
    assert head["registry_sha256"] == sha256(inputs["p4.json"]).hexdigest() and head["base_registry_sha256"] == sha256(inputs["p2.json"]).hexdigest()
    assert head["registration_sha256"] == evaluation.source.execution.envelope.registration_sha256
    assert head["policy_registry"] == {"path": POLICY, "sha256": sha256(files[POLICY]).hexdigest(), "basis": "declared"}
    assert head["denominator"] == {"declared_policies": 1, "declared_participant_occurrences": 2}
    assert head["coverage"]["state"] == "unknown" and head["coverage"]["reason"] == "denominator_open"
    assert len(facts) == 6 and {row["fact"] for row in facts} == {ROLE, ROOT}
    assert [(row["subject"], row["fact"]) for row in facts] == sorted((row["subject"], row["fact"]) for row in facts)
    check, = checks
    assert (check["state"], check["reason"], check["conditional"]) == (state, reason, True)
    assert [hop["id"] for hop in check["hops"]] == ["declared_scope", "reported_role", "reported_root_guard"][:prefix]
    assert check["evidence"] == [ref for hop in check["hops"] for ref in hop["state"]["evidence"]]
    assert all(ref["kind"] == "registry" or ref["fact"] in (ROLE, ROOT) and ref["subject"] in (check["left"], check["right"]) for ref in check["evidence"])
    captures = {capture["id"]: capture for capture in head["captures"]}
    assert {capture["path"] for capture in captures.values()} == {row["path"] for row in json.loads(inputs["p4.json"])["captures"]}
    table = {(row["subject"], row["fact"]): row for row in facts}
    for value in (head, facts, checks):
        verify(value, inputs, files, captures, table)
    assert m.observations.analyse_folder(tmp_path, LIMITS) == ordinary


def test_empty_policy_coverage_uses_original_envelope_context_not_a_fake_policy(tmp_path):
    estate(tmp_path)
    inputs = snapshot(tmp_path)
    files = m.report_guard_comparisons(tmp_path, LIMITS, ())
    head = json.loads(files["result.json"])
    assert files[CHECKS] == b"" and json.loads(files[POLICY])["policies"] == [] and len(lines(files[FACTS])) == 6
    assert head["denominator"] == {"declared_policies": 0, "declared_participant_occurrences": 0}
    coverage = head["coverage"]
    assert coverage["state"] == "unknown" and coverage["reason"] == "denominator_open"
    ref, = coverage["evidence"]
    assert (ref["kind"], ref["table"], ref["row_id"], ref["table_digest"], ref["citation"], ref["value"]) == (
        "registry", "synthetic_p4.context", json.loads(inputs["p4.json"])["context"], sha256(inputs["p4.json"]).hexdigest(), "/context", head["context"])
    assert files["MANIFEST.sha256"] == manifest_oracle(files)


@pytest.mark.parametrize("field", ["artifact_bytes", "bundle_bytes", "artifacts"])
def test_exact_budget_counts_original_inputs_all_five_outputs_and_policy_once(tmp_path, field):
    estate(tmp_path)
    inputs = snapshot(tmp_path)
    files = m.report_guard_comparisons(tmp_path, LIMITS, (intent(),))
    cap = {"artifact_bytes": max(map(len, (*inputs.values(), *files.values()))),
        "bundle_bytes": sum(map(len, inputs.values())) + sum(map(len, files.values())),
        "artifacts": len(inputs) + len(files)}[field]
    assert m.report_guard_comparisons(tmp_path, replace(LIMITS, **{field: cap}), (intent(),)) == files
    with pytest.raises(BudgetExceeded):
        m.report_guard_comparisons(tmp_path, replace(LIMITS, **{field: cap - 1}), (intent(),))


@pytest.mark.parametrize("plant,code", [("foreign_subject", "reference"), ("foreign_fact", "reference"),
    ("policy_digest", "reference"), ("policy_pointer", "reference"), ("plan_raw", "policy"), ("plan_digest", "policy"),
    ("pair", "input"), ("envelope", "input"), ("coverage", "input"), ("census", "p4_observations_population"),
    ("hash", "p4_projection_span"), ("span", "p4_projection_scope")])
def test_report_refuses_valid_but_foreign_references_and_source_tampering(tmp_path, monkeypatch, plant, code):
    estate(tmp_path)
    evaluate = m.evaluate_guard_comparisons
    def changed(*args, **kwargs):
        out = evaluate(*args, **kwargs)
        finding = out.result.rows[0]
        foreign = next(row for row in out.source.result.rows if row.subject not in (finding.left, finding.right))
        if plant in ("hash", "span", "census"):
            row = next(row for row in out.source.result.rows if row.target.node.id == "a" and row.vlan == 1)
            if plant == "census":
                return replace(out, source=replace(out.source, result=replace(out.source.result, rows=tuple(item for item in out.source.result.rows if item is not row))))
            first = next(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            replacement = replace(first, excerpt_sha256="0" * 64) if plant == "hash" else next(ref for ref in foreign.value.evidence if type(ref) is k.EvidenceRef)
            value = replace(row.value, evidence=tuple(replacement if ref is first else ref for ref in row.value.evidence))
            out.source.result.store.values[k.FactRef(fact=ROOT, subject=row.subject)] = value
            rows = tuple(replace(item, value=value) if item is row else item for item in out.source.result.rows)
            return replace(out, source=replace(out.source, result=replace(out.source.result, rows=rows)))
        if plant in ("plan_raw", "plan_digest", "envelope"):
            values = {"plan_raw": {"raw": out.plan.raw + b" "}, "plan_digest": {"sha256": "0" * 64}, "envelope": {"envelope": replace(out.plan.envelope)}}[plant]
            return replace(out, plan=replace(out.plan, **values))
        if plant == "coverage":
            return replace(out, result=replace(out.result, coverage=replace(out.result.coverage)))
        if plant == "pair":
            finding = replace(finding, left=foreign.subject)
        else:
            ref = k.FactRef(fact=ROOT, subject=foreign.subject) if plant == "foreign_subject" else k.FactRef(fact=k.FactId("l2.etherchannel.reported_protocol"), subject=finding.left) if plant == "foreign_fact" else replace(
                finding.evidence[0], **({"table_digest": "0" * 64} if plant == "policy_digest" else {"citation": "/policies/1"}))
            finding = replace(finding, evidence=finding.evidence + (ref,))
        return replace(out, result=replace(out.result, rows=(finding,)))
    monkeypatch.setattr(m, "evaluate_guard_comparisons", changed)
    with pytest.raises(ValueError, match="^" + (code if code.startswith("p4_") else "stp_guard_report_" + code) + "$"):
        m.report_guard_comparisons(tmp_path, LIMITS, (intent(),))


@pytest.mark.parametrize("seed", ["1", "83"])
def test_same_raw_inputs_ignore_creation_policy_argument_order_and_hash_seed(tmp_path, seed):
    estate(tmp_path)
    policies = (intent("z"), intent("a", participants=(participant(vlan=2), participant("t1"))))
    inputs = snapshot(tmp_path)
    expected = m.report_guard_comparisons(tmp_path, LIMITS, policies)
    other = tmp_path.with_name(tmp_path.name + "-same")
    other.mkdir()
    for name in reversed(tuple(inputs)):
        (other / name).write_bytes(inputs[name])
    assert m.report_guard_comparisons(other, LIMITS, tuple(reversed(policies))) == expected
    code = ("import json,sys\n"
            "from pathlib import Path\n"
            "from atlas_brain.evidence.admission import Budgets\n"
            "from atlas_brain.runner.p4_guard_policy import report_guard_comparisons,policy\n"
            "def p(t,v): return policy.GuardParticipant(target_id=t,vlan=v,declared_mode='pvst',position='designated_downstream')\n"
            "policies=tuple(policy.GuardPolicy(id=i,domain='fabric',expectation='same_reported_root_guard',participants=(p('t0',v),p('t1',1))) for i,v in (('a',2),('z',1)))\n"
            "print(json.dumps({k:v.hex() for k,v in report_guard_comparisons(Path(sys.argv[1]),Budgets(1000000,1000000,1000),policies).items()},sort_keys=True))")
    child = subprocess.run([sys.executable, "-c", code, str(other)], env=dict(os.environ, PYTHONHASHSEED=seed),
        capture_output=True, text=True, check=True, timeout=60)
    assert json.loads(child.stdout) == {name: content.hex() for name, content in expected.items()} and snapshot(other) == inputs


def test_report_needs_original_folder_and_budgets_the_captured_snapshot_without_reread(tmp_path, monkeypatch):
    estate(tmp_path)
    inputs = snapshot(tmp_path)
    expected = m.report_guard_comparisons(tmp_path, LIMITS, (intent(),))
    detached = tmp_path.with_name(tmp_path.name + "-detached")
    detached.mkdir()
    for name, content in expected.items():
        path = detached / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    with pytest.raises(ValueError):
        m.report_guard_comparisons(detached, LIMITS, (intent(),))
    evaluate = m.evaluate_guard_comparisons
    def changed(*args, **kwargs):
        out = evaluate(*args, **kwargs)
        (tmp_path / "right.txt").write_bytes(b"x" * 2000000)
        return out
    monkeypatch.setattr(m, "evaluate_guard_comparisons", changed)
    cap = sum(map(len, inputs.values())) + sum(map(len, expected.values()))
    assert m.report_guard_comparisons(tmp_path, replace(LIMITS, bundle_bytes=cap), (intent(),)) == expected
