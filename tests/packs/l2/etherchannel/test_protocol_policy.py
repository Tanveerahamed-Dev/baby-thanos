"""Original-source protocol-policy preparation; no checker, inferred peers, mode or health."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l2.etherchannel import build as b
from atlas_brain.packs.l2.etherchannel import protocol_policy as policy_module
from atlas_brain.runner import p4
from atlas_brain.runner import p4_etherchannel_policy as runner
from tools import p4_estate_cases as estate

LIMITS = p4.Budgets(1000000, 1000000, 1000)
FACT = "l2.etherchannel.reported_protocol"
PAIR = (("ec", "1"), ("cold", "4"))


def folder(root, missing=None):
    files = estate.members(canonical, "baseline")
    files["cold.txt"] = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
        b"--+--+--+--\n4 Po4(SU) PAgP Gi1/0/1(P)\n")
    side = json.loads(files["p4.json"])
    next(row for row in side["targets"] if row["id"] == "cold")["params"]["ports"] = ["Gi1/0/1"]
    side["captures"].append({"target": "cold", "path": "cold.txt", "sha256": sha256(files["cold.txt"]).hexdigest()})
    if missing:
        files.pop(missing + ".txt")
        side["captures"] = [row for row in side["captures"] if row["target"] != missing]
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


def policy(participants=PAIR, identity="same"):
    return policy_module.ProtocolPolicy(id=identity, expectation="same_reported_protocol", participants=participants)


def subject(node, group):
    raw = canonical(("atlas-brain.etherchannel-group/1", "round", "node:demo:" + node, group))
    return k.EntityKey("etherchannel_group:" + sha256(raw).hexdigest())


@pytest.mark.parametrize("missing", [None, "ec", "cold"])
def test_original_source_census_and_declared_pair_proofs_survive_capture_removal(tmp_path, missing):
    inputs = folder(tmp_path / "inputs", missing=missing)
    prepared = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    assert prepared.plan.envelope is prepared.execution.envelope and len(prepared.source.rows) == 4
    assert len(prepared.source.store.values) == 8 and prepared.source.store.owners == {
        fact: "l2.etherchannel/parse_protocol" for fact in (FACT, "l2.etherchannel.reported_member_tokens")}
    row, = prepared.plan.rows
    assert tuple((p.target_id, p.group, p.subject) for p in row.participants) == (
        ("cold", "4", subject("a", "4")), ("ec", "1", subject("b", "1")))
    declaration = row.declaration
    ref, = declaration.evidence
    assert declaration.basis is k.Basis.DECLARED and declaration.raw == declaration.value == "same"
    assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == (
        "declared_etherchannel_protocol_policies", "same", sha256(prepared.plan.raw).hexdigest(), "/policies/0")
    assert prepared.plan.sha256 == ref.table_digest and prepared.plan.denominator == (
        ("declared_policies", 1), ("declared_participant_occurrences", 2))
    for fact, original, state in b.fact_rows(prepared.source):
        assert prepared.source.store.values[k.FactRef(fact=fact, subject=original.subject)] is state
        if original.target.node.id == ("b" if missing == "ec" else "a") and missing:
            assert type(state) is k.Unknown and state.reason is k.UnknownReason.NOT_COLLECTED
            assert state.next_evidence and state.next_evidence[0].reruns == ("l2.etherchannel/parse_protocol",)
        if fact == FACT and original.group == "2" and missing != "ec":
            assert (state.value, state.raw, state.basis) == ("none_reported", "-", k.Basis.OBSERVED)
    assert prepared.plan.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == inputs


@pytest.mark.parametrize("plant", ["id", "expectation", "arity", "inner", "group_bool", "group_zero", "target_op",
    "missing_group", "same_subject", "same_node", "duplicate_id", "duplicate_pair"])
def test_policy_selectors_bind_only_original_distinct_subjects_and_nodes(tmp_path, plant):
    folder(tmp_path / "inputs")
    result = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    domains = tuple({row.target.node.key: row.target for row in result.source.rows}.values())
    plan = policy_module.plan_for_declared_scope(result.execution.envelope, LIMITS, (policy(tuple(reversed(PAIR))),), tuple(reversed(domains)))
    assert plan.raw == result.plan.raw and plan.sha256 == result.plan.sha256
    selectors = {"arity": (("ec", "1"),), "inner": (["ec", "1"], ("cold", "4")), "group_bool": (("ec", True), ("cold", "4")),
        "group_zero": (("ec", "01"), ("cold", "4")), "target_op": (("tree", "1"), ("cold", "4")),
        "missing_group": (("ec", "9"), ("cold", "4")), "same_subject": (("ec", "1"), ("ec", "1")),
        "same_node": (("ec", "1"), ("ec", "2"))}
    selected = (replace(policy(), id="BAD"),) if plant == "id" else (replace(policy(), expectation="static"),) if plant == "expectation" else (
        (policy(), policy()) if plant == "duplicate_id" else (policy(), policy(tuple(reversed(PAIR)), "other")) if plant == "duplicate_pair"
        else (policy(selectors[plant]),))
    code = "value" if plant in ("id", "expectation") else "duplicate" if plant.startswith("duplicate") else "selector"
    with pytest.raises(ValueError, match="^etherchannel_protocol_policy_" + code + "$"):
        policy_module.plan_for_declared_scope(result.execution.envelope, LIMITS, selected, domains)


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("plant", ["mapped", "raw_mismatch", "basis", "false_unknown", "need", "member"])
def test_all_original_source_values_close_before_any_or_empty_comparisons(tmp_path, monkeypatch, plant, empty):
    folder(tmp_path / "inputs")
    finish = runner.SummaryPack.finish
    def changed(self, execution):
        result = finish(self, execution)
        row = next(row for row in result.rows if row.group == ("3" if plant == "need" else "2"))
        state = row.member_tokens if plant == "member" else row.value
        if plant == "need":
            forged = replace(state, next_evidence=(replace(state.next_evidence[0], reruns=()),))
        elif plant == "false_unknown":
            forged = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="forged", evidence=state.evidence, candidates=(), next_evidence=())
        elif plant == "basis":
            forged = replace(state, basis=k.Basis.DECLARED)
        else:
            forged = replace(state, value="pagp", raw="PAgP" if plant == "mapped" else state.raw)
        fact = b.REPORTED_MEMBER_TOKENS if plant == "member" else b.REPORTED_PROTOCOL
        result.store.values[k.FactRef(fact=fact, subject=row.subject)] = forged
        return replace(result, rows=tuple(replace(item, **{"member_tokens" if plant == "member" else "value": forged})
            if item is row else item for item in result.rows))
    monkeypatch.setattr(runner.SummaryPack, "finish", changed)
    monkeypatch.setattr(policy_module, "plan_for_declared_scope", lambda *_: pytest.fail("plan before original-source closure"))
    with pytest.raises(ValueError, match="^etherchannel_protocol_source_value$"):
        runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, () if empty else (policy(),))


@pytest.mark.parametrize("empty", [False, True])
def test_one_original_execution_all_owner_finishes_and_complete_project_reader(tmp_path, monkeypatch, empty):
    folder(tmp_path / "inputs")
    execute, parse = runner.p4_pipeline.execute_p4_folder, b.parse_summary.parse_capture
    cfinish, sfinish = runner.SummaryPack.finish, runner.StandbyBriefPack.finish
    calls, parsed, finished, reads = [], [], [], []
    def run(*args, **kwargs):
        result = execute(*args, **kwargs)
        calls.append(result)
        return result
    def parsing(capture, *args):
        parsed.append(capture.id)
        return parse(capture, *args)
    def finishing(self, execution):
        assert execution is calls[0]
        result = (cfinish if type(self) is runner.SummaryPack else sfinish)(self, execution)
        if type(self) is runner.SummaryPack:
            monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("source validator wrote facts"))
        finished.append(result)
        return result
    read = FactReader.read
    def reading(self, **kwargs):
        if self.step.id == p4.PROJECT.id and kwargs["fact"].startswith("l2.etherchannel."):
            reads.append((kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    monkeypatch.setattr(runner.p4_pipeline, "execute_p4_folder", run)
    monkeypatch.setattr(b.parse_summary, "parse_capture", parsing)
    monkeypatch.setattr(runner.SummaryPack, "finish", finishing)
    monkeypatch.setattr(runner.StandbyBriefPack, "finish", finishing)
    monkeypatch.setattr(FactReader, "read", reading)
    result = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, () if empty else (policy(),))
    assert len(calls) == 1 and len(finished) == 2 and result.source is finished[0] and result.execution is calls[0]
    assert len(parsed) == len(set(parsed)) == 2
    assert {fact for fact, _ in reads} == {FACT, "l2.etherchannel.reported_member_tokens"}
    assert {item for _, item in reads} == {subject("a", "4"), *(subject("b", str(i)) for i in (1, 2, 3))}
    assert len(result.source.rows) == 4 and len(result.plan.rows) == (0 if empty else 1)
    assert result.plan.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN


@pytest.mark.parametrize("carrier", ["plan", "store", "execution", "policy_list", "policy_member", "policy_count"])
def test_public_api_rejects_opaque_carriers_and_malformed_policy_inputs_before_execution(tmp_path, monkeypatch, carrier):
    folder(tmp_path / "inputs")
    result = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    root = result.plan if carrier == "plan" else result.source.store if carrier == "store" else result.execution if carrier == "execution" else tmp_path / "inputs"
    policies = [policy()] if carrier == "policy_list" else (object(),) if carrier == "policy_member" else (policy(),) * 65 if carrier == "policy_count" else (policy(),)
    monkeypatch.setattr(runner.stp, "build_root_guard_global", lambda *_a, **_k: pytest.fail("invalid input executed"))
    with pytest.raises(ValueError, match="^etherchannel_protocol_policy_input$"):
        runner.prepare_protocol_comparisons(root, LIMITS, policies)


@pytest.mark.parametrize("peer,fault,code", [("channel", "raise", "planted_peer_failure"), ("standby", "raise", "planted_peer_failure"),
    ("standby", "store", "p4_observations_store"), ("standby", "proof", "p4_projection_span")])
def test_peer_finish_store_and_byte_proofs_close_before_any_plan(tmp_path, monkeypatch, peer, fault, code):
    folder(tmp_path / "inputs")
    owner = runner.SummaryPack if peer == "channel" else runner.StandbyBriefPack
    finish = owner.finish
    def changed(self, execution):
        if fault == "raise":
            raise ValueError("planted_peer_failure")
        result = finish(self, execution)
        if fault == "store":
            result.store.owners.clear()
            return result
        row = next(row for row in result.rows if type(row.value) is k.Known)
        state = replace(row.value, evidence=row.value.evidence[:3] + (replace(row.value.evidence[3], excerpt_sha256="0" * 64),) + row.value.evidence[4:])
        result.store.values[k.FactRef(fact=runner.fhrp.REPORTED_STATE, subject=row.subject)] = state
        return replace(result, rows=tuple(replace(item, value=state) if item is row else item for item in result.rows))
    monkeypatch.setattr(owner, "finish", changed)
    monkeypatch.setattr(policy_module, "plan_for_declared_scope", lambda *_: pytest.fail("plan before complete peer closure"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))


def test_policy_budget_counts_original_inputs_and_canonical_registry_once(tmp_path):
    inputs = folder(tmp_path / "inputs")
    result = runner.prepare_protocol_comparisons(tmp_path / "inputs", LIMITS, (policy(),))
    domains = tuple({row.target.node.key: row.target for row in result.source.rows}.values())
    raw = result.plan.raw
    total, count = sum(map(len, inputs.values())) + len(raw), len(inputs) + 1
    assert policy_module.plan_for_declared_scope(result.execution.envelope, p4.Budgets(total, max(len(raw), max(map(len, inputs.values()))), count), (policy(),), domains).raw == raw
    for limits in (p4.Budgets(total - 1, 1000000, count), p4.Budgets(total, len(raw) - 1, count), p4.Budgets(total, 1000000, count - 1)):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as error:
            policy_module.plan_for_declared_scope(result.execution.envelope, limits, (policy(),), domains)
        assert error.value.member == "etherchannel_protocol_policy"
