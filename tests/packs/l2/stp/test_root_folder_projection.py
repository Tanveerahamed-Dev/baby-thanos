"""Root observations retain source truth, exact cell grants and closed profile admission."""
import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded, Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import p4 as m
from atlas_brain.runner.p4_refs import ProofIndex, RootProofIndex
from tools import p4_estate_cases as estate

LIMITS = Budgets(1000000, 1000000, 1000)
PRIORITY, MAC_FACT = "l2.stp.reported_root_priority", "l2.stp.reported_root_mac"
MAC = "aBcD.EF01.2345"
FACTS = ("facts/stp_port_vlan.jsonl", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl")


def fixture(root, case="baseline", *, reverse=False, roots=True):
    inputs = estate.members(canonical, case)
    if roots:
        raw = inputs["tree.txt"].replace(b"   Root guard is disabled on the port\n",
            b"   Root guard is disabled on the port\n   Designated root has priority 0, address aBcD.EF01.2345\n")
        inputs["tree.txt"] = raw
        side = json.loads(inputs["p4.json"])
        next(member for member in side["captures"] if member["target"] == "tree")["sha256"] = sha256(raw).hexdigest()
        inputs["p4.json"] = canonical(side)
    root.mkdir(parents=True, exist_ok=True)
    for name in sorted(inputs, reverse=reverse):
        (root / name).write_bytes(inputs[name])
    return inputs


def executed(root, *, legacy=False):
    channel, standby = m.SummaryPack(LIMITS), m.StandbyBriefPack(LIMITS)
    source = (b.build_root_guard_global if legacy else b.build_root_observations_global)(root, LIMITS, peers=(channel, standby))
    return source, channel.finish(source.execution), standby.finish(source.execution)


def rows(files):
    return [json.loads(line) for path in FACTS for line in files[path].splitlines()]


def root_spans(raw, vlan):
    header = raw.index(f"VLAN{vlan:04}".encode())
    start = raw.rfind(b"\n", 0, header) + 1
    end = raw.index(b"\n", header)
    port = raw.index(estate.PORT.encode(), start)
    root = raw.index(b"   Designated root has priority 0, address ", end)
    priority, address = root + len(b"   Designated root has priority "), root + len(b"   Designated root has priority 0, address ")
    return ((start, end), (port, port + len(estate.PORT)), (header + 4, header + 8),
            (root, raw.index(b"\n", root)), (priority, priority + 1), (address, address + 14))


@pytest.mark.parametrize("case,known,unknown", [("baseline", 15, 10), ("pagp", 15, 10), ("missing", 8, 17)])
def test_root_report_has_literal_values_original_pins_closed_census_and_no_health(tmp_path, case, known, unknown):
    inputs = fixture(tmp_path, case)
    files = m.analyse_root_observations_folder(tmp_path, LIMITS)
    assert set(files) == {"result.json", "MANIFEST.sha256", *FACTS}
    expected_manifest = b"".join(f"{sha256(files[name]).hexdigest()}  {name}\n".encode()
        for name in sorted(files) if name != "MANIFEST.sha256")
    assert files["MANIFEST.sha256"] == expected_manifest
    head, facts = json.loads(files["result.json"]), rows(files)
    assert (head["schema"], head["scope"], head["checks"], head["root_scope"]) == (
        "atlas-brain.p4-root-observations/1", "observations_only", "not_implemented", "local_reported_priority_and_mac_not_intended_root")
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}
    assert len(facts) == 25 and sum(row["state"] == "known" for row in facts) == known
    assert sum(row["state"] == "unknown" for row in facts) == unknown
    assert head["registry_sha256"] == sha256(inputs["p4.json"]).hexdigest() and head["base_registry_sha256"] == sha256(inputs["p2.json"]).hexdigest()
    for row in facts:
        if row["fact"] not in (PRIORITY, MAC_FACT) or row["vlan"] == 3:
            continue
        value, raw = (0, "0") if row["fact"] == PRIORITY else (MAC, MAC)
        assert (row["value"], row["raw"], row["basis"]) == (value, raw, "observed") and type(row["value"]) is type(value)
        refs = row["evidence"][3:]
        assert tuple((ref["start"], ref["end"]) for ref in refs) == root_spans(inputs["tree.txt"], row["vlan"])
        assert all(ref["target"] == "tree" and ref["path"] == "tree.txt" and ref["role"] == "subject"
            and ref["sha256"] == sha256(inputs["tree.txt"][ref["start"]:ref["end"]]).hexdigest() for ref in refs)
    assert {name: (tmp_path / name).read_bytes() for name in inputs} == inputs


def test_legacy_and_root_profile_indexes_refuse_each_others_real_execution(tmp_path):
    fixture(tmp_path)
    root, _, _ = executed(tmp_path)
    old, _, _ = executed(tmp_path, legacy=True)
    assert RootProofIndex(root.execution, LIMITS).execution is root.execution
    with pytest.raises(m.RunnerRefused, match="^p4_projection_profile$"):
        ProofIndex(root.execution, LIMITS)
    with pytest.raises(m.RunnerRefused, match="^p4_projection_profile$"):
        RootProofIndex(old.execution, LIMITS)


@pytest.mark.parametrize("missing", range(6))
def test_all_six_source_leaves_are_required_and_same_byte_neighbor_cannot_be_borrowed(tmp_path, missing):
    inputs = fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    index = RootProofIndex(source.execution, LIMITS)
    first, second = tuple(row for row in source.result.rows if row.vlan in (1, 2))
    for fact, state, position in ((PRIORITY, first.root_priority, 4), (MAC_FACT, first.root_mac, 5)):
        scope = index.scope(k.FactId(fact), first.subject)
        output, = tuple(out for out in source.execution.executed if out.receipt.capture.operation == "iosxe.show_spanning_tree_interface_detail")
        points = root_spans(inputs["tree.txt"], 1)
        assert {(span.start, span.end) for _, span in scope.required} == set(points)
        assert {(span.start, span.end) for _, span in scope.positive} == {points[position]}
        assert scope.required == scope.spans and len(scope.required) == 6
        refs = state.evidence
        with pytest.raises(m.RunnerRefused, match="^p4_projection_positive$"):
            index.resolve(scope, refs[:3], positive=True)
        with pytest.raises(m.RunnerRefused, match="^p4_projection_positive$"):
            index.resolve(scope, refs[:3] + refs[3:3 + missing] + refs[4 + missing:], positive=True)
        borrowed = second.root_priority if fact == PRIORITY else second.root_mac
        assert borrowed.value == state.value and all(ref.capture == output.receipt.capture.id for ref in borrowed.evidence[3:])
        with pytest.raises(m.RunnerRefused, match="^p4_projection_scope$"):
            index.resolve(scope, refs[:3] + borrowed.evidence[3:], positive=True)


@pytest.mark.parametrize("plant", ["row_adapter", "reader", "store_clone", "census"])
def test_original_row_store_reader_and_population_custody_closes_before_bundle(tmp_path, monkeypatch, plant):
    fixture(tmp_path)
    build, adapter, read = b.build_root_observations_global, b.root_fact_rows, FactReader.read
    def built(*args, **kwargs):
        source = build(*args, **kwargs)
        if plant in ("store_clone", "census"):
            victim = source.result.rows[0]
            if plant == "store_clone":
                ref = k.FactRef(fact=k.FactId(PRIORITY), subject=victim.subject)
                source.result.store.values[ref] = replace(victim.root_priority)
            else:
                source = replace(source, result=replace(source.result, rows=source.result.rows[:-1]))
        return source
    def mapped(owner):
        items = adapter(owner)
        fact, row, value = items[0]
        return ((fact, replace(row), value),) + items[1:] if plant == "row_adapter" else items
    def consumed(self, **kwargs):
        value = read(self, **kwargs)
        return replace(value) if plant == "reader" and kwargs["fact"] == PRIORITY else value
    monkeypatch.setattr(b, "build_root_observations_global", built)
    monkeypatch.setattr(b, "root_fact_rows", mapped)
    monkeypatch.setattr(FactReader, "read", consumed)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before source custody"))
    code = "population" if plant == "census" else "store" if plant in ("reader", "store_clone") else "row"
    with pytest.raises(ValueError, match="^p4_observations_" + code + "$"):
        m.analyse_root_observations_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("plant", ["priority", "bool", "mac", "role", "guard", "basis", "raw", "false_unknown", "need", "source"])
def test_same_typed_coherent_store_and_row_lies_are_refused_from_original_execution(tmp_path, monkeypatch, plant):
    fixture(tmp_path)
    build = b.build_root_observations_global
    def built(*args, **kwargs):
        source = build(*args, **kwargs)
        row = next(row for row in source.result.rows if row.vlan == (3 if plant == "need" else 1))
        field = "root_mac" if plant == "mac" else "role" if plant == "role" else "value" if plant == "guard" else "root_priority"
        state = getattr(row, field)
        fact = MAC_FACT if field == "root_mac" else "l2.stp.reported_role" if field == "role" else "l2.stp.root_guard" if field == "value" else PRIORITY
        if plant == "false_unknown":
            changed = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="forged", evidence=state.evidence, candidates=(), next_evidence=())
        elif plant == "need":
            changed = replace(state, next_evidence=(replace(state.next_evidence[0], reruns=()),))
        else:
            changed = replace(state, **({"value": False if plant == "bool" else MAC.lower() if plant == "mac" else "root" if plant == "role" else True if plant == "guard" else 1}
                if plant in ("priority", "bool", "mac", "role", "guard") else {"basis": k.Basis.DECLARED} if plant == "basis" else {"raw": "normalized"} if plant == "raw" else {}))
            changed = state if plant == "source" else changed
        altered = replace(row, target=replace(row.target, port="Gi1/0/1")) if plant == "source" else replace(row, **{field: changed})
        source.result.store.values[k.FactRef(fact=k.FactId(fact), subject=row.subject)] = changed
        return replace(source, result=replace(source.result, rows=tuple(altered if item is row else item for item in source.result.rows)))
    monkeypatch.setattr(b, "build_root_observations_global", built)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before original source semantic closure"))
    code = "p4_observations_value" if plant == "bool" else "stp_root_observation_" + ("source" if plant == "source" else "value")
    with pytest.raises(ValueError, match="^" + code + "$"):
        m.analyse_root_observations_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("family", ["channel", "standby"])
@pytest.mark.parametrize("plant", ["finish", "population", "state"])
def test_all_peer_owners_close_before_bundle(tmp_path, monkeypatch, family, plant):
    fixture(tmp_path)
    owner = m.SummaryPack if family == "channel" else m.StandbyBriefPack
    finish = owner.finish
    def changed(self, execution):
        if plant == "finish":
            raise RuntimeError("late_peer_failure")
        result = finish(self, execution)
        if plant == "population":
            return replace(result, rows=result.rows[:-1])
        row = next(row for row in result.rows if type(row.value) is k.Known)
        state = replace(row.value, value=False)
        fact = "l2.etherchannel.reported_protocol" if family == "channel" else "l3.fhrp.reported_state"
        result.store.values[k.FactRef(fact=k.FactId(fact), subject=row.subject)] = state
        return replace(result, rows=tuple(replace(item, value=state) if item is row else item for item in result.rows))
    monkeypatch.setattr(owner, "finish", changed)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before all peer closure"))
    code = "late_peer_failure" if plant == "finish" else "p4_observations_population" if plant == "population" else "p4_observations_value"
    with pytest.raises(RuntimeError if plant == "finish" else ValueError, match="^" + code + "$"):
        m.analyse_root_observations_folder(tmp_path, LIMITS)


def test_root_output_and_input_budgets_count_all_five_files_including_manifest(tmp_path):
    inputs = fixture(tmp_path)
    files = m.analyse_root_observations_folder(tmp_path, LIMITS)
    per = max(map(len, (*inputs.values(), *files.values())))
    total, count = sum(map(len, inputs.values())) + sum(map(len, files.values())), len(inputs) + len(files)
    assert max(map(len, files.values())) > max(map(len, inputs.values()))
    assert m.analyse_root_observations_folder(tmp_path, Budgets(total, per, count)) == files
    for limits in (Budgets(total, per - 1, count), Budgets(total - 1, per, count), Budgets(total, per, count - 1)):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as error:
            m.analyse_root_observations_folder(tmp_path, limits)
        assert error.value.member == "p4_root_observations_outputs"


@pytest.mark.parametrize("case", ["baseline", "pagp", "missing"])
def test_default_legacy_five_output_bytes_still_match_independent_qualified_oracle(tmp_path, case):
    files = fixture(tmp_path, case, roots=False)
    estate.validate(m.analyse_folder(tmp_path, LIMITS), files, case, canonical)


def test_root_bytes_are_identical_across_hash_seeds_and_reversed_input_creation(tmp_path):
    left, right = tmp_path / "left", tmp_path / "right"
    assert fixture(left) == fixture(right, reverse=True)
    code = ("import json,sys\n"
            "from pathlib import Path\n"
            "from atlas_brain.evidence.admission import Budgets\n"
            "from atlas_brain.runner.p4 import analyse_root_observations_folder\n"
            "print(json.dumps({k:v.hex() for k,v in analyse_root_observations_folder(Path(sys.argv[1]),Budgets(1000000,1000000,1000)).items()},sort_keys=True))")
    outputs = [subprocess.run([sys.executable, "-B", "-c", code, str(root)], env={**os.environ, "PYTHONHASHSEED": seed},
        check=True, capture_output=True, timeout=60).stdout for root, seed in ((left, "1"), (right, "83"))]
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("root,budgets", [(object(), LIMITS), (Path("."), object())])
def test_public_root_api_refuses_opaque_inputs_before_running(root, budgets, monkeypatch):
    monkeypatch.setattr(b, "build_root_observations_global", lambda *args, **kwargs: pytest.fail("run before public root-input gate"))
    with pytest.raises(ValueError, match="^p4_observations_root_input$"):
        m.analyse_root_observations_folder(root, budgets)


@pytest.mark.parametrize("vlan", [True, 4])
def test_root_leaf_selector_cannot_coerce_bool_or_select_an_undeclared_vlan(tmp_path, vlan):
    fixture(tmp_path)
    source, _, _ = executed(tmp_path)
    row = source.result.rows[0]
    output, = tuple(out for out in source.execution.executed if out.receipt.capture.operation == "iosxe.show_spanning_tree_interface_detail")
    with pytest.raises(ValueError, match="^stp_projection_scope$"):
        b.root_projection_leaves(k.FactId(PRIORITY), row.target, vlan, output)


@pytest.mark.parametrize("removed", [False, True])
def test_missing_root_evidence_keeps_all_subjects_unknown_without_default_values(tmp_path, removed):
    inputs = fixture(tmp_path, roots=False)
    if removed:
        side = json.loads(inputs["p4.json"])
        side["captures"] = [row for row in side["captures"] if row["target"] != "tree"]
        (tmp_path / "p4.json").write_bytes(canonical(side))
        (tmp_path / "tree.txt").unlink()
    files = m.analyse_root_observations_folder(tmp_path, LIMITS)
    selected = [row for row in rows(files) if row["fact"] in (PRIORITY, MAC_FACT)]
    assert len(rows(files)) == 25 and len(selected) == 6 and json.loads(files["result.json"])["denominator"]["l2.stp"] == 3
    for row in selected:
        reason = "not_collected" if removed else "subject_absent_from_capture" if row["vlan"] == 3 else "field_not_printed"
        assert row["state"] == "unknown" and row["reason"] == reason and "value" not in row
        assert row["next_evidence"][0]["reruns"] == ["l2.stp/parse_root_guard"]
