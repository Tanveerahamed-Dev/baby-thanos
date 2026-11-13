"""Original-source HSRP qualification; no gateway binding, inferred peers or health."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.runner import p4
from atlas_brain.runner import p4_fhrp_policy as runner
from tools import p4_estate_cases as estate

LIMITS = p4.Budgets(1000000, 1000000, 1000)
FACT = "l3.fhrp.reported_state"


def folder(root, missing=None):
    files = estate.members(canonical, "baseline")
    files["cold-gateway.txt"] = (
        b"                     P indicates configured to preempt.\n                     |\n"
        b"Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
        b"BD10        1    100   Standby 192.0.2.3       local           192.0.2.99\n")
    side = json.loads(files["p4.json"])
    next(row for row in side["targets"] if row["id"] == "hsrp-cold")["params"]["groups"].append(["BD10", "1"])
    side["captures"].append({"target": "hsrp-cold", "path": "cold-gateway.txt", "sha256": sha256(files["cold-gateway.txt"]).hexdigest()})
    if missing:
        targets = ("hsrp", "hsrp-cold") if missing == "both" else (missing,)
        paths = {row["path"] for row in side["captures"] if row["target"] in targets}
        for name in paths:
            files.pop(name)
        side["captures"] = [row for row in side["captures"] if row["target"] not in targets]
    files["p4.json"] = canonical(side)
    root.mkdir()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


def subject(node, interface, group):
    raw = canonical(("atlas-brain.fhrp-local/1", "round", "node:demo:" + node, interface, "ipv4", "hsrp", group))
    return k.EntityKey("fhrp_local:" + sha256(raw).hexdigest())


def literal_spans(raw, interface, group, state, addresses):
    line = next(line for line in raw.splitlines(keepends=True) if line.startswith(interface.encode() + b" "))
    start, cursor = raw.index(line), 0
    spans = [(start, start + len(line.rstrip(b"\n")))]
    for value in (interface, group, state, *addresses):
        offset = line.index(value.encode(), cursor)
        cursor = offset + len(value)
        spans.append((start + offset, start + cursor))
    return tuple(sorted(spans))


@pytest.mark.parametrize("missing", [None, "hsrp", "hsrp-cold", "both"])
def test_original_source_population_and_literal_states_survive_capture_loss(tmp_path, missing):
    inputs = folder(tmp_path / "inputs", missing)
    prepared = runner.prepare_fhrp_source(tmp_path / "inputs", LIMITS)
    assert len(prepared.source.rows) == len(prepared.source.store.values) == 6
    assert prepared.source.store.owners == {FACT: "l3.fhrp/parse_hsrp_brief"}
    assert {domain.node.id for domain in prepared.domains} == {"a", "b"}
    observed = {("a", "Vl20"): ("init", "Init"), ("a", "Vl10"): ("active", "Active"),
        ("a", "BD3329"): ("standby", "Standby"), ("b", "BD10"): ("standby", "Standby")}
    addresses = {"Vl20": ("203.0.113.1",), "Vl10": ("192.0.2.2", "192.0.2.1"),
        "BD3329": ("198.51.100.2", "198.51.100.1"), "BD10": ("192.0.2.3", "192.0.2.99")}
    absent_nodes = {"a", "b"} if missing == "both" else {"a"} if missing == "hsrp" else {"b"} if missing else set()
    for row in prepared.source.rows:
        assert row.subject == subject(row.target.node.id, row.interface, row.group)
        assert row.target is next(domain for domain in prepared.domains if domain.node is row.target.node)
        assert prepared.source.store.values[k.FactRef(fact=FACT, subject=row.subject)] is row.value
        if row.target.node.id in absent_nodes:
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
        elif (row.target.node.id, row.interface) in observed:
            assert (row.value.value, row.value.raw, row.value.basis) == (*observed[row.target.node.id, row.interface], k.Basis.OBSERVED)
            raw = inputs["hsrp.txt" if row.target.node.id == "a" else "cold-gateway.txt"]
            refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            original = next(output.receipt.capture for output in prepared.source.executed if output.receipt.capture.source == row.target.node.key)
            assert original.raw == raw
            expected = literal_spans(raw, row.interface, row.group, observed[row.target.node.id, row.interface][1], addresses[row.interface])
            assert tuple((ref.locator.start, ref.locator.end) for ref in refs) == expected
            assert all(ref.capture == original.id and ref.role is k.EvidenceRole.SUBJECT and ref.excerpt_sha256 == sha256(raw[a:z]).hexdigest()
                for ref, (a, z) in zip(refs, expected, strict=True))
        else:
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
        if type(row.value) is k.Unknown:
            assert row.value.detail == "hsrp_state_unresolved"
            need, = row.value.next_evidence
            assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (
                row.target.node.key, estate.HSRP, (("group", row.group), ("interface", row.interface)), (FACT,), ("l3.fhrp/parse_hsrp_brief",))
    assert {p.name: p.read_bytes() for p in (tmp_path / "inputs").iterdir()} == inputs


@pytest.mark.parametrize("plant", ["mapped", "raw", "basis", "false_unknown", "reason", "need"])
def test_every_original_state_closes_before_publishing_source(tmp_path, monkeypatch, plant):
    folder(tmp_path / "inputs")
    finish = runner.StandbyBriefPack.finish
    def changed(self, execution):
        result = finish(self, execution)
        row = next(row for row in result.rows if row.interface == ("Vl30" if plant in ("reason", "need") else "BD3329"))
        state = row.value
        if plant == "need":
            forged = replace(state, next_evidence=(replace(state.next_evidence[0], reruns=()),))
        elif plant == "reason":
            forged = replace(state, reason=k.UnknownReason.NOT_COLLECTED)
        elif plant == "false_unknown":
            forged = k.Unknown(reason=k.UnknownReason.NOT_COLLECTED, detail="forged", evidence=state.evidence, candidates=(), next_evidence=())
        elif plant == "basis":
            forged = replace(state, basis=k.Basis.DECLARED)
        else:
            forged = replace(state, value="active", raw="Active" if plant == "mapped" else state.raw)
        result.store.values[k.FactRef(fact=FACT, subject=row.subject)] = forged
        return replace(result, rows=tuple(replace(item, value=forged) if item is row else item for item in result.rows))
    monkeypatch.setattr(runner.StandbyBriefPack, "finish", changed)
    monkeypatch.setattr(runner.FhrpSource, "__init__", lambda *_a, **_k: pytest.fail("carrier before source closure"))
    with pytest.raises(ValueError, match="^hsrp_gateway_source_value$"):
        runner.prepare_fhrp_source(tmp_path / "inputs", LIMITS)


@pytest.mark.parametrize("plant,code", [("missing_row", "p4_observations_population"),
    ("duplicate_row", "p4_observations_population"), ("missing_output", "hsrp_gateway_source_population"),
    ("reverse_outputs", "hsrp_gateway_source_population"), ("clone_value", "hsrp_gateway_source_population")])
def test_original_census_and_owned_execution_identity_precede_source_carrier(tmp_path, monkeypatch, plant, code):
    folder(tmp_path / "inputs")
    finish = runner.StandbyBriefPack.finish
    def changed(self, execution):
        result = finish(self, execution)
        if plant == "missing_row":
            return replace(result, rows=result.rows[:-1])
        if plant == "duplicate_row":
            return replace(result, rows=result.rows + (result.rows[0],))
        outputs = () if plant == "missing_output" else tuple(reversed(result.executed)) if plant == "reverse_outputs" else (
            replace(result.executed[0], value=replace(result.executed[0].value)), *result.executed[1:])
        return replace(result, executed=outputs)
    monkeypatch.setattr(runner.StandbyBriefPack, "finish", changed)
    monkeypatch.setattr(runner.FhrpSource, "__init__", lambda *_a, **_k: pytest.fail("carrier before original census"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        runner.prepare_fhrp_source(tmp_path / "inputs", LIMITS)


def test_fresh_execution_original_targets_full_reader_and_no_replay(tmp_path, monkeypatch):
    folder(tmp_path / "inputs")
    execute, parse = runner.p4_pipeline.execute_p4_folder, b.hsrp.parse_capture
    cfinish, sfinish, read = runner.SummaryPack.finish, runner.StandbyBriefPack.finish, FactReader.read
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
        if type(self) is runner.StandbyBriefPack:
            monkeypatch.setattr(b, "bind_writer", lambda *_a, **_k: pytest.fail("source validator wrote"))
        finished.append(result)
        return result
    def reading(self, **kwargs):
        if kwargs["fact"] == FACT:
            reads.append((self.step.id, kwargs["subject"]))
        return read(self, **kwargs)
    monkeypatch.setattr(runner.p4_pipeline, "execute_p4_folder", run)
    monkeypatch.setattr(b.hsrp, "parse_capture", parsing)
    monkeypatch.setattr(runner.SummaryPack, "finish", finishing)
    monkeypatch.setattr(runner.StandbyBriefPack, "finish", finishing)
    monkeypatch.setattr(FactReader, "read", reading)
    result = runner.prepare_fhrp_source(tmp_path / "inputs", LIMITS)
    assert len(calls) == 1 and len(finished) == 2 and result.source is finished[1] and result.execution is calls[0]
    assert len(parsed) == len(set(parsed)) == 2
    assert b.SOURCE_STEP.reads == (FACT,) and b.SOURCE_STEP.produces == () and b.DECLARATION.steps == (b.STEP,)
    assert {value for _, value in reads} == {row.subject for row in result.source.rows} and len(reads) == 12
    assert {step for step, _ in reads} == {p4.PROJECT.id, b.SOURCE_STEP.id}
    assert all(row.target is next(domain for domain in result.domains if domain.node is row.target.node) for row in result.source.rows)
    assert all(output.receipt is next(original.receipt for original in result.execution.executed
        if original.receipt.capture.id == output.receipt.capture.id) for output in result.source.executed)


@pytest.mark.parametrize("carrier", ["prepared", "source", "store", "execution", "domains", "text", "budget"])
def test_opaque_carriers_and_budget_shape_refuse_before_execution(tmp_path, monkeypatch, carrier):
    folder(tmp_path / "inputs")
    result = runner.prepare_fhrp_source(tmp_path / "inputs", LIMITS)
    roots = {"prepared": result, "source": result.source, "store": result.source.store, "execution": result.execution,
        "domains": result.domains, "text": str(tmp_path / "inputs"), "budget": tmp_path / "inputs"}
    monkeypatch.setattr(runner.stp, "build_root_guard_global", lambda *_a, **_k: pytest.fail("invalid input executed"))
    with pytest.raises(ValueError, match="^fhrp_source_input$"):
        runner.prepare_fhrp_source(roots[carrier], object() if carrier == "budget" else LIMITS)


@pytest.mark.parametrize("owner,fault,code", [("channel", "raise", "planted_peer_failure"), ("channel", "store", "p4_observations_store"),
    ("channel", "proof", "p4_projection_span"), ("standby", "proof", "p4_projection_span")])
def test_all_owner_completion_and_original_byte_proofs_precede_source(tmp_path, monkeypatch, owner, fault, code):
    folder(tmp_path / "inputs")
    capsule = runner.SummaryPack if owner == "channel" else runner.StandbyBriefPack
    finish = capsule.finish
    def changed(self, execution):
        if fault == "raise":
            raise ValueError("planted_peer_failure")
        result = finish(self, execution)
        if fault == "store":
            result.store.owners.clear()
            return result
        row = next(row for row in result.rows if type(row.value) is k.Known)
        forged = replace(row.value, evidence=row.value.evidence[:3] + (replace(row.value.evidence[3], excerpt_sha256="0" * 64),) + row.value.evidence[4:])
        fact = "l2.etherchannel.reported_protocol" if owner == "channel" else FACT
        result.store.values[k.FactRef(fact=fact, subject=row.subject)] = forged
        return replace(result, rows=tuple(replace(item, value=forged) if item is row else item for item in result.rows))
    monkeypatch.setattr(capsule, "finish", changed)
    monkeypatch.setattr(runner.FhrpSource, "__init__", lambda *_a, **_k: pytest.fail("carrier before peer closure"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        runner.prepare_fhrp_source(tmp_path / "inputs", LIMITS)


def test_source_budget_counts_only_original_files_and_refuses_before_parsing(tmp_path, monkeypatch):
    inputs = folder(tmp_path / "inputs")
    total, count = sum(map(len, inputs.values())), len(inputs)
    largest = max(inputs, key=lambda name: len(inputs[name]))
    limits = p4.Budgets(total, len(inputs[largest]), count)
    assert len(runner.prepare_fhrp_source(tmp_path / "inputs", limits).source.rows) == 6
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *_: pytest.fail("budget failure parsed"))
    for limits, member in ((p4.Budgets(total - 1, 1000000, count), "bundle"),
        (p4.Budgets(total, len(inputs[largest]) - 1, count), largest), (p4.Budgets(total, 1000000, count - 1), "bundle")):
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as error:
            runner.prepare_fhrp_source(tmp_path / "inputs", limits)
        assert error.value.member == member
