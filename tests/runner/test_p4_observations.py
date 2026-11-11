import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256

import pytest
from test_p4_leaf_refs import assert_leaf
from test_p4_proof_index import LIMITS, P, estate

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.model.store import FactReader
from atlas_brain.runner import p4 as m

FACTS = ("facts/stp_port_vlan.jsonl", "facts/etherchannel_group.jsonl")


def snapshot(root):
    return {p.name: p.read_bytes() for p in root.iterdir()}


def unpack(files):
    assert set(files) == {"result.json", "MANIFEST.sha256", *FACTS}
    entries = [line.split("  ") for line in files["MANIFEST.sha256"].decode().splitlines()]
    assert [name for _, name in entries] == sorted(set(files) - {"MANIFEST.sha256"})
    assert all(sha256(files[name]).hexdigest() == digest for digest, name in entries)
    head = json.loads(files["result.json"])
    assert canonical(head) == files["result.json"]
    for path, fact, pack in zip(FACTS, (m.stp.ROOT_GUARD, m.ec.REPORTED_PROTOCOL), (m.stp.PACK, m.ec.PACK), strict=True):
        assert all((row["fact"], row["pack"]) == (fact, pack) for row in map(json.loads, files[path].splitlines()))
    rows = [json.loads(line) for path in FACTS for line in files[path].splitlines()]
    assert all(b"".join(canonical(json.loads(line)) + b"\n" for line in files[path].splitlines()) == files[path] for path in FACTS)
    return head, rows


def semantics(files):
    head, rows = unpack(files)
    return head["denominator"], [(r["subject"], r["fact"], r["state"], r.get("value"), r.get("reason"), r.get("basis"), r.get("raw")) for r in rows]


@pytest.mark.parametrize("guard,protocol,expected", [(b"enabled", b"LACP", "lacp"), (b"disabled", b"-", "none_reported"), (None, b"PAgP", "pagp")])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_real_folder_returns_canonical_partial_bundle_only_after_both_finishes_and_reader(tmp_path, monkeypatch, guard, protocol, expected, ending):
    estate(tmp_path, guard, protocol, ending)
    before, runs, finishes, reads = snapshot(tmp_path), [], [], []
    factory, finish, read, bundle = m.stp.build_root_guard_global, m.SummaryPack.finish, FactReader.read, m.result_bundle
    def built(*args, **kwargs):
        out = factory(*args, **kwargs)
        runs.append(out)
        return out
    def finished(self, execution):
        assert len(runs) == 1 and execution is runs[0].execution
        out = finish(self, execution)
        finishes.append(out)
        return out
    def consumed(self, **kwargs):
        assert len(finishes) == 1
        reads.append((self.step.reads, kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    def bundled(*args, **kwargs):
        assert len(runs) == len(finishes) == 1 and reads
        return bundle(*args, **kwargs)
    monkeypatch.setattr(m.stp, "build_root_guard_global", built)
    monkeypatch.setattr(m.SummaryPack, "finish", finished)
    monkeypatch.setattr(FactReader, "read", consumed)
    monkeypatch.setattr(m, "result_bundle", bundled)
    files = m.analyse_folder(tmp_path, LIMITS)
    head, rows = unpack(files)
    assert snapshot(tmp_path) == before
    assert (head["schema"], head["scope"], head["checks"], head["variant_support"]) == ("atlas-brain.p4-observations/1", "observations_only", "not_implemented", "allowlisted")
    assert head["semantic_group"] == "declared_synthetic" and head["context"] == "round"
    assert head["registration_sha256"] == runs[0].execution.envelope.registration_sha256
    assert head["registry_sha256"] == sha256(before["p4.json"]).hexdigest() and head["base_registry_sha256"] == sha256(before["p2.json"]).hexdigest()
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4} and len(rows) == len(reads) == 7
    assert {(f, s) for _, f, s in reads} == {(r["fact"], r["subject"]) for r in rows} and all(set(declared) == {m.stp.ROOT_GUARD, m.ec.REPORTED_PROTOCOL} and fact in declared for declared, fact, _ in reads)
    root = next(r for r in rows if r["fact"] == m.stp.ROOT_GUARD and r["vlan"] == 1)
    assert (root["state"], root.get("value", root.get("reason"))) == (("unknown", "field_not_printed") if guard is None else ("known", guard == b"enabled"))
    channel = next(r for r in rows if r["fact"] == m.ec.REPORTED_PROTOCOL and r["group"] == "2")
    assert (channel["value"], channel["raw"]) == (expected, protocol.decode())
    original = {o.receipt.capture.id: o for o in runs[0].execution.executed}
    assert len(head["captures"]) == len(original) == 2 and {c["id"] for c in head["captures"]} == set(original)
    for capture in head["captures"]:
        item = original[capture["id"]]
        assert (capture["source"], capture["operation"], capture["rendered"], capture["owner"]) == (item.receipt.capture.source, item.receipt.capture.operation, item.receipt.capture.rendered, item.receipt.owner)
        clock = capture["collected_utc"]
        assert capture["read_scope"] == capture["view"] == "unknown" and capture["codec"] == "utf-8" and capture["channel"] == "cli"
        assert capture["scope"]["node"] == capture["source"] and capture["scope"]["plane"] == "exec" and all(capture["scope"][key] is None for key in ("context", "vrf", "instance", "vdc", "tenant", "afi"))
        assert capture["error"] is capture["envelope"] is None and capture["context"] == "round" and capture["read_scope_evidence"] == [] and capture["integrity"] == capture["parse"] == "complete"
        assert (clock["state"], clock["reason"], clock["detail"]) == ("unknown", "as_of_missing", "no_collector_time") and clock["evidence"] == capture["integrity_evidence"] and clock["candidates"] == clock["next_evidence"] == []
        assert clock["evidence"][0]["locator"] == "whole_capture" and clock["evidence"][0]["capture"] == capture["id"]
        assert capture["sha256"] == sha256(before[capture["path"]]).hexdigest() and capture["registration_sha256"] == head["registration_sha256"]
    expected = {(fact, row.subject): row.value.evidence
                for fact, owner in ((m.stp.ROOT_GUARD, runs[0].result), (m.ec.REPORTED_PROTOCOL, finishes[0])) for row in owner.rows}
    for row in rows:
        for original, projected in zip(expected[(row["fact"], row["subject"])], row["evidence"], strict=True):
            assert_leaf(original, projected, runs[0].execution)


@pytest.mark.parametrize("seed", ["1", "83"])
def test_same_raw_bytes_are_identical_across_directory_and_hash_seed(tmp_path, seed):
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    estate(left)
    raw = snapshot(left)
    for name in reversed(tuple(raw)):
        (right / name).write_bytes(raw[name])
    expected = m.analyse_folder(left, LIMITS)
    assert m.analyse_folder(right, LIMITS) == expected and snapshot(left) == snapshot(right) == raw
    code = "from pathlib import Path\nimport sys\nfrom atlas_brain.evidence.admission import Budgets\nfrom atlas_brain.runner.p4 import analyse_folder\nprint(analyse_folder(Path(sys.argv[1]), Budgets(1000000,1000000,1000))['MANIFEST.sha256'].hex())"
    child = subprocess.run([sys.executable, "-c", code, str(right)], env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, text=True, check=True, timeout=60)
    assert child.stdout.strip() == expected["MANIFEST.sha256"].hex()


def test_iteration_does_not_change_bytes_but_raw_registry_or_line_endings_change_provenance(tmp_path, monkeypatch):
    side = estate(tmp_path)
    original = m.analyse_folder(tmp_path, LIMITS)
    factory = m.stp.build_root_guard_global
    def reordered(*args, **kwargs):
        out = factory(*args, **kwargs)
        return replace(out, execution=replace(out.execution, executed=tuple(reversed(out.execution.executed))),
                       result=replace(out.result, rows=tuple(reversed(out.result.rows))))
    monkeypatch.setattr(m.stp, "build_root_guard_global", reordered)
    assert m.analyse_folder(tmp_path, LIMITS) == original
    side["targets"].reverse()
    side["captures"].reverse()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    changed = m.analyse_folder(tmp_path, LIMITS)
    assert changed != original and semantics(changed) == semantics(original)
    estate(tmp_path, ending=b"\r\n")
    crlf = m.analyse_folder(tmp_path, LIMITS)
    assert crlf != original and semantics(crlf) == semantics(original)


@pytest.mark.parametrize("mode", ["missing", "error", "partial"])
def test_missing_failed_and_partial_capture_remain_unknown_with_original_denominators(tmp_path, mode):
    side = estate(tmp_path, trailer=b"% Invalid input\n" if mode == "error" else b"unrecognised trailer\n" if mode == "partial" else b"")
    if mode == "missing":
        side["captures"].clear()
        (tmp_path / "tree.txt").unlink()
        (tmp_path / "ec.txt").unlink()
        (tmp_path / "p4.json").write_bytes(canonical(side))
    head, rows = unpack(m.analyse_folder(tmp_path, LIMITS))
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4} and len(rows) == 7
    selected = rows if mode == "missing" else [r for r in rows if r["fact"] == m.stp.ROOT_GUARD]
    assert all(r["state"] == "unknown" and r["reason"] == {"missing": "not_collected", "error": "capture_error", "partial": "parse_partial"}[mode] for r in selected)
    need = next(r for r in selected if r["fact"] == m.stp.ROOT_GUARD)["next_evidence"][0]
    assert need["params"] == [["port", P]] and need["after_s"] is None and need["unprintable"] == []


@pytest.mark.parametrize("delay", [None, 0, 7])
def test_unknown_detail_candidates_and_all_need_fields_are_lossless(tmp_path, monkeypatch, delay):
    estate(tmp_path)
    factory, expected = m.stp.build_root_guard_global, {}
    def enriched(*args, **kwargs):
        out = factory(*args, **kwargs)
        row = out.result.rows[2]
        need = k.EvidenceNeed(node=row.target.node.key, operation=m.stp.stp.OP, params=(("hint", ""), ("port", P)),
            resolves=("l2.stp.root_guard", "l2.stp.scope"), reruns=("l2.stp/parse", "l2.stp/recheck"), after_s=delay, unprintable=("first", "second"))
        candidates = tuple(sorted(n.key for n in out.execution.envelope.base.nodes))
        value = replace(row.value, detail="explicit_uncertainty", candidates=candidates, next_evidence=(need,))
        expected.update(node=str(need.node), operation=need.operation, params=[list(p) for p in need.params], resolves=list(need.resolves), reruns=list(need.reruns), after_s=delay, unprintable=list(need.unprintable))
        out.result.store.values[k.FactRef(fact=m.stp.ROOT_GUARD, subject=row.subject)] = value
        return replace(out, result=replace(out.result, rows=out.result.rows[:2] + (replace(row, value=value),)))
    monkeypatch.setattr(m.stp, "build_root_guard_global", enriched)
    _, rows = unpack(m.analyse_folder(tmp_path, LIMITS))
    row = next(r for r in rows if r["fact"] == m.stp.ROOT_GUARD and r["vlan"] == 3)
    assert row["detail"] == "explicit_uncertainty" and row["candidates"] == ["node:demo:a", "node:demo:b"] and row["next_evidence"] == [expected]


@pytest.mark.parametrize("plant", ["declaration_type", "declaration_subject", "declaration_root", "budget", "late_finish", "ec_bool", "owner", "read", "positive", "mismatch", "missing", "duplicate", "extra", "scope", "swap", "int", "registry", "citation", "target", "capture", "span", "hash", "factref", "absent", "na"])
def test_forged_owner_state_inventory_or_proof_never_reaches_bundle(tmp_path, monkeypatch, plant):
    estate(tmp_path, guard=b"disabled" if plant == "positive" else b"enabled")
    factory, seen = m.stp.build_root_guard_global, []
    if plant == "budget":
        monkeypatch.setattr(m.stp.p4_pipeline, "execute_parsers", lambda *args: pytest.fail("parser before whole-folder budget"))
    if plant.startswith("declaration_"):
        declaration = m.stp.DECLARATION
        facts = tuple(replace(f, **({"value_type": "text"} if plant == "declaration_type" else {"subject": "etherchannel_group"})) if f.id == m.stp.ROOT_GUARD else f for f in declaration.facts) if plant != "declaration_root" else declaration.facts
        kinds = tuple(replace(kind, root=True) if kind.id == "stp_port_vlan" else kind for kind in declaration.entity_kinds) if plant == "declaration_root" else declaration.entity_kinds
        monkeypatch.setattr(m.stp, "DECLARATION", replace(declaration, facts=facts, entity_kinds=kinds))
    def corrupted(*args, **kwargs):
        out = factory(*args, **kwargs)
        if plant == "late_finish":
            seen.append(out)
            return out
        if plant == "ec_bool" or plant.startswith("declaration_"):
            return out
        built, row = out.result, out.result.rows[0]
        value, ref = row.value, k.FactRef(fact=m.stp.ROOT_GUARD, subject=row.subject)
        if plant == "read":
            monkeypatch.setattr(m, "PROJECT", replace(m.PROJECT, reads=()))
        elif plant == "owner":
            built.store.owners[m.stp.ROOT_GUARD] = m.ec.STEP.id
        elif plant == "missing":
            built.store.values.pop(ref)
            return replace(out, result=replace(built, rows=built.rows[1:]))
        elif plant == "duplicate":
            return replace(out, result=replace(built, rows=built.rows + (row,)))
        elif plant == "extra":
            extra = replace(row, subject=k.EntityKey("subject:extra"))
            built.store.values[k.FactRef(fact=m.stp.ROOT_GUARD, subject=extra.subject)] = extra.value
            return replace(out, result=replace(built, rows=built.rows + (extra,)))
        elif plant == "scope":
            other = next(n for n in out.execution.envelope.base.nodes if n.id == "b")
            return replace(out, result=replace(built, rows=(replace(row, target=replace(row.target, node=other)),) + built.rows[1:]))
        elif plant == "swap":
            second = built.rows[1]
            swapped = (replace(row, subject=second.subject), replace(second, subject=row.subject))
            for changed in swapped:
                built.store.values[k.FactRef(fact=m.stp.ROOT_GUARD, subject=changed.subject)] = changed.value
            return replace(out, result=replace(built, rows=swapped + built.rows[2:]))
        elif plant == "positive":
            value = replace(value, evidence=value.evidence[:3])
        elif plant == "mismatch":
            return replace(out, result=replace(built, rows=(replace(row, value=replace(value)),) + built.rows[1:]))
        elif plant in ("int", "factref", "absent", "na"):
            witness = next(e for e in value.evidence if type(e) is k.EvidenceRef)
            value = (replace(value, value=1) if plant == "int" else replace(value, evidence=value.evidence + (ref,)) if plant == "factref" else
                k.Absent(kind="configured_line", basis=k.Basis.CONFIGURED, evidence=(replace(witness, role=k.EvidenceRole.ABSENCE_WITNESS),)) if plant == "absent" else k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=value.evidence))
        else:
            index = next(i for i, e in enumerate(value.evidence) if type(e) is k.RegistryRef and e.table == "synthetic_p4.targets") if plant == "target" else next(i for i, e in enumerate(value.evidence) if type(e) is (k.RegistryRef if plant in ("registry", "citation") else k.EvidenceRef))
            leaf = value.evidence[index]
            if plant in ("registry", "citation"):
                leaf = replace(leaf, **({"table_digest": "0" * 64} if plant == "registry" else {"citation": "/nodes/999"}))
            elif plant == "target":
                leaf = next(t for t in out.execution.envelope.targets if t.id == "cold").declaration.evidence[0]
            elif plant == "capture":
                other = next(c for c in out.execution.envelope.captures if c.target.id == "ec")
                leaf = replace(leaf, capture=other.id, excerpt_sha256=sha256(other.raw[leaf.locator.start:leaf.locator.end]).hexdigest())
            else:
                leaf = replace(leaf, **({"locator": k.ByteSpan(start=0, end=0), "excerpt_sha256": sha256(b"").hexdigest()} if plant == "span" else {"excerpt_sha256": "0" * 64}))
            value = replace(value, evidence=tuple(leaf if i == index else e for i, e in enumerate(value.evidence)))
        built.store.values[ref] = value
        return replace(out, result=replace(built, rows=(replace(row, value=value),) + built.rows[1:]))
    if plant == "ec_bool":
        finish = m.SummaryPack.finish
        def corrupted_ec(self, execution):
            out = finish(self, execution)
            row = next(r for r in out.rows if type(r.value) is k.Known)
            value = replace(row.value, value=False)
            out.store.values[k.FactRef(fact=m.ec.REPORTED_PROTOCOL, subject=row.subject)] = value
            return replace(out, rows=tuple(replace(r, value=value) if r is row else r for r in out.rows))
        monkeypatch.setattr(m.SummaryPack, "finish", corrupted_ec)
    elif plant == "late_finish":
        def failed(*args):
            assert len(seen) == 1 and seen[0].result.store.values
            raise RuntimeError("EC finish failed")
        monkeypatch.setattr(m.SummaryPack, "finish", failed)
        monkeypatch.setattr(FactReader, "read", lambda *args, **kwargs: pytest.fail("reader before both finishes"))
    monkeypatch.setattr(m.stp, "build_root_guard_global", corrupted)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before ownership/custody closure"))
    pattern = "^p4_observations_spec$" if plant.startswith("declaration_") else "^budget_exceeded$" if plant == "budget" else "^EC finish failed$" if plant == "late_finish" else "^p4_observations_value$" if plant == "ec_bool" else "^(p4_(observations|projection)_|undeclared_read:)"
    with pytest.raises(RuntimeError if plant == "late_finish" else ValueError, match=pattern):
        m.analyse_folder(tmp_path, replace(LIMITS, artifact_bytes=1) if plant == "budget" else LIMITS)


@pytest.mark.parametrize("plant", ["registry", "foreign", "known"])
def test_original_capture_time_cannot_borrow_registry_other_capture_or_become_known(tmp_path, monkeypatch, plant):
    estate(tmp_path)
    factory = m.stp.build_root_guard_global
    def corrupted(*args, **kwargs):
        out = factory(*args, **kwargs)
        item = next(e for e in out.execution.executed if e.receipt.capture.operation == m.stp.stp.OP)
        metadata = item.receipt.capture.resolved_metadata
        if plant == "known":
            time = TimeInterval(earliest=0, latest=1, clock="collector:fixture", bound=BoundSource.COLLECTOR_RECORDED)
        else:
            evidence = out.execution.envelope.declaration.evidence if plant == "registry" else next(e.receipt.capture.collected_utc.evidence for e in out.execution.executed if e is not item)
            time = replace(metadata.collected_utc, evidence=evidence)
        capture = replace(item.receipt.capture, metadata=replace(metadata, collected_utc=time))
        changed = replace(item, receipt=replace(item.receipt, capture=capture))
        return replace(out, execution=replace(out.execution, executed=tuple(changed if e is item else e for e in out.execution.executed)))
    monkeypatch.setattr(m.stp, "build_root_guard_global", corrupted)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before time custody"))
    with pytest.raises(m.RunnerRefused, match="^p4_(observations_time|projection_)"):
        m.analyse_folder(tmp_path, LIMITS)
