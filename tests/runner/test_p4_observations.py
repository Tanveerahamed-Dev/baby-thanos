import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256

import pytest
from test_p4_hsrp_proofs import ACTIVE, BODY, INIT, estate3
from test_p4_leaf_refs import assert_leaf
from test_p4_proof_index import LIMITS, P, estate, expected_references

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.store import FactReader
from atlas_brain.runner import p4 as m

FACTS = ("facts/stp_port_vlan.jsonl", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl")


def snapshot(root):
    return {p.name: p.read_bytes() for p in root.iterdir()}


def unpack(files):
    assert set(files) == {"result.json", "MANIFEST.sha256", *FACTS}
    entries = [line.split("  ") for line in files["MANIFEST.sha256"].decode().splitlines()]
    assert [name for _, name in entries] == sorted(set(files) - {"MANIFEST.sha256"})
    assert all(sha256(files[name]).hexdigest() == digest for digest, name in entries)
    head = json.loads(files["result.json"])
    assert canonical(head) == files["result.json"]
    for path, declaration in zip(FACTS, (m.stp.DECLARATION, m.ec.DECLARATION, m.fhrp.DECLARATION), strict=True):
        facts = {spec.id for spec in declaration.facts}
        assert all(row["fact"] in facts and row["pack"] == declaration.pack for row in map(json.loads, files[path].splitlines()))
    rows = [json.loads(line) for path in FACTS for line in files[path].splitlines()]
    assert all(b"".join(canonical(json.loads(line)) + b"\n" for line in files[path].splitlines()) == files[path] for path in FACTS)
    return head, rows


def semantics(files):
    head, rows = unpack(files)
    return head["denominator"], [(r["subject"], r["fact"], r["state"], r.get("value"), r.get("reason"), r.get("basis"), r.get("raw")) for r in rows]


def expected_observations(side, envelope):
    peers = dict(side, targets=[target for target in side["targets"] if target["operation"] != m.fhrp.hsrp.OP])
    refs = expected_references(peers, envelope)
    nodes = {node.id: node for node in envelope.base.nodes}
    for item in side["targets"]:
        if item["operation"] == m.fhrp.hsrp.OP:
            target = m.fhrp.Target(context=side["context"], node=nodes[item["node"]], groups=tuple(tuple(pair) for pair in item["params"]["groups"]))
            refs.update(k.FactRef(fact=m.fhrp.REPORTED_STATE, subject=m.fhrp.subject(target, interface, group)) for interface, group in target.groups)
    return refs


@pytest.mark.parametrize("guard,protocol,expected,with_hsrp", [(b"enabled", b"LACP", "lacp", False), (b"disabled", b"-", "none_reported", False),
    (None, b"PAgP", "pagp", False), (b"disabled", b"-", "none_reported", True)])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_real_folder_returns_canonical_partial_bundle_only_after_all_finishes_and_reader(tmp_path, monkeypatch, guard, protocol, expected, ending, with_hsrp):
    side = estate3(tmp_path, ending=ending) if with_hsrp else estate(tmp_path, guard, protocol, ending)
    before, runs, finishes, reads = snapshot(tmp_path), [], [], []
    factory, finish, hfinish = m.stp.build_root_guard_global, m.SummaryPack.finish, m.StandbyBriefPack.finish
    read, bind, bundle = FactReader.read, m.bind_reader, m.result_bundle
    def built(*args, **kwargs):
        out = factory(*args, **kwargs)
        runs.append(out)
        return out
    def finished(self, execution):
        assert len(runs) == 1 and execution is runs[0].execution
        out = (finish if isinstance(self, m.SummaryPack) else hfinish)(self, execution)
        finishes.append(out)
        return out
    def consumed(self, **kwargs):
        assert len(finishes) == 2
        reads.append((self.step.reads, kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    def bound(*args, **kwargs):
        assert len(finishes) == 2
        return bind(*args, **kwargs)
    def bundled(*args, **kwargs):
        assert len(runs) == 1 and len(finishes) == 2 and reads
        return bundle(*args, **kwargs)
    monkeypatch.setattr(m.stp, "build_root_guard_global", built)
    monkeypatch.setattr(m.SummaryPack, "finish", finished)
    monkeypatch.setattr(m.StandbyBriefPack, "finish", finished)
    monkeypatch.setattr(m, "bind_reader", bound)
    monkeypatch.setattr(FactReader, "read", consumed)
    monkeypatch.setattr(m, "result_bundle", bundled)
    files = m.analyse_folder(tmp_path, LIMITS)
    head, rows = unpack(files)
    assert snapshot(tmp_path) == before
    assert (head["schema"], head["scope"], head["checks"], head["variant_support"]) == ("atlas-brain.p4-observations/1", "observations_only", "not_implemented", "allowlisted")
    assert head["semantic_group"] == "declared_synthetic" and head["context"] == "round"
    assert head["registration_sha256"] == runs[0].execution.envelope.registration_sha256
    assert head["registry_sha256"] == sha256(before["p4.json"]).hexdigest() and head["base_registry_sha256"] == sha256(before["p2.json"]).hexdigest()
    expected_refs = expected_observations(side, runs[0].execution.envelope)
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5 if with_hsrp else 0}
    assert len(rows) == len(reads) == 6 + 4 * len(m.ec.STEP.produces) + (5 if with_hsrp else 0)
    assert {k.FactRef(fact=k.FactId(row["fact"]), subject=k.EntityKey(row["subject"])) for row in rows} == expected_refs
    assert {(f, s) for _, f, s in reads} == {(r["fact"], r["subject"]) for r in rows} and all(set(declared) == {m.stp.ROOT_GUARD, m.stp.REPORTED_ROLE, *m.ec.STEP.produces, *m.fhrp.STEP.produces} and fact in declared for declared, fact, _ in reads)
    role_rows = {row["vlan"]: row for row in rows if row["fact"] == m.stp.REPORTED_ROLE}
    assert set(role_rows) == {1, 2, 3} and role_rows[3]["reason"] == "subject_absent_from_capture"
    assert all((role_rows[vlan]["state"], role_rows[vlan]["value"], role_rows[vlan]["raw"], role_rows[vlan]["basis"])
               == ("known", "designated", "designated", "observed") for vlan in (1, 2))
    root = next(r for r in rows if r["fact"] == m.stp.ROOT_GUARD and r["vlan"] == 1)
    assert (root["state"], root.get("value", root.get("reason"))) == (("unknown", "field_not_printed") if guard is None else ("known", guard == b"enabled"))
    channel = next(r for r in rows if r["fact"] == m.ec.REPORTED_PROTOCOL and r["group"] == "2")
    assert (channel["value"], channel["raw"]) == (expected, protocol.decode())
    original = {o.receipt.capture.id: o for o in runs[0].execution.executed}
    assert len(head["captures"]) == len(original) == (3 if with_hsrp else 2) and {c["id"] for c in head["captures"]} == set(original)
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
    channel, standby = next(out for out in finishes if type(out) is m.ec.Result), next(out for out in finishes if type(out) is m.fhrp.Result)
    original_rows = [(fact, row, state) for row in runs[0].result.rows
                     for fact, state in ((m.stp.ROOT_GUARD, row.value), (m.stp.REPORTED_ROLE, row.role))]
    original_rows += list(m.ec.fact_rows(channel)) + list(m.fhrp.fact_rows(standby))
    expected = {(fact, row.subject): value.evidence for fact, row, value in original_rows}
    if with_hsrp:
        local = {(row["interface"], row["group"]): row for row in rows if row["fact"] == m.fhrp.REPORTED_STATE}
        assert set(local) == {("Vl20", "0"), ("Vl10", "1"), ("BD3329", "129"), ("Vl99", "2"), ("Vl30", "2")}
        for key, value, raw in ((("Vl20", "0"), "init", "Init"), (("Vl10", "1"), "active", "Active"), (("BD3329", "129"), "standby", "Standby")):
            assert (local[key]["state"], local[key]["value"], local[key]["raw"], local[key]["basis"]) == ("known", value, raw, "observed")
            assert local[key]["address_family"] == "ipv4" and local[key]["protocol"] == "hsrp"
        assert local[("Vl99", "2")]["reason"] == "subject_absent_from_capture" and local[("Vl30", "2")]["reason"] == "not_collected"
        assert local[("Vl99", "2")]["next_evidence"][0]["params"] == [["group", "2"], ["interface", "Vl99"]]
    for row in rows:
        for original, projected in zip(expected[(row["fact"], row["subject"])], row["evidence"], strict=True):
            assert_leaf(original, projected, runs[0].execution)


@pytest.mark.parametrize("with_hsrp", [False, True])
@pytest.mark.parametrize("seed", ["1", "83"])
def test_same_raw_bytes_are_identical_across_directory_and_hash_seed(tmp_path, seed, with_hsrp):
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    if with_hsrp:
        estate3(left)
    else:
        estate(left)
    raw = snapshot(left)
    for name in reversed(tuple(raw)):
        (right / name).write_bytes(raw[name])
    expected = m.analyse_folder(left, LIMITS)
    assert m.analyse_folder(right, LIMITS) == expected and snapshot(left) == snapshot(right) == raw
    code = "from pathlib import Path\nimport sys\nfrom atlas_brain.evidence.admission import Budgets\nfrom atlas_brain.runner.p4 import analyse_folder\nprint(analyse_folder(Path(sys.argv[1]), Budgets(1000000,1000000,1000))['MANIFEST.sha256'].hex())"
    child = subprocess.run([sys.executable, "-c", code, str(right)], env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, text=True, check=True, timeout=60)
    assert child.stdout.strip() == expected["MANIFEST.sha256"].hex()


@pytest.mark.parametrize("with_hsrp", [False, True])
def test_iteration_does_not_change_bytes_but_raw_registry_or_line_endings_change_provenance(tmp_path, monkeypatch, with_hsrp):
    side = estate3(tmp_path) if with_hsrp else estate(tmp_path)
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
    if with_hsrp:
        estate3(tmp_path, ending=b"\r\n")
    else:
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
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 0} and len(rows) == 6 + 4 * len(m.ec.STEP.produces)
    selected = rows if mode == "missing" else [r for r in rows if r["pack"] == "l2.stp"]
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


@pytest.mark.parametrize("plant", ["declaration_type", "declaration_subject", "declaration_root", "budget", "late_finish", "ec_bool", "member_store", "member_type", "member_spec", "owner", "read", "positive", "mismatch", "missing", "duplicate", "extra", "scope", "swap", "int", "registry", "citation", "target", "capture", "span", "hash", "factref", "absent", "na"])
def test_forged_owner_state_inventory_or_proof_never_reaches_bundle(tmp_path, monkeypatch, plant):
    estate(tmp_path, guard=b"disabled" if plant == "positive" else b"enabled")
    factory, seen = m.stp.build_root_guard_global, []
    if plant == "budget":
        monkeypatch.setattr(m.stp.p4_pipeline, "execute_parsers", lambda *args: pytest.fail("parser before whole-folder budget"))
    if plant == "member_spec":
        declaration = replace(m.ec.DECLARATION, facts=tuple(replace(fact, value_type="boolean") if fact.id == m.ec.REPORTED_MEMBER_TOKENS else fact for fact in m.ec.DECLARATION.facts))
        monkeypatch.setattr(m.ec, "DECLARATION", declaration)
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
        if plant == "ec_bool" or plant.startswith(("declaration_", "member_")):
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
    if plant in ("ec_bool", "member_store", "member_type"):
        finish = m.SummaryPack.finish
        def corrupted_ec(self, execution):
            out = finish(self, execution)
            field = "value" if plant == "ec_bool" else "member_tokens"
            fact = m.ec.REPORTED_PROTOCOL if plant == "ec_bool" else m.ec.REPORTED_MEMBER_TOKENS
            row = next(row for row in out.rows if type(getattr(row, field)) is k.Known)
            reference = k.FactRef(fact=fact, subject=row.subject)
            if plant == "member_store":
                out.store.values.pop(reference)
                return out
            value = replace(getattr(row, field), value=False)
            out.store.values[reference] = value
            return replace(out, rows=tuple(replace(original, **{field: value}) if original is row else original for original in out.rows))
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
    if plant.startswith("member_"):
        pattern = "^p4_observations_" + {"member_store": "store", "member_type": "value", "member_spec": "spec"}[plant] + "$"
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


@pytest.mark.parametrize("plant", [
    "adapter_empty", "adapter_missing", "adapter_duplicate", "adapter_foreign_fact", "adapter_row_clone",
    "adapter_state_clone", "adapter_foreign_row", "adapter_list", "adapter_item_list",
    "scope_missing", "scope_extra", "scope_substitute", "scope_unknown_operation", "store_missing", "store_extra", "store_substitute", "store_owner", "store_state_clone",
    "reader_clone", "step_produces", "coupled_census_drop", "adapter_store_extra", "adapter_owner_change",
])
def test_ec_adapter_cannot_define_its_own_census_or_bypass_original_rows_and_store(tmp_path, monkeypatch, plant):
    estate(tmp_path)
    adapter, finish, indexer, read = m.ec.fact_rows, m.SummaryPack.finish, m.ProofIndex, FactReader.read
    def mapped(owner):
        if plant == "step_produces":
            return tuple((m.ec.REPORTED_PROTOCOL, row, row.value) for row in owner.rows)
        values = adapter(owner)
        fact, row, value = values[0]
        if plant == "adapter_store_extra":
            owner.store.values[k.FactRef(fact=m.stp.ROOT_GUARD, subject=row.subject)] = value
        elif plant == "adapter_owner_change":
            owner.store.owners[fact] = m.stp.STEP.id
        if plant == "adapter_empty":
            return ()
        if plant == "adapter_missing":
            return values[1:]
        if plant == "adapter_duplicate":
            return values[:-1] + (values[0],)
        if plant == "adapter_foreign_fact":
            return ((m.stp.ROOT_GUARD, row, value),) + values[1:]
        if plant == "adapter_row_clone":
            return ((fact, replace(row), value),) + values[1:]
        if plant == "adapter_state_clone":
            return ((fact, row, replace(value)),) + values[1:]
        if plant == "adapter_foreign_row":
            return ((fact, replace(row, subject=k.EntityKey("subject:foreign")), value),) + values[1:]
        if plant == "adapter_list":
            return list(values)
        if plant == "adapter_item_list":
            return (list(values[0]),) + values[1:]
        return values
    def finished(self, execution):
        out = finish(self, execution)
        row = next(row for row in out.rows if row.group == "4") if plant == "coupled_census_drop" else out.rows[0]
        reference = k.FactRef(fact=m.ec.REPORTED_PROTOCOL, subject=row.subject)
        if plant == "coupled_census_drop":
            for fact in m.ec.STEP.produces:
                out.store.values.pop(k.FactRef(fact=fact, subject=row.subject))
            return replace(out, rows=tuple(original for original in out.rows if original is not row))
        if plant == "store_missing":
            out.store.values.pop(reference)
        elif plant in ("store_extra", "store_substitute"):
            if plant == "store_substitute":
                out.store.values.pop(reference)
            out.store.values[k.FactRef(fact=m.stp.ROOT_GUARD, subject=row.subject)] = row.value
        elif plant == "store_owner":
            out.store.owners[m.ec.REPORTED_PROTOCOL] = m.stp.STEP.id
        elif plant == "store_state_clone":
            out.store.values[reference] = replace(row.value)
        elif plant == "step_produces":
            monkeypatch.setattr(m.ec, "STEP", replace(m.ec.STEP, produces=()))
        return out
    def indexed(*args):
        index = indexer(*args)
        scopes = index.scopes
        selected = next(scope for scope in scopes if scope.reference.fact == m.ec.REPORTED_PROTOCOL)
        if plant == "coupled_census_drop":
            cold = next(target for target in index.execution.envelope.targets if target.id == "cold")
            envelope = replace(index.execution.envelope, targets=tuple(target for target in index.execution.envelope.targets if target is not cold))
            index.execution = replace(index.execution, envelope=envelope)
            index.ordered = tuple(scope for scope in scopes if scope.target is not cold)
            assert any(target.id == "cold" for target in args[0].envelope.targets) and any(target["id"] == "cold" for target in json.loads(envelope.raw)["targets"])
        elif plant == "scope_missing":
            index.ordered = tuple(scope for scope in scopes if scope is not selected)
        elif plant in ("scope_extra", "scope_substitute", "scope_unknown_operation"):
            extra = (replace(selected, target=replace(selected.target, operation="synthetic.extra")) if plant == "scope_unknown_operation" else
                replace(selected, reference=k.FactRef(fact=m.ec.REPORTED_PROTOCOL, subject=k.EntityKey("subject:extra"))))
            index.ordered = tuple(scope for scope in scopes if plant != "scope_substitute" or scope is not selected) + (extra,)
        return index
    def consumed(self, **kwargs):
        state = read(self, **kwargs)
        return replace(state) if plant == "reader_clone" and kwargs["fact"] == m.ec.REPORTED_PROTOCOL else state
    monkeypatch.setattr(m.ec, "fact_rows", mapped)
    monkeypatch.setattr(m.SummaryPack, "finish", finished)
    monkeypatch.setattr(m, "ProofIndex", indexed)
    monkeypatch.setattr(FactReader, "read", consumed)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before independent EC closure"))
    pattern = ("^p4_observations_profile$" if plant == "coupled_census_drop" else "^p4_observations_store$" if plant in ("adapter_store_extra", "adapter_owner_change")
               else "^p4_(observations_population|projection_scope)$" if plant.startswith("scope_") else "^p4_observations_")
    with pytest.raises(m.RunnerRefused, match=pattern):
        m.analyse_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("family", ["etherchannel", "hsrp"])
@pytest.mark.parametrize("canonical_clone", [False, True])
def test_owner_adapter_returns_original_rows_and_states_and_order_does_not_change_bytes(tmp_path, monkeypatch, canonical_clone, family):
    if family == "hsrp":
        estate3(tmp_path)
    else:
        estate(tmp_path)
    original = m.analyse_folder(tmp_path, LIMITS)
    module, pack = (m.fhrp, m.StandbyBriefPack) if family == "hsrp" else (m.ec, m.SummaryPack)
    adapter, finish = module.fact_rows, pack.finish
    def finished(self, execution):
        owner = finish(self, execution)
        values = adapter(owner)
        assert type(values) is tuple and {fact for fact, _, _ in values} == set(module.STEP.produces)
        assert len(values) == len(owner.rows) * len(module.STEP.produces)
        assert all(any(row is original for original in owner.rows) for _, row, _ in values)
        assert all(owner.store.values[k.FactRef(fact=fact, subject=row.subject)] is state for fact, row, state in values)
        assert all(state is row.value for fact, row, state in values if fact in (m.ec.REPORTED_PROTOCOL, m.fhrp.REPORTED_STATE))
        if canonical_clone:
            fact, row, state = next(item for item in values if type(item[2]) is k.Known)
            canonical = replace(state)
            owner.store.values[k.FactRef(fact=fact, subject=row.subject)] = canonical
            assert canonical == row.value and canonical is not row.value
        return owner
    def mapped(owner):
        return tuple((fact, row, owner.store.values[k.FactRef(fact=fact, subject=row.subject)]) for fact, row, _ in reversed(adapter(owner)))
    monkeypatch.setattr(pack, "finish", finished)
    monkeypatch.setattr(module, "fact_rows", mapped)
    assert m.analyse_folder(tmp_path, LIMITS) == original


@pytest.mark.parametrize("removed", ["tree", "ec"])
def test_empty_owner_population_keeps_registered_fact_profile_and_five_files(tmp_path, removed):
    side = estate(tmp_path)
    operation = m.stp.stp.OP if removed == "tree" else m.ec.parse_summary.OP
    side["targets"] = [target for target in side["targets"] if target["operation"] != operation]
    side["captures"] = [capture for capture in side["captures"] if capture["target"] != removed]
    (tmp_path / (removed + ".txt")).unlink()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    before = snapshot(tmp_path)
    head, rows = unpack(m.analyse_folder(tmp_path, LIMITS))
    assert head["denominator"] == {"l2.stp": 0 if removed == "tree" else 3, "l2.etherchannel": 0 if removed == "ec" else 4, "l3.fhrp": 0}
    assert len(rows) == (4 * len(m.ec.STEP.produces) if removed == "tree" else 6)
    assert all(row["pack"] != ("l2.stp" if removed == "tree" else "l2.etherchannel") for row in rows)
    assert snapshot(tmp_path) == before


# Native 2442488 four-file receipts remain reference; the three-owner profile changes P4 bytes, never input pins.
@pytest.mark.parametrize("guard,protocol,ending,inputs,pure,cli", [
    (b"disabled", b"-", b"\n",
        {
            "discovery.txt": "c7ebce2d080affaba5445d91c7e0cc9eec38e794c4bbb8a29eb4bdd72464aa45",
            "ec.txt": "9fd83a208713d3e8dafe9810e57204b37a3d26b77a95299d0d74f99dc74f171e",
            "p2.json": "3ea15bada1de6bd4c36fca9c51818686a3dfba532c52fe05b92553c2e3066889",
            "p4.json": "c8d1dabd5616ba0c632d0fdde98221201ec907ed4f8887c7f7c6a01eb8951b68",
            "tree.txt": "5a8db7f352b71286e26b90b23249fa1da773cc81bee943bb9ec9a2f6e00e0f27",
        },
        {
            "MANIFEST.sha256": "8c6f8cf852d00fcd75e6f9401226b5f2aa9f5e1c0b1176292331e92ccfdd656c",
            "facts/etherchannel_group.jsonl": "79a75c751a5a1f814e7e89ec9eacf15b1dca8a7757297edba8622311d426796e",
            "facts/stp_port_vlan.jsonl": "3388e36bb8716d6d7be2aac36342e387acdd33c91529880acbb53f891120e2dd",
            "result.json": "36b1b440d3322772ed82df22af03ae1b4a3a66d88b2be24537ed6a57f87af802",
        },
        {
            "result.json": "164fa647de5d1462b8c90bf37959af88d12e2011704b739178b18cfebd33149f",
            "MANIFEST.sha256": "b07bb92f188472d8ce8dab7c83465b3b487a2bfbd29d903d216b425f970f809c",
        }),
    (None, b"PAgP", b"\r\n",
        {
            "discovery.txt": "c7ebce2d080affaba5445d91c7e0cc9eec38e794c4bbb8a29eb4bdd72464aa45",
            "ec.txt": "be2cf7643fa0794765bb46fc26a26a5d709cc90f30206c394d0795d67053355d",
            "p2.json": "3ea15bada1de6bd4c36fca9c51818686a3dfba532c52fe05b92553c2e3066889",
            "p4.json": "e7f7dce8611fa547d021e565e51e0bf021bf1223d306bf92812d319633291981",
            "tree.txt": "275ef71fbefcaa6ee638678f8c7847d2f5d3a012e3e04905a8a64eecd621909c",
        },
        {
            "MANIFEST.sha256": "fd378fb5d249a40740b3b529cd38d0cd4eee2657fbf0afd9b0b4e6b660985ade",
            "facts/etherchannel_group.jsonl": "59ad9326097532fef5c5754bae893d6a87e286088a982f8323728c3e6f787fbf",
            "facts/stp_port_vlan.jsonl": "1afacb516bc78405e5c4c8541109efb499e0cbe8760a5183eac693ac403e777e",
            "result.json": "fd4c3a087a03427e17ad2d3807808427467ef2b9f89828d90f6ba2bf4269afbf",
        },
        {
            "result.json": "01fa83552e9e3431e798499584981d82785cd44cc1d03f17227cbce0d2bd7f1e",
            "MANIFEST.sha256": "67b8729099cd102cee2e272642c30da74235e0c3661003d8b8c396e033084781",
        }),
])
def test_three_owner_profile_changes_previous_p4_bytes_with_independent_content_and_cli_checks(tmp_path, guard, protocol, ending, inputs, pure, cli):
    estate(tmp_path, guard, protocol, ending)
    before = snapshot(tmp_path)
    assert {name: sha256(raw).hexdigest() for name, raw in before.items()} == inputs
    files = m.analyse_folder(tmp_path, LIMITS)
    current = {name: sha256(raw).hexdigest() for name, raw in files.items()}
    assert set(current) == set(pure) | {"facts/fhrp_local.jsonl"} and not files["facts/fhrp_local.jsonl"] and all(current[name] != pure[name] for name in pure)
    head, rows = unpack(files)
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 0} and len(rows) == 14
    assert head["registration_sha256"] == compile_packs((m.stp.DECLARATION, m.ec.DECLARATION, m.fhrp.DECLARATION)).registration_sha256
    assert {row["fact"] for row in rows} == {m.stp.ROOT_GUARD, m.stp.REPORTED_ROLE, m.ec.REPORTED_PROTOCOL, m.ec.REPORTED_MEMBER_TOKENS}
    members = {row["group"]: row for row in rows if row["fact"] == m.ec.REPORTED_MEMBER_TOKENS}
    assert set(members) == {"1", "2", "3", "4"}
    for group, token in (("1", "Gi1/0/1(P)"), ("2", "Gi1/0/2(D)")):
        assert (members[group]["state"], members[group]["value"], members[group]["raw"], members[group]["basis"]) == ("known", token, None, "derived")
    assert members["3"]["reason"] == "subject_absent_from_capture" and members["4"]["reason"] == "not_collected"
    previous = None
    for workers, seed in ((1, "1"), (4, "83")):
        out = tmp_path.with_name(tmp_path.name + "-cli-" + str(workers))
        command = [sys.executable, "-m", "atlas_brain.runner", "--format", "p4-observations",
                   "--evidence", str(tmp_path), "--out", str(out), "--workers", str(workers)]
        child = subprocess.run(command, env=dict(os.environ, PYTHONHASHSEED=seed), capture_output=True, text=True, check=True, timeout=60)
        published = {path.relative_to(out).as_posix(): path.read_bytes() for path in out.rglob("*") if path.is_file()}
        assert child.stdout.strip() == "runner: ok egress_denied=40"
        old_cli = pure | cli
        assert set(published) == set(old_cli) | {"facts/fhrp_local.jsonl"} and not published["facts/fhrp_local.jsonl"] and all(sha256(published[name]).hexdigest() != old_cli[name] for name in old_cli)
        published_head, published_rows = unpack(published)
        execution = published_head.pop("execution")
        assert published_head == head and published_rows == rows
        assert execution == {"schema": "atlas-brain.runner-witness/1", "plan": {"steps": 8, "witness_attempts": 4},
            "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
            "steps": [{"denied": 4, "id": f"witness/{i:02d}"} for i in range(8)]}
        assert previous is None or previous == published
        previous = published
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("raw,mode,reason", [
    (BODY, "no_captures", "not_collected"), (BODY + ACTIVE, "normal", "conflicting_evidence"),
    (BODY + INIT.replace(b"203.0.113.1", b"unknown"), "normal", "identity_unresolved"),
    (BODY + b"unrecognized trailer\n", "normal", "parse_partial"),
    (BODY.replace(ACTIVE, ACTIVE.replace(b"Active", b"Listen")), "normal", "parse_partial"),
    (BODY + b"% Invalid input\n", "normal", "capture_error"), (BODY + b"--More--\n", "normal", "capture_truncated"),
])
def test_hsrp_unknown_population_candidate_records_and_local_needs_survive_output(tmp_path, raw, mode, reason):
    estate3(tmp_path, raw, mode)
    head, rows = unpack(m.analyse_folder(tmp_path, LIMITS))
    local = [row for row in rows if row["fact"] == m.fhrp.REPORTED_STATE]
    assert head["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5} and len(local) == 5
    assert all(row["state"] == "unknown" and row["reason"] == reason for row in local if row["node"] == "a")
    assert next(row for row in local if row["node"] == "b")["reason"] == "not_collected"
    row = next(row for row in local if row["interface"] == "Vl10")
    assert row["next_evidence"] == [{"node": "node:demo:a", "operation": "iosxe.show_standby_brief",
        "params": [["group", "1"], ["interface", "Vl10"]], "resolves": ["l3.fhrp.reported_state"],
        "reruns": ["l3.fhrp/parse_hsrp_brief"], "after_s": None, "unprintable": []}]
    captures = [ref for ref in row["evidence"] if ref["kind"] == "capture"]
    assert all(ref["role"] == "witness" for ref in captures)
    if mode == "no_captures":
        assert not captures
    else:
        assert captures[0]["locator"] == "whole_capture"
        assert len([ref for ref in captures if ref["locator"] == "bytes"]) == (2 if reason == "conflicting_evidence" else 1)


@pytest.mark.parametrize("plant,code", [
    ("finish", "late_hsrp"), ("owner", "store"), ("store_extra", "store"), ("missing", "population"), ("duplicate", "population"),
    ("row", "row"), ("state", "store"), ("foreign_fact", "row"), ("reader", "store"), ("scope", "scope"), ("value", "value"),
    ("positive", "positive"), ("coupled_drop", "population"), ("spec_type", "spec"), ("spec_subject", "spec"), ("spec_root", "spec"),
])
def test_hsrp_owner_adapter_and_projection_fail_before_any_bundle(tmp_path, monkeypatch, plant, code):
    estate3(tmp_path)
    finish, adapter, read = m.StandbyBriefPack.finish, m.fhrp.fact_rows, FactReader.read
    if plant.startswith("spec_"):
        declaration = m.fhrp.DECLARATION
        facts = declaration.facts if plant == "spec_root" else tuple(replace(fact, **({"value_type": "boolean"} if plant == "spec_type" else {"subject": "etherchannel_group"})) for fact in declaration.facts)
        kinds = tuple(replace(kind, root=True) for kind in declaration.entity_kinds) if plant == "spec_root" else declaration.entity_kinds
        monkeypatch.setattr(m.fhrp, "DECLARATION", replace(declaration, facts=facts, entity_kinds=kinds))
    def finished(self, execution):
        if plant == "finish":
            raise RuntimeError("late_hsrp")
        owner = finish(self, execution)
        row = owner.rows[0]
        if plant == "owner":
            owner.store.owners[m.fhrp.REPORTED_STATE] = m.ec.STEP.id
        elif plant == "store_extra":
            owner.store.values[k.FactRef(fact=m.fhrp.REPORTED_STATE, subject=k.EntityKey("subject:extra"))] = row.value
        elif plant in ("missing", "duplicate"):
            return replace(owner, rows=owner.rows[:-1] if plant == "missing" else (row,) + owner.rows[:-1])
        elif plant == "coupled_drop":
            cold = next(item for item in owner.rows if item.target.node.id == "b")
            owner.store.values.pop(k.FactRef(fact=m.fhrp.REPORTED_STATE, subject=cold.subject))
            return replace(owner, rows=tuple(item for item in owner.rows if item is not cold))
        elif plant in ("scope", "value", "positive"):
            changed = replace(row, target=replace(row.target, context="foreign")) if plant == "scope" else replace(row, value=replace(row.value, value=False))
            if plant == "positive":
                raw = next(rich for rich in owner.executed[0].value.rows if (rich.interface.raw, rich.group.raw) == (row.interface, row.group))
                value = replace(row.value, evidence=tuple(ref for ref in row.value.evidence if not (type(ref) is k.EvidenceRef and ref.locator == raw.af_spans[-1])))
                changed = replace(row, value=value)
            owner.store.values[k.FactRef(fact=m.fhrp.REPORTED_STATE, subject=row.subject)] = changed.value
            return replace(owner, rows=(changed,) + owner.rows[1:])
        return owner
    def mapped(owner):
        items = adapter(owner)
        if plant in ("row", "state", "foreign_fact"):
            fact, row, value = items[0]
            changed = (fact, replace(row), value) if plant == "row" else (fact, row, replace(value)) if plant == "state" else (m.ec.REPORTED_PROTOCOL, row, value)
            return (changed,) + items[1:]
        return items
    def consumed(self, **kwargs):
        value = read(self, **kwargs)
        return replace(value) if plant == "reader" and kwargs["fact"] == m.fhrp.REPORTED_STATE else value
    if plant == "coupled_drop":
        constructor = m.ProofIndex.__init__
        def indexed(self, *args, **kwargs):
            constructor(self, *args, **kwargs)
            self.ordered = tuple(scope for scope in self.scopes if scope.target.id != "hsrp-cold")
        monkeypatch.setattr(m.ProofIndex, "__init__", indexed)
    monkeypatch.setattr(m.StandbyBriefPack, "finish", finished)
    monkeypatch.setattr(m.fhrp, "fact_rows", mapped)
    monkeypatch.setattr(FactReader, "read", consumed)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before HSRP closure"))
    if plant == "finish":
        monkeypatch.setattr(m, "bind_reader", lambda *args, **kwargs: pytest.fail("reader before final owner finish"))
    with pytest.raises(RuntimeError if plant == "finish" else ValueError, match="^" + ("late_hsrp" if plant == "finish" else "p4_projection_positive" if plant == "positive" else "p4_observations_" + code) + "$"):
        m.analyse_folder(tmp_path, LIMITS)
