"""Genuine fresh Root9 report integration; no origin, publication, heap or acceptance claim."""
import json
from dataclasses import asdict, replace
from hashlib import sha256

import pytest
from test_mixed_proofs import custody
from test_root_mixed_component import MAC, ROOT_FACTS, folder, frozen
from test_root_mixed_proofs import references, saved
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.runner import p4_mixed_refs as proofs
from atlas_brain.runner import p4_root_mixed_report as report

KINDS = ("stp_port_vlan", "etherchannel_group", "fhrp_local")
NAMES = {"result.json", "MANIFEST.sha256", *(f"facts/{kind}.jsonl" for kind in KINDS)}
MODES = ("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all", "no_all_target", "zero_vrrp")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def prepared(root, mode="normal"):
    folder(root, mode) if mode == "zero_vrrp" else saved(root, mode)
    files = {path.name: path.read_bytes() for path in root.iterdir()}
    if "tree.txt" in files:
        raw = files["tree.txt"].replace(b"enabled", b"disabled").replace(b"priority 32769", b"priority 0")
        side = json.loads(files["p4.json"])
        next(row for row in side["captures"] if row["path"] == "tree.txt")["sha256"] = sha256(raw).hexdigest()
        (root / "tree.txt").write_bytes(raw)
        (root / "p4.json").write_bytes(canonical(side))
    return {path.name: path.read_bytes() for path in root.iterdir()}


def invoke(root, limits, monkeypatch, *, phase=None, plant=None):
    calls, held, leaves = [], [], []
    owner, index = report.owning.RootMixedComponentRun, report.RootMixedProofIndex
    init, build, current, indexing, bulk = owner.__init__, owner.build, owner.current_component, index.__init__, index.resolve_all
    bundling, pipeline = report.result_bundle, report.owning.execution.pipeline
    admit, dispatch = pipeline.p4.admit_folder, pipeline.execute_parsers
    def damage(run):
        if plant == "run":
            run.attempted = False
        elif plant in ("source", "result"):
            setattr(run, plant, replace(getattr(run, plant)))
        elif plant == "budget_pointer":
            run.budgets = replace(run.budgets)
        else:
            object.__setattr__(run.budgets, plant, getattr(run.budgets, plant) + 1)
    with monkeypatch.context() as patch:
        def admitting(*args, **kwargs):
            calls.append("admit")
            return admit(*args, **kwargs)
        def dispatching(*args, **kwargs):
            calls.append("dispatch")
            return dispatch(*args, **kwargs)
        patch.setattr(pipeline.p4, "admit_folder", admitting)
        patch.setattr(pipeline, "execute_parsers", dispatching)
        def starting(self, *args):
            calls.append("new")
            init(self, *args)
        def building(self):
            calls.append("build")
            result = build(self)
            held.append(self)
            frozen(patch)
            if phase == "before":
                damage(self)
            return result
        def getting(self):
            calls.append("current")
            return current(self)
        def opening(self, *args):
            calls.append("index")
            indexing(self, *args)
        def resolving(self):
            calls.append("bulk")
            result = bulk(self)
            leaves.extend(result)
            return result
        def formatting(*args, **kwargs):
            result = bundling(*args, **kwargs)
            if phase == "after":
                damage(held[0])
            return result
        for cls, name, value in ((owner, "__init__", starting), (owner, "build", building),
                (owner, "current_component", getting), (index, "__init__", opening), (index, "resolve_all", resolving)):
            patch.setattr(cls, name, value)
        patch.setattr(report, "result_bundle", formatting)
        files = report.analyse_root_mixed_folder(root, limits)
    assert calls.count("new") == calls.count("build") == calls.count("index") == calls.count("bulk") == 1
    assert calls.count("current") == 5 and calls.count("admit") == calls.count("dispatch") == len(held) == 1
    return files, held[0], tuple(leaves)


def state_wire(value):
    if type(value) is k.Known:
        return {"state": "known", "basis": str(value.basis), "value": value.value, "raw": value.raw}
    return json.loads(encoded({"state": "unknown", "reason": str(value.reason), "detail": value.detail,
        "candidates": value.candidates, "next_evidence": [{"node": need.node, "operation": need.operation,
            "params": need.params, "resolves": need.resolves, "reruns": need.reruns,
            "after_s": need.after_s, "unprintable": need.unprintable} for need in value.next_evidence]}))


def local_rows(component):
    result = {}
    for field, fact, name in ROOT_FACTS:
        for row in getattr(component, field).rows:
            local = {"protocol": "stp" if field == "tree" else "etherchannel" if field == "channel" else "vrrp" if field == "vrrp" else "hsrp",
                "node": row.target.node.key}
            local.update({"port": row.target.port, "vlan": row.vlan} if field == "tree" else
                {"group": row.group} if field == "channel" else {"interface": row.interface, "group": row.group})
            result[k.FactRef(fact=fact, subject=row.subject)] = local
    return result


@pytest.mark.parametrize("mode", MODES)
def test_genuine_modes_preserve_every_original_raw_leaf_cell_local_identity_and_five_canonical_files(tmp_path, monkeypatch, mode):
    inputs = prepared(tmp_path, mode)
    files, run, leaves = invoke(tmp_path, replace(LIMITS), monkeypatch)
    assert list(files) == sorted(NAMES) and all(type(raw) is bytes for raw in files.values())
    header = json.loads(files["result.json"])
    assert files["result.json"] == encoded(header)
    assert set(header) == {"schema", "semantic_group", "scope", "qualification", "checks", "group", "context",
        "registration_sha256", "root_scope", "denominator", "raws", "captures", "registry_records", "registries"}
    assert (header["schema"], header["semantic_group"], header["scope"], header["qualification"], header["checks"]) == (
        "atlas-brain.p4-root-mixed-observations/1", "declared_synthetic", "observations_only", "synthetic_observations_only", "not_implemented")
    assert header["root_scope"] == "local_reported_priority_and_mac_not_intended_root"
    envelope = run.source.execution.envelope
    assert (header["group"], header["context"], header["registration_sha256"]) == (envelope.base.id, envelope.context, envelope.registration_sha256)
    expected = (0, 0, 0, 2) if mode == "only_vrrp" else (1, 1, 5, 0 if mode == "zero_vrrp" else 1 if mode in ("no_all", "no_all_target") else 2)
    assert header["denominator"] == {name: {"kind": KINDS[index if index < 2 else 2], "declared": count}
        for index, (name, count) in enumerate(zip(("stp", "etherchannel", "hsrp", "vrrp"), expected, strict=True))}
    blobs = {row["sha256"]: bytes.fromhex(row["data"]) for row in header["raws"]}
    assert blobs == {sha256(raw).hexdigest(): raw for raw in inputs.values()}
    assert [row["sha256"] for row in header["raws"]] == sorted(blobs)
    assert all(row == {"sha256": digest, "bytes": len(blobs[digest]), "encoding": "hex", "data": blobs[digest].hex()}
        for row in header["raws"] for digest in (row["sha256"],))
    assert header["registries"] == [{"layer": layer, "raw": sha256(inputs[name]).hexdigest()} for layer, name in (("p2", "p2.json"), ("p4", "p4.json"))]
    originals = {("p2", cap.id): cap for cap in envelope.base.captures}
    originals.update({("p4", out.receipt.capture.id): out.receipt.capture for out in run.source.execution.executed})
    captures = {(row["layer"], row["id"]): row for row in header["captures"]}
    assert len(captures) == len(header["captures"]) == len(originals) and set(captures) == set(originals)
    assert [(row["layer"], row["id"]) for row in header["captures"]] == sorted(originals)
    for key, cap in originals.items():
        row = captures[key]
        assert row["raw"] == sha256(cap.raw).hexdigest() and blobs[row["raw"]] == cap.raw
        assert (row["node"], row["operation"], row["rendered"], row["codec"]) == (cap.source, cap.operation, cap.rendered, cap.codec)
        assert row["metadata_recorded"] is (cap.metadata is not None) and row["metadata"]["scope"] == asdict(cap.scope)
        if key[0] == "p4":
            member = next(item for item in envelope.captures if item.id == cap.id)
            receipt = next(out.receipt for out in run.source.execution.executed if out.receipt.capture is cap)
            assert (row["path"], row["target"], row["owner"], row["context"], row["registration_sha256"], row["parse_quality"], row["params"]) == (
                member.path, member.target.id, receipt.owner, receipt.context, receipt.registration_sha256, receipt.parse.quality, json.loads(member.target.params))
    ledger = {row["id"]: row for row in header["registry_records"]}
    assert list(ledger) == [f"registry-{index}" for index in range(len(ledger))] and len(ledger) == len(header["registry_records"])
    assert len({(row["table"], row["row_id"], row["table_sha256"], row["pointer"]) for row in ledger.values()}) == len(ledger)
    rows = []
    for kind in KINDS:
        current = [json.loads(raw) for raw in files[f"facts/{kind}.jsonl"].splitlines()]
        assert files[f"facts/{kind}.jsonl"] == b"".join(encoded(row) + b"\n" for row in sorted(current, key=lambda row: (row["subject"], row["fact"])))
        rows.extend(current)
    values, labels = dict(references(run.result)), local_rows(run.result)
    by_ref = {k.FactRef(fact=row["fact"], subject=row["subject"]): row for row in rows}
    assert len(rows) == len(by_ref) == len(leaves) == len(values) and set(by_ref) == set(values) == set(labels)
    for proof in leaves:
        ref, value = proof.reference, values[proof.reference]
        custody(run, ref, value, proof)
        row = by_ref[ref]
        assert set(row) == {"fact", "subject", "local", "value", "registry", "evidence"}
        assert row["local"] == labels[ref] and row["value"] == state_wire(value)
        assert len(row["registry"]) == len(proof.registry_leaves) and len(row["evidence"]) == len(proof.capture_leaves)
        for identity, leaf in zip(row["registry"], proof.registry_leaves, strict=True):
            record, reference = ledger[identity], leaf.reference
            parsed = json.loads(blobs[record["raw"]])
            for part in reference.citation.split("/")[1:]:
                parsed = parsed[int(part)] if type(parsed) is list else parsed[part]
            assert record == {"id": identity, "table": reference.table, "row_id": reference.row_id,
                "table_sha256": reference.table_digest, "pointer": reference.citation, "raw": reference.table_digest,
                "encoding": "hex", "canonical": encoded(parsed).hex()}
            assert bytes.fromhex(record["canonical"]) == leaf.canonical_value
        for record, leaf in zip(row["evidence"], proof.capture_leaves, strict=True):
            reference, point = leaf.reference, leaf.reference.locator
            locator = {"kind": "whole_capture"} if type(point) is k.WholeCapture else {"kind": "bytes", "start": point.start, "end": point.end}
            assert record == {"type": "capture", "layer": "p4", "capture": reference.capture, "role": str(reference.role),
                "locator": locator, "excerpt_sha256": sha256(leaf.raw).hexdigest()}
    assert files["MANIFEST.sha256"] == b"".join(f"{sha256(files[name]).hexdigest()}  {name}\n".encode() for name in sorted(NAMES - {"MANIFEST.sha256"}))
    if mode == "normal":
        assert {ref.fact for ref in by_ref} == {fact for _, fact, _ in ROOT_FACTS}
        priority = by_ref[next(ref for ref in by_ref if ref.fact == report.owning.stp.REPORTED_ROOT_PRIORITY)]["value"]
        guard = by_ref[next(ref for ref in by_ref if ref.fact == report.owning.stp.ROOT_GUARD)]["value"]
        mac = by_ref[next(ref for ref in by_ref if ref.fact == report.owning.stp.REPORTED_ROOT_MAC)]["value"]
        assert type(priority["value"]) is int and priority["value"] == 0 and priority["raw"] == "0"
        assert type(guard["value"]) is bool and guard["value"] is False and mac["value"] == mac["raw"] == MAC
    if mode in ("no_all", "no_all_target"):
        assert any(type(row.value) is k.Known for row in run.result.state.rows)
        assert all(type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED for row in run.result.version.rows)
        assert all(not row["evidence"] for ref, row in by_ref.items() if ref.fact == report.owning.version_profile.REPORTED_PROTOCOL_VERSION)
    vrrp = [proof for proof in leaves if proof.reference.fact == report.owning.vrrp_profile.REPORTED_VRRP_STATE]
    if mode in ("none", "cold_vrrp", "empty"):
        selected = leaves if mode == "none" else vrrp
        assert selected and all(type(proof.state) is k.Unknown for proof in selected)
        assert all(not proof.capture_leaves for proof in selected) if mode != "empty" else all(
            any(type(leaf.reference.locator) is k.WholeCapture and leaf.raw == b"" for leaf in proof.capture_leaves) for proof in selected)
    if mode == "partial":
        assert any(row.get("parse_quality") == "partial" for row in captures.values())
    if mode == "zero_vrrp":
        assert run.result.vrrp.rows == () and vrrp == []
    if mode == "only_vrrp":
        assert all(row["local"]["protocol"] == "vrrp" for row in rows)
        assert files["facts/stp_port_vlan.jsonl"] == files["facts/etherchannel_group.jsonl"] == b""
    assert all("vlan" not in row["local"] for row in rows if row["local"]["protocol"] in ("hsrp", "vrrp"))
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == inputs


@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("plant", ["run", "source", "result", "budget_pointer", "bundle_bytes", "artifact_bytes", "artifacts",
    "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
def test_original_run_source_result_and_budget_drift_refuse_before_returning_a_bundle(tmp_path, monkeypatch, phase, plant):
    inputs = prepared(tmp_path)
    code = "fhrp_mixed_component_source" if plant in ("run", "source", "result") else "fhrp_mixed_execution_current"
    with pytest.raises(ValueError, match="^" + code + "$"):
        invoke(tmp_path, replace(LIMITS), monkeypatch, phase=phase, plant=plant)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == inputs


@pytest.mark.parametrize("field", ["artifacts", "artifact_bytes", "bundle_bytes"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_independent_physical_inputs_plus_all_five_outputs_define_exact_limits(tmp_path, monkeypatch, field, delta):
    inputs = prepared(tmp_path)
    files, _, _ = invoke(tmp_path, replace(LIMITS), monkeypatch)
    exact = {"artifacts": len(inputs) + 5, "artifact_bytes": max(map(len, (*inputs.values(), *files.values()))),
        "bundle_bytes": sum(map(len, inputs.values())) + sum(map(len, files.values()))}
    limits = replace(LIMITS, **{**exact, field: exact[field] + delta})
    if delta < 0:
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
            invoke(tmp_path, limits, monkeypatch)
        assert caught.value.member == "p4_root_mixed_observations_outputs"
    else:
        assert invoke(tmp_path, limits, monkeypatch)[0] == files
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == inputs


@pytest.mark.parametrize("field", ["artifacts", "bundle_bytes"])
def test_budget_refuses_before_avoidable_raw_formatting_and_old_source_api_is_preserved(tmp_path, monkeypatch, field):
    inputs = prepared(tmp_path)
    old = report.owning.build_mixed_source(tmp_path, replace(LIMITS))
    old_index = proofs.MixedProofIndex(old)
    original = [(k.FactRef(fact=fact, subject=row.subject), getattr(row, name))
        for field, fact, name in ROOT_FACTS[:7] for row in getattr(old.result, field).rows]
    assert all(old_index.resolve(ref).state is value for ref, value in original)
    files, _, _ = invoke(tmp_path, replace(LIMITS), monkeypatch)
    manifest = len(files["MANIFEST.sha256"])
    with monkeypatch.context() as patch:
        patch.setattr(report.records, "raw_blobs", lambda *_: pytest.fail("avoidable raw formatting reached"))
        with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
            limits = {"artifacts": len(inputs) + 4} if field == "artifacts" else {"bundle_bytes": sum(map(len, inputs.values())) + manifest + 1}
            invoke(tmp_path, replace(LIMITS, **limits), patch)
        assert caught.value.member == "p4_root_mixed_observations_outputs"
    assert all(old_index.resolve(ref).state is value for ref, value in original)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == inputs


@pytest.mark.parametrize("name", ["source", "state", "positive", "evidence", "profile"])
def test_no_supplied_source_cell_profile_or_caller_grants_are_accepted(tmp_path, name):
    with pytest.raises(TypeError):
        report.analyse_root_mixed_folder(tmp_path / "absent", replace(LIMITS), **{name: object()})
