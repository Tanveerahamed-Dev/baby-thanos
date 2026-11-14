"""Full VERSION metadata and base-five proofs; no Source or six-fact value seal."""
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest
from test_peer_execution import forbidden, no_writers
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader, FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import peer_execution as runtime
from atlas_brain.packs.l3.fhrp import peer_profile, version_profile
from atlas_brain.runner import p4
from atlas_brain.runner import p4_pipeline as pipeline
from atlas_brain.runner import p4_refs as refs

VERSION = version_profile.REPORTED_PROTOCOL_VERSION


def close(component, index=None):
    index = refs.FhrpVersionProofIndex(component.execution, LIMITS) if index is None else index
    return p4.close_owned_facts(index, component.tree, component.channel, component.state)


def inputs(root, **kwargs):
    files = folder(root, **kwargs)
    for name in ("brief.txt", "all.txt"):
        if name not in files:
            (root / name).unlink(missing_ok=True)


def actual(root, monkeypatch, mode="normal"):
    def zero(side, files):
        side["targets"] = [target for target in side["targets"] if target["id"] in ("tree", "channel")]
        side["captures"] = [row for row in side["captures"] if row["target"] in ("tree", "channel")]
        files.pop("brief.txt")
        files.pop("all.txt")
    inputs(root, mode="normal" if mode == "zero" else mode, change=zero if mode == "zero" else None)
    component = runtime.build_peer_state_version_component(root, LIMITS)
    no_writers(monkeypatch)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    monkeypatch.setattr(pipeline, "execute_parsers", forbidden)
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, runtime.all_hsrp):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    assert tuple(map(len, close(component))) == (1, 1, 0 if mode == "zero" else 4 if mode == "unselected_b" else 5)
    return component


@pytest.mark.parametrize("mode", ["normal", "no_all_target", "no_all_capture", "no_all",
    "no_brief_capture", "no_captures", "unselected_b", "zero"])
def test_original_full_ledger_and_base_five_scopes_close_without_replaying_work(tmp_path, monkeypatch, mode):
    component = actual(tmp_path, monkeypatch, mode)
    execution = component.execution
    index = refs.FhrpVersionProofIndex(execution, LIMITS)
    assert index.execution is execution and index.execution.envelope is execution.envelope
    assert len(index.scopes) == 4 + len(component.state.rows)
    assert {scope.reference for scope in index.scopes} == set().union(
        *(set(owner.store.values) for owner in (component.tree, component.channel, component.state)))
    assert {scope.reference.fact for scope in index.scopes} <= set(p4.PROJECT.reads)
    assert index.registry_sha256 == sha256(execution.envelope.raw).hexdigest()
    assert index.base_registry_sha256 == sha256(execution.envelope.base.raw).hexdigest()
    assert len(index.captures) == len(execution.executed) == len(execution.envelope.captures)
    for output in execution.executed:
        capture, receipt = output.receipt.capture, output.receipt
        assert index.snapshots[capture.id] is capture and index.receipts[capture.id] is receipt
        assert index.hashes[capture.id] == capture.bytes_sha256
        assert receipt.parse is output.value.parse
    assert all(scope.target.operation != runtime.all_hsrp.OP for scope in index.scopes)
    for row in component.state.rows:
        scope = index.scope(fhrp.REPORTED_STATE, row.subject)
        assert scope.target.node is row.target.node and len(scope.declarations) == 3
        assert index.resolve(scope, row.value.evidence, positive=type(row.value) is k.Known)
        with pytest.raises(ValueError, match="^p4_projection_scope$"):
            index.scope(VERSION, row.subject)
    if mode.startswith("no_all") or mode == "no_captures":
        assert all(capture.operation != runtime.all_hsrp.OP for capture in index.captures)
    assert close(component, index) == close(component)


@pytest.mark.parametrize("kind", ["legacy", "root", "vip", "subclass"])
def test_fixed_opt_in_does_not_open_old_profiles_or_new_subclasses(tmp_path, monkeypatch, kind):
    component = actual(tmp_path, monkeypatch)
    class Derived(refs.FhrpVersionProofIndex):
        pass
    cls = {"legacy": refs.ProofIndex, "root": refs.RootProofIndex,
        "vip": refs.FhrpVipProofIndex, "subclass": Derived}[kind]
    with pytest.raises(ValueError, match="^p4_projection_profile$"):
        cls(component.execution, LIMITS)


def output_change(execution, output, changed):
    return replace(execution, executed=tuple(changed if old is output else old for old in execution.executed))


@pytest.mark.parametrize("fault", ["execution", "profile", "registry", "base_registry", "coverage", "duplicate",
    "owner", "context", "registration", "source", "operation", "raw", "parse", "value_type", "cross_type",
    "target_owner", "member_hash", "member_target", "members_type", "all_reason", "all_column", "all_span"])
def test_full_profile_capture_and_canonical_all_claims_refuse_after_valid_baseline(tmp_path, monkeypatch, fault):
    component = actual(tmp_path, monkeypatch)
    execution, envelope = component.execution, component.execution.envelope
    output = next(out for out in execution.executed if out.receipt.capture.operation == runtime.all_hsrp.OP)
    if fault == "execution":
        execution = SimpleNamespace(envelope=envelope, executed=execution.executed)
    elif fault in ("profile", "registry", "base_registry", "members_type"):
        changes = {"profile": {"registration_sha256": version_profile.compile_state_version_profile().registration_sha256},
            "registry": {"raw": envelope.raw + b"\n"}, "base_registry": {"base": replace(envelope.base, raw=envelope.base.raw + b"\n")},
            "members_type": {"captures": (object(), *envelope.captures[1:])}}[fault]
        execution = replace(execution, envelope=replace(envelope, **changes))
    elif fault in ("coverage", "duplicate"):
        execution = replace(execution, executed=tuple(out for out in execution.executed if out is not output)
            if fault == "coverage" else execution.executed + (output,))
    elif fault in ("target_owner", "member_hash", "member_target"):
        member = next(member for member in envelope.captures if member.id == output.receipt.capture.id)
        if fault == "target_owner":
            object.__setattr__(member.target, "owner", fhrp.STEP.id)
        else:
            changed = replace(member, **({"sha256": "0" * 64} if fault == "member_hash" else
                {"target": replace(member.target)}))
            execution = replace(execution, envelope=replace(envelope,
                captures=tuple(changed if old is member else old for old in envelope.captures)))
    elif fault in ("all_reason", "all_column", "all_span"):
        value = output.value
        if fault == "all_reason":
            value = replace(value, reason=k.UnknownReason.PARSE_PARTIAL)
        else:
            row = value.rows[0]
            token = replace(row.version, **({"raw": "9", "value": "9"} if fault == "all_column" else
                {"span": k.ByteSpan(start=row.version.span.start - 1, end=row.version.span.end - 1)}))
            header = replace(row.header, fields=tuple((name, token if name == "version" else old)
                for name, old in row.header.fields))
            parsed = replace(value.parse, records=tuple(header if old is row.header else old for old in value.parse.records))
            value = replace(value, parse=parsed, rows=(replace(row, header=header, version=token), *value.rows[1:]))
        changed = replace(output, value=value, receipt=replace(output.receipt, parse=value.parse))
        assert changed.receipt.parse is changed.value.parse
        execution = output_change(execution, output, changed)
    elif fault in ("value_type", "cross_type"):
        value = object() if fault == "value_type" else component.state.executed[0].value
        changed = replace(output, value=value, receipt=output.receipt if fault == "value_type"
            else replace(output.receipt, parse=value.parse))
        execution = output_change(execution, output, changed)
    else:
        receipt = output.receipt
        if fault in ("source", "operation", "raw"):
            capture = replace(receipt.capture)
            object.__setattr__(capture, fault, {"source": k.EntityKey("node:wrong"),
                "operation": fhrp.hsrp.OP, "raw": capture.raw + b"changed"}[fault])
            receipt = replace(receipt, capture=capture)
        else:
            receipt = replace(receipt, **{"owner": {"owner": fhrp.STEP.id}, "context": {"context": "other"},
                "registration": {"registration_sha256": "0" * 64}, "parse": {"parse": replace(receipt.parse)}}[fault])
        execution = output_change(execution, output, replace(output, receipt=receipt))
    with pytest.raises(ValueError):
        refs.FhrpVersionProofIndex(execution, LIMITS)


def rebound(root, component, change):
    inputs(root, change=change)
    envelope = pipeline.p4.admit_folder(root, LIMITS, declarations=peer_profile.DECLARATIONS)
    ledger = []
    for member in envelope.captures:
        original = next(out for out in component.execution.executed
            if out.receipt.capture.operation == member.target.operation)
        assert original.receipt.capture.raw == member.raw
        capture = replace(original.receipt.capture, id=member.id, source=member.target.node.key, metadata=None)
        ledger.append(replace(original, receipt=replace(original.receipt, capture=capture,
            owner=member.target.owner, context=envelope.context, registration_sha256=envelope.registration_sha256)))
    return replace(component.execution, envelope=envelope, executed=tuple(ledger))


@pytest.mark.parametrize("plant", ["groups", "orphan", "duplicate_all", "duplicate_brief", "duplicate_capture", "wrong_node"])
def test_coherent_declared_population_twins_cannot_bypass_all_to_brief_correspondence(tmp_path, monkeypatch, plant):
    component = actual(tmp_path / "base", monkeypatch)
    good = rebound(tmp_path / "good", component, None)
    assert len(refs.FhrpVersionProofIndex(good, LIMITS).scopes) == 9
    def changing(side, files):
        selected = next(target for target in side["targets"] if target["id"] == "all-a")
        if plant == "groups":
            selected["params"]["groups"][0][0] = "Vlan20"
        elif plant == "orphan":
            side["targets"] = [target for target in side["targets"] if target["id"] != "brief-a"]
            side["captures"] = [row for row in side["captures"] if row["target"] != "brief-a"]
            files.pop("brief.txt")
        elif plant in ("duplicate_all", "duplicate_brief"):
            target = selected if plant == "duplicate_all" else next(target for target in side["targets"] if target["id"] == "brief-a")
            side["targets"].append(dict(target, id="extra", params={"groups": [["Vl20", "9"]]}))
        elif plant == "duplicate_capture":
            files["second.txt"] = files["all.txt"]
            side["captures"].append({"target": "all-a", "path": "second.txt"})
        else:
            selected["node"] = "b"
            side["targets"] = [target for target in side["targets"] if target["id"] != "all-b"]
    execution = rebound(tmp_path / "changed", component, changing)
    with pytest.raises(ValueError, match="^p4_projection_(population|capture)$"):
        refs.FhrpVersionProofIndex(execution, LIMITS)


@pytest.mark.parametrize("family", ["tree", "channel", "state"])
@pytest.mark.parametrize("fault", ["rows", "duplicate", "owners", "missing_cell", "extra_cell", "value_clone", "reader_clone", "evidence"])
def test_base_owner_cells_actual_reads_population_and_leaf_custody_remain_closed(tmp_path, monkeypatch, family, fault):
    component = actual(tmp_path, monkeypatch)
    owner = getattr(component, family)
    reference = next(iter(owner.store.values))
    if fault in ("rows", "duplicate"):
        owner = replace(owner, rows=owner.rows[:-1] if fault == "rows" else owner.rows + owner.rows[:1])
    elif fault == "owners":
        owner.store.owners[reference.fact] = "wrong/owner"
    elif fault == "missing_cell":
        owner.store.values.pop(reference)
    elif fault == "extra_cell":
        owner.store.values[k.FactRef(fact=reference.fact, subject=k.EntityKey("extra:subject"))] = owner.store.values[reference]
    elif fault == "value_clone":
        owner.store.values[reference] = replace(owner.store.values[reference])
    elif fault == "reader_clone":
        read = FactReader.read
        monkeypatch.setattr(FactReader, "read", lambda self, **kwargs: replace(read(self, **kwargs)))
    else:
        row = next(row for row in owner.rows if type(row.value) is k.Known)
        ref = next(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
        value = replace(row.value, evidence=tuple(replace(ref, excerpt_sha256="0" * 64) if item is ref else item
            for item in row.value.evidence))
        owner = replace(owner, rows=tuple(replace(row, value=value) if old is row else old for old in owner.rows))
        fact = stp.ROOT_GUARD if family == "tree" else ec.REPORTED_PROTOCOL if family == "channel" else fhrp.REPORTED_STATE
        owner.store.values[k.FactRef(fact=fact, subject=row.subject)] = value
    component = replace(component, **{family: owner})
    with pytest.raises(ValueError, match="^p4_(observations|projection)_"):
        close(component)


def test_equal_current_data_is_not_an_origin_token_or_six_fact_source_seal(tmp_path, monkeypatch):
    component = actual(tmp_path, monkeypatch)
    execution = replace(component.execution, executed=tuple(replace(out, receipt=replace(out.receipt))
        for out in component.execution.executed))
    index = refs.FhrpVersionProofIndex(execution, LIMITS)
    assert close(component, index) == close(component)
    assert not any(scope.reference.fact == VERSION for scope in index.scopes)
    assert len(component.version.store.values) == 5


def test_full_all_capture_metadata_never_grants_all_body_leaves_to_a_state_subject(tmp_path, monkeypatch):
    component = actual(tmp_path, monkeypatch)
    index = refs.FhrpVersionProofIndex(component.execution, LIMITS)
    metadata = p4.project_capture_metadata(index)
    assert {row["id"] for row in metadata} == {str(capture.id) for capture in index.captures}
    assert {row["operation"] for row in metadata} == {stp.stp.OP, ec.parse_summary.OP, fhrp.hsrp.OP, runtime.all_hsrp.OP}
    output = next(out for out in component.execution.executed if out.receipt.capture.operation == runtime.all_hsrp.OP)
    capture = output.receipt.capture
    leaves = index.metadata_evidence(capture.id, capture.resolved_metadata.integrity_evidence)
    assert leaves and all(leaf["target"] == "all-a" and leaf["capture"] == str(capture.id) for leaf in leaves)
    row = next(row for row in component.state.rows if type(row.value) is k.Known)
    scope = index.scope(fhrp.REPORTED_STATE, row.subject)
    point = output.value.rows[0].header.span
    donated = k.EvidenceRef(capture=capture.id, locator=point, role=k.EvidenceRole.SUBJECT,
        excerpt_sha256=sha256(capture.raw[point.start:point.end]).hexdigest())
    assert index.resolve(scope, row.value.evidence, positive=True)
    evidence = tuple(ref for ref in row.value.evidence if type(ref) is k.RegistryRef) + (donated,)
    with pytest.raises(ValueError, match="^p4_projection_scope$"):
        index.resolve(scope, evidence, positive=True)


def test_base_five_census_refuses_premature_version_scopes_on_negative_brief_anchor(tmp_path, monkeypatch):
    component = actual(tmp_path, monkeypatch, "no_all")
    index = refs.FhrpVersionProofIndex(component.execution, LIMITS)
    assert close(component, index) == close(component)
    state = next(scope for scope in index.scopes if scope.reference.fact == fhrp.REPORTED_STATE)
    reference = k.FactRef(fact=VERSION, subject=state.reference.subject)
    premature = replace(state, reference=reference, spans=frozenset(), positive=frozenset(),
        required=frozenset(), witnesses=frozenset())
    index.bound[reference] = premature
    index.ordered += (premature,)
    with pytest.raises(ValueError, match="^p4_observations_population$"):
        close(component, index)


@pytest.mark.parametrize("field", ["node_id", "target_id", "target_owner", "target_operation", "target_params", "member_id", "member_raw"])
def test_finite_declared_graph_types_refuse_before_metadata_dictionary_keys(tmp_path, monkeypatch, field):
    component = actual(tmp_path, monkeypatch)
    envelope = component.execution.envelope
    target = next(target for target in envelope.targets if target.operation == runtime.all_hsrp.OP)
    member = next(member for member in envelope.captures if member.target is target)
    obj, name = {"node_id": (target.node, "id"), "target_id": (target, "id"), "target_owner": (target, "owner"),
        "target_operation": (target, "operation"), "target_params": (target, "params"),
        "member_id": (member, "id"), "member_raw": (member, "raw")}[field]
    object.__setattr__(obj, name, [])
    with pytest.raises(ValueError):
        refs.FhrpVersionProofIndex(component.execution, LIMITS)


@pytest.mark.parametrize("operation", [fhrp.hsrp.OP, runtime.all_hsrp.OP])
def test_empty_groups_are_refused_rather_than_declared_as_zero_population(tmp_path, monkeypatch, operation):
    component = actual(tmp_path / "base", monkeypatch)
    assert len(refs.FhrpVersionProofIndex(rebound(tmp_path / "good", component, None), LIMITS).scopes) == 9
    def changing(side, _files):
        next(target for target in side["targets"] if target["operation"] == operation)["params"]["groups"] = []
    execution = rebound(tmp_path / "empty", component, changing)
    with pytest.raises(ValueError):
        refs.FhrpVersionProofIndex(execution, LIMITS)
