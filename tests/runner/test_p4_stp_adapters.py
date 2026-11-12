"""Pinned d697 STP projection policy; adapters must preserve current bytes and authority."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_p4_hsrp_proofs import estate3, execute3
from test_p4_observations import snapshot
from test_p4_proof_index import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepId
from atlas_brain.runner import p4 as m
from atlas_brain.runner import p4_refs as r

ROOT_SPEC = (k.FactId("l2.stp.root_guard"), k.PackId("l2.stp"), StepId("l2.stp/parse_root_guard"), "stp_port_vlan", bool)
ROOT = ROOT_SPEC[0]
OWNER_ROWS, OWNER_LEAVES = m.stp.fact_rows, m.stp.projection_leaves
OWNER_STATE, OWNER_POLICY = m.stp.original_state, m.stp.requires_all


def legacy_rows(owner):
    return tuple((ROOT, row, row.value) for row in owner.rows) + tuple(item for item in OWNER_ROWS(owner) if item[0] != ROOT)


def legacy_leaves(fact, domain, vlan, output):
    if fact != ROOT:
        return OWNER_LEAVES(fact, domain, vlan, output)
    row, = tuple(row for row in output.value.rows if row.port == domain.port and row.vlan == vlan)
    spans = frozenset((*row.spans, *(token.span for _, token in row.fields))) if row.fields else frozenset()
    tokens = tuple(token for name, token in row.fields if name == "root_guard")
    complete = output.value.reason is None and row.reason is None and output.receipt.capture.integrity is k.IntegrityState.COMPLETE and output.receipt.parse.quality == "complete"
    return spans, frozenset((tokens[0].span,)) if complete and len(tokens) == 1 else frozenset(), frozenset()


def prepared(root, mode="normal", ending=b"\n"):
    side = estate3(root, ending=ending)
    path = root / "tree.txt"
    raw = path.read_bytes()
    if mode == "enabled":
        raw = raw.replace(b"disabled", b"enabled")
    elif mode == "omitted":
        raw = b"".join(line for line in raw.splitlines(keepends=True) if b"Root guard is " not in line)
    elif mode == "partial":
        raw += b"unmodelled" + ending
    elif mode == "duplicate":
        raw += raw
    elif mode == "error":
        raw += b"% Invalid input" + ending
    if mode == "missing":
        path.unlink()
        side["captures"] = [row for row in side["captures"] if row["target"] != "tree"]
    else:
        path.write_bytes(raw)
        next(row for row in side["captures"] if row["target"] == "tree")["sha256"] = sha256(raw).hexdigest()
    (root / "p4.json").write_bytes(canonical(side))


@pytest.mark.parametrize("mode", ["normal", "enabled", "omitted", "partial", "duplicate", "error", "missing"])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_raw_scope_whitelist_and_all_five_files_equal_pinned_legacy_policy(tmp_path, monkeypatch, mode, ending):
    prepared(tmp_path, mode, ending)
    before = snapshot(tmp_path)
    tree, channel, standby = execute3(tmp_path)
    monkeypatch.setattr(m.stp, "reported_root_guard_proofs", lambda *args: pytest.fail("new seven-leaf policy replaced legacy scope"))
    index = r.ProofIndex(tree.execution, LIMITS)
    target = next(target for target in tree.execution.envelope.targets if target.id == "tree")
    raw_side, raw_base = json.loads(before["p4.json"]), json.loads(before["p2.json"])
    ti, raw_target = next((i, target) for i, target in enumerate(raw_side["targets"]) if target["id"] == "tree")
    ni = next(i for i, node in enumerate(raw_base["nodes"]) if node["id"] == raw_target["node"])
    domain = m.stp.Target(context=raw_side["context"], node=target.node, port=raw_target["params"]["port"], vlans=tuple(raw_target["params"]["vlans"]))
    wanted = {k.FactRef(fact=ROOT, subject=m.stp.subject(domain, vlan)) for vlan in raw_target["params"]["vlans"]}
    assert {scope.reference for scope in index.scopes if scope.target is target and scope.reference.fact == ROOT} == wanted
    declarations = (k.RegistryRef(table="synthetic_p2.nodes", row_id=raw_target["node"], table_digest=sha256(before["p2.json"]).hexdigest(), citation=f"/nodes/{ni}"),
        k.RegistryRef(table="synthetic_p4.context", row_id=raw_side["context"], table_digest=sha256(before["p4.json"]).hexdigest(), citation="/context"),
        k.RegistryRef(table="synthetic_p4.targets", row_id=raw_target["id"], table_digest=sha256(before["p4.json"]).hexdigest(), citation=f"/targets/{ti}"))
    assert tuple(spec for spec in m.stp.projection_contract() if spec[0] == ROOT) == (ROOT_SPEC,)
    items = tuple(item for item in m.stp.fact_rows(tree.result) if item[0] == ROOT)
    assert len(items) == len(tree.result.rows) and all(fact == ROOT and row is original and value is row.value
        for (fact, row, value), original in zip(items, tree.result.rows, strict=True))
    for row in tree.result.rows:
        scope = index.scope(ROOT, row.subject)
        expected = [set(), set(), set()]
        for output in index.by_target[target.id]:
            for actual, spans in zip(expected, legacy_leaves(ROOT, row.target, row.vlan, output), strict=True):
                actual.update((output.receipt.capture.id, span) for span in spans)
            assert m.stp.projection_leaves(ROOT, row.target, row.vlan, output) == legacy_leaves(ROOT, row.target, row.vlan, output)
        assert (scope.spans, scope.positive, scope.required) == tuple(frozenset(points) for points in expected)
        assert scope.required == scope.witnesses == frozenset() and scope.target is target
        assert scope.labels == (("context", tree.execution.envelope.context), ("node", raw_target["node"]),
            ("port", raw_target["params"]["port"]), ("target", raw_target["id"]), ("vlan", row.vlan))
        assert scope.declarations == declarations == row.value.evidence[:3] and row.target.node is target.node
        assert scope.reference == k.FactRef(fact=ROOT, subject=m.stp.subject(domain, row.vlan))
        if type(row.value) is k.Known:
            refs = tuple(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
            output, = index.by_target[target.id]
            rich = next(value for value in output.value.rows if value.vlan == row.vlan)
            fields = dict(rich.fields)
            header = next(record.span for record in output.value.parse.records if record.span in rich.spans and record.rule_id.startswith("header_"))
            guard = next(record.span for record in output.value.parse.records if record.span in rich.spans and record.rule_id == "root_guard")
            assert tuple(ref.locator for ref in refs) == (fields["root_guard"].span, guard, fields["port"].span, fields["vlan"].span, header)
            assert all(ref.capture == output.receipt.capture.id and ref.role is k.EvidenceRole.SUBJECT
                and ref.excerpt_sha256 == sha256(output.receipt.capture.raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
            assert refs[0].locator in {point for _, point in scope.positive}
            assert len(index.resolve(scope, scope.declarations + refs[:1], positive=True)) == 4
            with pytest.raises(m.RunnerRefused, match="^p4_projection_positive$"):
                index.resolve(scope, scope.declarations + refs[1:], positive=True)
    actual = m.analyse_folder(tmp_path, LIMITS)
    signatures = index.scopes
    with monkeypatch.context() as patch:
        patch.setattr(m.stp, "original_state", lambda fact, row: row.value if fact == ROOT else OWNER_STATE(fact, row))
        patch.setattr(m.stp, "requires_all", lambda fact: False if fact == ROOT else OWNER_POLICY(fact))
        patch.setattr(m.stp, "fact_rows", legacy_rows)
        patch.setattr(m.stp, "projection_leaves", legacy_leaves)
        reference = m.analyse_folder(tmp_path, LIMITS)
        assert r.ProofIndex(tree.execution, LIMITS).scopes == signatures
    assert actual == reference and set(actual) == {"result.json", "MANIFEST.sha256", "facts/stp_port_vlan.jsonl", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl"} and snapshot(tmp_path) == before
    head = json.loads(actual["result.json"])
    assert (head["schema"], head["scope"], head["checks"], head["variant_support"]) == ("atlas-brain.p4-observations/1", "observations_only", "not_implemented", "allowlisted")
    assert head["registry_sha256"] == sha256(before["p4.json"]).hexdigest() and head["base_registry_sha256"] == sha256(before["p2.json"]).hexdigest()
    assert head["registration_sha256"] == tree.execution.envelope.registration_sha256
    assert {capture["id"] for capture in head["captures"]} == {output.receipt.capture.id for output in tree.execution.executed}
    assert {k.FactRef(fact=row["fact"], subject=row["subject"]) for row in map(json.loads, actual["facts/stp_port_vlan.jsonl"].splitlines()) if row["fact"] == ROOT} == wanted
    assert m.ec.fact_rows(channel) and m.fhrp.fact_rows(standby)


def test_coherent_text_metadata_rows_and_canonical_store_cannot_redefine_intrinsic_boolean(tmp_path, monkeypatch):
    prepared(tmp_path)
    original = m.stp.build_root_guard_global
    declaration = replace(m.stp.DECLARATION, facts=tuple(replace(fact, value_type="text") for fact in m.stp.DECLARATION.facts))
    monkeypatch.setattr(m.stp, "DECLARATION", declaration)
    def built(*args, **kwargs):
        result = original(*args, **kwargs)
        rows = tuple(replace(row, value=replace(row.value, value=row.value.raw)) if type(row.value) is k.Known else row for row in result.result.rows)
        result.result.store.values.update({k.FactRef(fact=ROOT, subject=row.subject): row.value for row in rows})
        return replace(result, result=replace(result.result, rows=rows))
    monkeypatch.setattr(m.stp, "build_root_guard_global", built)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle accepted redefined Boolean"))
    assert tuple(spec for spec in m.stp.projection_contract() if spec[0] == ROOT) == (ROOT_SPEC,)
    with pytest.raises(m.RunnerRefused, match="^p4_observations_spec$"):
        m.analyse_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("plant", ["producer", "extra", "unregistered"])
def test_literal_contract_is_independent_of_coherently_modified_catalogue(tmp_path, monkeypatch, plant):
    declaration, producer = m.stp.DECLARATION, m.stp.STEP
    if plant == "producer":
        producer = replace(producer, id=StepId("l2.stp/foreign_producer"))
        declaration = replace(declaration, facts=tuple(replace(fact, step=producer.id) for fact in declaration.facts),
            steps=(producer,), operations=(replace(m.stp.BINDING, step=producer.id),))
    else:
        extra = replace(declaration.facts[0], id=k.FactId("l2.stp.unregistered"))
        producer = replace(producer, produces=tuple(sorted((*producer.produces, extra.id))))
        declaration = replace(declaration, facts=declaration.facts + (extra,), steps=(producer,))
    monkeypatch.setattr(m.stp, "STEP", producer)
    monkeypatch.setattr(m.stp, "DECLARATION", declaration)
    assert tuple(spec for spec in m.stp.projection_contract() if spec[0] == ROOT) == (ROOT_SPEC,)
    with pytest.raises(m.RunnerRefused, match="^p4_observations_spec$"):
        m._spec(ROOT if plant != "unregistered" else k.FactId("l2.stp.unregistered"))


@pytest.mark.parametrize("plant", ["omit", "duplicate", "list", "item_list", "fact", "row_clone", "state_clone", "alien_row"])
def test_fact_adapter_cannot_change_registered_census_or_original_identity(tmp_path, monkeypatch, plant):
    prepared(tmp_path)
    original = m.stp.fact_rows
    def mapped(owner):
        supplied = original(owner)
        items = tuple(item for item in supplied if item[0] == ROOT)
        others = tuple(item for item in supplied if item[0] != ROOT)
        fact, row, value = items[0]
        if plant in ("omit", "duplicate", "list"):
            return items[1:] + others if plant == "omit" else items[:-1] + items[:1] + others if plant == "duplicate" else list(items + others)
        first = list(items[0]) if plant == "item_list" else (
            k.FactId("l2.stp.unregistered") if plant == "fact" else fact,
            replace(row, subject=k.EntityKey("subject:alien")) if plant == "alien_row" else replace(row) if plant == "row_clone" else row,
            replace(value) if plant == "state_clone" else value)
        return (first,) + items[1:] + others
    monkeypatch.setattr(m.stp, "fact_rows", mapped)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before adapter closure"))
    with pytest.raises(m.RunnerRefused, match="^p4_observations_(row|population|store)$"):
        m.analyse_folder(tmp_path, LIMITS)


def test_canonical_store_state_cannot_hide_a_different_original_stp_row_state(tmp_path, monkeypatch):
    prepared(tmp_path)
    factory = m.stp.build_root_guard_global
    def built(*args, **kwargs):
        result = factory(*args, **kwargs)
        row = result.result.rows[0]
        return replace(result, result=replace(result.result, rows=(replace(row, value=replace(row.value)),) + result.result.rows[1:]))
    monkeypatch.setattr(m.stp, "build_root_guard_global", built)
    monkeypatch.setattr(m.stp, "fact_rows", lambda owner: tuple((ROOT, row,
        owner.store.values[k.FactRef(fact=ROOT, subject=row.subject)]) for row in owner.rows)
        + tuple(item for item in OWNER_ROWS(owner) if item[0] != ROOT))
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("store masked row state"))
    with pytest.raises(m.RunnerRefused, match="^p4_observations_store$"):
        m.analyse_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("plant", ["arity", "mutable", "pair", "object", "foreign", "positive_subset", "required", "low_level"])
def test_leaf_adapter_cannot_change_shape_capture_or_subject_authority(tmp_path, monkeypatch, plant):
    prepared(tmp_path)
    original = m.stp.projection_leaves
    def leaves(fact, domain, vlan, output):
        spans, positive, required = original(fact, domain, vlan, output)
        if fact != ROOT or vlan != 1:
            return spans, positive, required
        foreign = next(token.span for row in output.value.rows if row.vlan != vlan and row.fields for _, token in row.fields)
        if plant == "low_level":
            raise ValueError("stp_projection_scope")
        if plant == "arity":
            return spans, positive
        if plant == "mutable":
            return set(spans), positive, required
        if plant in ("pair", "object", "foreign"):
            value = (output.receipt.capture.id, next(iter(spans))) if plant == "pair" else object() if plant == "object" else foreign
            return frozenset((*spans, value)), positive, required
        return (spans, frozenset((foreign,)), required) if plant == "positive_subset" else (spans, positive, positive)
    monkeypatch.setattr(m.stp, "projection_leaves", leaves)
    with pytest.raises(m.RunnerRefused, match="^p4_projection_scope$"):
        m.analyse_folder(tmp_path, LIMITS)


def test_metadata_roles_and_capture_error_precede_bad_role_without_new_required_leaves(tmp_path):
    prepared(tmp_path)
    tree, _, _ = execute3(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    row = tree.result.rows[0]
    scope = index.scope(ROOT, row.subject)
    ref = next(ref for ref in row.value.evidence if type(ref) is k.EvidenceRef)
    assert scope.required == scope.witnesses == frozenset()
    with pytest.raises(m.RunnerRefused, match="^p4_projection_role$"):
        index.resolve(scope, scope.declarations + (replace(ref, role=k.EvidenceRole.WITNESS),))
    output = next(output for output in tree.execution.executed if output.receipt.capture.id == ref.capture)
    whole = k.EvidenceRef(capture=ref.capture, locator=k.WholeCapture(), role=k.EvidenceRole.SUBJECT,
        excerpt_sha256=output.receipt.capture.bytes_sha256)
    assert index.metadata_evidence(ref.capture, (whole,))[0]["role"] == "subject"
    with pytest.raises(m.RunnerRefused, match="^p4_projection_role$"):
        index.metadata_evidence(ref.capture, (replace(whole, role=k.EvidenceRole.WITNESS),))
    index.snapshots[ref.capture] = replace(output.receipt.capture, integrity=k.IntegrityState.ERROR)
    with pytest.raises(m.RunnerRefused, match="^p4_projection_capture$"):
        index.resolve(scope, scope.declarations + (replace(ref, role=k.EvidenceRole.WITNESS),), positive=True)


@pytest.mark.parametrize("plant", ["clone", "object", "low_level"])
def test_core_uses_fact_specific_owning_state_before_canonical_reader(tmp_path, monkeypatch, plant):
    prepared(tmp_path)
    def state(fact, row):
        if fact != ROOT:
            return OWNER_STATE(fact, row)
        if plant == "low_level":
            raise ValueError("stp_projection_rows")
        return replace(row.value) if plant == "clone" else object()
    monkeypatch.setattr(m.stp, "original_state", state)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before original state closure"))
    with pytest.raises(m.RunnerRefused, match="^p4_observations_store$"):
        m.analyse_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("policy,mandatory,accepted", [
    (False, "empty", True), (True, "all", True), (False, "all", False), (False, "anchor", False),
    (True, "empty", False), (True, "anchor", False), (0, "empty", False), (1, "all", False),
    (None, "empty", False), ([], "empty", False), ("false", "empty", False), ("raise", "empty", False)])
def test_required_policy_is_strict_boolean_and_matches_the_complete_granted_set(tmp_path, monkeypatch, policy, mandatory, accepted):
    prepared(tmp_path)
    tree, _, _ = execute3(tmp_path)
    def requires_all(fact):
        if fact != ROOT:
            return OWNER_POLICY(fact)
        if policy == "raise":
            raise ValueError("stp_projection_fact")
        return policy
    def leaves(fact, domain, vlan, output):
        spans, positive, required = OWNER_LEAVES(fact, domain, vlan, output)
        if fact == ROOT:
            if spans:
                assert positive and positive != spans
            else:
                assert not positive
            required = {"empty": frozenset(), "all": spans, "anchor": positive}[mandatory]
        return spans, positive, required
    monkeypatch.setattr(m.stp, "requires_all", requires_all)
    monkeypatch.setattr(m.stp, "projection_leaves", leaves)
    if not accepted:
        with pytest.raises(m.RunnerRefused, match="^p4_projection_scope$"):
            r.ProofIndex(tree.execution, LIMITS)
    else:
        index = r.ProofIndex(tree.execution, LIMITS)
        scopes = tuple(scope for scope in index.scopes if scope.reference.fact == ROOT)
        assert scopes and all(scope.required == (scope.spans if policy else frozenset()) for scope in scopes)
