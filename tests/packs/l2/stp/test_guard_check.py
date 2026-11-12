"""Caller-declared comparisons consume closed facts; untimed equality never means healthy."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_declared_root_guard_scope import declared_oracle
from test_global_root_guard import LIMITS, P, scenario, write
from test_guard_policy import intent

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactReader
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import p4_guard_policy as m

ROLE, ROOT = k.FactId("l2.stp.reported_role"), k.FactId("l2.stp.root_guard")
D = ("designated", "designated")
U, NA = k.UnknownReason, k.NAReason


def raw(word, role, vlan=1):
    header = f"Port 1 ({P}) of VLAN{vlan:04d} is {role} forwarding\n".encode()
    return header + (b"" if word is None else f"   Root guard is {word} on the port\n".encode())


def estate(root, left="enabled", right="disabled", roles=D, missing=False):
    files, side = scenario(raw=raw(left, roles[0]) + raw(left, roles[0], 2))
    next(target for target in side["targets"] if target["id"] == "ec")["params"] = {"groups": ["1"], "ports": ["Gi1/0/1"]}
    if not missing:
        content = raw(right, roles[1])
        files["right.txt"] = content
        side["captures"].append({"target": "t1", "path": "right.txt", "sha256": sha256(content).hexdigest()})
    write(root, files, side)


def subjects(envelope):
    domains = (declared_oracle(envelope, target.id)[0] for target in envelope.targets if target.operation == b.stp.OP)
    return tuple(sorted(b.subject(domain, vlan) for domain in domains for vlan in domain.vlans))


@pytest.mark.parametrize("left,right,roles,missing,gapped,wanted", [
    ("enabled", "disabled", D, False, False, ("problem", None, 3)),
    ("disabled", "enabled", D, False, False, ("problem", None, 3)),
    ("enabled", "enabled", D, False, False, ("unknown", U.AS_OF_MISSING, 3)),
    ("disabled", "disabled", D, False, False, ("unknown", U.AS_OF_MISSING, 3)),
    (None, "disabled", D, False, False, ("unknown", U.FIELD_NOT_PRINTED, 3)),
    ("enabled", None, D, False, False, ("unknown", U.FIELD_NOT_PRINTED, 3)),
    ("enabled", "disabled", ("root", "designated"), False, False, ("not_applicable", NA.ROLE_EXCLUDES, 2)),
    ("enabled", "disabled", ("alternate", "designated"), False, False, ("not_applicable", NA.ROLE_EXCLUDES, 2)),
    ("enabled", "disabled", ("backup", "designated"), False, False, ("not_applicable", NA.ROLE_EXCLUDES, 2)),
    ("enabled", "disabled", ("disabled", "designated"), False, False, ("not_applicable", NA.ROLE_EXCLUDES, 2)),
    ("enabled", "disabled", ("designated", "root"), False, False, ("not_applicable", NA.ROLE_EXCLUDES, 2)),
    ("enabled", "disabled", D, True, False, ("unknown", U.NOT_COLLECTED, 2)),
    ("enabled", "disabled", ("root", "designated"), True, False, ("not_applicable", NA.ROLE_EXCLUDES, 2)),
    ("enabled", "disabled", ("root", "designated"), True, True, ("unknown", U.ANALYSIS_GAP, 1)),
    ("enabled", "disabled", D, False, True, ("unknown", U.ANALYSIS_GAP, 1))])
def test_real_report_matrix_has_ordered_conditional_hops_and_resolvable_sources(tmp_path, left, right, roles, missing, gapped, wanted):
    estate(tmp_path, left, right, roles, missing)
    out = m.evaluate_guard_comparisons(tmp_path, LIMITS, (intent(domain=None if gapped else "fabric"),))
    finding, = out.result.rows
    policy, = out.plan.rows
    assert (finding.state, finding.reason, len(finding.hops)) == wanted
    assert finding.check == "l2.stp.reported_root_guard_mismatch" and finding.policy_id == "one" and finding.conditional is True
    assert (finding.left, finding.right) == tuple(point.subject for point in policy.participants) and finding.gaps == policy.gaps
    assert tuple(hop.id for hop in finding.hops) == ("declared_scope", "reported_role", "reported_root_guard")[:wanted[2]]
    ref = k.RegistryRef(table="declared_stp_guard_policies", row_id="one", table_digest=sha256(out.plan.raw).hexdigest(), citation="/policies/0")
    assert out.plan.sha256 == ref.table_digest and policy.declaration.evidence == (ref,)
    expected = (ref,) + tuple(k.FactRef(fact=fact, subject=point.subject)
        for fact in (ROLE, ROOT)[:wanted[2] - 1] for point in policy.participants)
    assert finding.evidence == expected and finding.evidence == tuple(ref for hop in finding.hops for ref in hop.state.evidence)
    assert out.plan.envelope is out.source.execution.envelope and out.result.coverage is out.plan.coverage
    assert out.result.denominator == (("declared_policies", 1), ("declared_participant_occurrences", 2))
    assert out.result.coverage.reason is U.DENOMINATOR_OPEN
    if finding.state == "not_applicable":
        assert finding.next_evidence == () and any(type(out.source.result.store.values[ref]) is k.Known
            and out.source.result.store.values[ref].value != "designated" for ref in expected[1:])
    elif finding.reason in (U.FIELD_NOT_PRINTED, U.NOT_COLLECTED):
        original = next(out.source.result.store.values[ref] for ref in expected[1:] if type(ref) is k.FactRef
            and type(out.source.result.store.values[ref]) is k.Unknown)
        assert finding.next_evidence == original.next_evidence
    else:
        assert len(finding.next_evidence) == 2
        for point, need in zip(policy.participants, finding.next_evidence, strict=True):
            assert (need.node, need.operation, need.params, need.resolves, need.reruns, need.after_s, need.unprintable) == (
                point.target.node.key, b.stp.OP, (("port", P),), (ROLE, ROOT), (m.check.STEP.id,), None,
                ("collector_recorded_time", "declared_guard_policy"))


@pytest.mark.parametrize("empty", [False, True])
def test_public_run_finishes_all_owners_reads_all_subjects_first_and_preserves_observation_bytes(tmp_path, monkeypatch, empty):
    estate(tmp_path)
    before = m.observations.analyse_folder(tmp_path, LIMITS)
    inputs = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    runs, finishes, reads, indexes = [], [], [], []
    execute, read, hop, index = b.p4_pipeline.execute_p4_folder, FactReader.read, m.check.Hop.__init__, m.ProofIndex.__init__
    def running(*args, **kwargs):
        result = execute(*args, **kwargs)
        runs.append(result)
        return result
    def reading(self, **kwargs):
        if self.step.id == m.check.STEP.id:
            assert self.step.reads == (ROLE, ROOT) and self.step.produces == () and self.step.kind == "check"
            reads.append((kwargs["fact"], kwargs["subject"]))
        return read(self, **kwargs)
    def hopping(self, **kwargs):
        assert reads == [(fact, subject) for subject in subjects(runs[0].envelope) for fact in (ROLE, ROOT)]
        hop(self, **kwargs)
    def indexing(self, execution, budgets):
        indexes.append(execution)
        index(self, execution, budgets)
    with monkeypatch.context() as patch:
        patch.setattr(b.p4_pipeline, "execute_p4_folder", running)
        patch.setattr(FactReader, "read", reading)
        patch.setattr(m.check.Hop, "__init__", hopping)
        patch.setattr(m.ProofIndex, "__init__", indexing)
        for cls in (m.SummaryPack, m.StandbyBriefPack):
            original = cls.finish
            def finished(self, execution, original=original):
                finishes.append(execution)
                return original(self, execution)
            patch.setattr(cls, "finish", finished)
        out = m.evaluate_guard_comparisons(tmp_path, LIMITS, () if empty else (intent(),))
    assert len(runs) == len(indexes) == 1 and runs[0] is indexes[0] is out.source.execution
    assert len(finishes) == 2 and all(run is runs[0] for run in finishes)
    assert reads == [(fact, subject) for subject in subjects(out.source.execution.envelope) for fact in (ROLE, ROOT)]
    assert out.plan.envelope is runs[0].envelope and out.result.coverage is out.plan.coverage
    assert len(out.result.rows) == (0 if empty else 1) and out.result.coverage.reason is U.DENOMINATOR_OPEN
    assert m.check.STEP.id not in {step.id for step in b.DECLARATION.steps}
    assert b.STEP.produces == (ROLE, ROOT) and all(fact.id != m.check.CHECK for fact in b.DECLARATION.facts)
    assert m.observations.analyse_folder(tmp_path, LIMITS) == before and {path.name: path.read_bytes() for path in tmp_path.iterdir()} == inputs


@pytest.mark.parametrize("field", ["root_basis", "root_raw", "role_basis", "role_raw", "role_closed"])
@pytest.mark.parametrize("mode", ["normal", "empty", "gap", "excluded"])
@pytest.mark.parametrize("last", [False, True])
def test_all_semantic_inputs_close_before_any_prefix_even_unselected_or_empty(tmp_path, monkeypatch, field, mode, last):
    estate(tmp_path, roles=("root", "designated") if mode == "excluded" else D)
    factory = b.build_root_guard_global
    def poisoned(*args, **kwargs):
        out = factory(*args, **kwargs)
        victim = max(out.result.rows, key=lambda row: row.subject) if last else next(row for row in out.result.rows if row.vlan == 2)
        fact, name = (ROOT, "value") if field.startswith("root") else (ROLE, "role")
        value = getattr(victim, name)
        changes = {"basis": k.Basis.CONFIGURED} if field.endswith("basis") else {"raw": "bad_raw"} if field.endswith("raw") else {"value": "not_a_role", "raw": "not_a_role"}
        changed = replace(victim, **{name: replace(value, **changes)})
        out.result.store.values[k.FactRef(fact=fact, subject=victim.subject)] = getattr(changed, name)
        return replace(out, result=replace(out.result, rows=tuple(changed if row is victim else row for row in out.result.rows)))
    monkeypatch.setattr(b, "build_root_guard_global", poisoned)
    monkeypatch.setattr(m.check.Hop, "__init__", lambda *args, **kwargs: pytest.fail("verdict before whole semantic matrix"))
    policies = () if mode == "empty" else (intent(domain=None if mode == "gap" else "fabric"),)
    with pytest.raises(ValueError, match="^stp_guard_check_input$"):
        m.evaluate_guard_comparisons(tmp_path, LIMITS, policies)


@pytest.mark.parametrize("peer", ["ec", "hsrp", "proof"])
@pytest.mark.parametrize("empty", [False, True])
def test_public_owner_and_byte_closure_precedes_checker_even_without_policies(tmp_path, monkeypatch, peer, empty):
    estate(tmp_path)
    if peer == "proof":
        factory = b.build_root_guard_global
        def source(*args, **kwargs):
            out = factory(*args, **kwargs)
            row = next(row for row in out.result.rows if type(row.value) is k.Known)
            refs = tuple(replace(ref, excerpt_sha256="0" * 64) if type(ref) is k.EvidenceRef else ref for ref in row.value.evidence)
            changed = replace(row, value=replace(row.value, evidence=refs))
            out.result.store.values[k.FactRef(fact=ROOT, subject=row.subject)] = changed.value
            return replace(out, result=replace(out.result, rows=tuple(changed if original is row else original for original in out.result.rows)))
        monkeypatch.setattr(b, "build_root_guard_global", source)
    else:
        cls = m.SummaryPack if peer == "ec" else m.StandbyBriefPack
        finish = cls.finish
        def damaged(self, execution):
            out = finish(self, execution)
            out.store.owners.clear()
            return out
        monkeypatch.setattr(cls, "finish", damaged)
    monkeypatch.setattr(m.check, "evaluate_declared", lambda *args: pytest.fail("checker before complete source closure"))
    with pytest.raises(m.observations.RunnerRefused, match="^p4_(projection_span|observations_store)$"):
        m.evaluate_guard_comparisons(tmp_path, LIMITS, () if empty else (intent(),))


@pytest.mark.parametrize("plant", ["plan", "store", "execution", "source", "budget", "list", "member", "count"])
def test_public_boundary_refuses_opaque_carriers_and_bad_inputs_before_execution(tmp_path, monkeypatch, plant):
    estate(tmp_path)
    out = m.evaluate_guard_comparisons(tmp_path, LIMITS, (intent(),))
    root, budgets, policies = tmp_path, LIMITS, (intent(),)
    if plant in ("plan", "store", "execution", "source"):
        root = {"plan": out.plan, "store": out.source.result.store, "execution": out.source.execution, "source": out.source}[plant]
    elif plant == "budget":
        budgets = object()
    else:
        policies = list(policies) if plant == "list" else (object(),) if plant == "member" else (object(),) * 65
    monkeypatch.setattr(b, "build_root_guard_global", lambda *args, **kwargs: pytest.fail("source before public preflight"))
    with pytest.raises(ValueError, match="^stp_guard_check_" + ("policies" if plant in ("list", "member", "count") else "input") + "$"):
        m.evaluate_guard_comparisons(root, budgets, policies)


@pytest.mark.parametrize("plant", ["guard_int", "role_enum", "other", "fact_authority"])
def test_trusted_hook_uses_strict_fact_states_without_claiming_public_store_admission(tmp_path, monkeypatch, plant):
    estate(tmp_path)
    out = m.evaluate_guard_comparisons(tmp_path, LIMITS, (intent(),))
    ref = k.FactRef(fact=ROOT if plant == "guard_int" else ROLE, subject=out.plan.rows[0].participants[0].subject)
    original = out.source.result.store.values[ref]
    changes = {"guard_int": {"value": 1, "raw": "enabled"}, "role_enum": {"value": b.stp.Role.DESIGNATED},
               "fact_authority": {"value": "root", "raw": "root"}}
    out.source.result.store.values[ref] = object() if plant == "other" else replace(original, **changes[plant])
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("trusted checker replayed parser"))
    if plant == "fact_authority":
        result = m.check.evaluate_declared(out.plan, out.source.result.store, subjects(out.source.execution.envelope))
        assert result.rows[0].state == "not_applicable" and result.rows[0].reason is NA.ROLE_EXCLUDES
    else:
        with pytest.raises(ValueError, match="^stp_guard_check_input$"):
            m.check.evaluate_declared(out.plan, out.source.result.store, subjects(out.source.execution.envelope))
