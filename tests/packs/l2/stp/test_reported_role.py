"""Reported STP role is a primitive observation with exactly five authenticated header leaves."""
import json
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256

import pytest
from test_build import P, body, request, target
from test_folder import LIMITS, scenario, write
from test_header_proofs import header_oracle, header_run
from test_root_guard_proofs import oracle as root_oracle
from test_root_guard_proofs import token_plant

from atlas_brain.evidence.capture import ErrorKind
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import p4 as m
from atlas_brain.runner import p4_refs as r

ROLE, ROOT, STATE = (k.FactId("l2.stp." + name) for name in ("reported_role", "root_guard", "reported_state"))
ROLES = ("designated", "root", "alternate", "backup", "disabled")
STATES = ("forwarding", "blocking", "learning", "listening", "disabled")


def captures(value):
    return tuple(ref for ref in value.evidence if type(ref) is k.EvidenceRef)


def assert_leaves(value, output, expected):
    refs = captures(value)
    assert len(refs) == len(expected) and all(type(ref.locator) is k.ByteSpan for ref in refs)
    assert tuple((ref.locator.start, ref.locator.end) for ref in refs) == expected
    assert all(ref.capture == output.receipt.capture.id and ref.role is k.EvidenceRole.SUBJECT
        and ref.excerpt_sha256 == sha256(output.receipt.capture.raw[start:end]).hexdigest()
        for ref, (start, end) in zip(refs, expected, strict=True))
    return refs


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("printed", [False, True])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_raw_role_is_guard_independent_and_preserves_root_bytes(role, state, printed, ending):
    item, output, result = header_run(printed=printed, role=role, state=state, ending=ending,
        indent=b" \t" if ending == b"\r\n" else b"", padding=b"\t " if ending == b"\r\n" else b"")
    assert b.REPORTED_ROLE == ROLE and b.STEP.produces == tuple(sorted((ROLE, ROOT)))
    assert result.store.owners == {ROLE: b.STEP.id, ROOT: b.STEP.id}
    assert set(result.store.values) == {k.FactRef(fact=fact, subject=row.subject) for fact in (ROLE, ROOT) for row in result.rows}
    items = b.fact_rows(result)
    assert len(items) == 2 * len(result.rows)
    for row in result.rows:
        assert type(row.role) is k.Known and type(row.role.value) is str
        assert (row.role.value, row.role.raw, row.role.basis) == (role, role, k.Basis.OBSERVED)
        expected = header_oracle(output.receipt.capture.raw, P, row.vlan)
        assert_leaves(row.role, output, expected)
        assert row.role.evidence[:-5] == row.value.evidence[:1] == item.node.declaration.evidence
        for fact, value in ((ROLE, row.role), (ROOT, row.value)):
            assert b.original_state(fact, row) is result.store.values[k.FactRef(fact=fact, subject=row.subject)] is value
            assert any(fid == fact and source is row and state is value for fid, source, state in items)
        spans = frozenset(k.ByteSpan(start=start, end=end) for start, end in expected)
        allowed, positive, required = b.projection_leaves(ROLE, item, row.vlan, output)
        assert allowed == required == spans and positive == {k.ByteSpan(start=expected[3][0], end=expected[3][1])}
        if printed:
            assert (row.value.value, row.value.raw) == (row.vlan == 1, "enabled" if row.vlan == 1 else "disabled")
            old = root_oracle(output.receipt.capture.raw, row.vlan)
            assert_leaves(row.value, output, tuple(old[i] for i in (6, 5, 1, 2, 0)))
        else:
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.FIELD_NOT_PRINTED
        assert b.projection_leaves(ROOT, item, row.vlan, output)[2] == frozenset()
    assert b.requires_all(ROLE) is True and b.requires_all(ROOT) is False
    for method in (lambda: b.original_state(STATE, result.rows[0]), lambda: b.requires_all(STATE),
                   lambda: b.projection_leaves(STATE, item, 1, output)):
        with pytest.raises(ValueError, match="^stp_projection_fact$"):
            method()


@pytest.mark.parametrize("kind,integrity,reason", [
    ("missing", k.IntegrityState.COMPLETE, k.UnknownReason.NOT_COLLECTED),
    ("empty", k.IntegrityState.COMPLETE, k.UnknownReason.EMPTY_UNREGISTERED),
    ("partial", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    ("duplicate", k.IntegrityState.COMPLETE, k.UnknownReason.CONFLICTING_EVIDENCE),
    ("unknown", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    ("bad_guard", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_PARTIAL),
    ("unsupported", k.IntegrityState.COMPLETE, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    ("normal", k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    ("normal", k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    ("normal", k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED)])
def test_unresolved_roles_keep_only_declarations_and_target_local_whole_witness(kind, integrity, reason):
    item = target(vlans=(1,))
    raw = body(item, None)
    raw = b"" if kind == "empty" else raw + b"unmodelled\n" if kind == "partial" else raw * 2 if kind == "duplicate" else raw
    raw = raw.replace(b"designated", b"inherit") if kind == "unknown" else raw
    raw = body(item, "inherit") if kind == "bad_guard" else raw.replace(b"VLAN0001", b"MST0") if kind == "unsupported" else raw
    result = b.build_root_guard((item,), () if kind == "missing" else (request(item, raw, integrity=integrity),))
    row, = result.rows
    assert type(row.role) is k.Unknown and row.role.reason is reason
    assert row.role.evidence[:1] == item.node.declaration.evidence
    refs = captures(row.role)
    assert len(refs) == bool(result.executed) and all(type(ref.locator) is k.WholeCapture
        and ref.role is k.EvidenceRole.WITNESS and ref.capture == result.executed[0].receipt.capture.id
        and ref.excerpt_sha256 == sha256(raw).hexdigest() for ref in refs)
    need, = row.role.next_evidence
    assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (item.node.key, b.stp.OP, (("port", P),), (ROLE,), (b.STEP.id,))
    assert b.original_state(ROLE, row) is row.role
    assert need.after_s is None and need.unprintable == ()
    if result.executed:
        assert b.projection_leaves(ROLE, item, 1, result.executed[0]) == (frozenset(), frozenset(), frozenset())


@pytest.mark.parametrize("kind,reason", [
    (k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR), (None, k.UnknownReason.CAPTURE_ERROR),
    (k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED), (k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED), ("mapped", k.UnknownReason.PARSE_PARTIAL)])
def test_clean_parser_flags_cannot_mask_capture_or_mapped_role_uncertainty(monkeypatch, kind, reason):
    item, parser = target(vlans=(1,)), b.execute_parsers
    raw = b"" if kind is k.IntegrityState.EMPTY else body(item, None)
    raw = raw.replace(b"designated", b"inherit") if kind == "mapped" else raw
    def produced(*args):
        output, = parser(*args)
        value = replace(output.value, reason=None, rows=tuple(replace(row, reason=None) for row in output.value.rows),
            parse=replace(output.value.parse, quality="complete"))
        cap = output.receipt.capture
        cap = replace(cap, metadata=replace(cap.resolved_metadata, error=ErrorKind.TIMEOUT)) if kind is None else cap if kind == "mapped" else replace(cap, integrity=kind)
        return (replace(output, value=value, receipt=replace(output.receipt, capture=cap, parse=value.parse)),)
    monkeypatch.setattr(b, "execute_parsers", produced)
    row, = b.build_root_guard((item,), (request(item, raw),)).rows
    assert type(row.role) is k.Unknown and row.role.reason is reason and not any(type(ref.locator) is k.ByteSpan for ref in captures(row.role))


@pytest.mark.parametrize("field", ["role", "state"])
def test_role_publisher_authenticates_same_byte_neighbor_header_before_writer(monkeypatch, field):
    item, parser = target(), b.execute_parsers
    raw = body(item, None, 1) + body(item, None, 2)
    def produced(*args):
        output, = parser(*args)
        return (token_plant(output, field, dict(output.value.rows[1].fields)[field]),)
    monkeypatch.setattr(b, "execute_parsers", produced)
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before header authentication"))
    with pytest.raises(ValueError, match="^stp_proof_header$"):
        b.build_root_guard((item,), (request(item, raw),))


def populated(root, printed=True):
    point = target()
    raw = body(point, "enabled" if printed else None, 1) + body(point, "disabled" if printed else None, 2)
    files, side = scenario(raw)
    write(root, files, side)
    return b.build_root_guard_global(root, LIMITS, peers=(m.SummaryPack(LIMITS), m.StandbyBriefPack(LIMITS)))


@pytest.mark.parametrize("printed", [False, True])
def test_global_role_scope_and_cli_observations_are_exact_and_additive(tmp_path, printed):
    tree = populated(tmp_path, printed)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    index = r.ProofIndex(tree.execution, LIMITS)
    output, = tree.execution.executed
    known = tuple(row for row in tree.result.rows if type(row.role) is k.Known)
    assert len(tree.result.rows) == 3 and len(known) == 2 and len(tree.result.store.values) == 6
    for row in known:
        expected = header_oracle(output.receipt.capture.raw, P, row.vlan)
        refs = assert_leaves(row.role, output, expected)
        scope = index.scope(ROLE, row.subject)
        wanted = frozenset((output.receipt.capture.id, k.ByteSpan(start=start, end=end)) for start, end in expected)
        assert scope.spans == scope.required == wanted and scope.positive == {(refs[3].capture, refs[3].locator)}
        assert scope.witnesses == frozenset() and row.role.evidence[:3] == scope.declarations
        assert [ref.table for ref in scope.declarations] == ["synthetic_p2.nodes", "synthetic_p4.context", "synthetic_p4.targets"]
        assert len(index.resolve(scope, row.role.evidence, positive=True)) == 8
        with pytest.raises(m.RunnerRefused, match="^p4_projection_positive$"):
            index.resolve(scope, scope.declarations + refs[3:4], positive=True)
        other = next(source for source in known if source is not row)
        with pytest.raises(m.RunnerRefused, match="^p4_projection_scope$"):
            index.resolve(scope, scope.declarations + captures(other.role), positive=True)
        whole = k.EvidenceRef(capture=output.receipt.capture.id, locator=k.WholeCapture(),
            role=k.EvidenceRole.WITNESS, excerpt_sha256=output.receipt.capture.bytes_sha256)
        with pytest.raises(m.RunnerRefused, match="^p4_projection_reference$"):
            index.resolve(scope, scope.declarations + (whole,), positive=True)
        assert index.scope(ROOT, row.subject).required == frozenset()
    missing, = tuple(row for row in tree.result.rows if type(row.role) is k.Unknown)
    assert missing.role.reason is k.UnknownReason.NOT_COLLECTED and not captures(missing.role)
    actual = m.analyse_folder(tmp_path, LIMITS)
    rows = tuple(map(json.loads, actual["facts/stp_port_vlan.jsonl"].splitlines()))
    assert len(rows) == 6 and {row["fact"] for row in rows} == {ROOT, ROLE}
    assert sum(row["state"] == "known" for row in rows if row["fact"] == ROLE) == 2
    head = json.loads(actual["result.json"])
    assert head["denominator"]["l2.stp"] == 3 and head["checks"] == "not_implemented"
    assert head["registration_sha256"] == tree.execution.envelope.registration_sha256
    assert head["registry_sha256"] == sha256(before["p4.json"]).hexdigest() and head["base_registry_sha256"] == sha256(before["p2.json"]).hexdigest()
    out = tmp_path.with_name(tmp_path.name + "-role-cli")
    child = subprocess.run([sys.executable, "-m", "atlas_brain.runner", "--format", "p4-observations",
        "--evidence", str(tmp_path), "--out", str(out), "--workers", "1"], capture_output=True, text=True, check=True, timeout=60)
    assert child.stdout.startswith("runner: ok ")
    assert (out / "facts/stp_port_vlan.jsonl").read_bytes() == actual["facts/stp_port_vlan.jsonl"]
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize("plant,code", [("mask", "store"), ("type", "value"), ("spec", "spec"), ("drop", "store"), ("extra", "store"), ("subject", "population")])
def test_role_state_census_and_store_cannot_be_masked_by_root(tmp_path, monkeypatch, plant, code):
    populated(tmp_path)
    factory, adapter = b.build_root_guard_global, b.fact_rows
    if plant == "spec":
        monkeypatch.setattr(b, "DECLARATION", replace(b.DECLARATION, facts=tuple(replace(fact, value_type="boolean") if fact.id == ROLE else fact for fact in b.DECLARATION.facts)))
    def built(*args, **kwargs):
        tree = factory(*args, **kwargs)
        row = next(row for row in tree.result.rows if type(row.role) is k.Known)
        if plant in ("mask", "type", "spec"):
            changed = replace(row, role=replace(row.role, **({"value": False} if plant != "mask" else {})))
            if plant in ("type", "spec"):
                tree.result.store.values[k.FactRef(fact=ROLE, subject=row.subject)] = changed.role
            return replace(tree, result=replace(tree.result, rows=tuple(changed if source is row else source for source in tree.result.rows)))
        if plant == "drop":
            tree.result.store.values.pop(k.FactRef(fact=ROLE, subject=row.subject))
        elif plant == "extra":
            tree.result.store.values[k.FactRef(fact=STATE, subject=row.subject)] = row.role
        else:
            return replace(tree, result=replace(tree.result, rows=tuple(source for source in tree.result.rows if source is not row)))
        return tree
    if plant == "mask":
        monkeypatch.setattr(b, "fact_rows", lambda owner: tuple((fact, row, owner.store.values[k.FactRef(fact=fact, subject=row.subject)])
            if fact == ROLE else (fact, row, value) for fact, row, value in adapter(owner)))
    monkeypatch.setattr(b, "build_root_guard_global", built)
    monkeypatch.setattr(m, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before role closure"))
    with pytest.raises(m.RunnerRefused, match="^p4_observations_" + code + "$"):
        m.analyse_folder(tmp_path, LIMITS)


def test_fact_rows_exposes_original_fields_without_reusing_the_validation_hook(monkeypatch):
    _, _, result = header_run()
    expected = tuple((ROLE, row, row.role) for row in result.rows) + tuple((ROOT, row, row.value) for row in result.rows)
    monkeypatch.setattr(b, "original_state", lambda *args: pytest.fail("fact tuple reused independent validation hook"))
    actual = b.fact_rows(result)
    assert len(actual) == len(expected) and all(fact == wanted and row is original and value is state
        for (fact, row, value), (wanted, original, state) in zip(actual, expected, strict=True))
