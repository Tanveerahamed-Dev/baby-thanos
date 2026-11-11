"""Three-owner HSRP proof routing; synthetic bytes, no peer or health inference."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_p4_leaf_refs import assert_leaf
from test_p4_proof_index import LIMITS, estate

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as h
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner import p4_refs as r
from atlas_brain.runner.pack_runtime import Handler, Parser

LEGEND = b"                     P indicates configured to preempt.\n                     |\n"
HEADER = b"Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
INIT = b"Vl20        0    100   Init    unknown         unknown         203.0.113.1\n"
ACTIVE = b"Vl10        1    110 P Active  local           192.0.2.2       192.0.2.1\n"
STANDBY = b"BD3329      129  90 P Standby 198.51.100.2    local           198.51.100.1\n"
BODY = LEGEND + HEADER + INIT + ACTIVE + STANDBY


def estate3(root, raw=BODY, mode="normal", ending=b"\n"):
    side = estate(root, guard=b"disabled", protocol=b"-", ending=ending)
    if mode != "no_targets":
        side["targets"] += [
            {"id": "hsrp", "node": "a", "operation": h.hsrp.OP, "params": {"groups": [["Vl20", "0"], ["Vl10", "1"], ["BD3329", "129"], ["Vl99", "2"]]}},
            {"id": "hsrp-cold", "node": "b", "operation": h.hsrp.OP, "params": {"groups": [["Vl30", "2"]]}},
        ]
        if mode != "no_captures":
            raw = raw.replace(b"\n", ending)
            (root / "hsrp.txt").write_bytes(raw)
            side["captures"].append({"target": "hsrp", "path": "hsrp.txt", "sha256": sha256(raw).hexdigest()})
    (root / "p4.json").write_bytes(canonical(side))
    return side


def execute3(root, *, finish=True):
    channel = SummaryPack[stp.stp.Result | h.hsrp.Result](LIMITS)
    standby = StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(channel, standby))
    return tree, channel.finish(tree.execution), standby.finish(tree.execution) if finish else standby


def hsrp_output(tree):
    identity = next(member.id for member in tree.execution.envelope.captures if member.target.id == "hsrp")
    return next(out for out in tree.execution.executed if out.receipt.capture.id == identity)


def leaf(output, span, role=k.EvidenceRole.SUBJECT):
    raw = output.receipt.capture.raw
    return k.EvidenceRef(capture=output.receipt.capture.id, locator=span, role=role,
                         excerpt_sha256=sha256(raw[span.start:span.end]).hexdigest())


def raw_claims(raw, row):
    line, cursor, fields = raw[row.span.start:row.span.end], row.span.start, []
    for token in line.split():
        start = raw.index(token, cursor)
        fields.append(k.ByteSpan(start=start, end=start + len(token)))
        cursor = start + len(token)
    state = 4 if len(fields) == 8 else 3
    selected = {fields[0], fields[1], fields[state], k.ByteSpan(start=row.span.start, end=row.span.end)}
    selected.update(span for token, span in zip(line.split()[-3:], fields[-3:], strict=True) if b"." in token and b":" not in token)
    return frozenset(selected)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("shared", [False, True])
def test_real_three_owner_scopes_bind_exact_raw_claims_and_keep_legacy_false_dash(tmp_path, monkeypatch, ending, shared):
    raw = BODY if not shared else BODY.replace(b"198.51.100.2", b"192.0.2.2").replace(b"198.51.100.1", b"192.0.2.1")
    estate3(tmp_path, raw, ending=ending)
    tree, channel, result = execute3(tmp_path)
    for module in (stp.stp, ec.parse_summary, h.hsrp):
        monkeypatch.setattr(module, "parse_capture", lambda *args: pytest.fail("proof routing replayed parser"))
    output = hsrp_output(tree)
    proofs = h.reported_state_proofs(output)
    index = r.ProofIndex(tree.execution, LIMITS)
    assert index.execution is tree.execution and len(index.scopes) == 3 + 4 * len(ec.STEP.produces) + 5
    assert tuple(row for row, _ in proofs) == output.value.rows
    for row, claims in proofs:
        assert row is next(original for original in output.value.rows if original is row)
        expected = raw_claims(output.receipt.capture.raw, row)
        assert claims == tuple(sorted(expected, key=lambda span: (span.start, span.end)))
        owned = next(item for item in result.rows if item.interface == row.interface.raw and item.group == row.group.raw)
        scope = index.scope(h.REPORTED_STATE, owned.subject)
        pairs = frozenset((output.receipt.capture.id, span) for span in expected)
        assert scope.spans == scope.required == pairs and scope.positive == {(output.receipt.capture.id, row.state.span)}
        assert scope.witnesses == frozenset() and scope.target is next(target for target in tree.execution.envelope.targets if target.id == "hsrp")
        assert scope.labels == (("address_family", "ipv4"), ("context", "round"), ("group", owned.group), ("interface", owned.interface),
                                ("node", "a"), ("protocol", "hsrp"), ("target", "hsrp"))
        assert index.scope(h.REPORTED_STATE, owned.subject) is scope and owned.value.evidence[:3] == scope.declarations
        leaves = index.resolve(scope, owned.value.evidence, positive=True)
        for original, resolved in zip(owned.value.evidence, leaves, strict=True):
            assert_leaf(original, resolved, tree.execution)
    assert all(type(scope.witnesses) is frozenset and not scope.witnesses for scope in index.scopes)
    with pytest.raises(AttributeError):
        scope.witnesses = frozenset()
    for capture in index.captures:
        assert index.metadata_evidence(capture.id, capture.collected_utc.evidence)[0]["locator"] == "whole_capture"
    assert tree.result.rows[0].value.value is False and next(row for row in channel.rows if row.group == "2").value.value == "none_reported"
    false_row = tree.result.rows[0]
    with pytest.raises(r.RunnerRefused, match="^p4_projection_positive$"):
        index.resolve(index.scope(stp.ROOT_GUARD, false_row.subject), false_row.value.evidence[:3], positive=True)


@pytest.mark.parametrize("missing", ["interface", "group", "state", "record", "active", "standby", "virtual_ip"])
def test_each_hsrp_known_leaf_is_mandatory(tmp_path, missing):
    estate3(tmp_path, BODY.replace(b"local           192.0.2.2", b"192.0.2.2       192.0.2.2"))
    tree, _, result = execute3(tmp_path)
    output, index = hsrp_output(tree), r.ProofIndex(tree.execution, LIMITS)
    parsed = next(row for row in output.value.rows if row.interface.raw == "Vl10")
    row = next(row for row in result.rows if row.interface == "Vl10")
    span = parsed.span if missing == "record" else getattr(parsed, missing).token.span if missing in ("active", "standby", "virtual_ip") else getattr(parsed, missing).span
    supplied = tuple(ref for ref in row.value.evidence if not (type(ref) is k.EvidenceRef and ref.locator == span))
    assert len(supplied) == len(row.value.evidence) - 1
    with pytest.raises(r.RunnerRefused, match="^p4_projection_positive$"):
        index.resolve(index.scope(h.REPORTED_STATE, row.subject), supplied, positive=True)


@pytest.mark.parametrize("raw,reason", [
    (BODY + ACTIVE, k.UnknownReason.CONFLICTING_EVIDENCE),
    (BODY + INIT.replace(b"203.0.113.1", b"unknown"), k.UnknownReason.IDENTITY_UNRESOLVED),
    (BODY + b"unrecognized trailer\n", k.UnknownReason.PARSE_PARTIAL),
    (BODY.replace(b"Active", b"Listen"), k.UnknownReason.PARSE_PARTIAL),
    (b"fixture#show standby brief\n" + BODY + b"--More--\n", k.UnknownReason.CAPTURE_TRUNCATED),
    (b"fixture#show standby brief\n" + BODY + b"% Invalid input\n", k.UnknownReason.CAPTURE_ERROR),
])
def test_poisoned_candidates_are_role_disjoint_record_witnesses_only(tmp_path, raw, reason):
    estate3(tmp_path, raw)
    tree, _, result = execute3(tmp_path)
    output, index = hsrp_output(tree), r.ProofIndex(tree.execution, LIMITS)
    for row in (row for row in result.rows if row.target.node.id == "a"):
        scope = index.scope(h.REPORTED_STATE, row.subject)
        expected = frozenset((output.receipt.capture.id, candidate.span) for candidate in output.value.rows
                             if (candidate.interface.raw, candidate.group.raw) == (row.interface, row.group))
        assert row.value.reason is reason and scope.witnesses == expected
        assert scope.spans == scope.required == scope.positive == frozenset()
        leaves = index.resolve(scope, row.value.evidence)
        for original, resolved in zip(row.value.evidence, leaves, strict=True):
            assert_leaf(original, resolved, tree.execution)
        for identity, span in expected:
            witness = leaf(output, span, k.EvidenceRole.WITNESS)
            assert witness.capture == identity and index.resolve(scope, scope.declarations + (witness,))
            for positive in (False, True):
                with pytest.raises(r.RunnerRefused, match="^p4_projection_" + ("capture" if positive else "scope") + "$"):
                    index.resolve(scope, scope.declarations + (replace(witness, role=k.EvidenceRole.SUBJECT),), positive=positive)
            with pytest.raises(r.RunnerRefused, match="^p4_projection_capture$"):
                index.resolve(scope, scope.declarations + (witness,), positive=True)
            with pytest.raises(r.RunnerRefused, match="^p4_projection_role$"):
                index.metadata_evidence(identity, (witness,))
            foreign = next(candidate for candidate in output.value.rows if candidate.interface.raw != row.interface)
            with pytest.raises(r.RunnerRefused, match="^p4_projection_role$"):
                index.resolve(scope, scope.declarations + (leaf(output, foreign.span, k.EvidenceRole.WITNESS),))


@pytest.mark.parametrize("positive", [False, True])
@pytest.mark.parametrize("foreign", ["neighbor", "capture", "witness"])
def test_hsrp_same_byte_neighbor_or_foreign_capture_and_known_role_splices_refuse(tmp_path, positive, foreign):
    side = estate3(tmp_path, BODY.replace(b"198.51.100.2", b"192.0.2.2").replace(b"198.51.100.1", b"192.0.2.1"))
    if foreign == "capture":
        raw = LEGEND + HEADER + ACTIVE.replace(b"Vl10", b"Vl30").replace(b" 1 ", b" 2 ")
        (tmp_path / "cold-hsrp.txt").write_bytes(raw)
        side["captures"].append({"target": "hsrp-cold", "path": "cold-hsrp.txt", "sha256": sha256(raw).hexdigest()})
        (tmp_path / "p4.json").write_bytes(canonical(side))
    tree, _, result = execute3(tmp_path)
    output, index = hsrp_output(tree), r.ProofIndex(tree.execution, LIMITS)
    row = next(row for row in result.rows if row.interface == "Vl10")
    scope = index.scope(h.REPORTED_STATE, row.subject)
    donor = next(item for item in tree.execution.executed if item.receipt.capture.id != output.receipt.capture.id and item.receipt.capture.operation == h.hsrp.OP) if foreign == "capture" else output
    parsed = next(item for item in donor.value.rows if item.interface.raw == ("Vl30" if foreign == "capture" else "BD3329"))
    ref = leaf(donor, parsed.state.span if foreign == "capture" else parsed.af_spans[0])
    own_row = next(item for item in output.value.rows if item.interface.raw == "Vl10")
    own_span = own_row.state.span if foreign != "neighbor" else own_row.af_spans[0]
    if foreign == "witness":
        ref = leaf(output, own_row.state.span, k.EvidenceRole.WITNESS)
    assert donor.receipt.capture.raw[ref.locator.start:ref.locator.end] == output.receipt.capture.raw[own_span.start:own_span.end]
    with pytest.raises(r.RunnerRefused, match="^p4_projection_" + ("role" if foreign == "witness" else "scope") + "$"):
        index.resolve(scope, row.value.evidence + (ref,), positive=positive)


@pytest.mark.parametrize("plant", ["output", "receipt", "capture", "value", "parse"])
def test_public_raw_proof_accessor_requires_exact_original_parse_association(tmp_path, monkeypatch, plant):
    estate3(tmp_path)
    tree, _, _ = execute3(tmp_path)
    output = hsrp_output(tree)
    monkeypatch.setattr(h.hsrp, "parse_capture", lambda *args: pytest.fail("raw accessor replay"))
    receipt = replace(output.receipt)
    if plant == "capture":
        object.__setattr__(receipt, "capture", object())
    changed = object() if plant == "output" else replace(output, **({"receipt": object()} if plant == "receipt" else
        {"receipt": receipt} if plant == "capture" else {"value": object()} if plant == "value" else
        {"receipt": replace(output.receipt, parse=replace(output.receipt.parse))}))
    with pytest.raises(ValueError, match="^hsrp_proof_input$"):
        h.reported_state_proofs(changed)


@pytest.mark.parametrize("mode", ["no_targets", "no_captures", "absent"])
def test_zero_own_population_and_capture_loss_keep_declared_scopes_without_invented_bytes(tmp_path, mode):
    estate3(tmp_path, mode="normal" if mode == "absent" else mode)
    tree, _, result = execute3(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    selected = [row for row in result.rows if mode != "absent" or row.interface in ("Vl99", "Vl30")]
    assert len(result.rows) == (0 if mode == "no_targets" else 5) and len(selected) == (2 if mode == "absent" else len(result.rows))
    for row in selected:
        scope = index.scope(h.REPORTED_STATE, row.subject)
        assert scope.spans == scope.required == scope.positive == scope.witnesses == frozenset()
        assert len(scope.declarations) == 3
        for original, resolved in zip(row.value.evidence, index.resolve(scope, row.value.evidence), strict=True):
            assert_leaf(original, resolved, tree.execution)
        with pytest.raises(r.RunnerRefused, match="^p4_projection_"):
            index.resolve(scope, row.value.evidence, positive=True)


def test_only_exact_two_or_three_pack_profiles_are_accepted(tmp_path):
    estate3(tmp_path, mode="no_targets")
    peer = SummaryPack[stp.stp.Result](LIMITS)
    tree = stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    legacy = r.ProofIndex(tree.execution, LIMITS)
    assert legacy.scopes and all(not scope.witnesses for scope in legacy.scopes)
    step = StepSpec(id=StepId("test.extra/parse"), pack=k.PackId("test.extra"), kind="parse_build", scope="device", reads=(), produces=(), evaluator="test.extra.parse")
    declaration = PackDeclaration(pack=step.pack, entity_kinds=(), facts=(), relations=(), steps=(step,),
                                  operations=(OperationBinding(operation="synthetic.extra", step=step.id),))
    class Extra(pipe.Pack[stp.stp.Result | ec.parse_summary.Result]):
        def declaration(self):
            return declaration
        def prepare(self, envelope):
            return pipe.Prepared[stp.stp.Result | ec.parse_summary.Result](targets=(), requests=(),
                handlers=(Handler[stp.stp.Result | ec.parse_summary.Result](binding=declaration.operations[0], parser=Parser[stp.stp.Result | ec.parse_summary.Result]()),))
    tree = stp.build_root_guard_global(tmp_path, LIMITS, peers=(SummaryPack[stp.stp.Result](LIMITS), Extra()))
    with pytest.raises(r.RunnerRefused, match="^p4_projection_profile$"):
        r.ProofIndex(tree.execution, LIMITS)


@pytest.mark.parametrize("which", [0, 1, 2])
def test_hsrp_requires_its_own_node_context_and_target_declaration(tmp_path, which):
    estate3(tmp_path)
    tree, _, result = execute3(tmp_path)
    index = r.ProofIndex(tree.execution, LIMITS)
    row = next(row for row in result.rows if row.interface == "Vl10")
    scope = index.scope(h.REPORTED_STATE, row.subject)
    refs = list(row.value.evidence)
    refs[which] = replace(refs[which], citation="/foreign")
    with pytest.raises(r.RunnerRefused, match="^p4_projection_registry$"):
        index.resolve(scope, tuple(refs), positive=True)


def test_legacy_two_pack_digest_cannot_authorize_uncaptured_hsrp_targets(tmp_path):
    estate3(tmp_path, mode="no_captures")
    tree, _, _ = execute3(tmp_path)
    execution, envelope = tree.execution, tree.execution.envelope
    registration = compile_packs((stp.DECLARATION, ec.DECLARATION)).registration_sha256
    ids = {member.id: k.CaptureId("cap:" + sha256(canonical(("atlas-brain.synthetic-p4/1", sha256(envelope.raw).hexdigest(),
        sha256(envelope.base.raw).hexdigest(), envelope.context, member.target.id, member.path, member.sha256, registration))).hexdigest())
        for member in envelope.captures}
    outputs = tuple(replace(out, receipt=replace(out.receipt, registration_sha256=registration,
        capture=replace(out.receipt.capture, id=ids[out.receipt.capture.id]))) for out in execution.executed)
    changed = replace(execution, envelope=replace(envelope, registration_sha256=registration,
        captures=tuple(replace(member, id=ids[member.id]) for member in envelope.captures)), executed=outputs)
    assert not any(out.receipt.capture.operation == h.hsrp.OP for out in changed.executed)
    with pytest.raises(r.RunnerRefused, match="^p4_projection_profile$"):
        r.ProofIndex(changed, LIMITS)


@pytest.mark.parametrize("extra", [ACTIVE.replace(b"Vl10", b"Vl11"), ACTIVE.replace(b" 1 ", b" 9 ")])
def test_complete_undeclared_hsrp_rows_cannot_disappear_from_the_proof_population(tmp_path, extra):
    estate3(tmp_path, BODY + extra)
    tree, _, _ = execute3(tmp_path, finish=False)
    output = hsrp_output(tree)
    assert output.value.reason is None and output.receipt.parse.quality == "complete" and len(output.value.rows) == 4
    with pytest.raises(r.RunnerRefused, match="^p4_projection_population$"):
        r.ProofIndex(tree.execution, LIMITS)


def test_same_capture_equal_byte_af_span_transplant_is_checked_before_scope_binding(tmp_path):
    estate3(tmp_path, BODY.replace(b"198.51.100.2", b"192.0.2.2").replace(b"198.51.100.1", b"192.0.2.1"))
    tree, _, _ = execute3(tmp_path)
    output = hsrp_output(tree)
    own = next(row for row in output.value.rows if row.interface.raw == "Vl10")
    donor = next(row for row in output.value.rows if row.interface.raw == "BD3329")
    raw, left, right = output.receipt.capture.raw, own.af_spans[0], donor.af_spans[0]
    assert left != right and raw[left.start:left.end] == raw[right.start:right.end]
    changed = replace(own, af_spans=(right,) + own.af_spans[1:])
    forged = replace(output, value=replace(output.value, rows=tuple(changed if row is own else row for row in output.value.rows)))
    assert forged.receipt.parse is forged.value.parse and changed.active is own.active and changed.standby is own.standby
    with pytest.raises(ValueError, match="^hsrp_af$"):
        h.reported_state_proofs(forged)
    execution = replace(tree.execution, executed=tuple(forged if item is output else item for item in tree.execution.executed))
    with pytest.raises(ValueError, match="^hsrp_af$"):
        r.ProofIndex(execution, LIMITS)
