from dataclasses import replace
from hashlib import sha256

import pytest
from test_global_protocol_finish import BODY, LIMITS, build, scenario
from test_member_proofs import required, wrapped
from test_reported_protocol_build import B, request, target

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.runner import p4
from atlas_brain.runner.p4_refs import ProofIndex


@pytest.mark.parametrize("protocol,expected_protocol", [(b"LACP", "lacp"), (b"PAgP", "pagp"), (b"-", "none_reported")])
def test_real_member_fact_consumes_original_accessor_once_and_closes_proofs_at_write(tmp_path, monkeypatch, protocol, expected_protocol):
    raw = wrapped().replace(b"LACP", protocol)
    scenario(tmp_path, raw)
    peer, tree = build(tmp_path)
    original = next(item for item in tree.execution.executed if item.receipt.capture.operation == ec.parse_summary.OP)
    index = ProofIndex(tree.execution, LIMITS)
    assert all(not scope.required for scope in index.scopes if scope.reference.fact in (p4.stp.ROOT_GUARD, ec.REPORTED_PROTOCOL))
    expected = {(original.receipt.capture.id, span) for span in required(raw).values()}
    calls, writes, accessor, write = [], [], ec.reported_member_proofs, FactWriter.write
    def checked_accessor(domain, output):
        assert output.receipt is original.receipt and output.value is original.value
        calls.append((domain, output))
        return accessor(domain, output)
    def checked_writer(self, **kwargs):
        if kwargs["fact"] == ec.REPORTED_MEMBER_TOKENS:
            value = kwargs["value"]
            scope = index.scope(ec.REPORTED_MEMBER_TOKENS, kwargs["subject"])
            assert tuple(ref for ref in value.evidence if type(ref) is k.RegistryRef) == scope.declarations
            if type(value) is k.Known:
                refs = tuple(ref for ref in value.evidence if type(ref) is k.EvidenceRef)
                assert type(scope.required) is frozenset
                assert scope.positive == {(original.receipt.capture.id, required(raw)["port0"])}
                assert {(ref.capture, ref.locator) for ref in refs} == scope.required == expected
                assert tuple((ref.capture, ref.locator) for ref in refs) == tuple(sorted(expected, key=lambda pair: (pair[1].start, pair[1].end)))
                assert all(ref.role is k.EvidenceRole.SUBJECT and ref.excerpt_sha256 == sha256(raw[ref.locator.start:ref.locator.end]).hexdigest() for ref in refs)
                assert index.resolve(scope, value.evidence, positive=True)
            writes.append(value)
        return write(self, **kwargs)
    monkeypatch.setattr(ec, "reported_member_proofs", checked_accessor)
    monkeypatch.setattr(FactWriter, "write", checked_writer)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("member materialization reparsed capture"))
    facts = peer.finish(tree.execution)
    cold, row, absent = facts.rows
    assert len(calls) == 1 and calls[0][0] is row.target and calls[0][1] is facts.executed[0]
    assert (row.member_tokens.value, row.member_tokens.raw, row.member_tokens.basis) == ("Gi1/0/1(P) Gi1/0/2(D)", None, k.Basis.DERIVED)
    assert (row.value.value, row.value.raw, row.value.basis) == (expected_protocol, protocol.decode(), k.Basis.OBSERVED)
    assert cold.member_tokens.reason is k.UnknownReason.NOT_COLLECTED and absent.member_tokens.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert writes == [row.member_tokens for row in facts.rows]
    assert ec.REPORTED_MEMBER_TOKENS == "l2.etherchannel.reported_member_tokens"


def test_late_accessor_failure_precedes_every_ec_writer(monkeypatch):
    first, last = target(), target(node=B)
    original = ec.reported_member_proofs
    calls = []
    def refused(domain, output):
        calls.append(domain.node.key)
        if domain.node.key == last.node.key:
            raise ValueError("planted_late_member_proof")
        return original(domain, output)
    monkeypatch.setattr(ec, "reported_member_proofs", refused)
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before all target proofs"))
    with pytest.raises(ValueError, match="^planted_late_member_proof$"):
        ec.build_reported_protocol((first, last), (request(first), request(last, identity="z")))
    assert calls == [first.node.key, last.node.key]


def test_omitted_member_column_preserves_protocol_and_requires_member_evidence():
    item = target()
    out = ec.build_reported_protocol((item,), (request(item, BODY.replace(b" Gi1/0/1(P)", b"")),))
    value = out.rows[0].member_tokens
    assert out.rows[0].value.value == "lacp" and type(value) is k.Unknown and value.reason is k.UnknownReason.FIELD_NOT_PRINTED
    need, = value.next_evidence
    assert (need.node, need.operation, need.params, need.resolves, need.reruns) == (item.node.key, ec.parse_summary.OP, (), (ec.REPORTED_MEMBER_TOKENS,), (ec.STEP.id,))


@pytest.mark.parametrize("part", ["group", "channel", "record", "wrap", "port0", "flag0", "token0", "port1", "flag1", "token1"])
def test_each_required_leaf_is_necessary_even_when_replaced_by_a_valid_duplicate(tmp_path, monkeypatch, part):
    raw = wrapped()
    scenario(tmp_path, raw)
    finish = gp.SummaryPack.finish
    def weakened(self, execution):
        out = finish(self, execution)
        row = next(row for row in out.rows if type(row.member_tokens) is k.Known)
        span = required(raw)[part]
        evidence = row.member_tokens.evidence
        removed = next(ref for ref in evidence if type(ref) is k.EvidenceRef and ref.locator == span)
        duplicate = next(ref for ref in evidence if type(ref) is k.EvidenceRef and ref is not removed)
        value = replace(row.member_tokens, evidence=tuple(ref for ref in evidence if ref is not removed) + (duplicate,))
        out.store.values[k.FactRef(fact=ec.REPORTED_MEMBER_TOKENS, subject=row.subject)] = value
        return replace(out, rows=tuple(replace(original, member_tokens=value) if original is row else original for original in out.rows))
    monkeypatch.setattr(gp.SummaryPack, "finish", weakened)
    monkeypatch.setattr(p4, "result_bundle", lambda *args, **kwargs: pytest.fail("bundle before complete member proof"))
    with pytest.raises(p4.RunnerRefused, match="^p4_projection_positive$"):
        p4.analyse_folder(tmp_path, LIMITS)


@pytest.mark.parametrize("positive", [False, True])
def test_same_capture_other_group_flag_with_identical_bytes_is_not_member_proof(tmp_path, positive):
    raw = BODY.replace(b"in use: 1", b"in use: 2").replace(b"aggregators: 1", b"aggregators: 2") + b"2 Po2(SU) LACP Gi1/0/2(P)\n"
    scenario(tmp_path, raw)
    peer, tree = build(tmp_path)
    out = peer.finish(tree.execution)
    rows = [row for row in out.rows if row.target.node.id == "b"]
    index = ProofIndex(tree.execution, LIMITS)
    flags = [next(ref for ref in row.member_tokens.evidence if type(ref) is k.EvidenceRef and raw[ref.locator.start:ref.locator.end] == b"P") for row in rows]
    assert flags[0].excerpt_sha256 == flags[1].excerpt_sha256 and flags[0].locator != flags[1].locator
    context = next(ref for ref in rows[0].value.evidence if type(ref) is k.EvidenceRef and raw[ref.locator.start:ref.locator.end] == b"LACP")
    assert index.resolve(index.scope(ec.REPORTED_MEMBER_TOKENS, rows[0].subject), rows[0].member_tokens.evidence + (context,), positive=True)
    evidence = tuple(flags[1] if ref is flags[0] else ref for ref in rows[0].member_tokens.evidence)
    with pytest.raises(p4.RunnerRefused, match="^p4_projection_scope$"):
        index.resolve(index.scope(ec.REPORTED_MEMBER_TOKENS, rows[0].subject), evidence, positive=positive)


