"""R1 candidates use actual admitted bytes and owner facts, never default MTU or health."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.mtu import build as l2_mtu
from atlas_brain.packs.l3.mtu import build as l3_mtu
from atlas_brain.packs.l3.ospf import build, r1, settle
from tools.p3_cases import CASES, IGNORE, INTERFACE_MTU, IP_MTU, NEIGHBOR, members


def prepared(case="supported", change=None):
    files = members(canonical, case)
    manifest = json.loads(files["p3.json"])
    if change is not None:
        for sample in manifest["samples"]:
            for capture in sample["captures"]:
                path = capture["path"]
                files[path] = change(sample, capture, files[path])
                capture["sha256"] = sha256(files[path]).hexdigest()
        files["p3.json"] = canonical(manifest)
    group, store = admit_members(files), FactStore()
    for node in group.base.nodes:
        discovery.build_node(group.base, node, store)
    for sample in group.samples:
        for node in group.base.nodes:
            l2_mtu.build_sample(group, sample, node, store)
            l3_mtu.build_sample(group, sample, node, store)
            build.build_sample(group, sample, node, store)
    link.build_group(group.base, store)
    settle.build_group(group, store)
    return group, store


def result(case="supported", change=None):
    group, store = prepared(case, change)
    return group, r1.build_group(group, store)


@pytest.mark.parametrize("case", CASES)
def test_every_generated_case_has_one_declared_candidate_result_and_open_coverage(case):
    group, answer = result(case)
    assert len(answer.rows) == 1
    assert answer.rows[0].state in ("problem", "unknown", "not_applicable")
    assert answer.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    assert dict(answer.denominator) == {"declared_adjacencies": 1, "rounds": len(group.samples),
                                       "expected_endpoint_samples": 2 * len(group.samples)}
    assert answer.rows[0].hops[0].id == "peer_context"
    if answer.rows[0].state == "unknown":
        assert answer.rows[0].next_evidence and isinstance(answer.rows[0].hops[-1].state, k.Unknown)


def test_positive_chain_is_ordered_directional_and_cites_every_round():
    group, answer = result()
    row, = answer.rows
    assert row.state == "problem" and row.reason is None
    assert tuple(h.id for h in row.hops) == ("peer_context", "ip_mtu", "sampled_persistence",
                                           "receiving_control", "candidate")
    assert row.receiving_endpoint == endpoint(group.adjacencies[0].right.node, group.adjacencies[0].right.port)
    assert all(isinstance(h.state, k.Known) and h.state.value is True for h in row.hops)
    assert len(row.hops[1].state.evidence) == 4 and len(row.hops[3].state.evidence) == 2
    assert all(isinstance(ref, k.FactRef) for ref in row.hops[1].state.evidence)
    assert row.next_evidence and all(need.after_s == 120 for need in row.next_evidence)


@pytest.mark.parametrize("case,hop,reason", [
    ("single_sample", "sampled_persistence", k.UnknownReason.SINGLE_SAMPLE),
    ("short_interval", "sampled_persistence", k.UnknownReason.SINGLE_SAMPLE),
    ("untimed", "sampled_persistence", k.UnknownReason.AS_OF_MISSING),
    ("untimed_conflict", "sampled_persistence", k.UnknownReason.CONFLICTING_EVIDENCE),
    ("different_clock", "sampled_persistence", k.UnknownReason.AS_OF_MISSING),
    ("changed_peer", "peer_context", k.UnknownReason.CONFLICTING_EVIDENCE),
    ("changed_receiver", "ip_mtu", k.UnknownReason.CONFLICTING_EVIDENCE),
    ("missing_mtu", "ip_mtu", k.UnknownReason.NOT_COLLECTED),
    ("missing_ignore", "receiving_control", k.UnknownReason.NOT_COLLECTED),
    ("no_rounds", "peer_context", k.UnknownReason.NOT_COLLECTED),
])
def test_named_unknown_stops_at_first_unresolved_premise(case, hop, reason):
    _, answer = result(case)
    row, = answer.rows
    assert row.state == "unknown" and row.reason is reason
    assert row.hops[-1].id == hop and all(h.id != "candidate" for h in row.hops)
    assert row.next_evidence


@pytest.mark.parametrize("case,hop", [("full", "sampled_persistence"), ("two_way", "sampled_persistence"),
                                     ("same_mtu", "ip_mtu")])
def test_non_candidates_are_not_applicable_never_healthy(case, hop):
    _, answer = result(case)
    row, = answer.rows
    assert row.state == "not_applicable" and row.reason is k.NAReason.ROLE_EXCLUDES
    assert row.hops[-1].id == hop and not row.next_evidence


def test_receiving_ignore_blocks_with_counter_evidence_but_larger_side_alone_does_not():
    _, blocked = result("mtu_ignore")
    row, = blocked.rows
    assert row.state == "not_applicable" and row.reason is k.NAReason.FEATURE_NOT_ENABLED
    assert row.hops[-1].id == "receiving_control"
    counters = [ref for ref in row.hops[-1].state.evidence if isinstance(ref, k.EvidenceRef)]
    assert counters and all(ref.role is k.EvidenceRole.COUNTER_EVIDENCE for ref in counters)
    def larger(sample, capture, raw):
        return raw.replace(b"no ip ospf mtu-ignore", b"ip ospf mtu-ignore") if capture["node"] == "a" and capture["operation"] == IGNORE else raw
    assert result(change=larger)[1].rows[0].state == "problem"
    assert result("missing_ignore", change=larger)[1].rows[0].reason is k.UnknownReason.NOT_COLLECTED


def test_any_receiver_ignore_is_a_countercondition_even_with_another_missing_control():
    def control(sample, capture, raw):
        if capture["operation"] == IGNORE and capture["node"] == "b":
            return raw.replace(b"no ip ospf mtu-ignore", b"ip ospf mtu-ignore" if sample["id"] == "first" else b"")
        return raw
    row = result(change=control)[1].rows[0]
    assert row.state == "not_applicable" and row.reason is k.NAReason.FEATURE_NOT_ENABLED


def test_l2_values_cannot_substitute_for_equal_or_omitted_ip_mtu():
    def l2_only(sample, capture, raw):
        return raw.replace(b"MTU 1500", b"MTU 9000") if capture["node"] == "a" and capture["operation"] == INTERFACE_MTU else raw
    assert result("same_mtu", change=l2_only)[1].rows[0].reason is k.NAReason.ROLE_EXCLUDES
    def omitted(sample, capture, raw):
        return raw.splitlines(keepends=True)[0] if capture["node"] == "b" and capture["operation"] == IP_MTU else raw
    row = result(change=omitted)[1].rows[0]
    assert row.state == "unknown" and row.reason is k.UnknownReason.FIELD_NOT_PRINTED and row.hops[-1].id == "ip_mtu"


def test_mixed_equal_mismatch_and_observed_state_disagreement_are_not_cherry_picked():
    def equal(sample, capture, raw):
        return raw.replace(b"9000", b"1500") if sample["id"] == "second" and capture["node"] == "a" and capture["operation"] == IP_MTU else raw
    assert result(change=equal)[1].rows[0].reason is k.UnknownReason.CONFLICTING_EVIDENCE
    def state(sample, capture, raw):
        return raw.replace(b"EXSTART", b"FULL") if sample["id"] == "second" and capture["operation"] == NEIGHBOR else raw
    assert result(change=state)[1].rows[0].reason is k.UnknownReason.CONFLICTING_EVIDENCE


def test_all_reads_precede_evaluation_and_correlation_does_not_write(monkeypatch):
    group, store = prepared()
    actual, reads = r1.bind_reader, []
    delegate = actual(store, step=r1.STEP)
    class Observed:
        def read(self, **kwargs):
            reads.append((kwargs["fact"], kwargs["subject"]))
            return delegate.read(**kwargs)
    typed = r1._typed
    def checked(*args):
        assert len(reads) == 3 + len(group.samples) * 4
        return typed(*args)
    monkeypatch.setattr(r1, "bind_reader", lambda *args, **kwargs: Observed())
    monkeypatch.setattr(r1, "_typed", checked)
    first = r1.build_group(group, store)
    reads.clear()
    assert r1.build_group(group, store) == first
    assert r1.STEP.produces == ()
    broken = replace(group, samples=tuple(reversed(group.samples)))
    reads.clear()
    assert r1.build_group(broken, store).rows[0].state == "problem"
