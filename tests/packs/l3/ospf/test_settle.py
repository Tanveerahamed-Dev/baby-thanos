"""Settlement tests populate actual owner declarations over admitted synthetic groups."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA, adjacency_subject, sample_subject
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.specs import StepSpec
from atlas_brain.model.store import FactStore, bind_reader, bind_writer
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l3.ospf import settle
from atlas_brain.packs.l3.ospf import specs as s


def gap(proof, reason=k.UnknownReason.PARSE_PARTIAL):
    return k.Unknown(reason=reason, detail="planted_gap", evidence=proof, candidates=(), next_evidence=())


def case(starts=(0, 120000000), *, timed=True, plant=None, peer=None, adjacencies=1):
    ports = [f"Gi1/0/{i + 1}" for i in range(adjacencies)]
    files = {n + ".txt": ("Device ID: sw-" + other + "\n").encode() for n, other in (("a", "b"), ("b", "a"))}
    files["p2.json"] = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "sw-" + n, "ports": ports} for n in ("a", "b")],
        "captures": [{"path": n + ".txt", "node": n, "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(files[n + ".txt"]).hexdigest()} for n in ("a", "b")]})
    def point(n, index):
        return {"node": n, "port": ports[index], "process": 1 if n == "a" else 2,
                "router_id": "192.0.2." + ("1" if n == "a" else "2"),
                "address": "198.51.100." + str(index * 2 + (1 if n == "a" else 2)), "vrf": "default"}
    manifest = {"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "base_sha256": sha256(files["p2.json"]).hexdigest(),
        "adjacencies": [{"id": f"adj{i}", "domain": "demo", "area": 0, "left": point("a", i),
                        "right": point("b", i)} for i in range(adjacencies)], "samples": []}
    for index, start in enumerate(starts):
        refs = []
        for node in ("a", "b"):
            path = f"round{index}-{node}.txt"
            files[path] = b"Neighbor ID Pri State Dead Time Address Interface\n"
            refs.append({"path": path, "node": node, "operation": "iosxe.show_ip_ospf_neighbor", "sha256": sha256(files[path]).hexdigest()})
        time = {"unit": "unix_us", "clock": "collector:test", "earliest": start, "latest": start, "bound": "collector_recorded"}
        manifest["samples"].append({"id": f"round{len(starts) - index:02d}", "time": time if timed else None, "captures": refs})
    group, store = admit_members({**files, "p3.json": canonical(manifest)}), FactStore()
    links, writer = bind_writer(store, step=link.STEP), bind_writer(store, step=s.STEP)
    for adjacency in group.adjacencies:
        for point, other in ((adjacency.left, adjacency.right), (adjacency.right, adjacency.left)):
            value = k.Known(value=str(endpoint(other.node, other.port)), basis=k.Basis.DERIVED, raw=None, evidence=adjacency.declaration.evidence + point.node.declaration.evidence)
            links.write(fact=link.PEER, subject=endpoint(point.node, point.port),
                        value=peer(value) if peer is not None else value)
            for sample in group.samples:
                capture = next(c for c in sample.captures if c.source == point.node.key)
                proof = adjacency.declaration.evidence + sample.declaration.evidence + capture.integrity_evidence
                values = {s.STATE: "EXSTART", s.ROLE: "-", s.NEIGHBOR_ID: other.router_id,
                    s.NEIGHBOR_ADDRESS: other.address, s.ROUTER_ID: point.router_id, s.ADDRESS: point.address,
                    s.PROCESS: point.process, s.AREA: adjacency.area, s.NETWORK: "POINT_TO_POINT", s.IGNORE: False,
                    s.VRF: gap(proof, k.UnknownReason.FIELD_NOT_PRINTED), s.ADJACENCY: str(adjacency_subject(adjacency)),
                    s.INTERFACE: str(endpoint(point.node, point.port))}
                for fact, value in zip(settle.TIME, (sample.time.clock, sample.time.earliest, sample.time.latest)
                                       if sample.time is not None else (None, None, None)):
                    values[fact] = value if value is not None else gap(proof, k.UnknownReason.AS_OF_MISSING)
                for fact in s.IDS:
                    value = values[fact]
                    basis = k.Basis.DECLARED if fact in settle.DECLARED else k.Basis.CONFIGURED if fact == s.IGNORE else k.Basis.OBSERVED
                    state = value if isinstance(value, k.Unknown) else k.Known(value=value, basis=basis, raw=None, evidence=proof)
                    if plant is not None:
                        state = plant(adjacency, sample, point, fact, state)
                    writer.write(fact=fact, subject=sample_subject(adjacency, point, sample), value=state)
    return group, store


def result(**kwargs):
    return settle.build_group(*case(**kwargs)).rows[0]


@pytest.mark.parametrize("separation,positive", [(119999999, False), (120000000, True)])
def test_threshold_and_reversed_round_ids_use_conservative_numeric_time(separation, positive):
    row = result(starts=(0, separation))
    assert row.context.value is True and row.span.value == separation
    if positive:
        assert row.persistent.value is True
    else:
        assert row.persistent.reason is k.UnknownReason.SINGLE_SAMPLE
    assert any(n.after_s == 120 for n in row.persistent.next_evidence) if not positive else True


def test_zero_one_and_one_untimed_round_have_visible_unknowns():
    empty, one, untimed = result(starts=()), result(starts=(0,)), result(starts=(0,), timed=False)
    assert empty.context.reason is empty.persistent.reason is empty.span.reason is k.UnknownReason.NOT_COLLECTED
    assert one.context.value is True and one.persistent.reason is one.span.reason is k.UnknownReason.SINGLE_SAMPLE
    assert untimed.persistent.reason is k.UnknownReason.SINGLE_SAMPLE and untimed.span.reason is k.UnknownReason.AS_OF_MISSING


@pytest.mark.parametrize("state", ["FULL", "2WAY", "DOWN", "INIT", "ATTEMPT", "LOADING"])
def test_repeated_nonstuck_states_are_conditional_false_even_when_untimed(state):
    row = result(timed=False, plant=lambda a, t, p, f, v: replace(v, value=state) if f == s.STATE else v)
    assert row.persistent.value is False and row.span.reason is k.UnknownReason.AS_OF_MISSING


@pytest.mark.parametrize("missing", [False, True])
def test_intermediate_full_or_unknown_is_never_skipped(missing):
    def plant(a, t, p, fact, value):
        if t.time.earliest == 120000000 and fact == s.STATE:
            return gap(value.evidence) if missing else replace(value, value="FULL")
        return value
    row = result(starts=(0, 120000000, 240000000), plant=plant)
    assert row.persistent.reason is (k.UnknownReason.PARSE_PARTIAL if missing else k.UnknownReason.CONFLICTING_EVIDENCE)
    assert row.span.value == 240000000
    assert len([ref for ref in row.persistent.evidence if isinstance(ref, k.FactRef)]) == 2 + 6 * len(s.IDS)
    assert row.context.evidence == row.persistent.evidence == row.span.evidence


def test_known_state_conflict_precedes_missing_collector_time():
    row = result(timed=False, plant=lambda a, t, p, f, v:
                 replace(v, value="EXCHANGE") if t.id == "round01" and f == s.STATE else v)
    assert row.persistent.reason is k.UnknownReason.CONFLICTING_EVIDENCE


@pytest.mark.parametrize("kind", ["clock", "overlap"])
def test_clock_change_and_duplicate_intervals_block_positive_persistence(kind):
    row = result(starts=(0, 0) if kind == "overlap" else (0, 120000000),
        plant=lambda a, t, p, f, v: replace(v, value="collector:other")
        if kind == "clock" and t.id == "round01" and f == s.CLOCK else v)
    reason = k.UnknownReason.NON_ATOMIC_VIEW if kind == "overlap" else k.UnknownReason.AS_OF_MISSING
    assert row.span.reason is row.persistent.reason is reason


@pytest.mark.parametrize("fact,new", [(s.PROCESS, 9), (s.ROUTER_ID, "192.0.2.9"), (s.NEIGHBOR_ADDRESS, "198.51.100.9"),
    (s.ADJACENCY, "ospf_adjacency:other"), (s.INTERFACE, "interface:other"), (s.AREA, 9)])
def test_identity_contradictions_block_context_without_erasing_known_span(fact, new):
    row = result(plant=lambda a, t, p, f, v: replace(v, value=new) if p.node.id == "a" and f == fact else v)
    assert row.context.reason is row.persistent.reason is k.UnknownReason.CONFLICTING_EVIDENCE
    assert row.span.value == 120000000


def test_peer_gaps_scope_guards_and_local_processes_are_independent():
    assert result().context.value is True  # Explicit local process 1 versus 2 is valid.
    row = result(peer=lambda value: replace(value, value="interface:other"))
    assert row.context.reason is k.UnknownReason.JOIN_UNPROVEN and row.span.value == 120000000
    for fact, value in ((s.NETWORK, "BROADCAST"), (s.ROLE, "DR"), (s.VRF, "other")):
        row = result(plant=lambda a, t, p, f, v, fact=fact, value=value: k.Known(value=value, basis=k.Basis.OBSERVED, raw=None, evidence=v.evidence) if f == fact else v)
        assert row.context.reason is k.UnknownReason.NOT_OBSERVABLE


def test_required_gaps_propagate_but_unknown_ignore_never_gates_persistence():
    for reason in (k.UnknownReason.NOT_COLLECTED, k.UnknownReason.CAPTURE_ERROR, k.UnknownReason.PARSE_PARTIAL):
        for fact in (s.STATE, s.PROCESS, s.VRF):
            row = result(plant=lambda a, t, p, f, v, fact=fact, reason=reason: gap(v.evidence, reason) if f == fact else v)
            assert row.persistent.reason is reason
    row = result(starts=(0,), plant=lambda a, t, p, f, v:
                 gap(v.evidence, k.UnknownReason.NOT_COLLECTED) if f == s.PROCESS else v)
    assert row.persistent.reason is k.UnknownReason.NOT_COLLECTED
    row = result(plant=lambda a, t, p, f, v: gap(v.evidence, k.UnknownReason.NOT_COLLECTED) if f == s.IGNORE else v)
    assert row.context.value is row.persistent.value is True
    row = result(plant=lambda a, t, p, f, v: replace(v, value=True) if f == s.IGNORE else v)
    assert row.persistent.value is True


def test_every_declared_read_precedes_writer_binding_and_facts_have_one_owner(monkeypatch):
    group, store = case(adjacencies=2)
    assert settle.TYPES == {spec.id: bool if spec.value_type == "boolean" else int if spec.value_type == "integer" else str for spec in s.FACTS}
    expected, reads = 2 * 2 + 2 * len(group.samples) * 2 * len(s.IDS), []
    original_reader, original_writer = settle.bind_reader, settle.bind_writer
    delegate = original_reader(store, step=s.SETTLE)
    class Counted:
        def read(self, **kwargs):
            reads.append((kwargs["fact"], kwargs["subject"]))
            return delegate.read(**kwargs)
    def writer(*args, **kwargs):
        assert len(reads) == expected
        return original_writer(*args, **kwargs)
    monkeypatch.setattr(settle, "bind_reader", lambda *args, **kwargs: Counted())
    monkeypatch.setattr(settle, "bind_writer", writer)
    rows = settle.build_group(group, store).rows
    assert len(rows) == 2 and len({subject for fact, subject in reads if fact != link.PEER}) == 8
    step = StepSpec(id="l3.ospf/test_projection", pack=s.PACK, kind="derive", scope="estate",
                    reads=s.SETTLE.produces, produces=(), evaluator="l3.ospf.test_projection")
    handle = bind_reader(store, step=step)
    assert all(handle.read(fact=s.CONTEXT, subject=row.subject) == row.context for row in rows)
    monkeypatch.setattr(settle, "bind_reader", original_reader)
    monkeypatch.setattr(settle, "bind_writer", original_writer)
    with pytest.raises(ValueError, match="duplicate_write"):
        settle.build_group(group, store)


@pytest.mark.parametrize("plant", ["bool", "basis", "closed"])
def test_late_invalid_owner_contract_prevents_every_settlement_write(monkeypatch, plant):
    def changed(a, t, p, fact, value):
        if a.id == "adj1" and fact == s.EARLIEST:
            if plant == "closed":
                return k.NotApplicable(reason=k.NAReason.ROLE_EXCLUDES, evidence=value.evidence)
            return replace(value, value=True) if plant == "bool" else replace(value, basis=k.Basis.OBSERVED)
        return value
    group, store = case(adjacencies=2, plant=changed)
    monkeypatch.setattr(settle, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before validation"))
    with pytest.raises(ValueError, match="ospf_settle_state" if plant == "closed" else "ospf_settle_fact_contract"):
        settle.build_group(group, store)


def test_printed_vrf_unknown_is_not_filled_and_missing_peer_propagates():
    group, store = case()
    row = settle.build_group(group, store).rows[0]
    original = bind_reader(store, step=s.SETTLE).read(fact=s.VRF,
        subject=sample_subject(group.adjacencies[0], group.adjacencies[0].left, group.samples[0]))
    assert row.context.value is True and original.reason is k.UnknownReason.FIELD_NOT_PRINTED
    row = result(peer=lambda value: gap(value.evidence, k.UnknownReason.PEER_NOT_COLLECTED))
    assert row.context.reason is row.persistent.reason is k.UnknownReason.PEER_NOT_COLLECTED
    assert row.span.value == 120000000


@pytest.mark.parametrize("foreign", [True, False])
def test_late_output_conflicts_leave_all_owners_and_values_unchanged(foreign):
    group, store = case(adjacencies=2)
    step = replace(s.SETTLE, id="l3.ospf/other", produces=(s.SETTLE.produces[-1],)) if foreign else s.SETTLE
    writer = bind_writer(store, step=step)
    if not foreign:
        adjacency = group.adjacencies[-1]
        writer.write(fact=s.CONTEXT, subject=adjacency_subject(adjacency),
                     value=k.Known(value=True, basis=k.Basis.DERIVED, raw=None, evidence=adjacency.declaration.evidence))
    before = (dict(store.owners), dict(store.values))
    with pytest.raises(ValueError, match="ospf_settle_owner" if foreign else "ospf_settle_duplicate_write"):
        settle.build_group(group, store)
    assert (store.owners, store.values) == before
