"""Generated admitted two-end/two-round OSPF cases; no imported fixtures."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore
from atlas_brain.packs.l3.ospf import build, ignore, interface, neighbor
from atlas_brain.packs.l3.ospf import specs as s

P = "GigabitEthernet1"


def bundle(overrides=None, missing=(), timed=True):
    discovery = b"Device ID: sw-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": name, "discovery_id": "sw-" + name, "ports": [P]} for name in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    def point(name, number):
        return {"node": name, "port": P, "process": number, "router_id": "192.0.2." + str(number),
                "address": "198.51.100." + str(number), "vrf": "default"}
    members, samples = {"p2.json": base, "discovery.txt": discovery}, []
    for round_id, start in (("first", 1000000), ("second", 122000000)):
        refs = []
        for name, number, peer in (("a", 1, 7), ("b", 7, 1)):
            bodies = {
                neighbor.OP: ("Neighbor ID Pri State Dead Time Address Interface\n"
                    f"192.0.2.{peer} 0 EXSTART/- 00:00:30 198.51.100.{peer} {P}\n").encode(),
                interface.OP: (f"{P} is up, line protocol is up\n  Internet Address 198.51.100.{number}/30, Area 0\n"
                    f"  Process ID {number}, VRF default Router ID 192.0.2.{number}, Network Type POINT_TO_POINT, Cost: 10\n").encode(),
                ignore.OP: f"interface {P}\n no ip ospf mtu-ignore\n!\nend\n".encode(),
            }
            for index, (operation, raw) in enumerate(bodies.items()):
                if (round_id, name, operation) in missing:
                    continue
                raw = (overrides or {}).get(operation, raw)
                path = f"{round_id}_{name}_{index}.txt"
                members[path] = raw
                refs.append({"path": path, "node": name, "operation": operation, "sha256": sha256(raw).hexdigest()})
        samples.append({"id": round_id, "time": {"unit": "unix_us", "clock": "collector:fixture", "earliest": start,
            "latest": start + 1, "bound": "collector_recorded"} if timed else None, "captures": refs})
    members["p3.json"] = canonical({"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "base_sha256": sha256(base).hexdigest(), "adjacencies": [{"id": "link", "domain": "lab", "area": 0,
            "left": point("a", 1), "right": point("b", 7)}], "samples": samples})
    return admit_members(members)


def facts(group, store=None):
    result = build.build_sample(group, group.samples[0], group.base.nodes[0], store if store is not None else FactStore())
    return result, dict(result.rows[0].facts)


def test_all_sixteen_owned_primitive_facts_bases_proofs_and_distinct_sample_keys():
    group, store = bundle(), FactStore()
    subjects = set()
    for sample in group.samples:
        for node in group.base.nodes:
            result = build.build_sample(group, sample, node, store)
            row, = result.rows
            values = dict(row.facts)
            assert result.quality == "complete" and len(result.parses) == 3 and set(values) == set(s.IDS)
            assert values[s.STATE].value == "EXSTART" and type(values[s.STATE].value) is str
            assert values[s.IGNORE].value is False and values[s.PROCESS].value == row.point.process
            assert values[s.CLOCK].value == "collector:fixture" and values[s.EARLIEST].value == sample.time.earliest
            subjects.add(row.subject)
            captures = {capture.id: capture for capture in sample.captures if capture.source == node.key}
            for identifier, value in row.facts:
                assert type(value.value) in (str, int, bool)
                expected = (k.Basis.CONFIGURED if identifier == s.IGNORE else k.Basis.DECLARED
                            if identifier in (s.CLOCK, s.EARLIEST, s.LATEST, s.ADJACENCY, s.INTERFACE) else k.Basis.OBSERVED)
                assert value.basis is expected
                if identifier in (s.CLOCK, s.EARLIEST, s.LATEST):
                    references = {ref.capture for ref in value.evidence if isinstance(ref, k.EvidenceRef)}
                    assert references == {next(cid for cid, cap in captures.items() if cap.operation == neighbor.OP)}
                assert store.values[k.FactRef(fact=identifier, subject=row.subject)] is value
                assert any(isinstance(ref, k.RegistryRef) and ref.table == "synthetic_p3.samples" for ref in value.evidence)
                for ref in (item for item in value.evidence if isinstance(item, k.EvidenceRef)):
                    raw = captures[ref.capture].raw
                    excerpt = raw[ref.locator.start:ref.locator.end] if isinstance(ref.locator, k.ByteSpan) else raw
                    assert ref.excerpt_sha256 == sha256(excerpt).hexdigest()
    assert len(subjects) == 4 and len(store.values) == 64 and store.owners == {identifier: s.STEP.id for identifier in s.IDS}
    before = dict(store.values)
    with pytest.raises(ValueError, match="ospf_duplicate_write"):
        build.build_sample(group, group.samples[0], group.base.nodes[0], store)
    assert store.values == before


@pytest.mark.parametrize("operation,identifier", [(neighbor.OP, s.STATE), (interface.OP, s.AREA), (ignore.OP, s.IGNORE)])
def test_missing_captures_preserve_all_fact_slots_and_targeted_needs(operation, identifier):
    original, _ = facts(bundle())
    result, values = facts(bundle(missing=(("first", "a", operation),)))
    assert result.rows[0].subject == original.rows[0].subject and len(values) == 16
    assert values[identifier].reason is k.UnknownReason.NOT_COLLECTED
    assert values[identifier].next_evidence[0].operation == operation
    if operation == neighbor.OP:
        assert all(values[key].reason is k.UnknownReason.NOT_COLLECTED for key in (s.CLOCK, s.EARLIEST, s.LATEST))


@pytest.mark.parametrize("operation,identifier,raw,reason", [
    (neighbor.OP, s.STATE, b"% Invalid input\n", k.UnknownReason.CAPTURE_ERROR),
    (interface.OP, s.PROCESS, b"unmodeled\n", k.UnknownReason.PARSE_PARTIAL),
    (ignore.OP, s.IGNORE, f"interface {P}\n source template BASE\nend\n".encode(), k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (ignore.OP, s.IGNORE, f"interface {P}\nend\n".encode(), k.UnknownReason.FIELD_NOT_PRINTED),
])
def test_parser_reasons_are_preserved_without_positive_defaults(operation, identifier, raw, reason):
    _, values = facts(bundle({operation: raw}))
    assert values[identifier].reason is reason


def test_multiple_distinct_peers_and_forged_duplicate_captures_cannot_select_favorable_evidence():
    group = bundle()
    sample = group.samples[0]
    capture = next(item for item in sample.captures if item.operation == neighbor.OP and item.source == group.base.nodes[0].key)
    raw = capture.raw + f"192.0.2.9 0 EXSTART/- 00:00:30 198.51.100.9 {P}\n".encode()
    _, values = facts(bundle({neighbor.OP: raw}))
    assert all(values[key].reason is k.UnknownReason.CONFLICTING_EVIDENCE
               for key in (s.STATE, s.ROLE, s.NEIGHBOR_ID, s.NEIGHBOR_ADDRESS))
    changed = replace(sample, captures=sample.captures + (capture,))
    changed_group = replace(group, samples=(changed,) + group.samples[1:])
    _, values = facts(changed_group)
    assert values[s.STATE].reason is values[s.CLOCK].reason is k.UnknownReason.CONFLICTING_EVIDENCE


def test_printed_identity_is_retained_and_missing_vrf_is_not_filled_from_declaration():
    raw = (f"{P} is up, line protocol is up\n  Internet Address 203.0.113.9/30, Area 192.0.2.9\n"
           "  Process ID 99, Router ID 192.0.2.99, Network Type POINT_TO_POINT, Cost: 10\n").encode()
    result, values = facts(bundle({interface.OP: raw}))
    assert result.quality == "partial" and values[s.VRF].reason is k.UnknownReason.FIELD_NOT_PRINTED
    assert (values[s.PROCESS].value, values[s.AREA].value) == (99, 3221225993)
    assert values[s.ROUTER_ID].value == "192.0.2.99" and values[s.ADDRESS].value == "203.0.113.9"
    assert all(parsed.quality == "complete" for _, parsed in result.parses)


def test_explicit_enabled_control_and_untimed_capture_do_not_invent_health_or_clock():
    raw = f"interface {P}\n ip ospf mtu-ignore\nend\n".encode()
    _, values = facts(bundle({ignore.OP: raw}, timed=False))
    assert values[s.IGNORE].value is True and values[s.IGNORE].basis is k.Basis.CONFIGURED
    assert values[s.STATE].value == "EXSTART"
    assert all(values[key].reason is k.UnknownReason.AS_OF_MISSING for key in (s.CLOCK, s.EARLIEST, s.LATEST))


@pytest.mark.parametrize("plant", ["time", "scope", "foreign"])
def test_all_three_parsers_and_binding_checks_precede_any_write(plant):
    group, store = bundle(), FactStore()
    if plant == "foreign":
        group = bundle({ignore.OP: b"interface GigabitEthernet99 malformed\nend\n"})
    else:
        sample = group.samples[0]
        capture = next(item for item in sample.captures if item.operation == ignore.OP and item.source == group.base.nodes[0].key)
        metadata = capture.resolved_metadata
        metadata = (replace(metadata, collected_utc=group.samples[1].time) if plant == "time" else
                    replace(metadata, scope=replace(metadata.scope, instance="99")))
        changed = replace(sample, captures=tuple(replace(item, metadata=metadata) if item.id == capture.id else item
                                                 for item in sample.captures))
        group = replace(group, samples=(changed,) + group.samples[1:])
    with pytest.raises(ValueError):
        build.build_sample(group, group.samples[0], group.base.nodes[0], store)
    assert not store.values and not store.owners


@pytest.mark.parametrize("state", ["FULL", "2WAY"])
def test_non_stuck_observations_stay_plain_values_without_a_health_verdict(state):
    raw = f"Neighbor ID Pri State Dead Time Address Interface\n192.0.2.7 0 {state}/- 00:00:30 198.51.100.7 {P}\n".encode()
    result, values = facts(bundle({neighbor.OP: raw}))
    assert values[s.STATE].value == state and type(values[s.STATE].value) is str
    assert not hasattr(result.rows[0], "verdict")


@pytest.mark.parametrize("plant", ["population", "bytes", "bounds"])
def test_corrupt_parser_receipt_is_refused_before_registering_any_owner(monkeypatch, plant):
    group, store = bundle(), FactStore()
    original = build.support.PARSERS[interface.OP]
    def broken(capture, ports):
        parsed = original(capture, ports)
        row, = parsed.rows
        if plant == "population":
            return replace(parsed, rows=())
        if plant == "bounds":
            return replace(parsed, rows=(replace(row, spans=(k.ByteSpan(start=0, end=len(capture.raw) + 1),)),))
        fields = dict(row.fields)
        fields["address"] = replace(fields["address"], raw="203.0.113.9", value="203.0.113.9")
        return replace(parsed, rows=(replace(row, fields=tuple(fields.items())),))
    monkeypatch.setitem(build.support.PARSERS, interface.OP, broken)
    with pytest.raises(ValueError):
        facts(group, store)
    assert not store.values and not store.owners


def test_existing_foreign_owner_is_not_partially_replaced_or_augmented():
    group, store = bundle(), FactStore()
    store.owners[s.AREA] = "other/step"
    before = dict(store.owners)
    with pytest.raises(ValueError, match="ospf_fact_owner"):
        facts(group, store)
    assert store.owners == before and not store.values
