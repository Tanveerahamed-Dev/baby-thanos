"""P3 identity primitives are independent of registry order and capture presence."""
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.p3_records import (
    Adjacency,
    Endpoint,
    P3Group,
    Sample,
    adjacency_subject,
    registry_ref,
    sample_subject,
)
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval


def group():
    raw = b'{"synthetic":"identity-test"}'
    def declaration(table, identifier, index):
        return k.Known(value=identifier, basis=k.Basis.DECLARED, raw=identifier,
                       evidence=(registry_ref(raw, table, identifier, index),))
    nodes = tuple(Node(group="demo", id=name, discovery_id="sw-" + name, ports=("Gi1/0/1",),
                       declaration=declaration("adjacencies", name, index))
                  for index, name in enumerate(("a", "b")))
    points = tuple(Endpoint(node=node, port="Gi1/0/1", process=1, router_id=f"192.0.2.{index + 1}",
                            address=f"198.51.100.{index + 1}", vrf="default") for index, node in enumerate(nodes))
    adjacency = Adjacency(id="ab", domain="demo", area=0, left=points[0], right=points[1],
                          declaration=declaration("adjacencies", "ab", 1))
    raw_capture = b"Neighbor ID Pri State Dead Time Address Interface\n"
    capture = Capture(id=k.CaptureId("cap:test"), source=nodes[0].key,
        operation="iosxe.show_ip_ospf_neighbor", rendered="show ip ospf neighbor", codec="utf-8",
        raw=raw_capture, integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw_capture, "utf-8"),
        read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)
    samples = tuple(Sample(id=name, time=None, captures=(capture,), declaration=declaration("samples", name, index))
                    for index, name in enumerate(("first", "second")))
    base = SyntheticGroup(id="demo", nodes=nodes, captures=(), raw=b"{}",
                          declaration=declaration("adjacencies", "demo", 0))
    return P3Group(base=base, raw=raw, adjacencies=(adjacency,), samples=samples)


def test_subjects_keep_full_declared_scope_but_ignore_capture_removal_time_and_registry_bytes():
    original = group()
    adjacency, sample = original.adjacencies[0], original.samples[1]
    expected = sample_subject(adjacency, adjacency.left, sample)
    interval = TimeInterval(earliest=0, latest=1, clock="collector:test", bound=BoundSource.COLLECTOR_RECORDED)
    changed = replace(original, raw=b"changed", samples=(replace(sample, time=interval, captures=()),))
    assert sample_subject(changed.adjacencies[0], adjacency.left, changed.samples[0]) == expected
    assert adjacency_subject(adjacency) == adjacency_subject(replace(adjacency,
        declaration=replace(adjacency.declaration, raw="different")))
    assert expected.startswith("ospf_sample:") and adjacency_subject(adjacency).startswith("ospf_adjacency:")
    assert sample_subject(adjacency, adjacency.right, sample) != expected
    assert sample_subject(adjacency, adjacency.left, replace(sample, id="third")) != expected


@pytest.mark.parametrize("field,value", [("id", "other"), ("domain", "other"), ("area", 1)])
def test_adjacency_context_changes_both_subject_identities(field, value):
    original = group()
    adjacency, sample = original.adjacencies[0], original.samples[0]
    changed = replace(adjacency, **{field: value})
    assert adjacency_subject(changed) != adjacency_subject(adjacency)
    assert sample_subject(changed, changed.left, sample) != sample_subject(adjacency, adjacency.left, sample)


@pytest.mark.parametrize("side", ["left", "right"])
@pytest.mark.parametrize("field,value", [("port", "Gi1/0/2"), ("process", 2), ("router_id", "192.0.2.9"),
                                        ("address", "198.51.100.9"), ("vrf", "other")])
def test_either_endpoint_scope_changes_both_subject_identities(side, field, value):
    original = group()
    adjacency, sample = original.adjacencies[0], original.samples[0]
    changed = replace(adjacency, **{side: replace(getattr(adjacency, side), **{field: value})})
    assert adjacency_subject(changed) != adjacency_subject(adjacency)
    assert sample_subject(changed, changed.left, sample) != sample_subject(adjacency, adjacency.left, sample)


def test_registry_ref_preserves_exact_bytes_and_original_index():
    raw = b'{"samples": [ "second", "first" ]}'
    ref = registry_ref(raw, "samples", "first", 1)
    assert (ref.table, ref.row_id, ref.citation, ref.table_digest) == (
        "synthetic_p3.samples", "first", "/samples/1", sha256(raw).hexdigest())
    for table, index in (("other", 0), ("samples", -1), ("samples", True)):
        with pytest.raises(ValueError):
            registry_ref(raw, table, "first", index)


def test_records_are_immutable_and_foreign_endpoint_is_refused():
    original = group()
    adjacency, sample = original.adjacencies[0], original.samples[0]
    for record, field in ((original, "raw"), (adjacency, "id"), (adjacency.left, "port"), (sample, "id")):
        with pytest.raises(FrozenInstanceError):
            setattr(record, field, "changed")
    with pytest.raises(ValueError, match="p3_endpoint_outside_adjacency"):
        sample_subject(adjacency, replace(adjacency.left, address="198.51.100.9"), sample)


@pytest.mark.parametrize("field,value", [("group", "other"), ("id", "other")])
def test_node_identity_is_part_of_adjacency_and_sample_scope(field, value):
    original = group()
    adjacency, sample = original.adjacencies[0], original.samples[0]
    changed = replace(adjacency, left=replace(adjacency.left, node=replace(adjacency.left.node, **{field: value})))
    assert adjacency_subject(changed) != adjacency_subject(adjacency)
    assert sample_subject(changed, changed.left, sample) != sample_subject(adjacency, adjacency.left, sample)
