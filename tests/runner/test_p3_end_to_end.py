"""End-to-end P3 regressions alter only generated CLI bytes and declared sidecars."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import adjacency_subject, sample_subject
from atlas_brain.evidence.synthetic import endpoint
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter, bind_reader
from atlas_brain.packs.l1.link import build as link
from atlas_brain.packs.l2.discovery import build as discovery
from atlas_brain.packs.l2.mtu import build as l2_mtu
from atlas_brain.packs.l3.mtu import build as l3_mtu
from atlas_brain.packs.l3.ospf import specs as s
from atlas_brain.runner import p3, p3_pipeline
from atlas_brain.runner.p3_evidence import resolve_evidence
from tools.p3_cases import IGNORE, INTERFACE_MTU, IP_MTU, NEIGHBOR, PORT, members


def prepared(case="supported", edit=None):
    files = members(canonical, case)
    base, sidecar = json.loads(files["p2.json"]), json.loads(files["p3.json"])
    if edit is not None:
        edit(files, base, sidecar)
    for capture in base["captures"]:
        capture["sha256"] = sha256(files[capture["path"]]).hexdigest()
    files["p2.json"] = canonical(base)
    sidecar["base_sha256"] = sha256(files["p2.json"]).hexdigest()
    assert sum(len(sample["captures"]) for sample in sidecar["samples"]) <= 64
    for sample in sidecar["samples"]:
        for capture in sample["captures"]:
            capture["sha256"] = sha256(files[capture["path"]]).hexdigest()
    files["p3.json"] = canonical(sidecar)
    return admit_members(files)


def projected(case="supported", edit=None):
    group = prepared(case, edit)
    payload, _ = p3.analyse_group(group)
    return group, payload


def walk(records):
    encoded = [canonical(record) for record in records]
    assert encoded == sorted(set(encoded))
    for record in records:
        yield record
        if record["kind"] == "fact":
            yield from walk(record["state"]["evidence"])


def verified_leaves(group, records):
    captures = {capture.id: capture for capture in group.base.captures}
    captures.update((capture.id, capture) for sample in group.samples for capture in sample.captures)
    seen = set()
    for record in walk(records):
        if record["kind"] == "capture":
            capture = captures[record["capture"]]
            assert record["source"] == capture.source and record["operation"] == capture.operation
            assert record["capture_sha256"] == sha256(capture.raw).hexdigest()
            if record["locator"] == "bytes":
                assert 0 <= record["start"] < record["end"] <= len(capture.raw)
                raw = capture.raw[record["start"]:record["end"]]
            else:
                assert record["locator"] == "whole_capture"
                raw = capture.raw
            assert record["sha256"] == sha256(raw).hexdigest()
            seen.add(record["capture"])
        elif record["kind"] == "registry":
            raw = group.base.raw if record["table"].startswith("synthetic_p2.") else group.raw
            assert record["table_digest"] == sha256(raw).hexdigest()
            value = json.loads(raw)
            for token in record["citation"].split("/")[1:]:
                value = value[int(token)] if isinstance(value, list) else value[token]
            assert record["value"] == value
        else:
            assert record["kind"] == "fact"
    return seen


@pytest.mark.parametrize("separation", [119000000, 119999999, 120000000])
def test_guaranteed_interval_boundary_survives_admission_owners_and_projection(separation):
    def edit(files, base, sidecar):
        first, second = sidecar["samples"]
        first["time"].update(earliest=0, latest=1000000)
        second["time"].update(earliest=1000000 + separation, latest=6000000 + separation)
        first["id"], second["id"] = "z_earlier", "a_later"
    group, payload = projected(edit=edit)
    facts = payload["adjacencies"][0]["facts"]
    assert facts[str(s.SPAN)]["state"] == "known" and facts[str(s.SPAN)]["value"] == separation
    finding = payload["findings"][0]
    if separation == 120000000:
        assert finding["state"] == "problem" and facts[str(s.PERSISTENT)]["value"] is True
    else:
        assert finding["state"] == "unknown" and finding["reason"] == "single_sample"
        assert facts[str(s.PERSISTENT)]["reason"] == "single_sample"
    assert {row["id"] for row in payload["samples"]} == {"z_earlier", "a_later"}
    verified_leaves(group, finding["evidence"])


@pytest.mark.parametrize("kind,reason", [("overlap", "non_atomic_view"), ("duplicate", "non_atomic_view"),
                                        ("clock", "as_of_missing")])
def test_collector_uncertainty_never_becomes_a_positive_candidate(kind, reason):
    def edit(files, base, sidecar):
        first, second = sidecar["samples"]
        if kind == "clock":
            second["time"]["clock"] = "collector:other"
        else:
            first["time"].update(earliest=0, latest=1000000)
            second["time"].update(earliest=1000000 if kind == "overlap" else 0,
                                  latest=2000000 if kind == "overlap" else 1000000)
    group, payload = projected(edit=edit)
    assert payload["findings"][0]["state"] == "unknown" and payload["findings"][0]["reason"] == reason
    assert payload["adjacencies"][0]["facts"][str(s.SPAN)]["reason"] == reason
    verified_leaves(group, payload["findings"][0]["evidence"])


@pytest.mark.parametrize("missing", [False, True])
def test_middle_full_or_missing_capture_is_retained_between_matching_endpoints(missing):
    def edit(files, base, sidecar):
        middle = json.loads(json.dumps(sidecar["samples"][0]))
        middle["id"] = "middle"
        middle["time"].update(earliest=50000000, latest=50000001)
        kept = []
        for capture in middle["captures"]:
            original = capture["path"]
            if missing and capture["node"] == "b" and capture["operation"] == NEIGHBOR:
                continue
            capture["path"] = "middle_" + original
            raw = files[original]
            files[capture["path"]] = raw.replace(b"EXSTART", b"FULL") if not missing and capture["operation"] == NEIGHBOR else raw
            kept.append(capture)
        middle["captures"] = kept
        sidecar["samples"].append(middle)
    group, payload = projected(edit=edit)
    assert payload["denominator"] == {"declared_adjacencies": 1, "rounds": 3, "expected_endpoint_samples": 6}
    assert {row["id"] for row in payload["samples"]} == {"first", "middle", "second"}
    finding = payload["findings"][0]
    assert finding["state"] == "unknown"
    assert finding["reason"] == ("not_collected" if missing else "conflicting_evidence")
    assert finding["next_evidence"] and all(hop["id"] != "candidate" for hop in finding["hops"])
    assert len(group.samples) == 3
    verified_leaves(group, finding["evidence"])


def test_untimed_disagreement_survives_projection_instead_of_becoming_only_a_time_gap():
    group, payload = projected("untimed_conflict")
    facts = payload["adjacencies"][0]["facts"]
    assert facts[str(s.SPAN)]["reason"] == "as_of_missing"
    assert facts[str(s.PERSISTENT)]["reason"] == "conflicting_evidence"
    assert payload["findings"][0]["reason"] == "conflicting_evidence"
    assert all(sample.time is None for sample in group.samples)


@pytest.mark.parametrize("node,blocked", [("a", False), ("b", True)])
def test_explicit_ignore_is_directional_and_counter_evidence_is_resolvable(node, blocked):
    def edit(files, base, sidecar):
        for sample in sidecar["samples"]:
            for capture in sample["captures"]:
                if capture["node"] == node and capture["operation"] == IGNORE:
                    path = capture["path"]
                    files[path] = files[path].replace(b"no ip ospf mtu-ignore", b"ip ospf mtu-ignore")
    group, payload = projected(edit=edit)
    finding = payload["findings"][0]
    assert finding["receiving_endpoint"] == endpoint(group.adjacencies[0].right.node, PORT)
    changed = [point["facts"][str(s.IGNORE)] for sample in payload["samples"]
               for point in sample["endpoints"] if point["node"] == node]
    assert changed and all(state["state"] == "known" and state["value"] is True for state in changed)
    assert finding["state"] == ("not_applicable" if blocked else "problem")
    if blocked:
        assert finding["reason"] == "feature_not_enabled"
        counters = [ref for ref in walk(finding["evidence"])
                    if ref["kind"] == "capture" and ref["role"] == "counter_evidence"]
        assert counters and all(ref["source"] == group.adjacencies[0].right.node.key for ref in counters)
        assert all(ref["operation"] == IGNORE for ref in counters)
    verified_leaves(group, finding["evidence"])


def two_adjacencies(files, base, sidecar):
    port = "GigabitEthernet2"
    for node in base["nodes"]:
        node["ports"].append(port)
    for capture in base["captures"]:
        path = capture["path"]
        files[path] += b"-------------------------\n" + files[path].replace(PORT.encode(), port.encode())
    second = json.loads(json.dumps(sidecar["adjacencies"][0]))
    second["id"] = "link2"
    for point in (second["left"], second["right"]):
        point["port"] = port
        point["address"] = point["address"].replace("198.51.100.", "203.0.113.")
    sidecar["adjacencies"].append(second)
    for sample in sidecar["samples"]:
        for capture in sample["captures"]:
            path, operation = capture["path"], capture["operation"]
            raw = files[path]
            extra = raw.replace(PORT.encode(), port.encode()).replace(b"198.51.100.", b"203.0.113.")
            if operation in (IP_MTU, INTERFACE_MTU):
                extra = extra.replace(b"9000", b"1500")
            if operation == NEIGHBOR:
                files[path] = raw + b"".join(extra.splitlines(keepends=True)[1:])
            elif operation == IGNORE:
                files[path] = raw.removesuffix(b"end\n") + b"!\n" + extra
            else:
                files[path] = raw + extra


def test_two_adjacencies_share_one_store_without_overwriting_samples_and_keep_full_proofs(monkeypatch):
    group = prepared(edit=two_adjacencies)
    written, original = [], FactWriter.write
    def observe(self, *, fact, subject, value):
        written.append((fact, subject, self.step.id))
        return original(self, fact=fact, subject=subject, value=value)
    with monkeypatch.context() as patch:
        patch.setattr(FactWriter, "write", observe)
        result = p3_pipeline.run(group)
    expected = {(fact, endpoint(node, port)) for node in group.base.nodes for port in node.ports
                for fact in discovery.IDS + (link.PEER,)}
    expected.update((fact, sample_subject(adjacency, point, sample)) for sample in group.samples
                    for adjacency in group.adjacencies for point in (adjacency.left, adjacency.right)
                    for fact in p3_pipeline.SAMPLE_FACTS)
    expected.update((fact, adjacency_subject(adjacency)) for adjacency in group.adjacencies
                    for fact in s.SETTLE.produces)
    assert len(written) == len(expected) == len({(fact, subject) for fact, subject, _ in written})
    assert {(fact, subject) for fact, subject, _ in written} == expected
    specs = discovery.FACTS + link.FACTS + l2_mtu.FACTS + l3_mtu.FACTS + s.FACTS + s.SETTLED_FACTS
    owners = {fact.id: fact.step for fact in specs}
    assert all(owner == owners[fact] for fact, _, owner in written)
    handle = bind_reader(result.store, step=p3.PROJECT)
    refs = tuple(k.FactRef(fact=fact, subject=subject) for fact, subject in sorted(expected))
    assert all(isinstance(handle.read(fact=ref.fact, subject=ref.subject), k.Known) for ref in refs)
    proofs = resolve_evidence(group, handle, refs)
    capture_ids = {capture.id for capture in group.base.captures}
    capture_ids.update(capture.id for sample in group.samples for capture in sample.captures)
    assert verified_leaves(group, proofs) == capture_ids
    assert len(result.receipts) == len(capture_ids) == 22
    payload, _ = p3.analyse_group(group)
    assert payload["denominator"] == {"declared_adjacencies": 2, "rounds": 2, "expected_endpoint_samples": 8}
    assert {row["adjacency"]: row["state"] for row in payload["findings"]} == {"link": "problem", "link2": "not_applicable"}
    assert all(len(sample["endpoints"]) == 4 for sample in payload["samples"])
