"""Generated P3 projection and unknown-hop cases; no qualified-device claims."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.evidence.p3_records import sample_subject
from atlas_brain.kernel import states as k
from atlas_brain.runner import p3
from atlas_brain.runner.records import RunnerRefused
from tools.p3_cases import members


def analyse(case="supported"):
    files = members(canonical, case)
    return files, p3.analyse_group(admit_members(files))


def leaves(records):
    for record in records:
        if record["kind"] == "fact":
            yield from leaves(record["state"]["evidence"])
        else:
            yield record


def test_supported_projection_retains_all_samples_owners_and_recursive_byte_proofs():
    files, (payload, lines) = analyse()
    assert payload["schema"] == p3.SCHEMA and payload["interpretation"] == p3.INTERPRETATION
    assert payload["scope"] == p3.SCOPE and payload["timing"] == p3.TIMING and payload["variant_support"] == "allowlisted"
    assert payload["denominator"] == {"declared_adjacencies": 1, "rounds": 2, "expected_endpoint_samples": 4}
    assert payload["coverage"]["state"] == "unknown" and payload["coverage"]["reason"] == "denominator_open"
    assert len(payload["nodes"]) == len(payload["endpoints"]) == len(payload["samples"]) == 2
    assert len(payload["captures"]) == 22 and len({item["id"] for item in payload["captures"]}) == 22
    assert all(len(sample["endpoints"]) == 2 and all(len(point["facts"]) == 18 for point in sample["endpoints"])
               for sample in payload["samples"])
    finding, = payload["findings"]
    assert finding["state"] == "problem" and finding["hops"][-1]["id"] == "candidate"
    observed_samples, sources = set(), set()
    for ref in leaves(finding["evidence"]):
        if ref["kind"] != "capture":
            continue
        raw = files[ref["path"]]
        excerpt = raw[ref["start"]:ref["end"]] if ref["locator"] == "bytes" else raw
        assert sha256(raw).hexdigest() == ref["capture_sha256"] and sha256(excerpt).hexdigest() == ref["sha256"]
        sources.add(ref["source"])
        if "sample" in ref:
            observed_samples.add(ref["sample"])
    assert len(sources) == 2 and observed_samples == {"first", "second"}
    assert any("unique cause is not proven" in line for line in lines)
    assert payload["registry_sha256"] == sha256(files["p3.json"]).hexdigest()


@pytest.mark.parametrize("case,state,reason,hop", [
    ("single_sample", "unknown", "single_sample", "sampled_persistence"),
    ("untimed_conflict", "unknown", "conflicting_evidence", "sampled_persistence"),
    ("missing_mtu", "unknown", "not_collected", "ip_mtu"),
    ("mtu_ignore", "not_applicable", "feature_not_enabled", "receiving_control"),
    ("missing_ignore", "unknown", "not_collected", "receiving_control"),
])
def test_required_negative_cases_stop_at_the_visible_owner_hop(case, state, reason, hop):
    _, (payload, lines) = analyse(case)
    finding, = payload["findings"]
    assert (finding["state"], finding["reason"], finding["hops"][-1]["id"]) == (state, reason, hop)
    assert finding["hops"][-1]["state"]["state"] == state
    assert any(hop + "=" in line for line in lines)
    if state == "unknown":
        assert finding["next_evidence"] and any(line.startswith("next_evidence=") for line in lines)
    assert all(item["state"] != "ok" for item in payload["findings"])


def test_ordering_does_not_change_payload_summary_or_catalogue():
    group = admit_members(members(canonical))
    expected, expected_lines = p3.analyse_group(group)
    changed = replace(group, base=replace(group.base, nodes=tuple(reversed(group.base.nodes)),
                      captures=tuple(reversed(group.base.captures))),
                      samples=tuple(reversed(tuple(replace(sample, captures=tuple(reversed(sample.captures)))
                                                   for sample in group.samples))),
                      adjacencies=tuple(reversed(group.adjacencies)))
    actual, actual_lines = p3.analyse_group(changed)
    assert canonical(actual) == canonical(expected) and actual_lines == expected_lines
    assert actual["catalogue_digest"] == expected["catalogue_digest"]


@pytest.mark.parametrize("case", ["untimed", "full", "two_way", "same_mtu", "short_interval", "unmodeled",
                                  "missing_neighbor", "no_rounds", "changed_peer", "different_clock",
                                  "missing_peer", "changed_receiver"])
def test_other_insufficient_or_countercondition_cases_never_publish_a_supported_candidate(case):
    _, (payload, _) = analyse(case)
    finding, = payload["findings"]
    assert finding["state"] in ("unknown", "not_applicable") and finding["hops"][-1]["id"] != "candidate"


@pytest.mark.parametrize("foreign", ["node", "round"])
def test_direct_output_fact_cannot_launder_another_valid_sample_leaf(monkeypatch, foreign):
    group = admit_members(members(canonical))
    result = p3.p3_pipeline.run(group)
    adjacency = group.adjacencies[0]
    first, second = group.samples
    target = sample_subject(adjacency, adjacency.left, first)
    other = sample_subject(adjacency, adjacency.right if foreign == "node" else adjacency.left,
                           first if foreign == "node" else second)
    destination = k.FactRef(fact=p3.s.STATE, subject=target)
    result.store.values[destination] = result.store.values[k.FactRef(fact=p3.s.STATE, subject=other)]
    monkeypatch.setattr(p3.p3_pipeline, "run", lambda supplied: result)
    with pytest.raises(RunnerRefused):
        p3.analyse_group(group)
