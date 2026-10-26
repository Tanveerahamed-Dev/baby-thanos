"""Expected-byte reuse must preserve uncached comparison and recursive validation."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.packs.l3.ospf import specs as s
from atlas_brain.runner import p3, p3_manifest
from atlas_brain.runner import p3_manifest_custody as custody
from atlas_brain.runner.records import RunnerRefused
from tools.p3_cases import members


@pytest.fixture(scope="module")
def encoded():
    payload, _ = p3.analyse_group(admit_members(members(canonical)))
    identity = {"captures": sorted(({"capture": row["id"], "sha256": row["sha256"]}
        for row in payload["captures"]), key=lambda row: row["capture"]),
        "registry_sha256": payload["registry_sha256"], "base_registry_sha256": payload["base_registry_sha256"]}
    metadata = {key: value for key, value in identity.items() if key != "captures"}
    metadata.update(digest=sha256(canonical(identity)).hexdigest(), captures=len(payload["captures"]),
                    files=len(payload["captures"]) + 2)
    return canonical((payload, metadata))


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def fact_rows(payload):
    rows = payload["endpoints"] + payload["adjacencies"]
    rows += [point for sample in payload["samples"] for point in sample["endpoints"]]
    return {(fact, row["subject"]): state for row in rows for fact, state in row["facts"].items()}


class FreshExpected(dict):
    """Oracle: compare against freshly encoded live expected data every occurrence."""
    def __init__(self, expected):
        super().__init__()
        self.expected = expected

    def __contains__(self, key):
        return key in self.expected

    def __getitem__(self, key):
        return canonical(self.expected[key])


def oracle(patch):
    original = custody._Custody.__init__
    def fresh(self, payload):
        original(self, payload)
        self.fact_bytes = FreshExpected(self.facts)
        self.registry_bytes = FreshExpected(self.registry)
    patch.setattr(custody._Custody, "__init__", fresh)


def test_valid_result_and_every_recursive_visit_match_fresh_expected_comparisons(encoded, monkeypatch):
    counts = []
    for uncached in (True, False):
        payload, metadata = json.loads(encoded)
        before = json.dumps(payload, sort_keys=True)
        visits = {"state": 0, "proofs": 0}
        state, proofs = custody._Custody.state, custody._Custody.proofs
        def visit_state(self, value, chain=(), method=state, counts=visits):
            counts["state"] += 1
            return method(self, value, chain)
        def visit_proofs(self, value, chain=(), method=proofs, counts=visits):
            counts["proofs"] += 1
            return method(self, value, chain)
        with monkeypatch.context() as patch:
            if uncached:
                oracle(patch)
            patch.setattr(custody._Custody, "state", visit_state)
            patch.setattr(custody._Custody, "proofs", visit_proofs)
            assert p3_manifest.validate(payload, metadata) is None
        assert json.dumps(payload, sort_keys=True) == before
        counts.append(visits)
    assert counts[0] == counts[1] and counts[0]["state"] > 100 and counts[0]["proofs"] > 100


def test_expected_encodings_are_bounded_but_every_incoming_proof_is_encoded(encoded, monkeypatch):
    payload, metadata = json.loads(encoded)
    declarations = [payload["group"]] + payload["nodes"] + payload["samples"] + payload["adjacencies"]
    expected = list(fact_rows(payload).values()) + [row["declaration"]["evidence"][0] for row in declarations]
    expected_ids = {id(row) for row in expected}
    incoming_ids = {id(row["state"]) for row in objects(payload) if row.get("kind") == "fact"}
    incoming_ids |= {id(row) for row in objects(payload) if row.get("kind") == "registry"}
    incoming_ids -= expected_ids
    calls = {}
    original = custody.canonical
    def observed(value):
        identity = id(value)
        if identity in expected_ids or identity in incoming_ids:
            calls[identity] = calls.get(identity, 0) + 1
        return original(value)
    monkeypatch.setattr(custody, "canonical", observed)
    p3_manifest.validate(payload, metadata)
    active = [calls[identity] for identity in expected_ids if identity in calls]
    assert active and set(active) == {2}  # First comparison plus final mutation recheck.
    assert incoming_ids and all(calls.get(identity, 0) >= 1 for identity in incoming_ids)


@pytest.mark.parametrize("plant", ["boolean", "float", "large_integer", "surrogate"])
def test_malformed_incoming_types_keep_the_same_refusal_as_uncached_comparison(encoded, monkeypatch, plant):
    for uncached in (True, False):
        payload, metadata = json.loads(encoded)
        proof = next(row for row in objects(payload) if row.get("kind") == "fact"
                     and row["fact"] == s.PROCESS and row["state"].get("value") == 1)
        if plant == "surrogate":
            proof["state"]["raw"] = "\ud800"
        else:
            proof["state"]["value"] = {"boolean": True, "float": 1.0, "large_integer": 9007199254740992}[plant]
        with monkeypatch.context() as patch:
            if uncached:
                oracle(patch)
            with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
                p3_manifest.validate(payload, metadata)


def test_each_invocation_rechecks_modified_expected_objects_and_recovers_after_refusal(encoded):
    payload, metadata = json.loads(encoded)
    p3_manifest.validate(payload, metadata)
    state = next(state for (fact, _), state in fact_rows(payload).items()
                 if fact == s.PROCESS and state["value"] == 1)
    state["value"] = 2
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)
    fresh_payload, fresh_metadata = json.loads(encoded)
    p3_manifest.validate(fresh_payload, fresh_metadata)


def test_static_aliases_do_not_require_a_new_authentication_or_identity_claim(encoded):
    payload, metadata = json.loads(encoded)
    expected = fact_rows(payload)
    for row in objects(payload):
        if row.get("kind") == "fact" and row["fact"] == s.PROCESS:
            row["state"] = expected[row["fact"], row["subject"]]
    p3_manifest.validate(payload, metadata)


@pytest.mark.parametrize("family", ["fact", "registry"])
def test_mutation_after_first_comparison_is_refused_at_final_expected_recheck(encoded, monkeypatch, family):
    payload, metadata = json.loads(encoded)
    key = next(key for key, state in fact_rows(payload).items() if key[0] == s.PROCESS and state["value"] == 1)
    changed = []
    original = custody._Custody.proofs
    def alter(self, value, chain=()):
        original(self, value, chain)
        if not changed and family == "fact" and key in self.fact_bytes:
            self.facts[key]["raw"] = "changed_after_comparison"
            changed.append(True)
        registry_key = "synthetic_p3.samples", "first"
        if not changed and family == "registry" and registry_key in self.registry_bytes:
            self.registry[registry_key]["value"]["captures"][0]["sha256"] = "0" * 64
            changed.append(True)
    monkeypatch.setattr(custody._Custody, "proofs", alter)
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)
    assert changed


def receiving_control_ref(payload, round_id):
    finding = payload["findings"][0]
    sample = next(row for row in payload["samples"] if row["id"] == round_id)
    point = next(row for row in sample["endpoints"]
                 if row["facts"][str(s.INTERFACE)]["value"] == finding["receiving_endpoint"])
    return next(ref for ref in finding["hops"][3]["state"]["evidence"]
                if ref["kind"] == "fact" and ref["fact"] == s.IGNORE and ref["subject"] == point["subject"])


@pytest.mark.parametrize("plant", ["false_zero", "one_true", "registry", "unknown_subject", "round_state"])
def test_late_incoming_proof_is_checked_after_valid_same_key_cache_hits(encoded, monkeypatch, plant):
    payload, metadata = json.loads(encoded)
    finding = payload["findings"][0]
    registered = fact_rows(payload)
    family = "registry" if plant == "registry" else "fact"
    if family == "registry":
        sample = next(row for row in payload["samples"] if row["id"] == "first")
        expected = sample["declaration"]["evidence"][0]
        key = expected["table"], expected["row_id"]
        selected = expected
    else:
        selected = (next(row for row in objects(payload) if row.get("kind") == "fact"
                         and row["fact"] == s.PROCESS and row["state"].get("value") == 1)
                    if plant == "one_true" else receiving_control_ref(payload, "first"))
        key = selected["fact"], selected["subject"]
        expected = registered[key]
        assert expected["state"] == "known"
        if plant != "one_true":
            assert expected["value"] is False and type(expected["value"]) is bool
    expected_bytes = canonical(expected)
    positive = json.loads(json.dumps(selected))
    corrupt = json.loads(json.dumps(selected))
    if plant in ("false_zero", "one_true"):
        corrupt["state"]["value"] = 0 if plant == "false_zero" else True
        assert corrupt["state"]["value"] == positive["state"]["value"]
        assert type(corrupt["state"]["value"]) is not type(positive["state"]["value"])
    elif plant == "registry":
        corrupt["value"]["time"]["earliest"] += 1
        assert corrupt["value"]["time"]["earliest"] <= corrupt["value"]["time"]["latest"]
        assert set(corrupt) == set(positive) and set(corrupt["value"]) == set(positive["value"])
    elif plant == "unknown_subject":
        corrupt["subject"] = "ospf_sample:" + "0" * 64
        assert (corrupt["fact"], corrupt["subject"]) not in registered
        assert canonical(corrupt["state"]) == canonical(positive["state"])
    else:
        second = receiving_control_ref(payload, "second")
        assert second["fact"] == positive["fact"] and second["subject"] != positive["subject"]
        assert second["state"]["value"] is positive["state"]["value"] is False
        corrupt["state"] = json.loads(json.dumps(second["state"]))
        assert canonical(corrupt["state"]) != canonical(positive["state"])
    if plant != "unknown_subject":
        assert ((corrupt["table"], corrupt["row_id"]) if family == "registry"
                else (corrupt["fact"], corrupt["subject"])) == key
    finding["evidence"].extend((positive, corrupt))
    positive_input = positive if family == "registry" else positive["state"]
    corrupt_input = corrupt if family == "registry" else corrupt["state"]
    instances, serialized, completed = [], [], []
    old_proofs, old_state, old_canonical = custody._Custody.proofs, custody._Custody.state, custody.canonical
    def observed_proofs(self, value, chain=()):
        if value is finding["evidence"]:
            cache = self.registry_bytes if family == "registry" else self.fact_bytes
            assert key in cache  # Earlier original proofs already populated this exact key.
            instances.append(self)
        return old_proofs(self, value, chain)
    def observed_state(self, value, chain=()):
        result = old_state(self, value, chain)
        if family == "fact" and value is positive_input:
            completed.append(True)
        return result
    def observed_canonical(value):
        if value is positive_input:
            serialized.append("positive")
        elif value is corrupt_input:
            serialized.append("corrupt")
        return old_canonical(value)
    monkeypatch.setattr(custody._Custody, "proofs", observed_proofs)
    monkeypatch.setattr(custody._Custody, "state", observed_state)
    monkeypatch.setattr(custody, "canonical", observed_canonical)
    with pytest.raises(RunnerRefused, match="^invalid_manifest$"):
        p3_manifest.validate(payload, metadata)
    assert len(instances) == 1 and canonical(expected) == expected_bytes
    if family == "fact":
        assert completed == [True]  # The appended valid control finished all recursive checks.
    if plant == "unknown_subject":
        unknown = corrupt["fact"], corrupt["subject"]
        assert unknown not in instances[0].facts and unknown not in instances[0].fact_bytes
        assert serialized == ["positive"]  # Unknown keys refuse before expected-byte lookup.
    else:
        assert serialized == ["positive", "corrupt"]
