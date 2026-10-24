"""Pure result-directory assembly: byte ordering, refusals and manifest custody."""
from hashlib import sha256

import pytest

from atlas_brain.contract.bundle import json_lines, result_bundle


def test_json_lines_use_authoritative_pair_keys_and_one_lf_per_object():
    rows = {("node:sw-b", "fact:a"): {"value": 2},
        ("node:sw-a", "fact:z"): {"value": 1},
        ("node:sw-a", "fact:a"): {"value": 0}}
    assert json_lines(rows) == b'{"value":0}\n{"value":1}\n{"value":2}\n'
    assert rows[("node:sw-b", "fact:a")] == {"value": 2}


@pytest.mark.parametrize("reverse_groups", [False, True])
@pytest.mark.parametrize("reverse_rows", [False, True])
def test_bundle_is_stable_under_group_row_and_result_insertion_order(reverse_groups, reverse_rows):
    rows = {("node:sw-b", "fact:b"): {"value": False},
        ("node:sw-a", "fact:a"): {"value": True}}
    if reverse_rows:
        rows = dict(reversed(list(rows.items())))
    facts = {"node": rows, "interface": {}}
    if reverse_groups:
        facts = dict(reversed(list(facts.items())))
    files = result_bundle({"status": "incomplete", "schema_version": "0.1.0"},
        facts=facts, checks={"l1.interface": {}})
    expected = result_bundle({"schema_version": "0.1.0", "status": "incomplete"},
        facts={"interface": {}, "node": {("node:sw-a", "fact:a"): {"value": True},
            ("node:sw-b", "fact:b"): {"value": False}}}, checks={"l1.interface": {}})
    assert files == expected
    assert list(files) == sorted(files)
    assert files["result.json"] == b'{"schema_version":"0.1.0","status":"incomplete"}'
    assert files["facts/node.jsonl"] == b'{"value":true}\n{"value":false}\n'


def test_bundle_manifest_hashes_every_payload_and_excludes_itself():
    files = result_bundle({"status": "incomplete"}, facts={"node": {}},
        checks={"l1.interface": {("l1.interface.oper", "node:sw-a"): {"state": "unknown"}}})
    assert set(files) == {"result.json", "facts/node.jsonl", "checks/l1.interface.jsonl", "MANIFEST.sha256"}
    lines = files["MANIFEST.sha256"].decode("ascii").splitlines()
    paths = []
    for line in lines:
        digest, path = line.split("  ")
        assert digest == sha256(files[path]).hexdigest()
        paths.append(path)
    assert paths == sorted(set(files) - {"MANIFEST.sha256"})
    assert files["facts/node.jsonl"] == b""
    assert files["checks/l1.interface.jsonl"] == b'{"state":"unknown"}\n'
    assert b"ok" not in files["result.json"]


def test_empty_result_has_only_supplied_root_and_manifest():
    files = result_bundle({"status": "incomplete"}, facts={}, checks={})
    assert set(files) == {"result.json", "MANIFEST.sha256"}
    assert files["result.json"] == b'{"status":"incomplete"}'
    assert json_lines({}) == b""


@pytest.mark.parametrize("key", [("one",), ("a", "b", "c"), "ab", (1, "id"),
    ("subject", None), type("PairSubclass", (tuple,), {})(("subject", "id")),
    ("subject", type("StringSubclass", (str,), {})("id"))])
def test_json_lines_refuse_invalid_or_custom_ordering_keys(key):
    with pytest.raises((TypeError, ValueError)):
        json_lines({key: {}})


@pytest.mark.parametrize("value", [None, [], True, "record", 1])
def test_records_and_result_root_must_be_json_objects(value):
    with pytest.raises(TypeError):
        json_lines({("subject", "id"): value})
    with pytest.raises(TypeError):
        result_bundle(value, facts={}, checks={})


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf"), 9007199254740992,
    -9007199254740992, {"nested": [0.5]}])
def test_writer_refusals_apply_to_root_and_every_jsonl_record(value):
    with pytest.raises((TypeError, ValueError)):
        result_bundle({"value": value}, facts={}, checks={})
    with pytest.raises((TypeError, ValueError)):
        result_bundle({}, facts={"node": {("subject", "id"): {"value": value}}}, checks={})


@pytest.mark.parametrize("kind,name", [("facts", "../node"), ("facts", "a/b"),
    ("facts", "node.json"), ("facts", "receipt.json"), ("facts", "Node"),
    ("checks", "receipt"), ("checks", "l1..interface"), ("checks", "l1.interface.extra"),
    ("checks", "l1/interface"), ("checks", "l1\\interface"), ("checks", "l1.interface\nother"),
    ("checks", "l1.Interface")])
def test_bundle_refuses_noncontract_paths_and_invalid_pack_ids(kind, name):
    with pytest.raises((TypeError, ValueError)):
        result_bundle({}, facts={name: {}} if kind == "facts" else {},
            checks={name: {}} if kind == "checks" else {})

def test_custom_pair_iteration_is_refused_before_it_can_run():
    class HostilePair(tuple):
        def __iter__(self):
            raise AssertionError("custom_iteration_ran")

    with pytest.raises(TypeError, match="non_json_type"):
        json_lines({HostilePair(("subject", "id")): {}})
