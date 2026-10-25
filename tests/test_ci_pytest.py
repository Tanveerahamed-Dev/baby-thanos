"""Synthetic receipt mutation gauntlet."""
from copy import deepcopy
from hashlib import sha256

import pytest

from tools.ci_pytest_receipts import ReceiptError, shard_for, verify_receipts

HEAD = "a" * 40
RUN_ID = "123"
ATTEMPT = "1"
COUNT = 3
FIFO = "tests/runner/test_evidence_facts.py::test_special_file_is_refused"
FIFO_REASON = "FIFO files are not supported on this platform"
NODES = tuple(f"tests/test_probe.py::test_{index:03d}" for index in range(24))


def _bucket(node, count):
    return int.from_bytes(sha256(node.encode("utf-8")).digest(), "big") % count + 1


def _normal_reports():
    return [
        {"when": phase, "outcome": "passed", "reason": ""}
        for phase in ("setup", "call", "teardown")
    ]


def _skip_reports():
    return [
        {"when": "setup", "outcome": "skipped", "reason": FIFO_REASON},
        {"when": "teardown", "outcome": "passed", "reason": ""},
    ]


def _receipts(*, count=COUNT, nodes=NODES, head=HEAD):
    result = []
    for index in range(1, count + 1):
        selected = [node for node in nodes if _bucket(node, count) == index]
        result.append({
            "schema": "atlas-brain.ci-pytest/1",
            "head": head,
            "run_id": RUN_ID,
            "run_attempt": ATTEMPT,
            "platform": "win32",
            "shard_index": index,
            "shard_count": count,
            "universe": list(nodes),
            "selected": selected,
            "finished": selected.copy(),
            "reports": {node: _normal_reports() for node in selected},
            "failed_reports": [],
            "collection_errors": [],
            "pytest_exit": 0,
            "session_exit": 0,
        })
    return result


def _verify(receipts, **overrides):
    context = {
        "head": HEAD, "run_id": RUN_ID,
        "run_attempt": ATTEMPT, "count": COUNT,
    }
    context.update(overrides)
    return verify_receipts(receipts, **context)


@pytest.mark.parametrize("count", [1, 3, 7])
def test_partition_is_full_sha256_and_independent_of_enumeration_order(count):
    nodes = [*NODES, "tests/test_probe.py::test_unicode[\u03b1]"]
    expected = {node: _bucket(node, count) for node in nodes}
    assert {node: shard_for(node, count) for node in nodes} == expected
    assert {node: shard_for(node, count) for node in reversed(nodes)} == expected
    assert set(expected.values()) <= set(range(1, count + 1))


@pytest.mark.parametrize("count", [0, -1, True, False, 1.0, "3"])
def test_partition_refuses_invalid_counts(count):
    with pytest.raises(ValueError):
        shard_for(NODES[0], count)


def test_complete_disjoint_partition_is_accepted():
    receipts = _receipts()
    selected = [node for receipt in receipts for node in receipt["selected"]]
    assert len(selected) == len(set(selected)) == len(NODES)
    assert set(selected) == set(NODES)
    summary = _verify(receipts)
    assert summary["tests"] == len(NODES)
    assert summary["shards"] == COUNT
    assert len(summary["universe_sha256"]) == 64


@pytest.mark.parametrize(("field", "value"), [
    ("schema", "wrong"), ("head", "b" * 40), ("head", HEAD.upper()),
    ("run_id", "124"), ("run_id", "01"), ("run_id", "0"),
    ("run_id", 123), ("run_id", "\u0661\u0662\u0663"),
    ("run_attempt", "2"), ("run_attempt", "01"), ("run_attempt", 1),
    ("platform", "linux"), ("shard_index", 0), ("shard_index", 4),
    ("shard_index", True), ("shard_count", 2), ("shard_count", True),
    ("pytest_exit", 1), ("pytest_exit", False),
    ("session_exit", 1), ("session_exit", False), ("session_exit", None),
    ("failed_reports", ["planted subtest failure"]),
    ("collection_errors", ["planted collection failure"]),
    ("reports", None),
])
def test_receipt_field_plants_are_refused(field, value):
    receipts = _receipts()
    receipts[0][field] = deepcopy(value)
    with pytest.raises(ReceiptError):
        _verify(receipts)


MUTATIONS = {
    "missing_receipt": lambda rs: rs.pop(),
    "duplicate_receipt": lambda rs: rs.append(deepcopy(rs[0])),
    "duplicate_index": lambda rs: rs[0].update(shard_index=2),
    "omitted_universe_item": lambda rs: rs[0]["universe"].pop(),
    "changed_universe_order": lambda rs: rs[0]["universe"].reverse(),
    "duplicate_universe_item": lambda rs: rs[0]["universe"].append(NODES[0]),
    "overlapping_selection": lambda rs: rs[0]["selected"].append(
        rs[1]["selected"][0]),
    "duplicate_selection": lambda rs: rs[0]["selected"].append(
        rs[0]["selected"][0]),
    "empty_selection": lambda rs: rs[0]["selected"].clear(),
    "missing_finish": lambda rs: rs[0]["finished"].pop(),
    "duplicate_finish": lambda rs: rs[0]["finished"].append(
        rs[0]["finished"][0]),
    "extra_finish": lambda rs: rs[0]["finished"].append(
        "tests/test_probe.py::test_extra"),
    "changed_finish_order": lambda rs: rs[0]["finished"].reverse(),
    "missing_reports": lambda rs: rs[0]["reports"].clear(),
    "missing_field": lambda rs: rs[0].pop("session_exit"),
    "unexpected_field": lambda rs: rs[0].update(unexpected=True),
}


@pytest.mark.parametrize("plant", MUTATIONS)
def test_partition_and_completion_plants_are_refused(plant):
    receipts = _receipts()
    MUTATIONS[plant](receipts)
    with pytest.raises(ReceiptError):
        _verify(receipts)


@pytest.mark.parametrize("nodes", [(), (NODES[0],), (NODES[0], NODES[0])])
def test_empty_duplicate_or_unpartitionable_universe_is_refused(nodes):
    with pytest.raises(ReceiptError):
        _verify(_receipts(nodes=nodes))


@pytest.mark.parametrize("context", [
    {"head": "b" * 40}, {"run_id": "124"}, {"run_attempt": "2"},
    {"run_attempt": 1}, {"count": True}, {"count": 2},
])
def test_expected_context_cannot_be_substituted(context):
    with pytest.raises(ReceiptError):
        _verify(_receipts(), **context)


@pytest.mark.parametrize("plant", [
    "missing_call", "duplicate_call", "failed_call", "missing_teardown",
    "wrong_phase_order", "unexpected_skip", "invalid_reason",
    "unexpected_report_field",
])
def test_finish_events_cannot_replace_successful_parent_reports(plant):
    receipts = _receipts()
    node = receipts[0]["selected"][0]
    reports = receipts[0]["reports"][node]
    if plant == "missing_call":
        reports.pop(1)
    elif plant == "duplicate_call":
        reports.insert(1, deepcopy(reports[1]))
    elif plant == "failed_call":
        reports[1].update(outcome="failed", reason="planted")
    elif plant == "missing_teardown":
        reports.pop()
    elif plant == "wrong_phase_order":
        reports.reverse()
    elif plant == "unexpected_skip":
        receipts[0]["reports"][node] = _skip_reports()
    elif plant == "invalid_reason":
        reports[1]["reason"] = None
    else:
        reports[1]["unexpected"] = True
    with pytest.raises(ReceiptError):
        _verify(receipts)


def test_only_allowlisted_skip_with_executed_calls_is_accepted():
    receipts = _receipts(count=1, nodes=(FIFO, NODES[0]))
    receipts[0]["reports"][FIFO] = _skip_reports()
    assert _verify(receipts, count=1)["tests"] == 2
    only_skip = _receipts(count=1, nodes=(FIFO,))
    only_skip[0]["reports"][FIFO] = _skip_reports()
    with pytest.raises(ReceiptError):
        _verify(only_skip, count=1)
