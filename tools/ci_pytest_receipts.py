"""CI-only receipt identities, partition and completed-test validation."""
import hashlib
import json
import re

SCHEMA = "atlas-brain.ci-pytest/1"
FIELDS = {
    "schema", "head", "run_id", "run_attempt", "platform",
    "shard_index", "shard_count", "universe", "selected", "finished",
    "reports", "failed_reports", "collection_errors", "pytest_exit", "session_exit",
}
SKIPS = {
    "tests/runner/test_evidence_facts.py::test_special_file_is_refused":
        "FIFO files are not supported on this platform",
}

LINUX_SKIPS = {
    "tests/test_ci_pytest_cli.py::test_run_receipt_gauntlet[" + plant + "]":
        "Windows run receipt witness"
    for plant in (
        "valid", "wrong-head", "selector", "silent-deselection",
        "module-skip", "precollection-hook", "precollection-list",
        "precollection-directory", "dirty-source", "source-change",
        "failed-subtest", "skipped-subtest", "xfail", "xpass",
    )
}
LINUX_SKIPS.update({
    "tests/runner/test_evidence_facts.py::"
    "test_windows_junction_root_and_members_are_refused[" + value + "]":
        "Windows directory junction control"
    for value in ("False", "True")
})


class ReceiptError(ValueError):
    pass


def _positive(value, label):
    if type(value) is not int or value < 1:
        raise ReceiptError("invalid_" + label)


def _metadata(head, run_id, run_attempt, count):
    if type(head) is not str or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ReceiptError("invalid_head")
    for label, value in (("run_id", run_id), ("run_attempt", run_attempt)):
        if type(value) is not str or re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise ReceiptError("invalid_" + label)
    _positive(count, "shard_count")


def _ids(value, label, nonempty=True):
    if (type(value) is not list
            or any(type(item) is not str or not item for item in value)
            or len(set(value)) != len(value)
            or (nonempty and not value)):
        raise ReceiptError("invalid_" + label)
    return value


def shard_for(nodeid, count):
    _positive(count, "shard_count")
    if type(nodeid) is not str or not nodeid:
        raise ReceiptError("invalid_nodeid")
    try:
        digest = hashlib.sha256(nodeid.encode("utf-8")).digest()
    except UnicodeError as error:
        raise ReceiptError("invalid_nodeid") from error
    return int.from_bytes(digest, "big") % count + 1


def _reports(reports, selected, production, platform="win32"):
    skip_policy = SKIPS if platform == "win32" else LINUX_SKIPS
    if type(reports) is not dict or set(reports) != set(selected):
        raise ReceiptError("report_population_mismatch")
    passed = 0
    for nodeid in selected:
        rows = reports[nodeid]
        if type(rows) is not list or any(
            type(row) is not dict or set(row) != {"when", "outcome", "reason"}
            or any(type(row[key]) is not str for key in row)
            for row in rows
        ):
            raise ReceiptError("invalid_parent_reports")
        phases = [(row["when"], row["outcome"]) for row in rows]
        if phases == [("setup", "passed"), ("call", "passed"), ("teardown", "passed")]:
            if any(row["reason"] for row in rows):
                raise ReceiptError("unexpected_pass_reason")
            passed += 1
            continue
        allowed = (
            [("setup", "skipped"), ("teardown", "passed")],
            [("setup", "passed"), ("call", "skipped"), ("teardown", "passed")],
        )
        if phases not in allowed:
            raise ReceiptError("incomplete_or_failed_parent_reports")
        skipped = [row for row in rows if row["outcome"] == "skipped"]
        reason = skipped[0]["reason"].removeprefix("Skipped: ")
        if not reason or any(row["reason"] for row in rows if row not in skipped):
            raise ReceiptError("invalid_skip_reason")
        if production and skip_policy.get(nodeid) != reason:
            raise ReceiptError("unapproved_skip")
    return passed


def verify_receipts(receipts, *, head, run_id, run_attempt, count, platform="win32"):
    if type(platform) is not str or platform not in ("win32", "linux"):
        raise ReceiptError("invalid_platform")
    _metadata(head, run_id, run_attempt, count)
    if type(receipts) is not list or len(receipts) != count:
        raise ReceiptError("receipt_count_mismatch")
    seen = set()
    universe = None
    selected_all = []
    passed = 0
    for receipt in receipts:
        if type(receipt) is not dict or set(receipt) != FIELDS:
            raise ReceiptError("receipt_fields_mismatch")
        expected = {
            "schema": SCHEMA, "head": head, "run_id": run_id,
            "run_attempt": run_attempt, "platform": platform, "shard_count": count,
        }
        if any(type(receipt[key]) is not type(value) or receipt[key] != value
               for key, value in expected.items()):
            raise ReceiptError("receipt_context_mismatch")
        index = receipt["shard_index"]
        _positive(index, "shard_index")
        if index > count or index in seen:
            raise ReceiptError("duplicate_or_invalid_shard")
        seen.add(index)
        current = _ids(receipt["universe"], "universe")
        if universe is None:
            universe = current
        elif universe != current:
            raise ReceiptError("ordered_universe_mismatch")
        selected = _ids(receipt["selected"], "selected")
        expected_selected = [item for item in current if shard_for(item, count) == index]
        if selected != expected_selected:
            raise ReceiptError("shard_selection_mismatch")
        if _ids(receipt["finished"], "finished") != selected:
            raise ReceiptError("ordered_execution_mismatch")
        for key in ("pytest_exit", "session_exit"):
            if type(receipt[key]) is not int or receipt[key] != 0:
                raise ReceiptError("nonzero_or_missing_" + key)
        for key in ("failed_reports", "collection_errors"):
            if type(receipt[key]) is not list or receipt[key]:
                raise ReceiptError("failed_or_incomplete_" + key)
        passed += _reports(receipt["reports"], selected, production=True, platform=platform)
        selected_all.extend(selected)
    if seen != set(range(1, count + 1)):
        raise ReceiptError("missing_shard")
    if len(selected_all) != len(universe) or set(selected_all) != set(universe):
        raise ReceiptError("coverage_union_mismatch")
    if passed == 0:
        raise ReceiptError("no_passed_calls")
    encoded = json.dumps(universe, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return {
        "head": head, "run_id": run_id, "run_attempt": run_attempt,
        "shards": count, "tests": len(universe),
        "universe_sha256": hashlib.sha256(encoded).hexdigest(),
    }
