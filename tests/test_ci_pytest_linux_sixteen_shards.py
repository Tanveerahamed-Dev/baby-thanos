"""Linux sixteen-shard receipt integrity; synthetic cohorts are not hosted-run attestations."""
import json
import sys
from copy import deepcopy
from enum import StrEnum
from hashlib import sha256
from types import SimpleNamespace

import pytest
import test_ci_pytest_cli
from test_ci_pytest import (
    ATTEMPT,
    FIFO,
    FIFO_REASON,
    HEAD,
    MUTATIONS,
    RUN_ID,
    _receipts,
)
from test_ci_pytest_cli import _cli, _commit
from test_ci_pytest_linux import LINUX, skipped

from tools import ci_pytest as driver
from tools import ci_pytest_receipts as receipts

isolated_repo = test_ci_pytest_cli.isolated_repo
NODES = tuple(f"tests/test_probe.py::test_{index:03d}" for index in range(256))


def cohort(platform="linux", count=16, nodes=NODES, head=HEAD):
    values = _receipts(count=count, nodes=nodes, head=head)
    for value in values:
        value["platform"] = platform
    return values


def verify(values, *, platform="linux", count=16, head=HEAD):
    return receipts.verify_receipts(values, head=head, run_id=RUN_ID,
        run_attempt=ATTEMPT, count=count, platform=platform)


def artifacts(root):
    values, paths = cohort(), []
    for index, value in enumerate(values, 1):
        folder = root / f"linux-pytest-{index}-{HEAD}-{RUN_ID}-{ATTEMPT}"
        folder.mkdir()
        path = folder / f"shard-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        paths.append(path)
    return SimpleNamespace(directory=root, head=HEAD, run_id=RUN_ID, attempt=ATTEMPT, count=16), paths


def test_linux_sixteen_complete_disjoint_receipts_keep_full_sha_digest_and_split_every_old_eight_bucket():
    values = cohort()
    original = deepcopy(values)
    summary = verify(values)
    assert all(value["selected"] for value in values) and values == original
    selected = [node for value in values for node in value["selected"]]
    assert len(selected) == len(set(selected)) == len(NODES) and set(selected) == set(NODES)
    encoded = json.dumps(list(NODES), ensure_ascii=True, separators=(",", ":")).encode()
    assert summary == {"head": HEAD, "run_id": RUN_ID, "run_attempt": ATTEMPT,
        "shards": 16, "tests": len(NODES), "universe_sha256": sha256(encoded).hexdigest()}
    for index, value in enumerate(values, 1):
        assert value["selected"] == [node for node in NODES if int.from_bytes(sha256(node.encode("utf-8")).digest(), "big") % 16 + 1 == index]
    assert verify(list(reversed(values))) == summary
    assert receipts.verify_receipts(values, head=HEAD, run_id=RUN_ID,
        run_attempt=ATTEMPT, count=16, platform="linux") == summary
    with pytest.raises(receipts.ReceiptError, match="^receipt_context_mismatch$"):
        receipts.verify_receipts(values, head=HEAD, run_id=RUN_ID, run_attempt=ATTEMPT, count=16)
    for index in range(1, 9):
        old = {node for node in NODES if receipts.shard_for(node, 8) == index}
        first, second = set(values[index - 1]["selected"]), set(values[index + 7]["selected"])
        assert old == first | second and not first & second
    assert verify(cohort("win32", 16), platform="win32", count=16)["universe_sha256"] == summary["universe_sha256"]


@pytest.mark.parametrize("plant", tuple(MUTATIONS))
def test_linux_all_existing_partition_and_completion_mutations_still_refuse_at_sixteen(plant):
    values = cohort()
    assert verify(values)["shards"] == 16
    MUTATIONS[plant](values)
    with pytest.raises(receipts.ReceiptError):
        verify(values)


@pytest.mark.parametrize("field,value", [("schema", "other"), ("head", "b" * 40), ("run_id", "124"),
    ("run_attempt", "2"), ("platform", "win32"), ("platform", StrEnum("Alias", {"VALUE": "linux"}).VALUE),
    ("shard_count", 8), ("shard_count", True), ("shard_index", True), ("pytest_exit", False),
    ("session_exit", 1)])
def test_linux_sixteen_receipts_cannot_mix_context_platform_count_or_exit_types(field, value):
    values = cohort()
    assert verify(values)["tests"] == len(NODES)
    values[0][field] = value
    with pytest.raises(receipts.ReceiptError):
        verify(values)


@pytest.mark.parametrize("plant", ["eight_expected", "eight_receipt", "missing_sixteenth", "duplicate_sixteenth"])
def test_linux_eight_and_sixteen_cohorts_never_substitute_for_each_other(plant):
    values = cohort()
    assert verify(values)["shards"] == 16
    if plant == "eight_receipt":
        values[15] = cohort(count=8)[0]
    elif plant == "missing_sixteenth":
        values.pop()
    elif plant == "duplicate_sixteenth":
        values[15] = deepcopy(values[0])
    with pytest.raises(receipts.ReceiptError):
        verify(values, count=8 if plant == "eight_expected" else 16)


@pytest.mark.parametrize("platform,count", [("linux", 16), ("win32", 16)])
def test_linux_sixteen_exact_windows_one_and_linux_sixteen_skip_allowances_remain_closed(platform, count):
    assert receipts.SKIPS == {FIFO: FIFO_REASON} and receipts.LINUX_SKIPS == LINUX and len(LINUX) == 16
    policy = {FIFO: FIFO_REASON} if platform == "win32" else LINUX
    nodes = (*NODES, FIFO, *LINUX)
    values = cohort(platform, count, nodes)
    for value in values:
        for node in value["selected"]:
            if node in policy:
                value["reports"][node] = skipped(policy[node])
    assert verify(values, platform=platform, count=count)["tests"] == len(nodes)
    node = next(iter(policy))
    receipt = next(value for value in values if node in value["selected"])
    receipt["reports"][node] = skipped(policy[node] + " changed")
    with pytest.raises(receipts.ReceiptError, match="^unapproved_skip$"):
        verify(values, platform=platform, count=count)


@pytest.mark.parametrize("plant", ["missing", "extra", "head", "run", "attempt", "os", "file_missing",
    "file_extra", "file_name", "swap", "context", "duplicate_json", "nonfinite"])
def test_linux_all_sixteen_artifact_directories_names_files_and_receipt_indices_are_exact(tmp_path, plant):
    args, paths = artifacts(tmp_path)
    assert verify(driver._read_directory(args, platform="linux"))["shards"] == 16
    path = paths[-1]
    folder = path.parent
    if plant == "missing":
        path.unlink()
        folder.rmdir()
    elif plant == "extra":
        (tmp_path / "unexpected").mkdir()
    elif plant in ("head", "run", "attempt", "os"):
        head, run, attempt = ("b" * 40 if plant == "head" else HEAD), ("124" if plant == "run" else RUN_ID), ("2" if plant == "attempt" else ATTEMPT)
        prefix = "windows" if plant == "os" else "linux"
        folder.rename(folder.with_name(f"{prefix}-pytest-16-{head}-{run}-{attempt}"))
    elif plant == "file_missing":
        path.unlink()
    elif plant == "file_extra":
        (folder / "other.json").write_text("{}", encoding="utf-8")
    elif plant == "file_name":
        path.rename(folder / "other.json")
    elif plant == "swap":
        first, last = paths[0].read_text(encoding="utf-8"), path.read_text(encoding="utf-8")
        paths[0].write_text(last, encoding="utf-8")
        path.write_text(first, encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
        if plant == "context":
            value = json.loads(text)
            value["run_attempt"] = "2"
            text = json.dumps(value)
        elif plant == "duplicate_json":
            text = text.replace('"schema":', '"schema":"other","schema":', 1)
        else:
            text = text[:-1] + ', "extra": NaN}'
        path.write_text(text, encoding="utf-8")
    code = "artifact_file_population_mismatch" if plant.startswith("file_") else "artifact_shard_index_mismatch" if plant == "swap" else (
        "receipt_context_mismatch" if plant == "context" else "duplicate_json_key" if plant == "duplicate_json" else
        "nonfinite_json_value" if plant == "nonfinite" else "artifact_directory_population_mismatch")
    with pytest.raises(receipts.ReceiptError, match="^" + code + "$"):
        verify(driver._read_directory(args, platform="linux"))


@pytest.mark.parametrize("index", range(1, 17))
def test_actual_native_driver_exercises_all_sixteen_positions_without_platform_spoofing(isolated_repo, index):
    root = isolated_repo
    (root / "tests" / "test_probe.py").write_text("".join(
        f"def test_{number:03d}():\n    assert True\n\n" for number in range(256)), encoding="utf-8")
    head = _commit(root)
    path = root / "receipts" / f"shard-{index}.json"
    result = _cli(root, "run", "--index", str(index), "--count", "16", "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--receipt", str(path))
    assert result.returncode == 0 and path.is_file(), result.stdout + result.stderr
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = [node for node in NODES if receipts.shard_for(node, 16) == index]
    assert expected and value["universe"] == list(NODES) and value["selected"] == value["finished"] == expected
    assert value["head"] == head and value["platform"] == sys.platform and value["shard_count"] == 16 and value["shard_index"] == index
    assert value["run_id"] == RUN_ID and value["run_attempt"] == ATTEMPT and value["pytest_exit"] == value["session_exit"] == 0
    assert value["failed_reports"] == value["collection_errors"] == []
    assert value["schema"] == "atlas-brain.ci-pytest/1"
    assert set(value["reports"]) == set(expected) and all(
        [(row["when"], row["outcome"], row["reason"]) for row in value["reports"][node]] ==
        [("setup", "passed", ""), ("call", "passed", ""), ("teardown", "passed", "")] for node in expected)
    # Independent per-position probes do not pretend to be a shared hosted Linux sixteen-receipt cohort.
