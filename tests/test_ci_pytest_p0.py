"""Closed P0 partitions retain full-suite guards and cannot qualify the full suite."""
import json
import sys
from copy import deepcopy
from enum import StrEnum
from hashlib import sha256
from types import SimpleNamespace

import pytest
import test_ci_pytest_cli
from test_ci_pytest import ATTEMPT, HEAD, MUTATIONS, RUN_ID, _bucket, _receipts
from test_ci_pytest_cli import _cli, _commit

from tools import ci_pytest as driver
from tools import ci_pytest_receipts as receipts

isolated_repo = test_ci_pytest_cli.isolated_repo
P0_SCHEMA = "atlas-brain.ci-p0-pytest/1"
NODES = tuple(f"tests/runner/test_probe.py::test_{i:03d}" for i in range(128))
PARAM = "tests/runner/test_probe.py::test_raw[a/../b\\\\raw::\u03b1\n]"
FIELDS = {"schema", "head", "run_id", "run_attempt", "platform", "shard_index", "shard_count",
          "universe", "selected", "finished", "reports", "failed_reports", "collection_errors", "pytest_exit", "session_exit"}
ROWS = [{"when": phase, "outcome": "passed", "reason": ""} for phase in ("setup", "call", "teardown")]


class Alias(StrEnum):
    P0 = "p0"


def values(*, scope="p0", nodes=NODES, platform="win32"):
    result = _receipts(count=4, nodes=nodes)
    for value in result:
        value.update(schema=P0_SCHEMA if scope == "p0" else "atlas-brain.ci-pytest/1", platform=platform)
    return result


def verify(data, *, scope="p0", platform="win32", **overrides):
    context = {"head": HEAD, "run_id": RUN_ID, "run_attempt": ATTEMPT, "count": 4, "platform": platform, "scope": scope}
    context.update(overrides)
    return receipts.verify_receipts(data, **context)


def summary(nodes, head, count, *, scope="full"):
    encoded = json.dumps(list(nodes), ensure_ascii=True, separators=(",", ":")).encode()
    expected = {"head": head, "run_id": RUN_ID, "run_attempt": ATTEMPT, "shards": count,
                "tests": len(nodes), "universe_sha256": sha256(encoded).hexdigest()}
    if scope == "p0":
        expected.update(schema=P0_SCHEMA, scope="p0")
    return expected


def test_full_legacy_summary_is_literal_and_profiles_are_disjoint():
    full = values(scope="full", nodes=(*NODES, PARAM))
    assert verify(full, scope="full") == summary((*NODES, PARAM), HEAD, 4)
    assert set(verify(full, scope="full")) == {"head", "run_id", "run_attempt", "shards", "tests", "universe_sha256"}
    p0 = values(nodes=(*NODES, PARAM))
    assert verify(p0) == summary((*NODES, PARAM), HEAD, 4, scope="p0")
    assert all(set(value) == FIELDS == receipts.FIELDS for value in full + p0)
    for data, scope in ((p0, "full"), (full, "p0")):
        with pytest.raises(receipts.ReceiptError, match="^receipt_context_mismatch$"):
            verify(data, scope=scope)


@pytest.mark.parametrize("plant", tuple(MUTATIONS))
def test_p0_retains_existing_partition_completion_mutation_guards(plant):
    data = values()
    if plant == "duplicate_universe_item":
        data[0]["universe"].append(data[0]["universe"][0])
    else:
        MUTATIONS[plant](data)
    with pytest.raises(receipts.ReceiptError, match="^invalid_universe$" if plant == "duplicate_universe_item" else None):
        verify(data)


@pytest.mark.parametrize("field,value", [
    ("head", "b" * 40), ("run_id", "124"), ("run_attempt", "2"), ("platform", "linux"),
    ("schema", "atlas-brain.ci-pytest/1"), ("shard_count", 3), ("shard_count", True),
    ("pytest_exit", False), ("session_exit", 1), ("session_exit", None),
    ("failed_reports", ["failed"]), ("collection_errors", ["omitted"]), ("reports", None),
])
def test_p0_refuses_context_and_failure_fields(field, value):
    data = values()
    data[0][field] = deepcopy(value)
    with pytest.raises(receipts.ReceiptError):
        verify(data)


@pytest.mark.parametrize("scope", [None, True, 0, "", "P0", "runner", "tests/runner", "p0/", Alias.P0])
def test_unknown_scopes_refuse_before_collection_or_directory_access(tmp_path, scope):
    with pytest.raises(receipts.ReceiptError, match="^invalid_scope$"):
        verify(values(), scope=scope)
    with pytest.raises(receipts.ReceiptError, match="^invalid_scope$"):
        driver._Collector(1, 4, scope=scope)
    with pytest.raises(receipts.ReceiptError, match="^invalid_scope$"):
        driver._read_directory(SimpleNamespace(count=4, directory=tmp_path), scope=scope)


@pytest.mark.parametrize("count", [0, -1, True, False, 1, 3, 5, 4.0, "4"])
def test_p0_requires_exactly_four_native_partitions(count, tmp_path):
    with pytest.raises(receipts.ReceiptError, match="^invalid_p0_shard_count$"):
        verify(values(), count=count)
    with pytest.raises(receipts.ReceiptError, match="^invalid_p0_shard_count$"):
        driver._Collector(1, count, scope="p0")
    with pytest.raises(receipts.ReceiptError, match="^invalid_p0_shard_count$"):
        driver._run(SimpleNamespace(count=count), scope="p0")
    with pytest.raises(receipts.ReceiptError, match="^invalid_p0_shard_count$"):
        driver._read_directory(SimpleNamespace(count=count, directory=tmp_path), scope="p0")


@pytest.mark.parametrize("path", [
    "tests/test_probe.py", "/tests/runner/test_probe.py", "C:/tests/runner/test_probe.py",
    "tests/runner/../test_probe.py", "tests//runner/test_probe.py", "tests/runner//test_probe.py",
    "tests/runner/./test_probe.py", "tests\\\\runner\\\\test_probe.py", "tests/runner/test_probe.txt",
    "tests/runner/test\0probe.py",
])
def test_entire_raw_p0_universe_requires_canonical_file_paths(path):
    data = values()
    omitted = next(node for node in NODES if node not in data[0]["selected"])
    bad = path + "::test_raw[a/../b\\\\raw]"
    for value in data:
        value["universe"][value["universe"].index(omitted)] = bad
    with pytest.raises(receipts.ReceiptError, match="^p0_test_root_mismatch$"):
        verify(data)
    collector = driver._Collector(1, 4, scope="p0")
    collector.raw = data[0]["universe"]
    with pytest.raises(pytest.UsageError, match="^p0_test_root_mismatch$"):
        collector.pytest_collection_modifyitems([SimpleNamespace(nodeid=node) for node in collector.raw])


@pytest.mark.parametrize("platform,node,reason", [
    ("win32", "tests/runner/test_evidence_facts.py::test_special_file_is_refused", "FIFO files are not supported on this platform"),
    ("linux", "tests/runner/test_evidence_facts.py::test_windows_junction_root_and_members_are_refused[False]", "Windows directory junction control"),
])
def test_p0_retains_only_existing_native_skip_permissions(platform, node, reason):
    data = values(nodes=(*NODES, node), platform=platform)
    owner = next(value for value in data if node in value["selected"])
    owner["reports"][node] = [{"when": "setup", "outcome": "skipped", "reason": reason}, {"when": "teardown", "outcome": "passed", "reason": ""}]
    assert verify(data, platform=platform)["tests"] == len(NODES) + 1
    owner["reports"][node][0]["reason"] = "new skip permission"
    with pytest.raises(receipts.ReceiptError, match="^unapproved_skip$"):
        verify(data, platform=platform)


def populate(root):
    path = root / "tests" / "runner" / "test_probe.py"
    path.write_text("\n\n".join(f"def test_{i:03d}():\n    assert True\n" for i in range(64)), encoding="utf-8")
    return path


def run_p0(root, head, index, *, extra=None):
    path = root / "receipts" / f"p0-{index}" / f"shard-{index}.json"
    result = _cli(root, "run", "--scope", "p0", "--count", "4", "--index", str(index), "--head", head,
                  "--run-id", RUN_ID, "--attempt", ATTEMPT, "--receipt", str(path), extra_env=extra)
    return result, path


def artifact(root, data, *, scope="p0"):
    directory = root / ("artifacts-" + scope)
    prefix = ("p0-" if scope == "p0" else "") + ("windows" if sys.platform == "win32" else "linux")
    for value in data:
        index = value["shard_index"]
        folder = directory / f"{prefix}-pytest-{index}-{value['head']}-{RUN_ID}-{ATTEMPT}"
        folder.mkdir(parents=True)
        (folder / f"shard-{index}.json").write_text(json.dumps(value), encoding="utf-8")
    return directory


def verify_cli(root, head, directory, *, count=4, scope="p0", jobs="success"):
    return _cli(root, "verify", "--scope", scope, "--platform", sys.platform, "--count", str(count),
                "--head", head, "--run-id", RUN_ID, "--attempt", ATTEMPT, "--directory", str(directory), "--jobs-result", jobs)


def test_actual_four_p0_cli_partitions_cover_runner_and_exclude_outside_poison(isolated_repo):
    root = isolated_repo
    populate(root)
    (root / "tests" / "test_poison.py").write_text("def test_outside_poison():\n    raise AssertionError('outside P0')\n", encoding="utf-8")
    head = _commit(root)
    data = []
    for index in range(1, 5):
        result, path = run_p0(root, head, index)
        assert result.returncode == 0, result.stdout + result.stderr
        data.append(json.loads(path.read_text(encoding="utf-8")))
    nodes = [f"tests/runner/test_probe.py::test_{i:03d}" for i in range(64)]
    assert all(value["universe"] == nodes and set(value) == FIELDS and value["finished"] == value["selected"] for value in data)
    assert all(rows == ROWS for value in data for rows in value["reports"].values())
    union = [node for value in data for node in value["finished"]]
    assert len(union) == len(set(union)) == len(nodes) and set(union) == set(nodes)
    directory = artifact(root, data)
    result = verify_cli(root, head, directory)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == json.dumps(summary(nodes, head, 4, scope="p0"), sort_keys=True) + "\n"
    assert verify_cli(root, head, directory, scope="full").returncode != 0
    full_names = artifact(root, data, scope="full")
    assert verify_cli(root, head, full_names, scope="full").returncode != 0
    for jobs in ("failure", "cancelled", "skipped"):
        assert verify_cli(root, head, directory, jobs=jobs).returncode != 0


@pytest.mark.parametrize("plant", ["dirty", "selector", "deselect", "reorder", "ignore", "directory_ignore", "module_skip", "source_change", "failed_subtest", "skipped_subtest", "xfail", "xpass"])
def test_p0_cli_retains_source_raw_collection_and_failure_gates(isolated_repo, plant):
    root = isolated_repo
    path = populate(root)
    conftest = root / "tests" / "conftest.py"
    if plant == "deselect":
        conftest.write_text("def pytest_collection_modifyitems(items):\n    items[:] = items[1:]\n", encoding="utf-8")
    elif plant == "reorder":
        conftest.write_text("def pytest_collection_modifyitems(items):\n    items.reverse()\n", encoding="utf-8")
    elif plant == "directory_ignore":
        hidden = root / "tests" / "runner" / "hidden"
        hidden.mkdir()
        (hidden / "test_hidden.py").write_text("def test_hidden():\n    assert False\n", encoding="utf-8")
        conftest.write_text("collect_ignore = ['runner/hidden']\n", encoding="utf-8")
    elif plant == "ignore":
        conftest.write_text("collect_ignore = ['runner/test_probe.py']\n", encoding="utf-8")
    elif plant == "module_skip":
        path.write_text("import pytest\npytest.skip('omitted module', allow_module_level=True)\n" + path.read_text(), encoding="utf-8")
    elif plant == "source_change":
        path.write_text(path.read_text().replace("def test_000():\n    assert True", "def test_000():\n    from pathlib import Path\n    p=Path(__file__)\n    p.write_text(p.read_text()+'\\n# changed\\n')"), encoding="utf-8")
    elif plant in ("failed_subtest", "skipped_subtest"):
        body = "assert value == 0" if plant == "failed_subtest" else "import pytest; pytest.skip('omitted subtest')"
        path.write_text(path.read_text().replace("def test_000():\n    assert True", "def test_000(subtests):\n    for value in (0,1):\n        with subtests.test(value=value):\n            " + body), encoding="utf-8")
    elif plant in ("xfail", "xpass"):
        body = "assert False" if plant == "xfail" else "assert True"
        path.write_text("import pytest\n@pytest.mark.xfail(strict=False)\n" + path.read_text().replace("def test_000():\n    assert True", "def test_000():\n    " + body), encoding="utf-8")
    head = _commit(root)
    if plant == "dirty":
        path.write_text(path.read_text() + "\n# dirty\n", encoding="utf-8")
    extra = {"PYTEST_ADDOPTS": "-k test_000"} if plant == "selector" else None
    index = _bucket("tests/runner/test_probe.py::test_000", 4)
    result, receipt = run_p0(root, head, index, extra=extra)
    assert result.returncode != 0, result.stdout + result.stderr
    if receipt.exists():
        value = json.loads(receipt.read_text(encoding="utf-8"))
        assert value["schema"] == P0_SCHEMA
        assert value["collection_errors"] or value["failed_reports"] or value["pytest_exit"] or value["session_exit"]


def test_default_full_cli_receipt_and_summary_bytes_match_frozen_contract(isolated_repo):
    root = isolated_repo
    (root / "tests" / "runner" / "test_full.py").write_text("def test_full_ok():\n    assert True\n", encoding="utf-8")
    (root / "tests" / "test_outside.py").write_text("def test_outside_ok():\n    assert True\n", encoding="utf-8")
    head = _commit(root)
    path = root / "receipts" / "full" / "shard-1.json"
    result = _cli(root, "run", "--count", "1", "--index", "1", "--head", head, "--run-id", RUN_ID, "--attempt", ATTEMPT, "--receipt", str(path))
    assert result.returncode == 0, result.stdout + result.stderr
    nodes = ["tests/runner/test_full.py::test_full_ok", "tests/test_outside.py::test_outside_ok"]
    expected = {"schema": "atlas-brain.ci-pytest/1", "head": head, "run_id": RUN_ID, "run_attempt": ATTEMPT, "platform": sys.platform,
                "shard_index": 1, "shard_count": 1, "universe": nodes, "selected": nodes, "finished": nodes,
                "reports": {node: deepcopy(ROWS) for node in nodes}, "failed_reports": [], "collection_errors": [], "pytest_exit": 0, "session_exit": 0}
    assert path.read_bytes() == (json.dumps(expected, ensure_ascii=True, sort_keys=True) + "\n").encode()
    directory = artifact(root, [expected], scope="full")
    result = _cli(root, "verify", "--platform", sys.platform, "--count", "1", "--head", head, "--run-id", RUN_ID, "--attempt", ATTEMPT,
                  "--directory", str(directory), "--jobs-result", "success")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == json.dumps(summary(nodes, head, 1), sort_keys=True) + "\n"


@pytest.mark.parametrize("plant", ["missing", "extra", "wrong_name", "swap", "duplicate_keys", "nonfinite", "head", "run", "attempt"])
def test_p0_artifact_namespace_population_and_json_are_closed(tmp_path, plant):
    data = values(platform=sys.platform)
    root = artifact(tmp_path, data)
    args = SimpleNamespace(directory=root, head=HEAD, run_id=RUN_ID, attempt=ATTEMPT, count=4)
    assert verify(driver._read_directory(args, platform=sys.platform, scope="p0"), platform=sys.platform)["tests"] == len(NODES)
    with pytest.raises(receipts.ReceiptError, match="^artifact_directory_population_mismatch$"):
        driver._read_directory(args, platform=sys.platform)
    full = artifact(tmp_path, values(scope="full", platform=sys.platform), scope="full")
    with pytest.raises(receipts.ReceiptError, match="^artifact_directory_population_mismatch$"):
        driver._read_directory(SimpleNamespace(**{**vars(args), "directory": full}), platform=sys.platform, scope="p0")
    paths = sorted(root.glob("*/shard-*.json"))
    if plant == "missing":
        paths[0].unlink()
    elif plant == "extra":
        (root / "unexpected").mkdir()
    elif plant == "wrong_name":
        paths[0].rename(paths[0].with_name("wrong.json"))
    elif plant == "swap":
        first, second = (path.read_text() for path in paths[:2])
        paths[0].write_text(second, encoding="utf-8")
        paths[1].write_text(first, encoding="utf-8")
    elif plant == "duplicate_keys":
        paths[0].write_text(paths[0].read_text().replace('"schema":', '"schema":"duplicate","schema":', 1), encoding="utf-8")
    elif plant == "nonfinite":
        paths[0].write_text(paths[0].read_text().replace('"pytest_exit": 0', '"pytest_exit": NaN'), encoding="utf-8")
    else:
        setattr(args, {"head": "head", "run": "run_id", "attempt": "attempt"}[plant], "b" * 40 if plant == "head" else "2")
    with pytest.raises(receipts.ReceiptError):
        driver._read_directory(args, platform=sys.platform, scope="p0")


@pytest.mark.parametrize("scope,root", [("full", "tests/runner"), ("p0", "tests")])
def test_configured_pytest_root_cannot_substitute_for_declared_scope(scope, root):
    collector = driver._Collector(1, 4, scope=scope)
    config = SimpleNamespace(args=[root], option=SimpleNamespace(), getini=lambda name: [])
    with pytest.raises(pytest.UsageError, match="^selection_configuration_refused$"):
        collector.pytest_configure(config)
