"""Synthetic receipt plants and isolated hosted CLI witnesses."""

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ci_pytest import ReceiptError, _read_directory, shard_for, verify_receipts

HEAD = "a" * 40
RUN_ID = "123"
ATTEMPT = "1"
COUNT = 3
FIFO = "tests/runner/test_evidence_facts.py::test_special_file_is_refused"
FIFO_REASON = "FIFO files are not supported on this platform"
NODES = tuple(f"tests/test_probe.py::test_{index:03d}" for index in range(24))
HELPER = Path(__file__).resolve().parents[1] / "tools" / "ci_pytest.py"


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


def _git(root, *arguments):
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True,
        text=True, timeout=30,
    ).stdout.strip()


def _commit(root):
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=CI Witness", "-c",
         "user.email=ci@example.invalid", "-c", "commit.gpgsign=false",
         "commit", "-qm", "synthetic witness")
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def isolated_repo(tmp_path):
    (tmp_path / "tools").mkdir()
    shutil.copyfile(HELPER, tmp_path / "tools" / "ci_pytest.py")
    (tmp_path / "tests" / "runner").mkdir(parents=True)
    (tmp_path / "tests" / "conftest.py").write_text("", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(
        "receipts/\nartifacts*/\n.pytest_cache/\n__pycache__/\n",
        encoding="utf-8",
    )
    _git(tmp_path, "init", "-q")
    return tmp_path


def _cli(root, *arguments, extra_env=None):
    env = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, str(root / "tools" / "ci_pytest.py"), *arguments],
        cwd=root, env=env, capture_output=True, text=True, timeout=30,
    )


def _run(root, head, label, extra_env=None):
    path = root / "receipts" / label / "shard-1.json"
    result = _cli(
        root, "run", "--index", "1", "--count", "1", "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--receipt", str(path),
        extra_env=extra_env,
    )
    return result, path


def _refused_receipt(path, head):
    if path.exists():
        with pytest.raises(ReceiptError):
            _verify([json.loads(path.read_text(encoding="utf-8"))],
                    count=1, head=head)


PROBE = """
def test_ok():
    assert True

def test_subcases(subtests):
    for value in (0, 1):
        with subtests.test(value=value):
            assert value in (0, 1)
"""


@pytest.mark.skipif(sys.platform != "win32", reason="Windows run receipt witness")
def test_real_run_binds_head_collection_reports_and_failures(isolated_repo):
    root = isolated_repo
    probe = root / "tests" / "test_probe.py"
    probe.write_text(PROBE, encoding="utf-8")
    (root / "tests" / "runner" / "test_evidence_facts.py").write_text(
        "import sys\nimport pytest\n"
        "@pytest.mark.skipif(sys.platform == 'win32', "
        f"reason={FIFO_REASON!r})\n"
        "def test_special_file_is_refused():\n    assert True\n",
        encoding="utf-8",
    )
    head = _commit(root)
    result, path = _run(root, head, "valid")
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(path.read_text(encoding="utf-8"))
    assert len(receipt["universe"]) == 3
    assert receipt["finished"] == receipt["selected"]
    assert len(receipt["finished"]) == len(set(receipt["finished"])) == 3
    assert len(receipt["reports"]["tests/test_probe.py::test_subcases"]) == 3
    assert _verify([receipt], count=1, head=head)["tests"] == 3

    for label, supplied_head, extra_env in [
        ("wrong-head", "0" * 40, None),
        ("selector", head, {"PYTEST_ADDOPTS": "-k test_ok"}),
    ]:
        result, path = _run(root, supplied_head, label, extra_env)
        assert result.returncode != 0
        _refused_receipt(path, head)

    conftest = root / "tests" / "conftest.py"
    conftest.write_text(
        "import pytest\n@pytest.hookimpl(trylast=True)\n"
        "def pytest_collection_modifyitems(items):\n"
        "    items[:] = [item for item in items if item.name != 'test_ok']\n",
        encoding="utf-8",
    )
    head = _commit(root)
    result, path = _run(root, head, "silent-deselection")
    assert result.returncode != 0
    _refused_receipt(path, head)

    conftest.write_text("", encoding="utf-8")
    (root / "tests" / "test_control.py").write_text(
        "def test_control():\n    assert True\n", encoding="utf-8",
    )
    probe.write_text(
        "import pytest\npytest.skip('planted module omission', allow_module_level=True)\n"
        + PROBE, encoding="utf-8",
    )
    head = _commit(root)
    result, path = _run(root, head, "module-skip")
    assert result.returncode != 0
    assert json.loads(path.read_text(encoding="utf-8"))["collection_errors"]
    _refused_receipt(path, head)

    probe.write_text(PROBE, encoding="utf-8")
    head = _commit(root)
    probe.write_text(PROBE + "\n# uncommitted source change\n", encoding="utf-8")
    result, path = _run(root, head, "dirty-source")
    assert result.returncode != 0
    _refused_receipt(path, head)

    probe.write_text(
        "from pathlib import Path\n"
        "def test_changes_tracked_source():\n"
        "    p = Path(__file__)\n"
        "    p.write_text(p.read_text() + '\\n# changed during execution\\n')\n",
        encoding="utf-8",
    )
    head = _commit(root)
    result, path = _run(root, head, "source-changed-during-test")
    assert result.returncode != 0
    assert json.loads(path.read_text(encoding="utf-8"))["collection_errors"]
    _refused_receipt(path, head)

    probe.write_text(PROBE.replace("assert value in (0, 1)",
                                   "assert value == 0"), encoding="utf-8")
    head = _commit(root)
    result, path = _run(root, head, "failing-subtest")
    assert result.returncode != 0
    assert json.loads(path.read_text(encoding="utf-8"))["failed_reports"]
    _refused_receipt(path, head)

    probe.write_text(
        PROBE + "\nimport pytest\n@pytest.mark.xfail(reason='planted')\n"
        "def test_xfail():\n    assert False\n", encoding="utf-8",
    )
    head = _commit(root)
    _, path = _run(root, head, "xfail")
    assert json.loads(path.read_text(encoding="utf-8"))["failed_reports"]
    _refused_receipt(path, head)


def _artifact(root, head, label, *, write=True):
    directory = root / f"artifacts-{label}"
    child = directory / f"windows-pytest-1-{head}-{RUN_ID}-{ATTEMPT}"
    child.mkdir(parents=True)
    path = child / "shard-1.json"
    if write:
        path.write_text(json.dumps(_receipts(count=1, head=head)[0]),
                        encoding="utf-8")
    return directory, child, path


def _verify_cli(root, directory, head):
    return _cli(
        root, "verify", "--directory", str(directory), "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--count", "1",
        "--jobs-result", "success",
    )


def test_real_verify_directory_refuses_malformed_or_extra_inputs(isolated_repo):
    root = isolated_repo
    head = _commit(root)
    directory, _, _ = _artifact(root, head, "valid")
    result = _verify_cli(root, directory, head)
    assert result.returncode == 0, result.stdout + result.stderr
    for plant in ("missing", "extra", "nested", "duplicate-keys", "wrong-name"):
        directory, child, path = _artifact(root, head, plant,
                                           write=plant != "missing")
        if plant == "extra":
            (directory / "unexpected").mkdir()
        elif plant == "nested":
            (child / "nested").mkdir()
        elif plant == "duplicate-keys":
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace(
                '"schema":', '"schema":"atlas-brain.ci-pytest/1","schema":', 1),
                encoding="utf-8")
        elif plant == "wrong-name":
            path.rename(child / "wrong.json")
        assert _verify_cli(root, directory, head).returncode != 0
    assert _cli(
        root, "verify", "--directory", str(directory), "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--count", "1",
        "--jobs-result", "cancelled",
    ).returncode != 0


def test_real_verify_rejects_directory_symlinks_and_windows_junctions(isolated_repo):
    root = isolated_repo
    head = _commit(root)
    _, target, _ = _artifact(root, head, "target")
    directory = root / "artifacts-link"
    directory.mkdir()
    link = directory / f"windows-pytest-1-{head}-{RUN_ID}-{ATTEMPT}"
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True, capture_output=True, text=True, timeout=30,
        )
    else:
        link.symlink_to(target, target_is_directory=True)
    assert _verify_cli(root, directory, head).returncode != 0


def test_artifact_directory_cannot_swap_shard_identity(tmp_path):
    args = SimpleNamespace(
        directory=str(tmp_path), head=HEAD, run_id=RUN_ID,
        attempt=ATTEMPT, count=COUNT,
    )
    receipts = _receipts()
    paths = []
    for index, receipt in enumerate(receipts, 1):
        folder = tmp_path / f"windows-pytest-{index}-{HEAD}-{RUN_ID}-{ATTEMPT}"
        folder.mkdir()
        path = folder / f"shard-{index}.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        paths.append(path)
    assert _verify(_read_directory(args))["tests"] == len(NODES)
    first, second = (path.read_text(encoding="utf-8") for path in paths[:2])
    paths[0].write_text(second, encoding="utf-8")
    paths[1].write_text(first, encoding="utf-8")
    with pytest.raises(ReceiptError, match="artifact_shard_index_mismatch"):
        _read_directory(args)
