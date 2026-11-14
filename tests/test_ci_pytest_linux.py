"""Linux/native receipt boundaries; real CLI probes run on both supported operating systems."""
import json
import sys
from copy import deepcopy
from enum import StrEnum
from hashlib import sha256
from types import SimpleNamespace

import pytest
from test_ci_pytest import ATTEMPT, COUNT, FIFO, FIFO_REASON, HEAD, MUTATIONS, NODES, RUN_ID, _receipts, _verify
from test_ci_pytest_cli import _cli, _commit, _run
from test_ci_pytest_cli import isolated_repo as isolated_repo

from tools import ci_pytest as driver
from tools import ci_pytest_receipts as receipts

PLANTS = ("valid", "wrong-head", "selector", "silent-deselection", "module-skip", "precollection-hook",
    "precollection-list", "precollection-directory", "dirty-source", "source-change", "failed-subtest", "skipped-subtest", "xfail", "xpass")
LINUX = {f"tests/test_ci_pytest_cli.py::test_run_receipt_gauntlet[{plant}]": "Windows run receipt witness" for plant in PLANTS}
LINUX.update({f"tests/runner/test_evidence_facts.py::test_windows_junction_root_and_members_are_refused[{value}]":
    "Windows directory junction control" for value in ("False", "True")})


class Alias(StrEnum):
    LINUX = "linux"


def native_receipts(platform="linux", *, count=COUNT, nodes=NODES):
    result = _receipts(count=count, nodes=nodes)
    for receipt in result:
        receipt["platform"] = platform
    return result


def verify(values, platform="linux", **changes):
    context = {"head": HEAD, "run_id": RUN_ID, "run_attempt": ATTEMPT, "count": COUNT, "platform": platform}
    context.update(changes)
    return receipts.verify_receipts(values, **context)


def skipped(reason, phase="setup"):
    rows = [{"when": "setup", "outcome": "skipped", "reason": reason},
        {"when": "teardown", "outcome": "passed", "reason": ""}]
    return rows if phase == "setup" else [{"when": "setup", "outcome": "passed", "reason": ""}, dict(rows[0], when="call"), rows[1]]


def artifacts(root, platform="linux", *, count=COUNT):
    values = native_receipts(platform, count=count)
    prefix = "linux" if platform == "linux" else "windows"
    paths = []
    for index, value in enumerate(values, 1):
        directory = root / f"{prefix}-pytest-{index}-{HEAD}-{RUN_ID}-{ATTEMPT}"
        directory.mkdir(parents=True)
        path = directory / f"shard-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        paths.append(path)
    args = SimpleNamespace(directory=str(root), head=HEAD, run_id=RUN_ID, attempt=ATTEMPT, count=count)
    return args, paths


def test_existing_windows_default_summary_schema_skip_policy_and_serialized_bytes_remain_compatible():
    values = _receipts()
    before = json.dumps(values, sort_keys=True)
    expected = {"head": HEAD, "run_id": RUN_ID, "run_attempt": ATTEMPT, "shards": COUNT, "tests": len(NODES),
        "universe_sha256": sha256(json.dumps(list(NODES), ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()}
    assert _verify(values) == verify(values, "win32") == expected
    assert json.dumps(values, sort_keys=True) == before
    assert receipts.SKIPS == {FIFO: FIFO_REASON}
    assert receipts.LINUX_SKIPS == LINUX and len(LINUX) == 16


@pytest.mark.parametrize("phase", ["setup", "call"])
def test_all_exact_sixteen_linux_skips_and_one_real_pass_are_accepted(phase):
    values = native_receipts(count=1, nodes=(*LINUX, NODES[0]))
    for nodeid, reason in LINUX.items():
        values[0]["reports"][nodeid] = skipped(reason, phase)
    original = deepcopy(values)
    assert verify(values, count=1)["tests"] == 17 and values == original
    values[0]["universe"].pop()
    values[0]["selected"].pop()
    values[0]["finished"].pop()
    values[0]["reports"].pop(NODES[0])
    with pytest.raises(receipts.ReceiptError, match="^no_passed_calls$"):
        verify(values, count=1)


@pytest.mark.parametrize("nodeid", tuple(LINUX))
@pytest.mark.parametrize("plant", ["reason", "identity"])
def test_skip_allowance_is_exact_per_nodeid_and_reason_without_wildcards(nodeid, plant):
    altered = nodeid if plant == "reason" else nodeid + "_other"
    values = native_receipts(count=1, nodes=(altered, NODES[0]))
    values[0]["reports"][altered] = skipped(LINUX[nodeid] + " " if plant == "reason" else LINUX[nodeid])
    with pytest.raises(receipts.ReceiptError, match="^unapproved_skip$"):
        verify(values, count=1)


@pytest.mark.parametrize("platform,nodeid,reason", [("linux", FIFO, FIFO_REASON),
    ("win32", next(iter(LINUX)), "Windows run receipt witness")])
def test_each_os_skip_policy_refuses_the_other_operating_system(platform, nodeid, reason):
    values = native_receipts(platform, count=1, nodes=(nodeid, NODES[0]))
    values[0]["reports"][nodeid] = skipped(reason)
    with pytest.raises(receipts.ReceiptError, match="^unapproved_skip$"):
        verify(values, platform, count=1)


@pytest.mark.parametrize("platform", ["darwin", "", None, False, [], Alias.LINUX])
def test_unknown_or_aliased_platform_is_refused_before_context_or_directory_access(tmp_path, platform):
    with pytest.raises(receipts.ReceiptError, match="^invalid_platform$"):
        verify(native_receipts(), platform)
    with pytest.raises(receipts.ReceiptError, match="^invalid_platform$"):
        driver._read_directory(SimpleNamespace(directory=tmp_path / "absent"), platform=platform)


@pytest.mark.parametrize("field,value", [("platform", "win32"), ("platform", Alias.LINUX), ("head", "b" * 40),
    ("run_id", "124"), ("run_attempt", "2"), ("schema", "other"), ("session_exit", 1),
    ("pytest_exit", 1), ("shard_count", True), ("shard_index", True)])
def test_linux_receipts_never_mix_os_head_run_attempt_schema_or_exit_evidence(field, value):
    values = native_receipts()
    assert verify(values)["tests"] == len(NODES)
    values[0][field] = value
    with pytest.raises(receipts.ReceiptError):
        verify(values)


@pytest.mark.parametrize("plant", tuple(MUTATIONS))
def test_complete_linux_partition_and_completion_guards_remain_closed(plant):
    values = native_receipts()
    assert verify(values)["tests"] == len(NODES)
    MUTATIONS[plant](values)
    with pytest.raises(receipts.ReceiptError):
        verify(values)


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_directory_names_bind_selected_os_and_windows_remains_default(tmp_path, platform):
    args, _ = artifacts(tmp_path, platform)
    data = driver._read_directory(args, platform=platform)
    assert verify(data, platform)["tests"] == len(NODES)
    if platform == "win32":
        assert driver._read_directory(args) == data
    else:
        with pytest.raises(receipts.ReceiptError, match="^artifact_directory_population_mismatch$"):
            driver._read_directory(args)


@pytest.mark.parametrize("plant", ["missing_directory", "extra_directory", "other_os", "other_head", "other_run", "other_attempt",
    "missing_file", "extra_file", "wrong_file", "schema", "platform", "swap", "duplicate_json", "nonfinite"])
def test_linux_artifact_population_filenames_and_receipts_are_exact(tmp_path, plant):
    args, paths = artifacts(tmp_path)
    assert verify(driver._read_directory(args, platform="linux"))["tests"] == len(NODES)
    path = paths[0]
    directory = path.parent
    if plant == "missing_directory":
        path.unlink()
        directory.rmdir()
    elif plant == "extra_directory":
        (tmp_path / "unexpected").mkdir()
    elif plant in ("other_os", "other_head", "other_run", "other_attempt"):
        prefix = "windows" if plant == "other_os" else "linux"
        head, run, attempt = ("b" * 40 if plant == "other_head" else HEAD), ("124" if plant == "other_run" else RUN_ID), ("2" if plant == "other_attempt" else ATTEMPT)
        directory.rename(directory.with_name(f"{prefix}-pytest-1-{head}-{run}-{attempt}"))
    elif plant == "missing_file":
        path.unlink()
    elif plant == "extra_file":
        (directory / "other.json").write_text("{}", encoding="utf-8")
    elif plant == "wrong_file":
        path.rename(directory / "wrong.json")
    elif plant in ("schema", "platform"):
        value = json.loads(path.read_text(encoding="utf-8"))
        value[plant] = "other" if plant == "schema" else "win32"
        path.write_text(json.dumps(value), encoding="utf-8")
    elif plant == "swap":
        first, second = (item.read_text(encoding="utf-8") for item in paths[:2])
        paths[0].write_text(second, encoding="utf-8")
        paths[1].write_text(first, encoding="utf-8")
    else:
        text = path.read_text(encoding="utf-8")
        text = text.replace('"schema":', '"schema":"other","schema":', 1) if plant == "duplicate_json" else text[:-1] + ', "extra": NaN}'
        path.write_text(text, encoding="utf-8")
    code = "artifact_file_population_mismatch" if plant in ("missing_file", "extra_file", "wrong_file") else (
        "receipt_context_mismatch" if plant in ("schema", "platform") else "artifact_shard_index_mismatch" if plant == "swap" else
        "duplicate_json_key" if plant == "duplicate_json" else "nonfinite_json_value" if plant == "nonfinite" else "artifact_directory_population_mismatch")
    with pytest.raises(receipts.ReceiptError, match="^" + code + "$"):
        verify(driver._read_directory(args, platform="linux"))


@pytest.mark.parametrize("plant", ["valid", "deselection", "collection_error", "subtest_failure", "module_skip", "unapproved_skip", "source_change", "selector"])
def test_actual_native_driver_gauntlet_uses_real_collection_reports_and_explicit_os_verification(isolated_repo, plant):
    root = isolated_repo
    assert sys.platform in ("linux", "win32")
    probe = "def test_ok():\n    assert True\n\ndef test_second():\n    assert True\n"
    if plant == "collection_error":
        probe = "def test_broken(:\n"
    elif plant == "subtest_failure":
        probe = "def test_failed(subtests):\n    with subtests.test(planted=True):\n        assert False\n"
    elif plant == "module_skip":
        probe = "import pytest\npytest.skip('planted omission', allow_module_level=True)\n" + probe
    elif plant == "unapproved_skip":
        probe = "import pytest\ndef test_unapproved():\n    pytest.skip('not allowlisted')\n"
    elif plant == "source_change":
        probe = "from pathlib import Path\ndef test_changes():\n    p=Path(__file__)\n    p.write_text(p.read_text()+'\\n# changed\\n')\n"
    (root / "tests" / "test_probe.py").write_text(probe, encoding="utf-8")
    (root / "tests" / "test_control.py").write_text("def test_control():\n    assert True\n", encoding="utf-8")
    if plant == "deselection":
        (root / "tests" / "conftest.py").write_text("import pytest\n@pytest.hookimpl(trylast=True)\ndef pytest_collection_modifyitems(items):\n    items[:]=[item for item in items if item.name!='test_ok']\n", encoding="utf-8")
    head = _commit(root)
    result, path = _run(root, head, "native", {"PYTEST_ADDOPTS": "-k test_ok"} if plant == "selector" else None)
    assert (result.returncode == 0) is (plant in ("valid", "unapproved_skip")), result.stdout + result.stderr
    assert path.is_file(), result.stdout + result.stderr
    receipt = json.loads(path.read_text(encoding="utf-8"))
    assert receipt["platform"] == sys.platform and receipt["head"] == head and receipt["run_attempt"] == ATTEMPT
    if plant == "valid":
        assert result.returncode == 0 and receipt["finished"] == receipt["selected"] == receipt["universe"]
        assert verify([receipt], sys.platform, head=head, count=1)["tests"] == 3
        spoofed = _cli(root, "run", "--platform", "linux" if sys.platform == "win32" else "win32", "--index", "1", "--count", "1",
            "--head", head, "--run-id", RUN_ID, "--attempt", ATTEMPT, "--receipt", str(root / "receipts" / "spoof.json"))
        assert spoofed.returncode == 2 and "unrecognized arguments" in spoofed.stderr
        assert not (root / "receipts" / "spoof.json").exists()
    else:
        with pytest.raises(receipts.ReceiptError):
            verify([receipt], sys.platform, head=head, count=1)
    directory = root / "artifacts-native"
    child = directory / f"{'linux' if sys.platform == 'linux' else 'windows'}-pytest-1-{head}-{RUN_ID}-{ATTEMPT}"
    child.mkdir(parents=True)
    (child / "shard-1.json").write_text(json.dumps(receipt), encoding="utf-8")
    arguments = ("verify", "--platform", sys.platform, "--directory", str(directory), "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--count", "1", "--jobs-result", "success")
    checked = _cli(root, *arguments)
    assert (checked.returncode == 0) is (plant == "valid"), checked.stdout + checked.stderr
    if plant == "valid":
        assert _cli(root, *arguments[:2], "linux" if sys.platform == "win32" else "win32", *arguments[3:]).returncode != 0


def test_run_cannot_be_platform_spoofed_and_unsupported_native_os_never_starts_pytest(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(driver.sys, "platform", "darwin")
        patch.setattr(driver.pytest, "main", lambda *_a, **_k: pytest.fail("unsupported native platform ran pytest"))
        with pytest.raises(receipts.ReceiptError, match="^unsupported_native_platform$"):
            driver._run(SimpleNamespace())


@pytest.mark.parametrize("count", [1, 4])
def test_linux_full_sha256_partitions_cover_one_complete_ordered_universe(count):
    nodes = tuple(f"tests/test_partition.py::test_{index:03d}" for index in range(128))
    values = native_receipts(count=count, nodes=nodes)
    assert all(value["selected"] for value in values)
    selected = [node for value in values for node in value["selected"]]
    assert len(selected) == len(set(selected)) == len(nodes) and set(selected) == set(nodes)
    assert verify(values, count=count)["tests"] == len(nodes)
