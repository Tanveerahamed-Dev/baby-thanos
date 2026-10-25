"""Hosted CLI gauntlet: each plant has an independent synthetic repository."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_ci_pytest import (
    ATTEMPT,
    COUNT,
    FIFO_REASON,
    NODES,
    RUN_ID,
    ReceiptError,
    _receipts,
    _verify,
)

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _git(root, *args):
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True,
        check=True, timeout=30,
    ).stdout.strip()


def _commit(root):
    _git(root, "add", "-A")
    _git(root, "-c", "user.name=CI Witness", "-c", "user.email=ci@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-qm", "synthetic witness")
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def isolated_repo(tmp_path):
    (tmp_path / "tools").mkdir()
    for name in ("ci_pytest.py", "ci_pytest_receipts.py"):
        source = TOOLS / name
        if source.is_file():
            shutil.copyfile(source, tmp_path / "tools" / name)
    (tmp_path / "tests" / "runner").mkdir(parents=True)
    (tmp_path / "tests" / "conftest.py").write_text("", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(
        "receipts/\nartifacts*/\n.pytest_cache/\n__pycache__/\n", encoding="utf-8",
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
        cwd=root, env=env, capture_output=True, text=True, check=False, timeout=30,
    )


def _run(root, head, label, extra_env=None):
    path = root / "receipts" / label / "shard-1.json"
    result = _cli(
        root, "run", "--index", "1", "--count", "1", "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--receipt", str(path),
        extra_env=extra_env,
    )
    return result, path


PROBE = """
def test_ok():
    assert True

def test_subcases(subtests):
    for value in (0, 1):
        with subtests.test(value=value):
            assert value in (0, 1)
"""
PLANTS = [
    "valid", "wrong-head", "selector", "silent-deselection",
    "module-skip", "precollection-hook", "precollection-list",
    "precollection-directory", "dirty-source", "source-change",
    "failed-subtest", "skipped-subtest", "xfail",
]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows run receipt witness")
@pytest.mark.parametrize("plant", PLANTS)
def test_run_receipt_gauntlet(isolated_repo, plant):
    root = isolated_repo
    probe, conftest = root / "tests" / "test_probe.py", root / "tests" / "conftest.py"
    probe.write_text(PROBE, encoding="utf-8")
    (root / "tests" / "test_control.py").write_text(
        "def test_control():\n    assert True\n", encoding="utf-8",
    )
    (root / "tests" / "runner" / "test_evidence_facts.py").write_text(
        "import sys\nimport pytest\n"
        "@pytest.mark.skipif(sys.platform == 'win32', "
        f"reason={FIFO_REASON!r})\n"
        "def test_special_file_is_refused():\n    assert True\n", encoding="utf-8",
    )
    if plant == "silent-deselection":
        conftest.write_text(
            "import pytest\n@pytest.hookimpl(trylast=True)\n"
            "def pytest_collection_modifyitems(items):\n"
            "    items[:] = [item for item in items if item.name != 'test_ok']\n",
            encoding="utf-8",
        )
    elif plant == "module-skip":
        probe.write_text(
            "import pytest\npytest.skip('planted module omission', allow_module_level=True)\n"
            + PROBE, encoding="utf-8",
        )
    elif plant in ("precollection-hook", "precollection-directory"):
        target = "test_probe.py" if plant == "precollection-hook" else "hidden"
        conftest.write_text(
            "def pytest_ignore_collect(collection_path):\n"
            f"    return collection_path.name == {target!r}\n", encoding="utf-8",
        )
        if plant == "precollection-directory":
            hidden = root / "tests" / "hidden"
            hidden.mkdir()
            (hidden / "test_hidden.py").write_text(
                "def test_hidden_fault():\n    assert False\n", encoding="utf-8",
            )
    elif plant == "precollection-list":
        conftest.write_text("collect_ignore = ['test_probe.py']\n", encoding="utf-8")
    elif plant == "source-change":
        probe.write_text(
            "from pathlib import Path\n"
            "def test_changes_source():\n"
            "    p = Path(__file__)\n"
            "    p.write_text(p.read_text() + '\\n# changed during test\\n')\n",
            encoding="utf-8",
        )
    elif plant == "failed-subtest":
        probe.write_text(PROBE.replace("assert value in (0, 1)", "assert value == 0"),
                         encoding="utf-8")
    elif plant == "skipped-subtest":
        probe.write_text(PROBE.replace(
            "assert value in (0, 1)",
            "import pytest\n            if value:\n"
            "                pytest.skip('planted subtest omission')\n"
            "            assert value == 0",
        ), encoding="utf-8")
    elif plant == "xfail":
        probe.write_text(
            PROBE + "\nimport pytest\n@pytest.mark.xfail(reason='planted')\n"
            "def test_xfail():\n    assert False\n", encoding="utf-8",
        )
    head = _commit(root)
    if plant == "dirty-source":
        probe.write_text(PROBE + "\n# uncommitted change\n", encoding="utf-8")
    supplied = "0" * 40 if plant == "wrong-head" else head
    extra = {"PYTEST_ADDOPTS": "-k test_ok"} if plant == "selector" else None
    result, path = _run(root, supplied, plant, extra)
    if plant == "valid":
        assert result.returncode == 0, result.stdout + result.stderr
        receipt = json.loads(path.read_text(encoding="utf-8"))
        assert len(receipt["universe"]) == 4
        assert receipt["finished"] == receipt["selected"]
        assert len(set(receipt["finished"])) == 4
        assert len(receipt["reports"]["tests/test_probe.py::test_subcases"]) == 3
        assert _verify([receipt], count=1, head=head)["tests"] == 4
    else:
        assert result.returncode != 0, result.stdout + result.stderr
        if path.exists():
            receipt = json.loads(path.read_text(encoding="utf-8"))
            with pytest.raises(ReceiptError):
                _verify([receipt], count=1, head=head)


def _artifact(root, head, label, *, write=True):
    directory = root / f"artifacts-{label}"
    child = directory / f"windows-pytest-1-{head}-{RUN_ID}-{ATTEMPT}"
    child.mkdir(parents=True)
    path = child / "shard-1.json"
    if write:
        path.write_text(json.dumps(_receipts(count=1, head=head)[0]), encoding="utf-8")
    return directory, child, path


def _verify_cli(root, directory, head, jobs_result="success"):
    return _cli(
        root, "verify", "--directory", str(directory), "--head", head,
        "--run-id", RUN_ID, "--attempt", ATTEMPT, "--count", "1",
        "--jobs-result", jobs_result,
    )


def test_verify_directory_gauntlet(isolated_repo):
    root = isolated_repo
    head = _commit(root)
    directory, _, _ = _artifact(root, head, "valid")
    result = _verify_cli(root, directory, head)
    assert result.returncode == 0, result.stdout + result.stderr
    for plant in ("missing", "extra", "nested", "duplicate-keys", "wrong-name"):
        directory, child, path = _artifact(root, head, plant, write=plant != "missing")
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
    for result in ("failure", "cancelled", "skipped"):
        assert _verify_cli(root, directory, head, result).returncode != 0


def test_verify_rejects_links_and_junctions(isolated_repo):
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


def test_artifact_directory_binds_shard_identity(tmp_path):
    from tools.ci_pytest import _read_directory

    head = "a" * 40
    args = SimpleNamespace(
        directory=str(tmp_path), head=head, run_id=RUN_ID, attempt=ATTEMPT, count=COUNT,
    )
    paths = []
    for index, receipt in enumerate(_receipts(), 1):
        folder = tmp_path / f"windows-pytest-{index}-{head}-{RUN_ID}-{ATTEMPT}"
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
