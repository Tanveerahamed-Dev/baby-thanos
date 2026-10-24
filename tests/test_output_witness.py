import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import source_allowed
from tools.output_witness import contract_path


@pytest.mark.parametrize("probe,expected", [("engine", 0), ("inside", 0), ("noncontract", 1), ("outside", 1), ("rename", 1), ("launch", 1)] + ([("fork", 1)] if hasattr(os, "fork") else []))
def test_output_witness(tmp_path, probe, expected):
    root = tmp_path / "contract"
    result = subprocess.run(
        [sys.executable, "-m", "tools.output_witness", "--root", str(root), "--probe", probe],
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, check=False,
    )
    assert result.returncode == expected, result.stderr
    assert not (tmp_path / "forbidden").exists()
    if probe == "inside":
        assert (root / "result.json").read_text(encoding="utf-8") == "{}"
    if probe == "noncontract":
        assert b"open" in result.stdout
        assert not (root / "notes.txt").exists()
    if probe in {"launch", "fork"}:
        expected_event = b"subprocess.Popen" if probe == "launch" else b"os.fork"
        assert expected_event in result.stdout


@pytest.mark.parametrize("name,expected", [
    ("result.json", True), ("MANIFEST.sha256", True), ("facts/interface.jsonl", True),
    ("checks/l2.vlan_trunk.jsonl", True), ("receipt.json", False), ("notes.txt", False),
    ("facts/notes.txt", False), ("checks/freeform.jsonl", False), ("facts/nested/interface.jsonl", False),
    ("facts/.jsonl", False), ("facts/Interface.jsonl", False), ("result.json/extra", False),
])
def test_contract_path_grammar(tmp_path, name, expected):
    assert contract_path(tmp_path / name, tmp_path) is expected


@pytest.mark.parametrize("name,expected", [("facts", True), ("checks", True), ("other", False), ("facts/nested", False)])
def test_contract_directory_grammar(tmp_path, name, expected):
    assert contract_path(tmp_path / name, tmp_path, directory=True) is expected


@pytest.mark.parametrize("name,expected", [("result.json", 0), ("notes.txt", 1)])
def test_import_write_obeys_contract_grammar(tmp_path, name, expected):
    package = tmp_path / "atlas_brain"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    target = tmp_path / "contract" / name
    (package / "probe.py").write_text("from pathlib import Path\nPath(" + repr(str(target)) + ").write_text('{}', encoding='utf-8')", encoding="utf-8")
    tool = str(Path("tools/output_witness.py").resolve())
    result = subprocess.run([sys.executable, tool, "--root", str(target.parent)], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
                            capture_output=True, check=False)
    assert result.returncode == expected, result.stderr
    assert target.exists() is (expected == 0)


def test_namespace_module_write_is_exercised_and_refused(tmp_path):
    package = tmp_path / "atlas_brain"
    for name, text in {"__init__.py": "", "safe.py": "", "namespace/probe.py":
                       "from pathlib import Path\nPath(" + repr(str(tmp_path / "forbidden")) + ").write_text('x', encoding='utf-8')"}.items():
        file = package / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
    tool = str(Path("tools/output_witness.py").resolve())
    result = subprocess.run([sys.executable, tool, "--root", str(tmp_path / "contract")], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
                            capture_output=True, check=False)
    assert result.returncode == 1, result.stderr
    assert not (tmp_path / "forbidden").exists()


def run_synthetic_engine(tmp_path, files):
    package = tmp_path / "atlas_brain"
    for name, source in files.items():
        file = package / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(source, encoding="utf-8")
    tool = str(Path("tools/output_witness.py").resolve())
    return subprocess.run([sys.executable, tool, "--root", str(tmp_path / "contract")], cwd=tmp_path,
                          env={**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("plant", ["module_exit", "root_exit", "caught_write_exit", "caught_write_continue", "silent_exit", "late_write_exit"])
def test_early_success_or_swallowed_violation_cannot_pass(tmp_path, plant):
    source = "raise SystemExit(0)"
    if plant.startswith("caught_write"):
        source = ("from pathlib import Path\ntry:\n Path(" + repr(str(tmp_path / "forbidden"))
                  + ").write_text('x', encoding='utf-8')\nexcept RuntimeError:\n pass\n"
                  + ("raise SystemExit(0)" if plant == "caught_write_exit" else ""))
    if plant == "silent_exit":
        source = "import os\nos._exit(0)"
    if plant == "late_write_exit":
        source = ("import atexit\nfrom pathlib import Path\ndef later():\n try:\n  Path("
                  + repr(str(tmp_path / "forbidden")) + ").write_text('x', encoding='utf-8')\n except RuntimeError:\n  pass\natexit.register(later)")
    assert source_allowed(source) is (plant not in {"silent_exit", "late_write_exit", "caught_write_exit", "caught_write_continue"})
    last = "from pathlib import Path\nPath(" + repr(str(tmp_path / "contract/result.json")) + ").write_text('{}', encoding='utf-8')"
    files = {"__init__.py": source if plant == "root_exit" else "",
             "aa_first.py": "" if plant == "root_exit" else source, "zz_last.py": last}
    result = run_synthetic_engine(tmp_path, files)
    assert result.returncode == 1, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["completed"] is False
    assert not (tmp_path / "forbidden").exists()
    assert (tmp_path / "contract/result.json").exists() is (plant == "late_write_exit")
    if plant.startswith("caught_write"):
        assert "open" in receipt["violations"]


def test_completion_receipt_follows_all_real_imports(tmp_path):
    last = "from pathlib import Path\nPath(" + repr(str(tmp_path / "contract/result.json")) + ").write_text('{}', encoding='utf-8')"
    result = run_synthetic_engine(tmp_path, {"__init__.py": "", "aa_first.py": "", "zz_last.py": last})
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["completed"] is True and receipt["violations"] == []
    assert receipt["modules"] == ["atlas_brain", "atlas_brain.aa_first", "atlas_brain.zz_last"]
    assert (tmp_path / "contract/result.json").read_text(encoding="utf-8") == "{}"


def test_import_origin_must_match_planned_source(tmp_path):
    result = run_synthetic_engine(tmp_path, {"__init__.py": "__file__ = 'other.py'", "probe.py": ""})
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["completed"] is False
