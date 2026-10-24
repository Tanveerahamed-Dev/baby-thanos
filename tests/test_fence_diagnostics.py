"""CLI diagnostics expose public path/API identities, never source or parser text."""
import json
import subprocess
import sys
from pathlib import Path

import pytest


def run_fence(root, files, *args):
    for name, text in {"pyproject.toml": "[project]\ndependencies = []\n", **files}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve()), *args],
                            cwd=root, capture_output=True, text=True, check=False)
    assert not result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    assert all(set(row) == {"path", "class", "name"} for row in rows)
    assert "DO_NOT_PRINT_SOURCE" not in result.stdout
    return result, rows


def test_cli_identifies_every_refusal_class_and_exact_endpoints(tmp_path):
    result, rows = run_fence(tmp_path, {
        "outside.txt": "DO_NOT_PRINT_SOURCE",
        "atlas_brain/probe.py": "import ast; ast.literal_eval('DO_NOT_PRINT_SOURCE'); ast.ClassDef",
        "governance/generators.json": '{"secret": "DO_NOT_PRINT_SOURCE"}',
        "pyproject.toml": '[project]\ndependencies = ["DO_NOT_PRINT_SOURCE"]\n',
    })
    assert result.returncode == 1
    assert {tuple(row[key] for key in ("path", "class", "name")) for row in rows} == {
        ("outside.txt", "path", "unapproved-path"),
        ("atlas_brain/probe.py", "import", "ast"),
        ("atlas_brain/probe.py", "import", "ast.ClassDef"),
        ("atlas_brain/probe.py", "import", "ast.literal_eval"),
        ("governance/generators.json", "machine-data", "invalid-shape"),
        ("pyproject.toml", "dependency", "project.dependencies/optional-dependencies"),
    }


@pytest.mark.parametrize("path,text,kind,name", [
    ("atlas_brain/probe.py", "import json\nDO_NOT_PRINT_SOURCE = (", "import", "invalid-syntax"),
    ("governance/generators.json", "DO_NOT_PRINT_SOURCE", "machine-data", "invalid-data"),
    ("pyproject.toml", "DO_NOT_PRINT_SOURCE", "dependency", "invalid-data"),
    ("atlas_brain/probe.py", "from math import prod", "import", "math.prod"),
    ("atlas_brain/probe.py", "from .bridge import value", "import", "atlas_brain.bridge.value"),
])
def test_cli_parse_and_provenance_failures_remain_closed(tmp_path, path, text, kind, name):
    result, rows = run_fence(tmp_path, {path: text})
    assert result.returncode == 1
    assert {"path": path, "class": kind, "name": name} in rows


def test_explicit_nonrepository_path_is_redacted(tmp_path):
    result, rows = run_fence(tmp_path, {}, str(tmp_path / "DO_NOT_PRINT_SOURCE.py"))
    assert result.returncode == 1
    assert rows == [{"path": "<non-repository-path>", "class": "path", "name": "unapproved-path"}]


def test_clean_tree_keeps_zero_refusal_summary(tmp_path):
    result, rows = run_fence(tmp_path, {"atlas_brain/probe.py": "import json; json.dumps({})"})
    assert result.returncode == 0 and rows == []
    assert "scope fence: 0 refused" in result.stdout
