import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import STDLIB_API, allowed, dependencies_allowed, source_allowed


@pytest.mark.parametrize("path", [
    "outside.txt", "prompts/x.md", "tools/prompts/x.md", "docs/adr/BOARD.md",
    "tools/agent-notes.md", "tests/AGENTS.md", "tools/CLAUDE.md",
    "tools/.claude/x", "tools/.codex/x", "tools/.agents/x", "tools/.mcp.json",
    "tools/.specify/x", "tools/specs/x", "tools/plans/x", "docs/other.md",
    "governance/STATUS.md", "governance/STATUS.json", "governance/probe.json",
    "governance/notes.txt", "governance/nested/readme.md",
])
def test_planted_paths_fail(path):
    assert not allowed(path)
    result = subprocess.run(
        [sys.executable, "tools/fence.py", path], capture_output=True, check=False,
    )
    assert result.returncode == 1


@pytest.mark.parametrize("path", [
    "README.md", "uv.lock", "atlas_brain/__init__.py", "tests/test_fence.py",
    "fixtures/example.txt", "docs/adr/0000-plan-approval.md",
    "docs/contract/v1.json", "tools/fence.py", "governance/review.schema.json",
    ".github/workflows/ci.yml",
])
def test_allowed_paths(path):
    assert allowed(path)


def test_current_tree_passes():
    subprocess.run([sys.executable, "tools/fence.py"], check=True)


@pytest.mark.parametrize("source", [
    "import webbrowser", "import tkinter.ttk", "from http import server",
    "from http.server import HTTPServer", "import curses", "import wsgiref",
    "import socketserver", "__import__('webbrowser')",
    "from importlib import import_module as load; load('http.server')",
    "__import__(module_name)", "import unapproved_third_party",
    "exec('import webbrowser')", "eval(\"__import__('webbrowser')\")",
    "compile('import webbrowser', 'synthetic', 'exec')",
    "from builtins import exec as run; run('import webbrowser')",
    "import builtins as b; b.exec('import webbrowser')",
    "run = exec; run('import webbrowser')", "__builtins__['exec']('import webbrowser')",
    "import builtins; getattr(builtins, 'exec')('import webbrowser')",
    "import importlib; load = importlib.import_module; load('webbrowser')",
    "import importlib; getattr(importlib, 'import_module')('webbrowser')",
    "load = __import__; load('webbrowser')",
    "from builtins import __import__ as load; load('webbrowser')",
    "getattr(__import__('builtins'), 'exec')('import webbrowser')",
    "__import__('json')",
    "import builtins as b; alias = b; getattr(alias, 'exec')('import webbrowser')",
    "import sys; sys.modules['builtins'].exec('import webbrowser')",
    "import sys; alias = sys; getattr(alias, 'modules')['builtins'].exec('import webbrowser')",
    "from sys import modules as loaded; loaded['builtins'].exec('import webbrowser')",
    "globals()['__builtins__']['exec']('import webbrowser')",
    "def helper(): pass\nhelper.__globals__['__builtins__']['exec']('import webbrowser')",
    "from inspect import currentframe; getattr(currentframe(), 'f_builtins')['__import__']('webbrowser')",
    "read = getattr; read(object(), 'synthetic')",
    "getattr(object(), ''.join(['f_', 'builtins']))",
    "setattr(object(), 'synthetic', 1)", "delattr(object(), 'synthetic')",
    "hasattr(object(), 'synthetic')", "dir(object())",
    "def frame(): yield\nframe().gi_frame.f_builtins['__import__']('webbrowser')",
    "import pkgutil; pkgutil.resolve_name('webbrowser')",
    "from pkgutil import resolve_name as load; load('webbrowser')",
    "import unittest.mock; unittest.mock.patch('webbrowser.open')",
    "import json; json.codecs.lookup('synthetic')",
    "import re; re.sys.modules['builtins']",
    "from json import codecs", "from json import *",
    "from .capture import *", "object().__getattribute__('synthetic')",
    "help('webbrowser')", "alias = help; alias('webbrowser')", "breakpoint()",
    "__loader__.load_module('webbrowser')", "__spec__.loader.load_module('webbrowser')",
])
def test_denied_engine_imports(source):
    assert not source_allowed(source)


@pytest.mark.parametrize("source", ["import json; json.dumps({})", "from json import dumps; dumps({})", "from typing import Literal", "from atlas_brain.kernel import states", "import re; re.compile('x')"])
def test_allowed_engine_imports(source):
    assert source_allowed(source, {"atlas_brain/kernel/states.py": "class State: pass"})


@pytest.mark.parametrize("endpoint", sorted(STDLIB_API))
def test_admitted_stdlib_api(endpoint):
    module, name = endpoint.rsplit(".", 1)
    assert source_allowed(f"from {module} import {name} as admitted; admitted")


@pytest.mark.parametrize("module", sorted(sys.stdlib_module_names - {name.split('.')[0] for name in STDLIB_API}))
def test_unadmitted_stdlib_modules_are_closed(module):
    assert not source_allowed(f"import {module}")
    assert not source_allowed(f"from atlas_brain import bridge; bridge.{module}",
                              {"atlas_brain/bridge.py": f"import {module}"})


@pytest.mark.parametrize("module", sorted({name.rsplit('.', 1)[0] for name in STDLIB_API}))
def test_unadmitted_exports_are_closed(module):
    for name in sorted(vars(importlib.import_module(module))):
        if name.isidentifier() and f"{module}.{name}" not in STDLIB_API:
            assert not source_allowed(f"from {module} import {name}"), f"{module}.{name}"
            assert not source_allowed(f"from atlas_brain import bridge; bridge.{module}.{name}",
                                      {"atlas_brain/bridge.py": f"import {module}"})


@pytest.mark.parametrize("source,expected", [
    ("from atlas_brain.evidence import admission; value = admission.math.prod((2, 3))", False),
    ("from atlas_brain.evidence.admission import math as m; m.prod((2, 3))", False),
    ("from atlas_brain.evidence import admission; borrowed = admission.math", False),
    ("from atlas_brain import bridge; bridge.forward.math.prod((2, 3))", False),
    ("from .evidence import admission; admission.math.prod((2, 3))", False),
    ("from atlas_brain import bridge; bridge.Namespace.math.prod((2, 3))", False),
    ("from atlas_brain.missing import unknown", False),
    ("from atlas_brain.cycle_a import shared; shared.prod((2, 3))", False),
    ("from atlas_brain.evidence import admission; admission.math.isfinite(1)", True),
    ("from atlas_brain.evidence.admission import math as m; m.isfinite(1)", True),
])
def test_internal_import_provenance(source, expected):
    sources = {"atlas_brain/evidence/admission.py": "import math",
               "atlas_brain/bridge.py": "from .evidence import admission as forward\nclass Namespace:\n import math",
               "atlas_brain/cycle_a.py": "from .cycle_b import shared",
               "atlas_brain/cycle_b.py": "from .cycle_a import shared"}
    assert source_allowed(source, sources) is expected


@pytest.mark.parametrize("container", ["atlas_brain/shadow.py", "atlas_brain/shadow/__init__.py"])
def test_ambiguous_module_export_is_closed(container):
    sources = {container: "import math", "atlas_brain/shadow/math.py": "def prod(values): return 0"}
    assert not source_allowed("from atlas_brain import shadow; shadow.math.prod((2, 3))", sources)


@pytest.mark.parametrize("config", [
    {"project": {"dependencies": ["unapproved==1.0"]}},
    {"project": {"dependencies": [], "optional-dependencies": {"extra": ["unapproved"]}}},
])
def test_runtime_dependency_allowlist(config):
    assert not dependencies_allowed(config)


def test_empty_runtime_dependencies_pass():
    assert dependencies_allowed({"project": {"dependencies": []}})


@pytest.mark.parametrize("plant", ["none", "import", "exec", "nested_builtin", "frame_reflection", "stdlib_loader", "internal_export", "dependency", "prose", "status_json", "invalid_json", "scalar_json", "wrong_gate_shape"])
def test_required_fence_command_refuses_real_tracked_plants(tmp_path, plant):
    source = "import webbrowser" if plant == "import" else "import json"
    if plant == "exec":
        source = "exec('import webbrowser')"
    if plant == "nested_builtin":
        source = "getattr(__import__('builtins'), 'exec')('import webbrowser')"
    if plant == "frame_reflection":
        source = "from inspect import currentframe; getattr(currentframe(), 'f_builtins')['__import__']('webbrowser')"
    if plant == "stdlib_loader":
        source = "import pkgutil; pkgutil.resolve_name('webbrowser')"
    if plant == "internal_export":
        source = "from atlas_brain.evidence import admission; value = admission.math.prod((2, 3))"
    deps = '["unapproved==1.0"]' if plant == "dependency" else "[]"
    files = {"pyproject.toml": f"[project]\ndependencies = {deps}\n",
             "atlas_brain/probe.py": source, "governance/generators.json": json.dumps({
                 "uv.lock": {"command": "uv lock", "tool": "uv==0.13.1", "inputs": ["pyproject.toml"]}})}
    if plant == "internal_export":
        files["atlas_brain/evidence/admission.py"] = "import math"
    if plant == "prose":
        files["governance/STATUS.md"] = "Synthetic process document."
    if plant == "status_json":
        files["governance/STATUS.json"] = '{"status": "Synthetic process document"}'
    if plant == "wrong_gate_shape":
        files["governance/generators.json"] = '{"status": "Synthetic process document"}'
    if plant in {"invalid_json", "scalar_json"}:
        files["governance/generators.json"] = "invalid" if plant == "invalid_json" else '"prose"'
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())
    result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == int(plant != "none"), result.stderr


@pytest.mark.parametrize("dependencies,extras,expected", [
    ([], {}, True), (["unapproved==1.0"], {}, False),
    ([], {"extra": ["unapproved"]}, False), ([], {"extra": []}, True),
])
def test_dependency_declarations_and_tracked_command(tmp_path, dependencies, extras, expected):
    assert dependencies_allowed({"project": {"dependencies": dependencies, "optional-dependencies": extras}}) is expected
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = " + json.dumps(dependencies) + "\n[project.optional-dependencies]\n"
        + "\n".join(f"{key} = {json.dumps(value)}" for key, value in extras.items()), encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())],
                            cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == int(not expected), result.stderr
