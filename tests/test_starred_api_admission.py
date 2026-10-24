"""Exact public using source is data; these tests never execute the K consumer."""
import ast
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from tools.check_ast_inventory import SOURCES
from tools.fence import RUNTIME_API, SCOPED_API, STDLIB_API, source_allowed

LINTS = "atlas_brain/kernel/lints.py"
TOKEN = "atlas_brain/kernel/token_lints.py"
PIN = "b5ddc54f6e4aa6332094561f79bda0af4fa3f690"
BLOB = "772852e25f13425aca12cc2c77b0c849794dd9f1"
DIGEST = "36817d7a9e4e75a935fc25a848008343cb7cadd0745af835607f61658f019f4f"


def using_source():
    raw = subprocess.check_output(["git", "show", f"{PIN}:{LINTS}"])
    blob = subprocess.check_output(["git", "rev-parse", f"{PIN}:{LINTS}"], text=True).strip()
    assert blob == BLOB and sha256(raw).hexdigest() == DIGEST
    return raw.decode("utf-8")


def test_exact_public_using_pin_and_only_one_additional_binding():
    source = using_source()
    used = {f"ast.{node.attr}" for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ast"}
    prior = subprocess.check_output(["git", "show", f"{SOURCES[LINTS]}:{LINTS}"], text=True)
    prior_used = {f"ast.{node.attr}" for node in ast.walk(ast.parse(prior))
                  if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "ast"}
    assert SOURCES[LINTS] == "fb1ce4754a1fa9d2e43f121b6a82cb7d832e3c5b"
    assert len(used) == len(prior_used) == 32
    assert used - prior_used == {"ast.Starred"} and prior_used - used == {"ast.parse"}
    assert used | prior_used == SCOPED_API[LINTS] and len(SCOPED_API[LINTS]) == 33
    assert len(SCOPED_API[TOKEN]) == 29 and len(STDLIB_API) == 22
    assert "ast.Starred" not in SCOPED_API[TOKEN]
    assert not any(api.startswith("ast.") for api in STDLIB_API)
    assert all(not any(api.startswith("ast.") for api in apis) for apis in RUNTIME_API.values())
    sources = {LINTS: source, TOKEN: Path(TOKEN).read_text(encoding="utf-8")}
    assert source_allowed(source, sources, LINTS)
    text = Path("docs/adr/0012-adr0002-k-starred.md").read_text(encoding="utf-8")
    assert re.findall(r"(?m)^Status: (.+)$", text) == ["accepted"]
    assert re.findall(r"(?m)^\| (ast\.\w+) \|", text) == ["ast.Starred"]
    assert all(value in text for value in (LINTS, PIN, BLOB, DIGEST))


@pytest.mark.parametrize("source", ["import ast; node = ast.Starred",
                                  "import ast as syntax; node = syntax.Starred",
                                  "from ast import Starred as Spread; node = Spread"])
def test_starred_direct_module_and_alias_bindings_stay_exact(source):
    assert source_allowed(source, path=LINTS)
    for path in (TOKEN, "atlas_brain/model/runtime.py", "tools/lints.py", LINTS + "/extra.py"):
        assert not source_allowed(source, path=path)


@pytest.mark.parametrize("call", ["re.compile('x', flags=re.ASCII)",
                                 "re.split('x', text, maxsplit=1, flags=re.ASCII)",
                                 "re.sub('x', 'y', text, count=1, flags=re.ASCII)",
                                 "re.subn('x', 'y', text, count=1, flags=re.ASCII)",
                                 "re.search('x', *args, flags=re.ASCII)"])
def test_explicit_flags_examples_remain_parsed_data(call):
    source = ("import ast\nnode = ast.parse(" + repr(call) + ")\n"
              "spread = isinstance(node, ast.Starred)\n")
    assert source_allowed(source, path=LINTS)


def test_actual_source_keeps_positional_arity_separate_from_explicit_keywords():
    source = using_source()
    assert "flag_index = 1 if short == 'compile' else 3 if short == 'split' else 4 if short in ('sub', 'subn') else 2" in source
    assert "positional = node.args[flag_index:flag_index + 1]" in source
    assert "if any(isinstance(argument, ast.Starred) for argument in node.args[:flag_index]):\n                positional = []" in source
    assert "flags = list(positional) + [k.value for k in node.keywords if k.arg == 'flags']" in source
    # Pinned syntax preservation is not a behavioral R12 verdict or K test replay.


@pytest.mark.parametrize("tail", ["import socket", "import ast; ast.literal_eval('0')", "from ast import *"])
def test_reforged_actual_source_does_not_expand_admission(tail):
    source = using_source() + "\n" + tail + "\n"
    assert sha256(source.encode()).hexdigest() != DIGEST
    assert not source_allowed(source, {LINTS: source}, LINTS)


@pytest.mark.parametrize("source", ["from atlas_brain.kernel.lints import node; node",
                                  "from atlas_brain.kernel import lints; lints.node",
                                  "from atlas_brain.bridge import node; node",
                                  "from atlas_brain import bridge; bridge.node"])
def test_starred_cannot_be_borrowed_through_direct_alias_or_bridge(source):
    sources = {LINTS: "import ast\nnode = ast.Starred",
               "atlas_brain/bridge.py": "from .kernel.lints import node"}
    assert not source_allowed(source, sources, "atlas_brain/model/runtime.py")
    assert not source_allowed(source, sources, TOKEN)


@pytest.mark.parametrize("plant", ["healthy", "unlisted", "wrong_file"])
def test_actual_pinned_source_through_real_tracked_cli(tmp_path, plant):
    sources = {LINTS: using_source(), TOKEN: Path(TOKEN).read_text(encoding="utf-8")}
    if plant == "unlisted":
        sources[LINTS] += "\nimport ast; ast.literal_eval('0')\n"
    if plant == "wrong_file":
        sources["atlas_brain/model/runtime.py"] = "from atlas_brain.kernel.lints import ast; ast.Starred"
    for path, source in sources.items():
        file = tmp_path / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())],
                            cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == (0 if plant == "healthy" else 1), result.stderr
