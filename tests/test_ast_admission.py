"""The supervisor-approved AST grant is exact and confined to its using paths."""
import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import SCOPED_API, STDLIB_API, source_allowed

TOKEN = "atlas_brain/kernel/token_lints.py"
LINTS = "atlas_brain/kernel/lints.py"
GRANTS = [(path, api) for path, apis in SCOPED_API.items() for api in sorted(apis)]
K_SCOPE_ADDITION = {"ast.AnnAssign", "ast.Assign", "ast.Compare", "ast.Constant", "ast.Expr",
                    "ast.MatchAs", "ast.MatchMapping", "ast.MatchStar", "ast.Return", "ast.stmt", "ast.Subscript"}
K_CONTEXT_ADDITION = {"ast.Eq", "ast.Raise", "ast.iter_fields"}
K_MEMBERSHIP_ADDITION = {"ast.In", "ast.NotIn"}
K_STARRED_ADDITION = {"ast.Starred"}


@pytest.mark.parametrize("path,api", GRANTS)
def test_exact_api_at_using_path_passes(path, api):
    assert source_allowed(f"import ast; {api}", path=path)
    assert source_allowed(f"from ast import {api[4:]} as node; node", path=path)


@pytest.mark.parametrize("path", [TOKEN, LINTS])
def test_actual_unlisted_ast_exports_stay_closed(path):
    for name in sorted(vars(ast)):
        if name.isidentifier() and f"ast.{name}" not in SCOPED_API[path]:
            assert not source_allowed(f"from ast import {name}", path=path), name
    assert not source_allowed("import ast; ast.literal_eval('0')", path=path)
    assert not source_allowed("from ast import *", path=path)
    assert not source_allowed("value = type(0).__name__", path=path)


@pytest.mark.parametrize("api", sorted(set().union(*SCOPED_API.values())))
@pytest.mark.parametrize("path", ["atlas_brain/kernel/runtime.py", "atlas_brain/runner/worker.py",
                                 "atlas_brain/kernel/lints.py/extra.py", "tools/lints.py"])
def test_listed_api_outside_exact_path_refused(api, path):
    assert not source_allowed(f"import ast; {api}", path=path)


def test_scoped_api_cannot_escape_through_internal_reexport():
    sources = {LINTS: "import ast", TOKEN: "import ast"}
    source = "from atlas_brain.kernel import lints; lints.ast.parse('')"
    assert source_allowed(source, sources, LINTS)
    assert not source_allowed(source, sources, "atlas_brain/model/runtime.py")
    assert not source_allowed(source, sources, TOKEN)


@pytest.mark.parametrize("source", [
    "from atlas_brain.kernel.lints import parser; parser('')",
    "from atlas_brain.kernel.lints import exported; exported()('')",
    "from atlas_brain.kernel import lints; lints.exported()",
    "from atlas_brain import bridge; bridge.parser('')",
])
def test_runtime_cannot_borrow_lint_capabilities(source):
    sources = {LINTS: "import ast\nparser = ast.parse\ndef exported(): return ast.parse",
               "atlas_brain/bridge.py": "from .kernel.lints import parser"}
    assert not source_allowed(source, sources, "atlas_brain/model/runtime.py")


def test_lint_to_lint_function_dependency_passes():
    sources = {TOKEN: "def fallback_node(node): return False"}
    assert source_allowed("from .token_lints import fallback_node; fallback_node(None)", sources, LINTS)


@pytest.mark.parametrize("source", [
    "from atlas_brain.kernel.lints import sha256; digest = sha256(raw)",
    "from atlas_brain.kernel import lints; digest = lints.sha256(raw)",
    "from atlas_brain.bridge import sha256; digest = sha256(raw)",
])
def test_global_reexport_cannot_hide_protected_import_hop(source):
    sources = {LINTS: "from hashlib import sha256",
               "atlas_brain/bridge.py": "from .kernel.lints import sha256"}
    assert not source_allowed(source, sources, "atlas_brain/model/runtime.py")
    assert source_allowed("from hashlib import sha256; digest = sha256(raw)", path="atlas_brain/model/runtime.py")


def test_amendment_matches_exact_grant_and_bounds():
    assert set(SCOPED_API) == {TOKEN, LINTS, "atlas_brain/evidence/parsekit/token_lint.py",
                               "atlas_brain/evidence/parsekit/token_audit.py"}
    endpoints = ((SCOPED_API[TOKEN] - K_SCOPE_ADDITION - K_CONTEXT_ADDITION - K_MEMBERSHIP_ADDITION)
                 | (SCOPED_API[LINTS] - K_STARRED_ADDITION))
    assert len(endpoints) == 40
    assert not any(api.startswith("ast.") for api in STDLIB_API)
    text = Path("docs/adr/0003-adr0002-ast-amendment.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == endpoints
    assert len(text.splitlines()) <= 60 and len(text) <= 4000


def test_k_class_scope_amendment_has_only_eleven_actual_using_bindings():
    assert len(SCOPED_API[TOKEN] - K_CONTEXT_ADDITION - K_MEMBERSHIP_ADDITION) == 24
    assert K_SCOPE_ADDITION <= SCOPED_API[TOKEN]
    text = Path("docs/adr/0006-adr0002-k-token-scope.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == K_SCOPE_ADDITION
    assert len(text.splitlines()) <= 60 and len(text) <= 4000
    for api in K_SCOPE_ADDITION:
        assert source_allowed(f"import ast; {api}", path=TOKEN)
        assert not source_allowed(f"import ast; {api}", path="atlas_brain/kernel/runtime.py")
    assert not source_allowed("import ast; ast.literal_eval('0')", path=TOKEN)
    assert not source_allowed("from .kernel.token_lints import ast; ast.Compare",
                              {TOKEN: "import ast"}, "atlas_brain/runtime.py")


def test_context_amendment_has_only_three_actual_using_bindings():
    assert len(SCOPED_API[TOKEN] - K_MEMBERSHIP_ADDITION) == 27
    assert K_CONTEXT_ADDITION <= SCOPED_API[TOKEN]
    assert len(STDLIB_API) == 22 and len(SCOPED_API[LINTS] - K_STARRED_ADDITION) == 32
    text = Path("docs/adr/0007-adr0002-k-context-scope.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == K_CONTEXT_ADDITION
    assert len(text.splitlines()) <= 60 and len(text) <= 4000


def test_membership_amendment_is_exact_and_bounded():
    assert len(SCOPED_API[TOKEN]) == 29 and K_MEMBERSHIP_ADDITION <= SCOPED_API[TOKEN]
    assert len(STDLIB_API) == 22 and len(SCOPED_API[LINTS] - K_STARRED_ADDITION) == 32
    text = Path("docs/adr/0008-adr0002-k-membership.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == K_MEMBERSHIP_ADDITION
    assert len(text.splitlines()) <= 60 and len(text) <= 4000


@pytest.mark.parametrize("api", sorted(K_CONTEXT_ADDITION | K_MEMBERSHIP_ADDITION))
def test_context_bindings_cannot_escape_or_reexport(api):
    assert source_allowed(f"import ast; {api}", path=TOKEN)
    assert not source_allowed(f"import ast; {api}", path=LINTS)
    sources = {TOKEN: f"import ast\nnode = {api}"}
    assert not source_allowed("from .kernel.token_lints import node; node", sources, "atlas_brain/runtime.py")
    sources["atlas_brain/bridge.py"] = "from .kernel.token_lints import node"
    assert not source_allowed("from .bridge import node; node", sources, "atlas_brain/runtime.py")


@pytest.mark.parametrize("path,source,expected", [
    (TOKEN, "import ast; ast.Name", 0), (LINTS, "import ast; ast.parse('')", 0),
    (TOKEN, "import ast; ast.Compare", 0), (TOKEN, "import ast; ast.literal_eval('0')", 1),
    (TOKEN, "import ast; ast.Eq", 0), (TOKEN, "import ast; ast.Raise", 0),
    (TOKEN, "import ast; ast.iter_fields", 0),
    (TOKEN, "import ast; ast.In", 0), (TOKEN, "import ast; ast.NotIn", 0),
    (LINTS, "import ast; ast.literal_eval('0')", 1),
    ("atlas_brain/kernel/runtime.py", "import ast; ast.Name", 1),
])
def test_tracked_cli_enforces_ast_scope(tmp_path, path, source, expected):
    file = tmp_path / path
    file.parent.mkdir(parents=True)
    file.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())],
                            cwd=tmp_path, capture_output=True, check=False)
    assert result.returncode == expected, result.stderr


@pytest.fixture
def inventory_source_transport(monkeypatch):
    from tools import check_ast_inventory as inventory

    real_read = inventory.subprocess.check_output
    historical = {}
    for path, revision in inventory.SOURCES.items():
        apis = SCOPED_API[path] - ({"ast.Starred"} if path == LINTS else set())
        historical[f"{revision}:{path}"] = "import ast\n" + "\n".join(sorted(apis)) + "\n"
    target = f"{inventory.STARRED_HEAD}:{LINTS}"
    transport = {"missing": False, "requests": []}

    def read(command, *args, **kwargs):
        if command[:2] == ["git", "show"] and command[2] in historical:
            return historical[command[2]]
        if command == ["git", "show", target]:
            transport["requests"].append(command)
            if transport["missing"]:
                raise subprocess.CalledProcessError(128, command, stderr=b"missing pinned source object")
            return b"import ast\nast.Starred\n"
        if command == ["git", "rev-parse", target]:
            return inventory.STARRED_BLOB + "\n"
        return real_read(command, *args, **kwargs)

    monkeypatch.setattr(inventory.subprocess, "check_output", read)
    return inventory, transport


def test_actual_inventory_refuses_an_absent_starred_source_object(inventory_source_transport):
    inventory, transport = inventory_source_transport
    transport["missing"] = True
    missing = ["git", "show", f"{inventory.STARRED_HEAD}:{LINTS}"]
    with pytest.raises(subprocess.CalledProcessError) as refused:
        inventory.main()
    assert refused.value.returncode == 128 and refused.value.cmd == missing
    assert transport["requests"] == [missing]


def test_actual_inventory_refuses_mismatched_digest_for_otherwise_allowed_source(inventory_source_transport):
    inventory, transport = inventory_source_transport
    target = ["git", "show", f"{inventory.STARRED_HEAD}:{LINTS}"]
    changed = b"import ast\nast.Starred\n"
    assert source_allowed(changed.decode("utf-8"), path=LINTS)
    assert inventory.sha256(changed).hexdigest() != inventory.STARRED_DIGEST
    with pytest.raises(ValueError, match="Starred source differs from the exact public pin"):
        inventory.main()
    assert transport["requests"] == [target]
