"""Standing-approved PK tooling gets only its actual per-file AST endpoints."""
import ast
import re
from pathlib import Path

import pytest

from tools.fence import SCOPED_API, STDLIB_API, source_allowed

TOKEN = "atlas_brain/evidence/parsekit/token_lint.py"
AUDIT = "atlas_brain/evidence/parsekit/token_audit.py"


@pytest.mark.parametrize("path", [TOKEN, AUDIT])
def test_unlisted_pk_ast_exports_refused(path):
    for name in sorted(vars(ast)):
        if name.isidentifier() and f"ast.{name}" not in SCOPED_API[path]:
            assert not source_allowed(f"from ast import {name}", path=path), name
    assert not source_allowed("import ast; ast.literal_eval('0')", path=path)
    assert not source_allowed("from ast import *", path=path)


@pytest.mark.parametrize("path,api", [(TOKEN, "ast.NodeVisitor"), (AUDIT, "ast.Dict")])
def test_other_tooling_file_does_not_inherit_grant(path, api):
    assert not source_allowed(f"import ast; {api}", path=path)


@pytest.mark.parametrize("source", [
    "from atlas_brain.evidence.parsekit.token_lint import parser; parser('')",
    "from atlas_brain.evidence.parsekit.token_audit import dataclass; dataclass(Record)",
    "from atlas_brain.bridge import dataclass; dataclass(Record)",
])
def test_pk_ast_and_global_reexports_cannot_escape(source):
    sources = {TOKEN: "import ast\nparser = ast.parse", AUDIT: "from dataclasses import dataclass",
               "atlas_brain/bridge.py": "from .evidence.parsekit.token_audit import dataclass"}
    assert not source_allowed(source, sources, "atlas_brain/packs/example.py")
    assert source_allowed("from dataclasses import dataclass; dataclass(Record)", path="atlas_brain/packs/example.py")


def test_pk_amendment_lists_exact_inventory_with_bounds():
    assert len(SCOPED_API[TOKEN]) == 34 and len(SCOPED_API[AUDIT]) == 10
    assert not any(api.startswith("ast.") for api in STDLIB_API)
    text = Path("docs/adr/0004-adr0002-pk-ast-amendment.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == SCOPED_API[TOKEN] | SCOPED_API[AUDIT]
    assert len(text.splitlines()) <= 60 and len(text) <= 4000


def test_class_scope_amendment_is_exact_and_bounded():
    assert source_allowed("import ast; ast.ClassDef", path=TOKEN)
    assert not source_allowed("import ast; ast.literal_eval('0')", path=TOKEN)
    assert not source_allowed("import ast; ast.ClassDef", path="atlas_brain/evidence/parsekit/runtime.py")
    sources = {TOKEN: "import ast\nnode = ast.ClassDef"}
    assert not source_allowed("from .evidence.parsekit.token_lint import node; node", sources)
    text = Path("docs/adr/0005-adr0002-pk-class-scope.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| (ast\.\w+) \|", text)) == {"ast.ClassDef"}
    assert len(text.splitlines()) <= 60 and len(text) <= 4000
