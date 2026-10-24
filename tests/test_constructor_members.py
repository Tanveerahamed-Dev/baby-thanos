"""Direct stdlib constructor receivers cannot hide unlisted member capabilities."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import STDLIB_API, constructor_members, source_allowed

EXPRESSIONS = ["Path('synthetic')", "P('synthetic')", "p.Path('synthetic')",
               "(Path('a') if True else Path('b'))", "(Path('synthetic') / 'child')"]
IMPORTS = "from pathlib import Path, Path as P\nimport pathlib as p\n"


def test_registered_class_namespace_is_derived_not_a_mutator_name_list():
    members = constructor_members(frozenset(STDLIB_API))
    assert members["pathlib.Path"] == {name for name in dir(Path) if name.isidentifier() and not name.startswith("_")}
    assert {"write_text", "write_bytes", "open", "unlink"} <= members["pathlib.Path"]
    with pytest.raises(ValueError, match="stdlib"):
        constructor_members(frozenset({"atlas_brain.probe.Record"}))
    for member in members["pathlib.Path"]:
        assert not source_allowed("from pathlib import Path\nPath('synthetic')." + member)


@pytest.mark.parametrize("expression", EXPRESSIONS)
def test_direct_stdlib_expression_member_refuses(expression):
    assert source_allowed(IMPORTS + expression)
    assert not source_allowed(IMPORTS + expression + ".write_text('x')")


def test_existing_path_reads_are_exactly_scoped_and_constructor_stays_callable():
    source = "from pathlib import PurePosixPath\nPurePosixPath('x').is_absolute()\nPurePosixPath('x').parts"
    assert source_allowed(source, path="atlas_brain/evidence/admission.py")
    assert not source_allowed(source)
    assert source_allowed("from hashlib import sha256\nsha256(b'x').hexdigest()")


@pytest.mark.parametrize("kind", ["outside", "noncontract"])
@pytest.mark.parametrize("conditional", [False, True])
def test_direct_constructor_actual_cli_and_output_negative(tmp_path: Path, kind, conditional):
    package = tmp_path / "atlas_brain"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    root = tmp_path / "contract"
    target = tmp_path / "forbidden" if kind == "outside" else root / "notes.txt"
    expression = "Path(" + repr(str(target)) + ")"
    if conditional:
        expression = f"({expression} if True else {expression})"
    probe = package / "probe.py"
    probe.write_text("from pathlib import Path\nvalue = " + expression + "\nvalue\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    def fence():
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        return subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert fence().returncode == 0
    probe.write_text("from pathlib import Path\n" + expression + ".write_text('x', encoding='utf-8')\n", encoding="utf-8")
    refused = fence()
    assert refused.returncode == 1 and "atlas_brain/probe.py" in refused.stdout
    witness = subprocess.run([sys.executable, str(Path("tools/output_witness.py").resolve()), "--root", str(root)],
                             cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
                             capture_output=True, text=True, check=False)
    receipt = json.loads(witness.stdout)
    assert witness.returncode == 1 and receipt["completed"] is False and "open" in receipt["violations"]
    assert not target.exists()
