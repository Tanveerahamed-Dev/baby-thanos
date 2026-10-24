"""One constructor-witness API at its using path; consumer source is data only."""
import ast
import dataclasses
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import RUNTIME_API, SCOPED_API, STDLIB_API, source_allowed

USING = "atlas_brain/kernel/population.py"
API = "dataclasses.InitVar"
REVISION = "0d1664c58e99dc42894323d182f05419b6597288"
BLOB = "2e207c167c9bc1b6190b7c2f8e9cadd0db1ffe85"
DIGEST = "1036383e0fa74d988be50f073d080a2c2cfa694e338c00c119e979c323d8fd1d"


def using_source():
    payload = Path("tests/fixtures/population.source.txt").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == DIGEST
    assert hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload,
                        usedforsecurity=False).hexdigest() == BLOB
    assert payload.count(b"\n") == 75
    return payload.decode("utf-8")


def test_pinned_population_inventory_and_exact_amendment():
    tree = ast.parse(using_source())
    record = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ExpectedSet")
    fields = [n for n in record.body if isinstance(n, ast.AnnAssign)]
    witness = next(n for n in fields if isinstance(n.target, ast.Name) and n.target.id == "candidates")
    assert isinstance(witness.annotation, ast.Subscript)
    assert isinstance(witness.annotation.value, ast.Name) and witness.annotation.value.id == "InitVar"
    assert witness.value is None and all(n.value is None for n in fields)
    assert sum(isinstance(n, ast.Name) and n.id == "InitVar" for n in ast.walk(tree)) == 1
    assert RUNTIME_API[USING] == {API} and USING not in SCOPED_API
    assert API not in STDLIB_API and len(STDLIB_API) == 22
    text = Path("docs/adr/0011-adr0002-population-initvar.md").read_text(encoding="utf-8")
    assert [line for line in text.splitlines() if line.startswith("Status:")] == ["Status: accepted"]
    assert all(value in text for value in (API, USING, REVISION, BLOB, DIGEST))
    assert len(text.splitlines()) <= 45 and len(text) <= 3500


@pytest.mark.parametrize("source", ["from dataclasses import InitVar\ncandidates: InitVar[tuple[str, ...]]",
                                  "from dataclasses import InitVar as Witness\nvalue: Witness[object]",
                                  "import dataclasses as data\nvalue: data.InitVar[object]"])
def test_initvar_exact_using_path_and_other_binding_refusals(source):
    assert source_allowed(source, path=USING)
    for path in ("atlas_brain/kernel/verdict.py", "atlas_brain/probe.py",
                 "atlas_brain/kernel/populations.py", USING + "/extra.py"):
        assert not source_allowed(source, path=path)


def test_unlisted_dataclasses_namespace_and_existing_protected_apis_refuse():
    for name in sorted(vars(dataclasses)):
        if name.isidentifier() and "dataclasses." + name not in STDLIB_API | {API}:
            assert not source_allowed(f"from dataclasses import {name}", path=USING), name
    for source in ("from dataclasses import *", "import ast; ast.parse('')", "import subprocess"):
        assert not source_allowed(source, path=USING)


def test_actual_tracked_source_and_public_records_do_not_export_the_api(tmp_path: Path):
    tracked = subprocess.check_output(["git", "ls-files", "-z", "atlas_brain"], encoding="utf-8").split("\0")
    sources = {path: Path(path).read_text(encoding="utf-8") for path in tracked if path.endswith(".py")}
    sources[USING] = using_source()
    assert source_allowed(sources[USING], sources, USING)
    for path, source in sources.items():
        file = tmp_path / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_bytes(Path("pyproject.toml").read_bytes())
    (tmp_path / "atlas_brain/bridge.py").write_text(
        "from .kernel.population import InitVar as witness\n", encoding="utf-8")
    # No imports of population or constructor execution: the real fence parses tracked files.
    consumer = tmp_path / "atlas_brain/probe.py"
    consumer.write_text("from .kernel.population import ExpectedSet, CoverageSummary, coverage\n"
                        "record = ExpectedSet\nsummary = CoverageSummary\nprojection = coverage\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    # Keep the capability-bearing bridge untracked for the must-pass public-record control.
    subprocess.run(["git", "-C", str(tmp_path), "add", "atlas_brain", "pyproject.toml"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "rm", "--cached", "atlas_brain/bridge.py"], check=True)
    subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
    for source in ("from dataclasses import InitVar\nInitVar(object)\n",
                   "import dataclasses\nvalue = dataclasses.InitVar\n",
                   "from .kernel.population import InitVar\nvalue = InitVar\n",
                   "from .kernel.population import InitVar as witness\nwitness(object)\n",
                   "from .kernel import population\nvalue = population.InitVar\n",
                   "from .bridge import witness\nwitness(object)\n"):
        assert not source_allowed(source, {**sources, "atlas_brain/bridge.py":
                                           "from .kernel.population import InitVar as witness\n"})
        consumer.write_text(source, encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout
    # An unlisted API at the admitted path must still fail in the actual tracked CLI.
    consumer.write_text("from .kernel.population import ExpectedSet\n", encoding="utf-8")
    (tmp_path / USING).write_text(sources[USING] + "\nfrom dataclasses import make_dataclass\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    refused = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert refused.returncode == 1 and USING in refused.stdout and "dataclasses.make_dataclass" in refused.stdout
