"""Assignments preserve import provenance; opaque protected roots fail closed."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import STDLIB_API, ImportIndex, source_allowed

USING = "atlas_brain/evidence/producer.py"
MODULE = "atlas_brain.evidence.producer."
SHAPES = {
    "plain": "leaked = capability",
    "chain": "first = capability\nleaked = first",
    "annotated": "leaked: object = capability",
    "tuple": "leaked, other = capability, 0",
    "module": "import zipfile\nleaked = zipfile.ZipFile",
    "conditional": "leaked = capability if flag else capability",
    "class": "class Holder:\n    leaked = capability",
    "boolean": "leaked = capability or capability",
    "named": "leaked = (other := capability)",
    "container": "leaked = (capability,)[0]",
}
BINDINGS = {
    "loop": "for leaked in (capability,):\n    pass",
    "unpack_loop": "for leaked, other in ((capability, 0),):\n    pass",
    "context": "with capability() as leaked:\n    pass",
    "augmented": "leaked = []\nleaked += [capability]",
    "subscript": "leaked = {}\nleaked['api'] = capability",
    "pattern": "match capability:\n    case leaked: pass",
    "annotation": "leaked: object",
    "type_alias": "type leaked = capability",
}


@pytest.mark.parametrize("shape", SHAPES)
def test_assignment_origin_is_canonical_or_refused_through_bridge(shape):
    symbol = "Holder.leaked" if shape == "class" else "leaked"
    sources = {USING: "from zipfile import ZipFile as capability\n" + SHAPES[shape],
               "atlas_brain/bridge.py": "from .evidence import producer\nexported = producer." + symbol}
    index = ImportIndex(sources)
    expected = None if shape == "container" else "zipfile.ZipFile"
    assert index.origin(MODULE + symbol) == expected
    assert index.origin("atlas_brain.bridge.exported") == expected
    assert not source_allowed("from .evidence import producer; producer." + symbol, sources)
    assert not source_allowed("from .bridge import exported; exported", sources)


@pytest.mark.parametrize("assignment", [
    "leaked = capability if flag else 0", "leaked = capability or 0",
    "leaked = 0\nleaked = capability", "leaked = capability\nleaked = 0",
    "leaked = [capability][0]", "leaked = {'api': capability}['api']",
    "leaked = (capability,)[0]\nleaked = leaked()",
    "leaked = unknown(capability)", "leaked, *rest = unknown(capability)",
])
def test_unproven_rhs_or_rebinding_is_not_an_engine_declaration(assignment):
    sources = {USING: "from zipfile import ZipFile as capability\n" + assignment}
    assert ImportIndex(sources).origin(MODULE + "leaked") is None
    assert not source_allowed("from .evidence.producer import leaked", sources)


@pytest.mark.parametrize("body", [
    "from pathlib import Path\nvalue = Path('synthetic')",
    "import re\nvalue = re.compile('synthetic')",
    "def helper(): pass\nvalue = helper()", "class Record: pass\nvalue = Record()",
    "value = {'synthetic': 1}", "value = [1, 2][0]",
    "class Record: pass\ntype value = Record | int",
    "class Record[T]: pass\ntype value[T] = Record[T] | None",
])
def test_ordinary_declarations_and_globally_admitted_data_stay_importable(body):
    sources = {USING: body + "\ndef public(value): return value\nclass PublicRecord: pass"}
    assert ImportIndex(sources).origin(MODULE + "value") == MODULE + "value"
    assert source_allowed("from .evidence.producer import value, public, PublicRecord", sources)
    assert len(STDLIB_API) == 22


@pytest.mark.parametrize("rhs", ["Path", "Path or Path", "(Path,)[0]", "Path('synthetic')"])
def test_actual_cli_keeps_globally_admitted_producers_and_public_declarations(tmp_path: Path, rhs):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from pathlib import Path\nvalue = " + rhs + "\ndef public(value): return value\nclass Record: pass\n", encoding="utf-8")
    (tmp_path / "atlas_brain/probe.py").write_text("from .evidence.producer import value, public, Record\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0 and "scope fence: 0 refused" in result.stdout


@pytest.mark.parametrize("binding", BINDINGS.values())
def test_other_binding_forms_do_not_create_unproven_public_declarations(binding):
    sources = {USING: "from zipfile import ZipFile as capability\n" + binding,
               "atlas_brain/bridge.py": "from .evidence.producer import leaked\nexported = leaked"}
    index = ImportIndex(sources)
    assert index.origin(MODULE + "leaked") in {None, "zipfile.ZipFile"}
    assert index.origin("atlas_brain.bridge.exported") in {None, "zipfile.ZipFile"}
    assert not source_allowed("from .evidence.producer import leaked", sources)
    assert not source_allowed("from .bridge import exported", sources)


@pytest.mark.parametrize("binding", [BINDINGS["loop"], BINDINGS["unpack_loop"],
                                   BINDINGS["context"], BINDINGS["augmented"], BINDINGS["subscript"], BINDINGS["pattern"]])
def test_actual_cli_reports_consumer_and_bridge_binding_refusals(tmp_path: Path, binding):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile as capability\n" + binding + "\ndef public(value): return value\nclass Record: pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    consumer = tmp_path / "atlas_brain/probe.py"
    consumer.write_text("from .evidence.producer import public, Record\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    def refused_paths():
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1
        return {json.loads(line)["path"] for line in result.stdout.splitlines() if line.startswith("{")}
    # A grants no ZIP API: distinguish the existing producer refusal from each consumer refusal.
    assert refused_paths() == {USING}
    consumer.write_text("from .evidence.producer import leaked\n", encoding="utf-8")
    assert refused_paths() == {USING, "atlas_brain/probe.py"}
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.producer import leaked\nexported = leaked\n", encoding="utf-8")
    consumer.write_text("from .bridge import exported\n", encoding="utf-8")
    assert refused_paths() == {USING, "atlas_brain/probe.py", "atlas_brain/bridge.py"}


def test_actual_cli_keeps_ordinary_loop_bindings_and_public_declarations(tmp_path: Path):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("for value in (1, 2):\n    pass\ndef public(value): return value\nclass Record: pass\ntype Evidence = Record | int\n", encoding="utf-8")
    (tmp_path / "atlas_brain/probe.py").write_text("from .evidence.producer import value, public, Record, Evidence\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0 and "scope fence: 0 refused" in result.stdout
