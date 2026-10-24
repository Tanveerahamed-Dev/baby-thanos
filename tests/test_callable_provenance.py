"""Public factories preserve exact-file capabilities without importing consumers."""
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import RUNTIME_API, source_allowed

USING = "atlas_brain/evidence/admission.py"
FACTORIES = ["def opener(): return PurePosixPath.is_absolute",
             "def helper(): return PurePosixPath.is_absolute\ndef opener(): return helper()",
             "def opener(): return (PurePosixPath.is_absolute,)[0]"]
RECEIVERS = ["opener()(value)", "method = opener()\nmethod(value)",
             "(opener() if flag else opener())(value)"]


def cli(root):
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    return subprocess.run([sys.executable, str(Path("tools/fence.py").resolve())], cwd=root,
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("factory", FACTORIES)
@pytest.mark.parametrize("receiver", RECEIVERS)
def test_actual_cli_public_factory_positive_then_returned_member_refusal(tmp_path: Path, factory, receiver):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from pathlib import PurePosixPath\n" + factory + "\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.admission import opener\n", encoding="utf-8")
    probe = tmp_path / "atlas_brain/probe.py"
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for module in (".evidence.admission", ".bridge"):
        prefix = f"from {module} import opener\n"
        probe.write_text(prefix + "opener()\n", encoding="utf-8")
        assert cli(tmp_path).returncode == 0
        probe.write_text(prefix + receiver + "\n", encoding="utf-8")
        refused = cli(tmp_path)
        assert refused.returncode == 1 and "atlas_brain/probe.py" in refused.stdout


@pytest.mark.parametrize("factory", ["def factory(x): return Path(x)",
    "def maker(x): return Path(x)\ndef factory(x): return maker(x)",
    "def factory(x): return (Path(x),)[0]"])
def test_returned_instances_and_global_class_positives(factory):
    sources = {USING: "from pathlib import Path\n" + factory}
    assert source_allowed("from .evidence.admission import factory\nfactory('x')", sources)
    assert not source_allowed("from .evidence.admission import factory\nfactory('x').write_text('x')", sources)
    sources[USING] = "from pathlib import Path\ndef factory(): return Path"
    assert source_allowed("from .evidence.admission import factory\nfactory()('x')", sources)


def test_scoped_class_result_refuses_without_banning_public_factory(monkeypatch):
    monkeypatch.setitem(RUNTIME_API, USING, RUNTIME_API[USING] | {"zipfile.ZipFile"})
    sources = {USING: "from zipfile import ZipFile\ndef factory(): return ZipFile"}
    prefix = "from .evidence.admission import factory\n"
    assert source_allowed(prefix + "factory()", sources)
    assert not source_allowed(prefix + "factory()(source)", sources)
    assert not source_allowed(prefix + "value = factory()\nvalue(source)", sources)


@pytest.mark.parametrize("value, member", [("isinstance(x, Path)", "bit_length()"),
    ("bool(x) and isinstance(x, Path)", "bit_length()"),
    ("'path' if isinstance(x, Path) else 'other'", "upper()")])
def test_predicates_and_ordinary_records_are_not_foreign_instances(value, member):
    sources = {USING: "from pathlib import Path\ndef plain(x): return " + value}
    assert source_allowed("from .evidence.admission import plain\nplain(x)." + member, sources)
    sources[USING] = "class Record:\n field = 1\ndef plain(x): return Record()"
    assert source_allowed("from .evidence.admission import plain\nplain(x).field", sources)


@pytest.mark.parametrize("source", ["from hashlib import sha256\nsha256(b'x').hexdigest()",
    "import json\njson.dumps('x').encode()", "from typing import cast\ncast(str, 'x').encode()",
    "import re\nvalue = re.compile('x', re.ASCII)\nvalue.match('x').end()"])
def test_ordinary_attribute_calls_keep_existing_primitive_operations(source):
    assert source_allowed(source)
