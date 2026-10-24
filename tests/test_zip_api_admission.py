"""ZIP primitives are exact per-file grants, never a runtime-module import ban."""
import re
import stat
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

from tools.check_zip_inventory import REVISION, source_inventory
from tools.fence import RUNTIME_API, SCOPED_API, STDLIB_API, source_allowed

USING = "atlas_brain/evidence/archives.py"
IMPORTED_APIS = {"zipfile.ZipFile", "zipfile.BadZipFile", "zipfile.ZIP_STORED", "zipfile.ZIP_DEFLATED",
                 "zlib.error", "zlib.decompressobj", "stat.S_IFMT"}
MEMBER_APIS = {"zipfile.ZipFile.infolist", "zipfile.ZipFile.open", "pathlib.Path.suffix"}
APIS = IMPORTED_APIS | MEMBER_APIS


def test_actual_pinned_zip_inventory_keeps_all_ten_endpoint_uses():
    payload = subprocess.check_output(["git", "show", f"{REVISION}:{USING}"])
    bindings, used = source_inventory(payload)
    assert used == APIS
    assert bindings["ZipFile"] == "zipfile.ZipFile"


def test_zip_amendment_and_existing_bounds_are_exact():
    assert RUNTIME_API[USING] == APIS and USING not in SCOPED_API
    assert len(STDLIB_API) == 22 and not APIS & STDLIB_API
    assert len(SCOPED_API["atlas_brain/kernel/token_lints.py"]) == 29
    assert len(SCOPED_API["atlas_brain/kernel/lints.py"] - {"ast.Starred"}) == 32
    text = Path("docs/adr/0010-adr0002-zip-runtime.md").read_text(encoding="utf-8")
    assert set(re.findall(r"(?m)^\| ([\w.]+) \|", text)) == APIS
    assert len(text.splitlines()) <= 60 and len(text) <= 4000


@pytest.mark.parametrize("api", sorted(IMPORTED_APIS))
def test_exact_zip_using_file_and_outside_refusal(api):
    module, name = api.rsplit(".", 1)
    source = f"from {module} import {name} as value; value"
    assert source_allowed(source, path=USING)
    for path in ("atlas_brain/packs/example.py", "atlas_brain/evidence/archive.py", USING + "/extra.py"):
        assert not source_allowed(source, path=path)


@pytest.mark.parametrize("module", [zipfile, zlib, stat])
def test_all_actual_unlisted_zip_namespace_names_refuse(module):
    for name in sorted(vars(module)):
        api = module.__name__ + "." + name
        if name.isidentifier() and api not in APIS | STDLIB_API:
            assert not source_allowed(f"from {module.__name__} import {name}", path=USING), api
    assert not source_allowed("from zipfile import *", path=USING)
    assert not source_allowed("import ast; ast.parse('')", path=USING)
    assert not source_allowed("import subprocess", path=USING)


@pytest.mark.parametrize("api", sorted(IMPORTED_APIS))
def test_zip_capability_reexports_refuse_without_blocking_public_declarations(api):
    module, name = api.rsplit(".", 1)
    sources = {USING: f"from {module} import {name} as leaked\ndef zip_members(path): return path",
               "atlas_brain/bridge.py": "from .evidence.archives import leaked"}
    assert source_allowed("from .evidence.archives import zip_members; zip_members(path)", sources)
    assert not source_allowed("from .evidence.archives import leaked; leaked", sources)
    assert not source_allowed("from .evidence import archives; archives.leaked", sources)
    assert not source_allowed("from .bridge import leaked; leaked", sources)


@pytest.mark.parametrize("api", sorted(IMPORTED_APIS))
@pytest.mark.parametrize("shape", ["plain", "chain", "annotated", "tuple", "module", "conditional", "class",
                                  "boolean", "named", "container", "loop"])
def test_assigned_zip_capabilities_keep_their_origin(api, shape):
    module, name = api.rsplit(".", 1)
    prefix = f"from {module} import {name}\n"
    assignments = {"plain": f"leaked = {name}", "chain": f"first = {name}\nleaked = first",
                   "annotated": f"leaked: object = {name}", "tuple": f"leaked, other = {name}, 0",
                   "module": f"import {module}\nleaked = {api}",
                   "conditional": f"leaked = {name} if flag else {name}",
                   "class": f"class Holder:\n    leaked = {name}", "boolean": f"leaked = {name} or {name}",
                   "named": f"leaked = (other := {name})", "container": f"leaked = ({name},)[0]",
                   "loop": f"for leaked in ({name},):\n    pass"}
    symbol = "Holder.leaked" if shape == "class" else "leaked"
    sources = {USING: prefix + assignments[shape] + "\ndef zip_members(path): return path\nclass PublicRecord: pass",
               "atlas_brain/bridge.py": "from .evidence import archives\nexported = archives." + symbol}
    assert source_allowed("from .evidence.archives import zip_members, PublicRecord; zip_members(path); PublicRecord()", sources)
    assert not source_allowed("from .evidence import archives; archives." + symbol, sources)
    assert not source_allowed("from .bridge import exported; exported", sources)


@pytest.mark.parametrize("api", sorted(IMPORTED_APIS))
@pytest.mark.parametrize("shape", ["plain", "boolean", "container", "loop"])
def test_actual_tracked_cli_refuses_direct_and_bridge_assignment_aliases(tmp_path: Path, api, shape):
    module, name = api.rsplit(".", 1)
    rhs = {"plain": name, "boolean": f"{name} or {name}", "container": f"({name},)[0]", "loop": name}[shape]
    binding = f"for leaked in ({name},):\n    pass" if shape == "loop" else f"leaked = {rhs}"
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(f"from {module} import {name}\n{binding}\ndef zip_members(value): return value\nclass PublicRecord: pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    consumer = tmp_path / "atlas_brain/probe.py"
    consumer.write_text("from .evidence.archives import zip_members, PublicRecord\n", encoding="utf-8")
    tool = str(Path("tools/fence.py").resolve())
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
    consumer.write_text("from .evidence.archives import leaked\nleaked(source)\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    direct = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert direct.returncode == 1 and "atlas_brain/probe.py" in direct.stdout
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import leaked\nexported = leaked\n", encoding="utf-8")
    consumer.write_text("from .bridge import exported\nexported(source)\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    bridge = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert bridge.returncode == 1 and "atlas_brain/probe.py" in bridge.stdout and "atlas_brain/bridge.py" in bridge.stdout


@pytest.mark.parametrize("api", sorted(IMPORTED_APIS))
def test_real_tracked_cli_uses_exact_zip_file_scope(tmp_path: Path, api):
    module, name = api.rsplit(".", 1)
    source = f"from {module} import {name}; {name}\n"
    file = tmp_path / USING
    file.parent.mkdir(parents=True)
    file.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())
    subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
    (tmp_path / "atlas_brain/probe.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 1 and "scope fence: 1 refused" in result.stdout
    assert api in result.stdout and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("api", sorted(MEMBER_APIS))
def test_exact_zip_member_uses_and_reexports(tmp_path: Path, api):
    endpoint, member = api.rsplit(".", 1)
    module, name = endpoint.rsplit(".", 1)
    # Source-only probes: no archive is opened and no consumer is imported.
    expression = f"{name}(source).{member}"
    text = f"from {module} import {name}\nvalue = {expression}\n"
    assert source_allowed(text, path=USING)
    assert not source_allowed(text, path="atlas_brain/probe.py")
    unlisted = "write_text" if name == "Path" else "extractall"
    assert not source_allowed(f"from {module} import {name}\n{name}(source).{unlisted}", path=USING)
    sources = {USING: f"from {module} import {name}\nleaked = {name}.{member}\ndef zip_members(x): return x",
               "atlas_brain/bridge.py": "from .evidence.archives import leaked"}
    assert source_allowed("from .evidence.archives import zip_members", sources)
    assert not source_allowed("from .evidence.archives import leaked; leaked", sources)
    assert not source_allowed("from .bridge import leaked; leaked", sources)
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(text, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())
    subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
    (tmp_path / "atlas_brain/probe.py").write_text(text, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("member", ["open", "infolist"])
@pytest.mark.parametrize("receiver", ["factory(source)", "(factory(source) if flag else factory(source))", "value"])
@pytest.mark.parametrize("producer", ["def factory(source): return ZipFile(source)",
    "def factory(source):\n value = ZipFile(source)\n return value",
    "def maker(source): return ZipFile(source)\ndef factory(source): return maker(source)",
    "def factory(source): return (ZipFile(source),)[0]"])
def test_public_factory_result_cannot_export_zip_members(tmp_path: Path, member, receiver, producer):
    sources = {USING: "from zipfile import ZipFile\n" + producer + "\n",
               "atlas_brain/bridge.py": "from .evidence.archives import factory"}
    consumer = "from .evidence.archives import factory\nvalue = factory(source)\n"
    assert source_allowed(consumer, sources)
    assert not source_allowed(consumer + receiver + "." + member + "()", sources)
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(sources[USING], encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text(sources["atlas_brain/bridge.py"], encoding="utf-8")
    probe = tmp_path / "atlas_brain/probe.py"
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    for origin in (".evidence.archives", ".bridge"):
        baseline = f"from {origin} import factory\nvalue = factory(source)\n"
        probe.write_text(baseline, encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(baseline + receiver + "." + member + "()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        refused = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert refused.returncode == 1 and "atlas_brain/probe.py" in refused.stdout


@pytest.mark.parametrize("producer", ["from hashlib import sha256\ndef text(): return sha256(b'x').hexdigest()",
                                      "import json\ndef text(): return json.dumps('x')"])
def test_plain_primitive_function_results_keep_their_operations(producer):
    sources = {"atlas_brain/plain.py": producer}
    assert source_allowed("from .plain import text\ntext().upper()", sources)


@pytest.mark.parametrize("result, member", [("isinstance(value, ZipFile)", "bit_length()"),
                                           ("bool(value) and isinstance(value, ZipFile)", "bit_length()"),
                                           ("'zip' if isinstance(value, ZipFile) else 'other'", "upper()")])
def test_class_predicates_do_not_return_the_tested_class(result, member):
    sources = {USING: "from zipfile import ZipFile\ndef factory(value): return " + result}
    assert source_allowed("from .evidence.archives import factory\nfactory(value)." + member, sources)


@pytest.mark.parametrize("returned", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("shape", ["direct", "assigned", "conditional"])
def test_actual_cli_refuses_returned_zip_class_and_member_calls(tmp_path: Path, returned, shape):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\ndef opener(): return " + returned + "\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import opener\n", encoding="utf-8")
    probe = tmp_path / "atlas_brain/probe.py"
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    args = "source" if returned == "ZipFile" else "archive, entry"
    consumer = {"direct": f"opener()({args})", "assigned": f"callback = opener()\ncallback({args})",
                "conditional": f"(opener() if flag else opener())({args})"}[shape]
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import opener\n"
        probe.write_text(prefix + "opener()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + consumer + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        refused = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert refused.returncode == 1 and "atlas_brain/probe.py" in refused.stdout
