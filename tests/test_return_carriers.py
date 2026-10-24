"""Known scoped capabilities cannot disappear inside dict or generator values."""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import ImportIndex, import_bindings, source_allowed

USING = "atlas_brain/evidence/archives.py"
CARRIERS = [("return {'cap': CAP}['cap']", "factory()"),
            ("return {key: CAP for key in ('cap',)}['cap']", "factory()"),
            ("return {CAP: 'data'}", "next(iter(factory()))"),
            ("yield CAP", "next(factory())"),
            ("yield from (CAP,)", "next(factory())"),
            ("return (CAP for _ in (0,))", "next(factory())"),
            ("yield from iter((CAP,))", "next(factory())"),
            ("return iter((CAP,))", "next(factory())"),
            ("it = iter\n yield from it((CAP,))", "next(factory())"),
            ("return next(iter((CAP,)))", "factory()"),
            ("return dict(cap=CAP)['cap']", "factory()"),
            ("return {'cap': CAP}.get('cap')", "factory()"),
            ("box = {'cap': CAP}\n return box.get('cap')", "factory()"),
            ("return cast(object, CAP)", "factory()"),
            ("return map(lambda item: item, (CAP,))", "next(factory())"),
            ("return filter(None, (CAP,))", "next(factory())"),
            ("return passthrough((CAP,))", "next(factory())"),
            ("return (lambda: CAP)()", "factory()"),
            ("return passthrough((lambda: CAP)())", "factory()"),
            ("maker = lambda: CAP\n return maker()", "factory()"),
            ("return (lambda value: value)(CAP)", "factory()"),
            ("carrier = iter\n if flag:\n  carrier = lambda values: values\n return carrier((CAP,))", "next(factory(False))"),
            ("carrier = iter if flag else iter\n if flag:\n  carrier = len\n return carrier((CAP,))", "next(factory(False))"),
            ("return [CAP for _ in (0,)][0]", "factory()")]


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("body, receiver", CARRIERS)
def test_actual_cli_data_positive_then_carried_capability_refusal(tmp_path: Path, capability, body, receiver):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\nfrom typing import cast\ndef passthrough(values): return values\ndef factory(flag=False):\n " + body.replace("CAP", capability)
                     + "\ndef public_data(): return {'count': 1}\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text(
        "from .evidence.archives import factory, public_data\n", encoding="utf-8")
    probe = tmp_path / "atlas_brain/probe.py"
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import factory, public_data\n"
        probe.write_text(prefix + "factory()\npublic_data()['count']\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + receiver + f"({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("body, receiver", [
    ("return {'ok': isinstance(value, ZipFile)}['ok']", "factory(value)"),
    ("yield isinstance(value, ZipFile)", "next(factory(value))"),
    ("return type(value) is ZipFile", "factory(value)"),
    ("box = {'ok': isinstance(value, ZipFile)}\n return box.get('ok')", "factory(value)"),
    ("it = iter\n return next(it((isinstance(value, ZipFile),)))", "factory(value)"),
    ("return (1 for _ in (0,) if isinstance(value, ZipFile))", "next(factory(value))"),
    ("return (lambda: isinstance(value, ZipFile))()", "factory(value)"),
    ("return (lambda item: isinstance(item, ZipFile))(value)", "factory(value)")])
def test_ordinary_predicate_and_generator_data_remain_public(body, receiver):
    sources = {USING: "from zipfile import ZipFile\ndef factory(value):\n " + body}
    assert source_allowed("from .evidence.archives import factory\n" + receiver + ".bit_length()", sources)


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("declaration", ["global", "nonlocal"])
def test_actual_cli_explicit_scope_carrier_cannot_be_certified_scalar(tmp_path, capability, declaration):
    body = "def factory(flag=False):\n DECL carrier\n if flag:\n  carrier = len\n return carrier((CAP,))\n"
    producer = "carrier = iter\n" + body.replace("DECL", "global")
    if declaration == "nonlocal":
        producer = "def outer():\n carrier = iter\n " + body.replace("DECL", "nonlocal").rstrip().replace("\n", "\n ") + "\n return factory\nfactory = outer()\n"
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\n" + producer.replace("CAP", capability)
                     + "\ndef public_data(): return {'count': 1}\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import factory, public_data\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import factory, public_data\n"
        probe.write_text(prefix + "factory(False)\npublic_data()['count']\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + f"next(factory(False))({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


def test_named_closure_binding_keeps_the_returned_function_level():
    source = "from zipfile import ZipFile\ndef outer():\n def factory(): return ZipFile\n return factory\nfactory = outer()\n"
    _, exports, _ = import_bindings(ast.parse(source), USING)
    assert exports["outer.$return"] == ("atlas_brain.evidence.archives.outer.factory",)
    assert exports["factory"] == "$callable:atlas_brain.evidence.archives.outer.factory"


FACTORIES = [("def choose(flag, opaque=None): return " + choice + "\nfactory = choose(True)\n", ordinary)
             for choice, ordinary in [
    ("first if flag else second", True), ("(first, second)[flag]", True),
    ("first if flag else opaque", False), ("first if flag else CAP", False)]] + [
    ("factory = first\n", True),
    ("flag = True\nfactory = first if flag else second\n", True),
    ("factory = first or second\n", True),
    ("factory = (first, second)[0]\n", True),
    ("factory = first\nif True:\n factory = second\n", True),
    ("opaque = None\nfactory = first\nif False:\n factory = opaque\n", False),
    ("flag = True\nfactory = first if flag else CAP\n", False),
    ("def choose(flag): return first if flag else second\nfactory = choose(True)\nif True:\n factory = second\n", True),
    ("def choose(flag): return first if flag else second\nfactory = first\nif True:\n factory = choose(True)\n", True)]


@pytest.mark.parametrize("factory_source, ordinary_callable", FACTORIES)
@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
def test_actual_cli_returned_function_union_keeps_capabilities(tmp_path, factory_source, ordinary_callable, capability):
    source = ("from zipfile import ZipFile\ndef first(): return CAP\ndef second(): return CAP\n"
              + factory_source
              + "def public_data(): return 1\n").replace("CAP", capability)
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text(source, encoding="utf-8")
    # Uncertain exports can refuse at the bridge import; keep the baseline data-only.
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import public_data\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        probe.write_text(f"from {module} import public_data\npublic_data().bit_length()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import factory, public_data\n", encoding="utf-8")
        prefix = f"from {module} import factory, public_data\n"
        if ordinary_callable:
            probe.write_text(prefix + "factory()\npublic_data()\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
            subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + f"factory()({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and ("atlas_brain/probe.py" if ordinary_callable else "atlas_brain/") in result.stdout
        (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import public_data\n", encoding="utf-8")


@pytest.mark.parametrize("factory_source", [
    "def choose(flag, opaque=None): return first if flag else second\nfactory = choose(True)",
    "def choose(flag, opaque=None): return first if flag else opaque\nfactory = choose(True)",
    "factory = first", "flag = True\nfactory = first if flag else second",
    "factory = first\nif True:\n factory = second",
    "opaque = None\nfactory = first\nif False:\n factory = opaque"])
def test_returned_callable_union_keeps_known_roots_and_evaluation_level(factory_source):
    source = ("from zipfile import ZipFile\ndef first(): return ZipFile\ndef second(): return ZipFile\n"
              + factory_source)
    index = ImportIndex({USING: source})
    assert index.foreign_roots("atlas_brain.evidence.archives.factory", callable_value=True) == {"zipfile.ZipFile"}
    assert not index.foreign_roots("atlas_brain.evidence.archives.factory", callable_value=True, evaluate_return=False)


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
def test_actual_cli_method_lookup_uses_module_carrier_not_class_scalar(tmp_path, capability):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\ncarrier = iter\nclass Reader:\n carrier = len\n"
                     + " @staticmethod\n def factory(): return carrier((" + capability + ",))\n"
                     + "def public_data(): return 1\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import Reader, public_data\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import Reader, public_data\n"
        probe.write_text(prefix + "Reader.factory()\npublic_data().bit_length()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + f"next(Reader.factory())({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("declarations", ["class Record: pass\ntype Public = Record | int",
                                        "class Record[T]: pass\ntype Public[T] = Record[T] | None",
                                        "class Record: pass\nPublic = Record | int"])
def test_actual_cli_type_data_and_callable_alias_keep_separate_origins(tmp_path, declarations):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\n" + declarations
                     + "\ndef first(): return ZipFile\nfactory = first\ndef public_data(): return 1\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import Public, factory, public_data\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import Public, factory, public_data\n"
        probe.write_text(prefix + "value: Public\nfactory()\npublic_data().bit_length()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + "factory()(source)\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("alias", ["Alias = Reader", "box = {'reader': Reader} | {}\nAlias = box['reader']"])
def test_actual_cli_class_alias_keeps_its_declared_method_namespace(tmp_path, capability, alias):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\nclass Record: pass\ntype Public = Record | int\n"
                     + "class Reader:\n @staticmethod\n def factory(): return " + capability
                     + "\n" + alias + "\ndef public_data(): return 1\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import Alias, Public, public_data\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import Alias, Public, public_data\n"
        probe.write_text(prefix + "value: Public\nAlias.factory()\npublic_data()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + f"Alias.factory()({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


def test_ordinary_record_construction_keeps_its_fields():
    sources = {"atlas_brain/records.py": "from pathlib import Path\nclass Record:\n def __init__(self, path): self.name = 'record'\ndef factory(): return Record(Path('x'))"}
    assert source_allowed("from .records import factory\nfactory().name.upper()", sources)


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("construction, receiver", [("Box(CAP)", "factory().capability"),
                                                    ("Box(capability=CAP)", "factory().capability"),
                                                    ("Box(CAP).capability", "factory()"),
                                                    ("forward(Box(CAP)).capability", "factory()"),
                                                    ("Box({'cap': CAP})", "factory().capability['cap']")])
def test_actual_cli_scoped_constructor_argument_cannot_escape_public_field(tmp_path, capability, construction, receiver):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\nfrom pathlib import Path\n"
                     + "class Box:\n def __init__(self, capability): self.capability = capability\n"
                     + "class Record:\n def __init__(self, path): self.name = 'record'\n"
                     + "def forward(value): return value\ndef record(): return Record(Path('x'))\ndef factory(): return "
                     + construction.replace("CAP", capability) + "\ndef public_data(): return 1\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import factory, public_data, record\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import factory, public_data, record\n"
        probe.write_text(prefix + "factory()\npublic_data().bit_length()\nrecord().name.upper()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + receiver + f"({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


@pytest.mark.parametrize("capability", ["ZipFile", "ZipFile.open"])
@pytest.mark.parametrize("classes", [
    "class Carrier:\n def __new__(cls, value): return value\n",
    "class Meta(type):\n def __call__(cls, value): return value\nclass Carrier(metaclass=Meta): pass\n",
    "class Carrier: pass\ndef Carrier(value): return value\n",
    "def passthrough(cls, value): return value\nclass Carrier:\n match passthrough:\n  case __new__: pass\n",
    "class Parent:\n def __new__(cls, value): return value\nclass Carrier(Parent): pass\n"])
def test_actual_cli_uncertain_constructor_keeps_known_argument(tmp_path, capability, classes):
    using = tmp_path / USING
    using.parent.mkdir(parents=True)
    using.write_text("from zipfile import ZipFile\n" + classes + "def factory(): return Carrier(" + capability
                     + ")\ndef public_data(): return 1\n", encoding="utf-8")
    (tmp_path / "atlas_brain/bridge.py").write_text("from .evidence.archives import factory, public_data\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    probe, tool = tmp_path / "atlas_brain/probe.py", str(Path("tools/fence.py").resolve())
    args = "source" if capability == "ZipFile" else "archive, entry"
    for module in (".evidence.archives", ".bridge"):
        prefix = f"from {module} import factory, public_data\n"
        probe.write_text(prefix + "factory()\npublic_data().bit_length()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
        probe.write_text(prefix + f"factory()({args})\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
        assert result.returncode == 1 and "atlas_brain/probe.py" in result.stdout


def test_possible_primitive_predicate_aliases_remain_primitive():
    sources = {USING: "from zipfile import ZipFile\ndef factory(value, flag):\n predicate = isinstance\n if flag: predicate = issubclass\n return predicate(value, ZipFile)"}
    assert source_allowed("from .evidence.archives import factory\nfactory(value, flag).bit_length()", sources)


@pytest.mark.parametrize("path", ["atlas_brain/kernel/token_lints.py", "atlas_brain/packs/platform/system/build.py",
                                  "atlas_brain/evidence/admission.py"])
def test_accepted_tracked_ast_and_record_field_sources_remain_admitted(path):
    paths = subprocess.check_output(["git", "ls-files", "-z", "atlas_brain"]).decode().rstrip("\0").split("\0")
    sources = {name: Path(name).read_text(encoding="utf-8") for name in paths if name.endswith(".py")}
    assert source_allowed(sources[path], sources, path)


def test_nested_public_record_data_remains_distinct_from_scoped_capabilities():
    sources = {"atlas_brain/records.py": "from dataclasses import dataclass\n@dataclass\nclass Record:\n name: str\n"
               + "def first(value): return Record(value)\ndef factory(value): return first(value)\n"}
    assert source_allowed("from .records import factory\nfactory('record').name.upper()", sources)


def test_admitted_function_result_fields_are_data_not_api_suffixes():
    source = "import ast\nvalues = ast.walk(tree)\nfor node in values:\n fields = node.body\n"
    assert source_allowed(source, path="atlas_brain/kernel/token_lints.py")


def test_primitive_assignment_result_keeps_ordinary_data_methods():
    sources = {USING: "from zipfile import ZipFile\ndef factory(value):\n result = isinstance(value, ZipFile)\n return result"}
    assert source_allowed("from .evidence.archives import factory\nfactory(value).bit_length()", sources)


@pytest.mark.parametrize("tail", ["", ".casefold()", ".casefold().upper()"])
def test_admitted_readonly_property_result_remains_plain_data(tail):
    sources = {USING: "from pathlib import Path\ndef factory(): return Path('data.txt').suffix" + tail}
    assert source_allowed("from .evidence.archives import factory\nfactory().upper()", sources)


def test_scoped_numeric_constant_result_keeps_data_methods():
    sources = {USING: "from zipfile import ZIP_STORED\ndef factory(): return ZIP_STORED"}
    assert source_allowed("from .evidence.archives import factory\nfactory().bit_length()", sources)


@pytest.mark.parametrize("kind", ["outside", "noncontract"])
@pytest.mark.parametrize("carrier, receiver", [("map(lambda item: item, (ZipFile,))", "next(factory())"),
                                              ("filter(None, (ZipFile,))", "next(factory())"),
                                              ("Carrier(ZipFile)", "factory()"),
                                              ("(lambda: ZipFile)()", "factory()"),
                                              ("passthrough((lambda: ZipFile)())", "factory()"),
                                              ("Box(ZipFile)", "factory().capability")])
def test_unproved_carrier_output_negative_creates_no_payload(tmp_path: Path, kind, carrier, receiver):
    package = tmp_path / "atlas_brain"
    (package / "evidence").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "evidence/archives.py").write_text(
        "from zipfile import ZipFile\nclass Carrier:\n def __new__(cls, value): return value\n"
        + "class Box:\n def __init__(self, capability): self.capability = capability\n"
        + "def passthrough(value): return value\n"
        + "def factory(): return " + carrier + "\n", encoding="utf-8")
    probe = package / "zz_consumer.py"
    prefix = "from .evidence.archives import factory\n"
    probe.write_text(prefix + "factory()\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    tool = str(Path("tools/fence.py").resolve())
    def fence():
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        return subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    root = tmp_path / "contract"
    witness = str(Path("tools/output_witness.py").resolve())
    env = {**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"}
    assert fence().returncode == 0
    assert subprocess.run([sys.executable, witness, "--root", str(root)], cwd=tmp_path, env=env,
                          capture_output=True, text=True, check=False).returncode == 0
    target = tmp_path / "forbidden.zip" if kind == "outside" else root / "notes.zip"
    probe.write_text(prefix + receiver + "(" + repr(str(target)) + ", 'w')\n", encoding="utf-8")
    assert fence().returncode == 1
    result = subprocess.run([sys.executable, witness, "--root", str(root)], cwd=tmp_path, env=env,
                            capture_output=True, text=True, check=False)
    receipt = json.loads(result.stdout)
    assert result.returncode == 1 and receipt["completed"] is False and "open" in receipt["violations"]
    assert not target.exists()
