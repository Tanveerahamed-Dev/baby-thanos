"""Invocation-local fence work and refusal freshness; counts are not elapsed-time evidence."""
import ast
import json
import sys
from collections import Counter

import pytest

from tools import fence

PATH = "atlas_brain/probe.py"
SAFE = "value = 1\n"
UNSAFE = "import webbrowser\nwebbrowser.open('x')\n"


def oracle(sources):
    return {path: fence.source_refusals(source, sources, path) for path, source in sources.items()}


@pytest.mark.parametrize("entry", ["bulk", "main"])
def test_one_parse_and_binding_per_file_keeps_all_scoped_and_ordinary_decisions(tmp_path, monkeypatch, capsys, entry):
    sources = {f"atlas_brain/item{number}.py": f"value = {number}\n" for number in range(7)}
    sources["atlas_brain/kernel/lints.py"] = "from ast import parse\nvalue = parse('x')\n"
    sources[PATH] = "from .kernel.lints import parse\nvalue = parse('x')\n"
    expected = oracle(sources)
    assert expected[PATH] and not expected["atlas_brain/kernel/lints.py"]
    assert all(not expected[path] for path in sources if path.startswith("atlas_brain/item"))
    if entry == "main":
        for path, source in sources.items():
            target = tmp_path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["fence.py", *sources])
    parse, binding = fence.ast.parse, fence.import_bindings
    parsed, bound = Counter(), Counter()
    def parsing(source, *args, **kwargs):
        if isinstance(source, str) and source in sources.values():
            parsed[source] += 1
        return parse(source, *args, **kwargs)
    def bindings(tree, path, ignored_arg_roots=None):
        assert isinstance(tree, ast.Module)
        bound[path] += 1
        return binding(tree, path, ignored_arg_roots)
    monkeypatch.setattr(fence.ast, "parse", parsing)
    monkeypatch.setattr(fence, "import_bindings", bindings)
    if entry == "bulk":
        assert fence.bulk_source_refusals(sources) == expected
    else:
        assert fence.main() == 1
        reports = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
        assert {report["path"] for report in reports} == {PATH}
        assert all(report["class"] == "import" for report in reports)
    assert parsed == Counter(sources.values())
    assert bound == Counter({path: 1 for path in sources})


def test_public_calls_rescan_safe_to_unsafe_to_safe_with_the_same_mutable_mapping():
    sources = {PATH: SAFE}
    assert fence.bulk_source_refusals(sources) == {PATH: set()}
    sources[PATH] = UNSAFE
    refused = fence.bulk_source_refusals(sources)
    assert refused == oracle(sources) and any("webbrowser" in item for item in refused[PATH])
    sources[PATH] = SAFE
    assert fence.bulk_source_refusals(sources) == {PATH: set()}


@pytest.mark.parametrize("direct,stored,allowed", [(UNSAFE, SAFE, False), (SAFE, UNSAFE, True)])
def test_direct_source_conflict_uses_the_supplied_body_with_the_existing_index_merge(direct, stored, allowed):
    sources = {PATH: stored}
    result = fence.source_refusals(direct, sources, PATH)
    assert (not result) is allowed
    if not allowed:
        assert any("webbrowser" in item for item in result)
    assert sources == {PATH: stored}


def test_owned_snapshot_does_not_retain_the_callers_mutable_mapping():
    sources = {PATH: SAFE}
    index = fence.ImportIndex(sources)
    sources[PATH] = UNSAFE
    assert fence._indexed_refusals(SAFE, PATH, index) == set()
    assert any("webbrowser" in item for item in fence._indexed_refusals(UNSAFE, PATH, index))
    assert fence._indexed_refusals(SAFE, PATH, index) == set()
    assert any("webbrowser" in item for item in fence._indexed_refusals(UNSAFE, "atlas_brain/missing.py", index))


def test_changed_argument_context_rebinds_and_keeps_actual_unsafe_endpoints(monkeypatch):
    sources = {PATH: UNSAFE}
    index = fence.ImportIndex(sources)
    expected = fence._indexed_refusals(UNSAFE, PATH, index)
    assert any("webbrowser" in item for item in expected)
    binding, calls = fence.import_bindings, []
    def bindings(tree, path, ignored_arg_roots=None):
        calls.append((path, frozenset(ignored_arg_roots)))
        return binding(tree, path, ignored_arg_roots)
    monkeypatch.setattr(fence, "import_bindings", bindings)
    index.ignored_arg_classes.add("planted.unused_class")
    assert fence._indexed_refusals(UNSAFE, PATH, index) == expected
    assert calls == [(PATH, frozenset(index.ignored_arg_classes))]


def test_changed_api_union_rebinds_and_permissions_recover_without_stale_verdicts(monkeypatch):
    source = "import math\nvalue = math.tan(0)\n"
    index = fence.ImportIndex({PATH: source})
    assert "math.tan" not in fence.admitted_apis()
    assert "math.tan" in fence._indexed_refusals(source, PATH, index)
    original, binding, calls = fence.STDLIB_API, fence.import_bindings, []
    def bindings(tree, path, ignored_arg_roots=None):
        calls.append(path)
        return binding(tree, path, ignored_arg_roots)
    monkeypatch.setattr(fence, "import_bindings", bindings)
    monkeypatch.setattr(fence, "STDLIB_API", original | {"math.tan"})
    assert fence._indexed_refusals(source, PATH, index) == set()
    assert calls == [PATH]
    monkeypatch.setattr(fence, "STDLIB_API", original)
    assert "math.tan" in fence._indexed_refusals(source, PATH, index)


def test_stdlib_subset_drift_invalidates_bindings_even_when_the_api_union_is_equal(monkeypatch):
    source = ("from pathlib import Path\nclass Box:\n"
        "    def __init__(self, arg): self.value = 1\nitem = Box(Path)\nitem.read_text()\n")
    sources = {PATH: source}
    index = fence.ImportIndex(sources)
    assert fence._indexed_refusals(source, PATH, index) == set()
    admitted = fence.admitted_apis()
    monkeypatch.setattr(fence, "STDLIB_API", fence.STDLIB_API - {"pathlib.Path"})
    monkeypatch.setattr(fence, "SCOPED_API", {**fence.SCOPED_API, PATH: {"pathlib.Path"}})
    assert fence.admitted_apis() == admitted
    expected = oracle(sources)[PATH]
    assert "$carrier:pathlib.Path.read_text" in expected
    binding, calls = fence.import_bindings, []
    def bindings(tree, path, ignored_arg_roots=None):
        calls.append(path)
        return binding(tree, path, ignored_arg_roots)
    monkeypatch.setattr(fence, "import_bindings", bindings)
    assert fence._indexed_refusals(source, PATH, index) == expected
    assert calls == [PATH]


def test_per_path_permission_changes_are_read_even_when_the_global_union_is_unchanged(monkeypatch):
    path = "atlas_brain/kernel/lints.py"
    source = "from pathlib import PurePosixPath\nvalue = PurePosixPath('x').is_absolute()\n"
    index = fence.ImportIndex({path: source})
    assert fence._indexed_refusals(source, path, index)
    admitted, original = fence.admitted_apis(), fence.SCOPED_API
    monkeypatch.setattr(fence, "SCOPED_API",
        {**original, path: original[path] | {"pathlib.PurePosixPath.is_absolute"}})
    assert fence.admitted_apis() == admitted
    assert fence._indexed_refusals(source, path, index) == set()
    monkeypatch.setattr(fence, "SCOPED_API", original)
    assert fence._indexed_refusals(source, path, index)


def test_shared_snapshot_views_keep_forbidden_permissions_and_mutable_maps_separate():
    scoped = "atlas_brain.kernel.lints"
    sources = {"atlas_brain/kernel/lints.py": "from ast import parse\n",
        "atlas_brain/helper.py": "import math\n", PATH: "from .helper import math\nvalue = math.isfinite(1)\n"}
    first = fence.ImportIndex(sources, (scoped,))
    second = fence.ImportIndex(first.snapshot)
    assert first.origin(scoped + ".parse") is None
    assert second.origin(scoped + ".parse") == "ast.parse"
    assert fence._indexed_refusals(sources[PATH], PATH, second) == set()
    first.modules["atlas_brain.helper"][0]["math"] = "webbrowser"
    first.classes.add("planted.Unused")
    first.ignored_arg_classes.add("planted.Unused")
    assert fence._indexed_refusals(sources[PATH], PATH, first)
    assert fence._indexed_refusals(sources[PATH], PATH, second) == set()
    third = fence.ImportIndex(first.snapshot)
    assert fence._indexed_refusals(sources[PATH], PATH, third) == set()
    assert "planted.Unused" not in second.classes | third.classes
    assert "planted.Unused" not in second.ignored_arg_classes | third.ignored_arg_classes


def test_recursive_visits_do_not_poison_later_origin_or_foreign_root_queries():
    sources = {"atlas_brain/a.py": "from .b import value\n", "atlas_brain/b.py": "from .a import value\n",
        "atlas_brain/safe.py": "import math\n"}
    index = fence.ImportIndex(sources)
    for _ in range(2):
        assert index.origin("atlas_brain.a.value") is None
        assert index.foreign_roots("atlas_brain.a.value") == set()
        assert index.origin("atlas_brain.safe.math.isfinite") == "math.isfinite"
        assert index.foreign_roots("atlas_brain.safe.math.isfinite") == {"math.isfinite"}


@pytest.mark.parametrize("entry", ["bulk", "direct", "stored"])
def test_syntax_errors_remain_visible_in_public_analysis(entry):
    bad = "def broken(:\n"
    with pytest.raises(SyntaxError):
        if entry == "bulk":
            fence.bulk_source_refusals({PATH: bad})
        elif entry == "direct":
            fence.source_refusals(bad, {PATH: SAFE}, PATH)
        else:
            fence.source_refusals(SAFE, {PATH: bad}, PATH)


def test_main_keeps_invalid_syntax_and_valid_denied_file_diagnostics_distinct(tmp_path, monkeypatch, capsys):
    sources = {"atlas_brain/broken.py": "def broken(:\n", PATH: UNSAFE, "atlas_brain/safe.py": SAFE}
    for path, source in sources.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["fence.py", *sources])
    assert fence.main() == 1
    reports = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert {"path": "atlas_brain/broken.py", "class": "import", "name": "invalid-syntax"} in reports
    assert any(row["path"] == PATH and "webbrowser" in row["name"] for row in reports)
    assert all(row["path"] != "atlas_brain/safe.py" for row in reports)


def test_new_view_rebuilds_cross_module_exports_after_union_preserving_policy_drift(monkeypatch):
    holder = "atlas_brain/holder.py"
    sources = {holder: ("from pathlib import Path\nclass Box:\n"
        "    def __init__(self, arg): self.value = 1\nitem = Box(Path)\n"),
        PATH: "from .holder import item\nitem.read_text()\n"}
    original = fence.ImportIndex(sources)
    assert fence._indexed_refusals(sources[PATH], PATH, original) == set()
    before, admitted = repr(original.modules), fence.admitted_apis()
    monkeypatch.setattr(fence, "STDLIB_API", fence.STDLIB_API - {"pathlib.Path"})
    monkeypatch.setattr(fence, "SCOPED_API", {**fence.SCOPED_API, holder: {"pathlib.Path"}})
    assert fence.admitted_apis() == admitted
    assert oracle(sources)[holder] == set()
    fresh = fence.ImportIndex(dict(sources))
    expected = fence._indexed_refusals(sources[PATH], PATH, fresh)
    assert any("read_text" in item for item in expected)
    rebuilt = fence.ImportIndex(original.snapshot)
    assert rebuilt.modules == fresh.modules
    assert fence._indexed_refusals(sources[PATH], PATH, rebuilt) == expected
    assert repr(original.modules) == before


@pytest.mark.parametrize("policy,removed,expression", [
    ("BUILTINS", "len", "len((Path,))"), ("SCALARS", "len", "len((Path,))"),
    ("SCALAR_APIS", "math.isfinite", "math.isfinite(Path)"),
])
def test_binding_helper_policy_drift_keeps_real_carrier_refusals(monkeypatch, policy, removed, expression):
    source = "import math\nfrom pathlib import Path\nitem = " + expression + "\nitem.read_text()\n"
    index = fence.ImportIndex({PATH: source})
    assert fence._indexed_refusals(source, PATH, index) == set()
    module = fence._binding_module
    monkeypatch.setattr(module, policy, getattr(module, policy) - {removed})
    expected = oracle({PATH: source})[PATH]
    assert any("read_text" in item for item in expected)
    assert fence._indexed_refusals(source, PATH, index) == expected


@pytest.mark.parametrize("policy", ["BUILTINS", "SCALARS", "SCALAR_APIS", "CARRIERS",
    "CALLABLE_VALUE", "CARRIER_RETURN", "RESULT_VALUE"])
def test_all_binding_policy_fields_force_real_fallback_without_erasing_refusals(monkeypatch, policy):
    index = fence.ImportIndex({PATH: UNSAFE})
    expected = fence._indexed_refusals(UNSAFE, PATH, index)
    assert any("webbrowser" in item for item in expected)
    module = fence if policy in ("CALLABLE_VALUE", "CARRIER_RETURN", "RESULT_VALUE") else fence._binding_module
    original = getattr(module, policy)
    changed = "$planted_" + original if type(original) is str else original | {"planted.unused"}
    monkeypatch.setattr(module, policy, changed)
    binding, calls = fence.import_bindings, []
    def bindings(tree, path, ignored_arg_roots=None):
        calls.append(path)
        return binding(tree, path, ignored_arg_roots)
    monkeypatch.setattr(fence, "import_bindings", bindings)
    assert fence._indexed_refusals(UNSAFE, PATH, index) == expected
    assert calls == [PATH]
