"""Exact module-prefix semantics and bounded lookup work; no elapsed-time claim."""
from itertools import combinations

import pytest

from tools import fence

PATH = "atlas_brain/probe.py"


def old_prefix(name, modules):
    return max((m for m in modules if name.startswith(m + ".")), key=len, default="")


MODULE_SETS = (
    (), ("a",), ("a", "a.b", "a.b.c"), ("a.bc", "ab", "a.b.c"),
    ("atlas_brain", "atlas_brain.a", "atlas_brain.abc", "atlas_brain.a.deep"),
    ("", ".", "..", ".a", ".a.", "a.", "a..", "a..b"),
    ("a", "a.\u03bc", "\u03b1", "\u03b1.\u03b2", "\u03b1.\u03b2.\u03b3"),
)
NAMES = ("", ".", "..", "...", ".a", ".a.member", ".a..member.", "a", "a.", "a..", "a..member",
    "a.b", "a.b.c", "a.b.c.member", "a.b.c.member.tail", "a.bc.member", "ab.member", "a.bcx.member",
    "missing.path.member", "atlas_brain", "atlas_brain.a", "atlas_brain.a.deep.member", "atlas_brain.abc.member",
    "atlas_brain_extra.a.member", "a.\u03bc", "a.\u03bc.member", "\u03b1.\u03b2.\u03b3.member", "\u03b1\u3002\u03b2.member")


@pytest.mark.parametrize("modules", MODULE_SETS)
@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("reversed_order", [False, True])
def test_exact_old_max_oracle_including_strict_self_exclusion_boundaries_and_dotted_edges(modules, name, reversed_order):
    ordered = tuple(reversed(modules)) if reversed_order else modules
    mapping = dict.fromkeys(ordered)
    expected = old_prefix(name, mapping)
    assert fence.module_prefix(name, mapping) == expected
    assert not expected or name.startswith(expected + ".") and name != expected


def test_all_small_overlapping_subsets_match_old_max_without_order_dependence():
    universe = ("a", "a.b", "a.b.c", "a.bc", "ab")
    for length in range(len(universe) + 1):
        for modules in combinations(universe, length):
            for name in ("a", "a.b", "a.b.c", "a.b.c.x", "a.bc.x", "ab.x", "abc.x", "a..x"):
                assert fence.module_prefix(name, dict.fromkeys(modules)) == old_prefix(name, modules)


class MembershipOnly(dict):
    def __init__(self, entries):
        super().__init__(entries)
        self.probes = []
    def __contains__(self, name):
        self.probes.append(name)
        return dict.__contains__(self, name)
    def __iter__(self):
        raise AssertionError("lookup iterated unrelated module keys")
    def keys(self):
        raise AssertionError("lookup requested all module keys")
    def items(self):
        raise AssertionError("lookup requested all module entries")
    def values(self):
        raise AssertionError("lookup requested all module values")


@pytest.mark.parametrize("unrelated", [0, 1, 777, 4096])
@pytest.mark.parametrize("name,hit", [
    ("atlas_brain.package.deep.leaf.member", "atlas_brain.package.deep.leaf"),
    ("atlas_brain.package.deep.leaf.member", "atlas_brain.package.deep"),
    ("atlas_brain.package.deep.leaf.member", "atlas_brain"),
    ("atlas_brain.package.deep.leaf.member", None), ("single", None),
    ("a..b.member.", "a..b"), (".a..member", ".a."), ("\u03b1.\u03b2.member", "\u03b1.\u03b2")])
def test_membership_work_is_dotted_depth_bounded_and_never_iterates_unrelated_modules(unrelated, name, hit):
    entries = {f"unrelated_{index}.module": index for index in range(unrelated)}
    if hit is not None:
        entries[hit] = object()
    expected = old_prefix(name, entries)
    mapping = MembershipOnly(entries)
    assert fence.module_prefix(name, mapping) == expected
    assert len(mapping.probes) <= name.count(".")
    assert all(name.startswith(candidate + ".") and candidate != name for candidate in mapping.probes)
    if expected:
        assert mapping.probes[-1] == expected
    assert len(mapping) == len(entries)


def test_prefix_decisions_read_live_additions_removals_and_ignore_mapping_values():
    mapping = {"a": "first"}
    name = "a.b.c.member"
    assert fence.module_prefix(name, mapping) == "a"
    for module in ("a.b", "a.b.c"):
        mapping[module] = object()
        assert fence.module_prefix(name, mapping) == old_prefix(name, mapping) == module
    mapping["a.b.c"] = None
    assert fence.module_prefix(name, mapping) == "a.b.c"
    del mapping["a.b.c"]
    assert fence.module_prefix(name, mapping) == "a.b"
    del mapping["a.b"]
    assert fence.module_prefix(name, mapping) == "a"
    del mapping["a"]
    assert fence.module_prefix(name, mapping) == ""


def sources():
    return {"atlas_brain/__init__.py": "", "atlas_brain/bridge/__init__.py": "import math as deep\n",
        "atlas_brain/bridge/nested/__init__.py": "from pathlib import Path\n",
        "atlas_brain/bridge/nested/leaf.py": "from math import isfinite as finite\n",
        "atlas_brain/holder.py": "from pathlib import Path\ndef expose(): return Path.read_text\n",
        "atlas_brain/a.py": "from .b import value\n", "atlas_brain/b.py": "from .a import value\n",
        "atlas_brain/kernel/lints.py": "from ast import parse\nvalue = parse('x')\n",
        PATH: "from .bridge.nested.leaf import finite\nvalue = finite(1)\n"}


QUERIES = ("atlas_brain", "atlas_brain.bridge", "atlas_brain.bridge.nested.leaf",
    "atlas_brain.bridge.nested.leaf.finite", "atlas_brain.bridge.deep.isfinite",
    "atlas_brain.bridge.nested.Path", "atlas_brain.bridge.nested.Path.read_text",
    "atlas_brain.holder.expose", "atlas_brain.a.value", "atlas_brain.kernel.lints.parse",
    "atlas_brain.bridge_absent.deep.isfinite", "math.isfinite",
    fence.RESULT_VALUE + "atlas_brain.holder.expose", fence.CALLABLE_VALUE + "atlas_brain.holder.expose",
    fence.CARRIER_RETURN + "atlas_brain.bridge.nested.Path")


def observations(index):
    return tuple((name, index.origin(name), index.foreign_roots(name),
        index.foreign_roots(name, callable_value=True), index.foreign_roots(name, evaluate_return=False)) for name in QUERIES)


@pytest.mark.parametrize("forbidden", [(), ("atlas_brain.kernel.lints",)])
def test_real_import_alias_carrier_cycle_and_namespace_paths_match_old_lookup(monkeypatch, forbidden):
    supplied = sources()
    optimized = fence.ImportIndex(supplied, forbidden)
    assert optimized.origin("atlas_brain.bridge.nested.leaf.finite") == "math.isfinite"
    assert optimized.foreign_roots("atlas_brain.bridge.nested.leaf.finite") == {"math.isfinite"}
    assert optimized.origin("atlas_brain.a.value") is None and optimized.foreign_roots("atlas_brain.a.value") == set()
    assert optimized.origin("atlas_brain.kernel.lints.parse") == (None if forbidden else "ast.parse")
    before = repr((optimized.modules, optimized.classes, optimized.ignored_arg_classes, optimized.forbidden))
    expected = observations(optimized)
    monkeypatch.setattr(fence, "module_prefix", old_prefix)
    reference = fence.ImportIndex(dict(reversed(tuple(supplied.items()))), forbidden)
    assert observations(reference) == expected
    assert observations(optimized) == expected
    assert repr((optimized.modules, optimized.classes, optimized.ignored_arg_classes, optimized.forbidden)) == before


def test_live_index_module_exports_and_namespace_mutations_never_use_a_cached_prefix():
    index = fence.ImportIndex({"atlas_brain/bridge/__init__.py": "import math as deep\n"})
    name = "atlas_brain.bridge.deep.isfinite"
    assert index.origin(name) == "math.isfinite" and index.foreign_roots(name) == {"math.isfinite"}
    index.modules["atlas_brain.bridge.deep"] = ({"isfinite": "webbrowser.open"}, set())
    assert index.origin(name) == "webbrowser.open" and index.foreign_roots(name) == {"webbrowser.open"}
    index.modules["atlas_brain.bridge.deep"][0]["isfinite"] = "json.dumps"
    assert index.origin(name) == "json.dumps" and index.foreign_roots(name) == {"json.dumps"}
    del index.modules["atlas_brain.bridge.deep"]
    assert index.origin(name) == "math.isfinite" and index.foreign_roots(name) == {"math.isfinite"}
    index.modules["atlas_brain.bridge"][0]["deep"] = "webbrowser"
    assert index.origin(name) == "webbrowser.isfinite" and index.foreign_roots(name) == {"webbrowser.isfinite"}
    fresh = fence.ImportIndex(index.snapshot)
    assert fresh.origin(name) == "math.isfinite" and fresh.foreign_roots(name) == {"math.isfinite"}


def test_actual_foreign_root_path_does_not_iterate_the_live_module_mapping():
    index = fence.ImportIndex({"atlas_brain/bridge/__init__.py": "from math import isfinite as finite\n"})
    assert index.foreign_roots("atlas_brain.bridge.finite") == {"math.isfinite"}
    index.modules = MembershipOnly(index.modules)
    assert index.foreign_roots("atlas_brain.bridge.finite") == {"math.isfinite"}
    assert len(index.modules.probes) <= "atlas_brain.bridge.finite".count(".")


@pytest.mark.parametrize("variant", ["safe", "scoped", "constructor", "cycle", "leak"])
def test_complete_ordinary_and_scoped_refusals_match_old_oracle_and_recover(monkeypatch, variant):
    supplied = sources()
    supplied[PATH] = {"safe": "from .bridge.nested.leaf import finite\nvalue = finite(1)\n",
        "scoped": "from .kernel.lints import parse\nvalue = parse('x')\n",
        "constructor": "from .holder import expose\nexpose()('x')\n",
        "cycle": "from .a import value\nvalue()\n",
        "leak": "import webbrowser\nwebbrowser.open('x')\n"}[variant]
    expected = fence.bulk_source_refusals(supplied)
    assert not expected["atlas_brain/kernel/lints.py"]
    assert bool(expected[PATH]) is (variant != "safe")
    monkeypatch.setattr(fence, "module_prefix", old_prefix)
    assert fence.bulk_source_refusals(dict(reversed(tuple(supplied.items())))) == expected
    assert {path: fence.source_refusals(source, supplied, path) for path, source in supplied.items()} == expected


def test_current_snapshot_reuses_source_bytes_but_keeps_index_views_and_policy_fresh(monkeypatch):
    supplied = {"atlas_brain/holder.py": "import math\n", PATH: "from .holder import math\nmath.isfinite(1)\n"}
    first = fence.ImportIndex(supplied)
    assert first.origin("atlas_brain.holder.math.isfinite") == "math.isfinite"
    supplied["atlas_brain/holder.py"] = "import webbrowser as math\n"
    assert first.origin("atlas_brain.holder.math.isfinite") == "math.isfinite"
    assert fence.ImportIndex(supplied).origin("atlas_brain.holder.math.isfinite") == "webbrowser.isfinite"
    second = fence.ImportIndex(first.snapshot)
    first.modules["atlas_brain.holder"][0]["math"] = "webbrowser"
    assert first.origin("atlas_brain.holder.math.isfinite") == "webbrowser.isfinite"
    assert second.origin("atlas_brain.holder.math.isfinite") == "math.isfinite"
    original = fence.STDLIB_API
    monkeypatch.setattr(fence, "STDLIB_API", original | {"math.tan"})
    rebuilt = fence.ImportIndex(second.snapshot)
    assert rebuilt is not second and rebuilt.modules == fence.ImportIndex(dict(second.snapshot.sources)).modules


def test_actual_origin_uses_prefix_helper_while_namespace_scans_remain_unchanged(monkeypatch):
    index = fence.ImportIndex({"atlas_brain/bridge/__init__.py": "import math as deep\n"})
    name = "atlas_brain.bridge.deep.isfinite"
    assert index.origin(name) == "math.isfinite"
    lookup, calls = fence.module_prefix, []
    def counting(candidate, modules):
        calls.append((candidate, modules))
        return lookup(candidate, modules)
    monkeypatch.setattr(fence, "module_prefix", counting)
    assert index.origin(name) == "math.isfinite"
    assert len(calls) == 1 and calls[0][0] == name and calls[0][1] is index.modules
