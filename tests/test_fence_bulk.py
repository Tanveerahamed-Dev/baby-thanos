"""Bulk fence checks preserve exact per-file decisions while sharing one source snapshot."""
import ast

import pytest

from tools import fence


def oracle(sources):
    return {path: fence.source_refusals(source, sources, path) for path, source in sources.items()}


@pytest.mark.parametrize("sources,positive", [
    ({"atlas_brain/safe.py": "value = 1\n", "atlas_brain/probe.py": "from .safe import value\nanswer = value\n"}, True),
    ({"atlas_brain/kernel/lints.py": "from ast import parse\nvalue = parse('x')\n"}, True),
    ({"atlas_brain/evidence/admission.py": "from pathlib import PurePosixPath\nvalue = PurePosixPath('x').is_absolute()\n"}, True),
    ({"atlas_brain/kernel/lints.py": "from ast import parse\n",
      "atlas_brain/probe.py": "from .kernel.lints import parse\nvalue = parse('x')\n"}, False),
    ({"atlas_brain/probe.py": "from pathlib import PurePosixPath\nvalue = PurePosixPath('x').is_absolute()\n"}, False),
    ({"atlas_brain/holder.py": "from pathlib import Path\ndef expose(): return Path.read_text\n",
      "atlas_brain/probe.py": "from .holder import expose\nexpose()('x')\n"}, False),
    ({"atlas_brain/a.py": "from .b import value\n", "atlas_brain/b.py": "from .a import value\n"}, False),
    ({"atlas_brain/a.py": "value = 1\n", "atlas_brain/a/__init__.py": "value = 2\n"}, False),
])
def test_bulk_decisions_match_fresh_public_oracle_with_explicit_allow_refuse_controls(sources, positive):
    expected = oracle(sources)
    assert fence.bulk_source_refusals(sources) == expected
    assert (not any(expected.values())) is positive
    assert fence.bulk_source_refusals(dict(reversed(tuple(sources.items())))) == expected


def test_scoped_and_ordinary_files_keep_different_admission_and_constructor_count(monkeypatch):
    sources = {f"atlas_brain/item{index}.py": "value = 1\n" for index in range(24)}
    sources["atlas_brain/kernel/lints.py"] = "from ast import parse\nvalue = parse('x')\n"
    sources["atlas_brain/probe.py"] = "from .kernel.lints import parse\nvalue = parse('x')\n"
    expected = oracle(sources)
    original, calls = fence.ImportIndex, []
    def counted(mapping, forbidden=()):
        calls.append((dict(mapping), frozenset(forbidden)))
        return original(mapping, forbidden)
    monkeypatch.setattr(fence, "ImportIndex", counted)
    assert fence.bulk_source_refusals(sources) == expected
    assert len(calls) == 2 and all(snapshot == sources for snapshot, _ in calls)
    forbidden = frozenset(path.removesuffix(".py").replace("/", ".") for path in fence.SCOPED_API)
    assert {denied for _, denied in calls} == {frozenset(), forbidden}
    assert not expected["atlas_brain/kernel/lints.py"] and expected["atlas_brain/probe.py"]
    # The next invocation is independent even when every source byte is unchanged.
    assert fence.bulk_source_refusals(sources) == expected and len(calls) == 4


def test_changed_source_snapshot_cannot_reuse_old_provenance(monkeypatch):
    sources = {"atlas_brain/safe.py": "value = 1\n", "atlas_brain/probe.py": "from .safe import value\n"}
    original, calls = fence.ImportIndex, []
    def counted(mapping, forbidden=()):
        calls.append(dict(mapping))
        return original(mapping, forbidden)
    monkeypatch.setattr(fence, "ImportIndex", counted)
    assert not any(fence.bulk_source_refusals(sources).values())
    sources["atlas_brain/safe.py"] = "from dataclasses import InitVar as value\n"
    second = fence.bulk_source_refusals(sources)
    assert len(calls) == 2 and calls[0] != calls[1] and all(second.values())
    assert second == oracle(sources)


def test_public_single_source_functions_still_build_fresh_indexes(monkeypatch):
    sources = {"atlas_brain/probe.py": "value = 1\n"}
    original, calls = fence.ImportIndex, []
    def counted(mapping, forbidden=()):
        calls.append(dict(mapping))
        return original(mapping, forbidden)
    monkeypatch.setattr(fence, "ImportIndex", counted)
    assert fence.source_allowed(sources["atlas_brain/probe.py"], sources)
    assert fence.source_refusals(sources["atlas_brain/probe.py"], sources) == set()
    assert len(calls) == 2


def test_failed_shared_index_is_fail_closed_for_every_affected_path(monkeypatch):
    sources = {"atlas_brain/a.py": "value = 1\n", "atlas_brain/b.py": "value = 2\n",
               "atlas_brain/kernel/lints.py": "from ast import parse\n"}
    original, calls = fence.ImportIndex, []
    def reject_ordinary(mapping, forbidden=()):
        calls.append(frozenset(forbidden))
        if forbidden:
            raise ValueError("planted invalid context")
        return original(mapping, forbidden)
    monkeypatch.setattr(fence, "ImportIndex", reject_ordinary)
    result = fence.bulk_source_refusals(sources)
    assert len(calls) == 2
    assert result["atlas_brain/a.py"] == result["atlas_brain/b.py"] == {"unresolved-provenance"}
    assert result["atlas_brain/kernel/lints.py"] == set()


def test_per_file_binding_failure_does_not_erase_another_files_decision(monkeypatch):
    sources = {"atlas_brain/a.py": "value = 1\n", "atlas_brain/b.py": "value = 2\n"}
    original, calls = fence.import_bindings, {}
    def broken(tree, path, ignored_arg_roots=None):
        calls[path] = calls.get(path, 0) + 1
        if path == "atlas_brain/a.py" and calls[path] == 2:
            raise ValueError("planted per-file error")
        return original(tree, path, ignored_arg_roots)
    monkeypatch.setattr(fence, "import_bindings", broken)
    assert fence.bulk_source_refusals(sources) == {
        "atlas_brain/a.py": {"unresolved-provenance"}, "atlas_brain/b.py": set()}


def test_bulk_checker_does_not_mutate_constructor_built_index(monkeypatch):
    sources = {"atlas_brain/a.py": "from .b import value\n", "atlas_brain/b.py": "value = 1\n"}
    original, instances = fence.ImportIndex, []
    def observed(mapping, forbidden=()):
        index = original(mapping, forbidden)
        before = repr((index.modules, index.classes, index.ignored_arg_classes, index.forbidden))
        instances.append((index, before))
        return index
    monkeypatch.setattr(fence, "ImportIndex", observed)
    assert not any(fence.bulk_source_refusals(sources).values())
    assert all(repr((index.modules, index.classes, index.ignored_arg_classes, index.forbidden)) == before
               for index, before in instances)


def test_checker_still_parses_each_supplied_file(monkeypatch):
    sources = {"atlas_brain/a.py": "value = 1\n", "atlas_brain/b.py": "value = 2\n"}
    original, seen = fence._indexed_refusals, []
    def checked(source, path, index):
        seen.append((source, path))
        assert isinstance(ast.parse(source), ast.Module)
        return original(source, path, index)
    monkeypatch.setattr(fence, "_indexed_refusals", checked)
    assert not any(fence.bulk_source_refusals(sources).values())
    assert seen == [(source, path) for path, source in sources.items()]
