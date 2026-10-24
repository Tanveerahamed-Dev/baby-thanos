"""The public scanner's binding and iteration foundations retain whole-source scope."""
import ast

import pytest

from atlas_brain.kernel.lints import binding_environment, unordered_iterations


def test_import_environment_preserves_aliases_and_whole_module_rebindings():
    tree = ast.parse('import re as rx\nfrom typing import cast as narrow\n'
                     'rx.ASCII = 0\ndef helper(narrow):\n local = 1\n return local')
    aliases, rebound = binding_environment(tree)
    assert aliases == {'rx': 're', 'narrow': 'typing.cast'}
    assert {'re.ASCII', 'typing.cast', 'helper', 'local'} <= rebound


def test_binding_inventory_contains_function_class_and_handler_names():
    tree = ast.parse('class Record: pass\nasync def worker(arg): pass\n'
                     'try: pass\nexcept ValueError as failure: pass')
    assert {'Record', 'worker', 'arg', 'failure'} <= binding_environment(tree)[1]


@pytest.mark.parametrize('source', [
    'items = {"b", "a"}\nfor item in items: pass',
    'items = frozenset(("b", "a"))\nresult = [item for item in items]',
    'from builtins import frozenset as Frozen\nitems = Frozen(("b", "a"))\nfor item in items: pass',
    'items: set[str]\nfor item in items: pass',
    'def inspect(items: frozenset[str]):\n return (item for item in items)',
    'for item in {"b", "a"}: pass',
    'result = [item for item in {value for value in ("a", "b")}]',
])
def test_each_unordered_iteration_shape_is_refused(source):
    tree = ast.parse(source)
    assert unordered_iterations(tree, binding_environment(tree)[0])


@pytest.mark.parametrize('source', [
    'items = {"b", "a"}\nfor item in sorted(items): pass',
    'items = frozenset(("b", "a"))\nresult = [item for item in sorted(items)]',
    'items = ("b", "a")\nfor item in items: pass',
    'items = ["b", "a"]\nresult = [item for item in items]',
])
def test_ordered_iteration_controls_are_retained(source):
    tree = ast.parse(source)
    assert not unordered_iterations(tree, binding_environment(tree)[0])
