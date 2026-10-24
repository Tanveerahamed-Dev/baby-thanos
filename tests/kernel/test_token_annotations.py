"""Pure type syntax is distinct from executable value and default expressions."""
import ast
from typing import cast

import pytest

from atlas_brain.kernel.lints import binding_environment
from atlas_brain.kernel.token_lints import fallback_nodes


def token_findings(source):
    tree = ast.parse(source)
    aliases, rebound = binding_environment(tree)
    return frozenset(cast(ast.stmt | ast.expr, node).lineno for node in fallback_nodes(tree, aliases, rebound))


@pytest.mark.parametrize('prefix,statement', [
    ('', 'pending: list[object] = []'),
    ('import ast', 'pending: set[ast.AST] = set()'),
    ('import ast as nodes', 'pending: set[nodes.AST] = set()'),
    ('from ast import AST as Node', 'pending: set[Node] = set()'),
    ('from builtins import set as S\nfrom ast import AST as Node', 'pending: S[Node] = S()'),
    ('', 'def helper(arg: list[object]): return arg'),
    ('', 'def helper() -> list[object]: return value'),
    ('from typing import cast\nimport ast', 'pending = cast(list[ast.AST], value)'),
])
def test_proven_type_annotations_are_not_value_lookups(prefix, statement):
    source = prefix + '\ndef inspect(value, ready):\n if ready:\n  ' + statement + '\n  return value\n return ()'
    assert not token_findings(source)


@pytest.mark.parametrize('prefix,statement', [
    ('', 'pending: mapping[raw] = ()'),
    ('', 'pending: (states[raw] if raw in states else "up") = ()'),
    ('', 'pending: list[mapping[raw]] = ()'),
    ('', 'pending: list[object] = mapping[raw]'),
    ('', 'def helper(arg: list[object] = mapping[raw]): return arg'),
    ('import ast\nast.AST = replacement', 'pending: set[ast.AST] = set()'),
    ('from ast import AST as Node\nNode = replacement', 'pending: set[Node] = set()'),
    ('from other import AST as Node', 'pending: set[Node] = set()'),
])
def test_annotations_cannot_hide_runtime_or_unproved_lookups(prefix, statement):
    source = prefix + '\ndef inspect(value, ready):\n if ready:\n  ' + statement + '\n  return value\n return ()'
    target_line = next(index for index, text in enumerate(source.splitlines(), 1) if text.strip() == statement)
    assert target_line in token_findings(source)


def test_pattern_capture_cannot_certify_an_ast_type_annotation():
    source = ('from ast import AST as Node\nmatch value:\n case {"type": Node}: pass\n'
              'def inspect(value, ready):\n if ready:\n  pending: set[Node] = set()\n return ()')
    assert 6 in token_findings(source)
