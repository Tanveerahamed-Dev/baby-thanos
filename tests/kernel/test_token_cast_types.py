"""Type-only subscriptions must not impersonate runtime token lookups."""
import ast
from typing import cast

import pytest

from atlas_brain.kernel.lints import binding_environment
from atlas_brain.kernel.token_lints import fallback_nodes


def token_findings(source):
    tree = ast.parse(source)
    aliases, rebound = binding_environment(tree)
    return frozenset(cast(ast.stmt | ast.expr, node).lineno for node in fallback_nodes(tree, aliases, rebound))


@pytest.mark.parametrize('prefix,expression', [
    ('from typing import cast', 'cast(list[object], value)'),
    ('from typing import cast as narrow', 'narrow(list[object], value)'),
    ('import typing as t', 't.cast(list[object], value)'),
    ('from typing import cast', 'cast(list[list[object]], value)'),
    ('from typing import cast\nimport builtins as b', 'cast(b.list[b.object], value)'),
])
def test_proven_builtin_cast_type_is_not_a_token_lookup(prefix, expression):
    source = prefix + '\ndef inspect(value):\n if isinstance(value, list):\n  return ' + expression + '\n return ()'
    assert not token_findings(source)


@pytest.mark.parametrize('prefix,expression', [
    ('from typing import cast\ncast = replacement', 'cast(list[object], value)'),
    ('from typing import cast\nlist = replacement', 'cast(list[object], value)'),
    ('from typing import cast\nobject = replacement', 'cast(list[object], value)'),
    ('import typing as t\nt.cast = replacement', 't.cast(list[object], value)'),
    ('from typing import cast\nimport builtins as b\nb.list = replacement', 'cast(b.list[b.object], value)'),
    ('from other import cast', 'cast(list[object], value)'),
    ('from typing import cast', 'cast(Container[object], value)'),
    ('from typing import cast', 'cast(list[mapping[raw]], value)'),
    ('from typing import cast', 'cast(list[object], mapping[raw])'),
    ('from typing import cast', 'cast(mapping[raw], value)'),
])
def test_cast_spelling_cannot_hide_a_runtime_or_unproved_lookup(prefix, expression):
    source = prefix + '\ndef inspect(value, ready):\n if ready:\n  return ' + expression + '\n return "up"'
    assert token_findings(source)


def test_pattern_capture_cannot_certify_a_shadowed_cast_type():
    source = ('from typing import cast\nmatch value:\n case {"type": list}: pass\n'
              'def inspect(value):\n if ready: return cast(list[object], value)\n return "up"')
    assert 5 in token_findings(source)
