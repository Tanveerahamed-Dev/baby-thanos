"""Nested import origins must not certify a different outer callable or class."""
import ast
import inspect

import pytest

from atlas_brain.kernel.lints import binding_environment
from atlas_brain.kernel.token_lints import binding_proof, fallback_nodes


def _unknown_function(raw: str, fallback: str = 'up') -> str:
    from builtins import str as U

    def local():
        from atlas_brain.kernel.states import Unknown as U
        return U

    states = {'known': 'up'}
    if raw not in states:
        return U(fallback)
    return states[raw]


def _unknown_class(raw: str, fallback: str = 'up') -> str:
    from builtins import str as U

    class Local:
        from atlas_brain.kernel.states import Unknown as U
        reference = U

    states = {'known': 'up'}
    if raw not in states:
        return U(fallback)
    return states[raw]


def _assertion_function(raw: str) -> str:
    from builtins import str as terminal

    def local():
        from typing import assert_never as terminal
        return terminal

    match raw:
        case 'known':
            return 'up'
        case _ as missing:
            terminal(missing)
    return 'up'


def _assertion_class(raw: str) -> str:
    from builtins import str as terminal

    class Local:
        from typing import assert_never as terminal
        reference = terminal

    match raw:
        case 'known':
            return 'up'
        case _ as missing:
            terminal(missing)
    return 'up'


def _fact_function(raw: str) -> str:
    from builtins import str as K
    from typing import assert_never as terminal

    def local():
        from atlas_brain.kernel.states import Known as K
        return K

    match raw:
        case K():
            return 'up'
        case _ as missing:
            terminal(missing)


def _fact_class(raw: str) -> str:
    from builtins import str as K
    from typing import assert_never as terminal

    class Local:
        from atlas_brain.kernel.states import Known as K
        reference = K

    match raw:
        case K():
            return 'up'
        case _ as missing:
            terminal(missing)


@pytest.mark.parametrize('runtime,target,kind', [
    (_unknown_function, 'atlas_brain.kernel.states.Unknown', 'calls'),
    (_unknown_class, 'atlas_brain.kernel.states.Unknown', 'calls'),
    (_assertion_function, 'typing.assert_never', 'calls'),
    (_assertion_class, 'typing.assert_never', 'calls'),
    (_fact_function, 'typing.assert_never', 'facts'),
    (_fact_class, 'typing.assert_never', 'facts'),
])
def test_nested_import_cannot_certify_a_different_outer_origin(runtime, target, kind):
    assert runtime('mystery') == 'up'  # The declared negative fixture manufactures health.
    tree = ast.parse(inspect.getsource(runtime))
    aliases, rebound = binding_environment(tree)
    calls, facts = binding_proof(tree, aliases, rebound, call_target=target)
    witnesses = calls if kind == 'calls' else facts
    guard = next(node for node in ast.walk(tree) if isinstance(node, (ast.If, ast.Match)))
    assert (len(witnesses), guard in fallback_nodes(tree, aliases, rebound)) == (0, True)


@pytest.mark.parametrize('source,expected', [
    ('from typing import assert_never as terminal\ndef local():\n from typing import assert_never as terminal\nterminal(value)', 1),
    ('from typing import assert_never as first\nfrom typing import assert_never as second\nfirst(value)\nsecond(value)', 2),
    ('from typing import assert_never as terminal\nfrom builtins import str as local\ndef helper():\n from builtins import int as local\nterminal(value)', 1),
])
def test_repeated_origins_and_unrelated_import_conflicts_preserve_genuine_calls(source, expected):
    tree = ast.parse(source)
    calls, _ = binding_proof(tree, *binding_environment(tree))
    assert len(calls) == expected
