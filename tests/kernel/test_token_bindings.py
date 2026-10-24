"""Binding witnesses are independently tested before fallback integration."""
import ast

import pytest

from atlas_brain.kernel.token_lints import binding_proof, bound_names


def test_capture_inventory_includes_mapping_rest_and_sequence_star():
    tree = ast.parse('match value:\n case {"key": local, **rest}: pass\n case [*tail]: pass')
    assert bound_names(tree) == frozenset({'local', 'rest', 'tail'})


@pytest.mark.parametrize('fact', ['Known', 'Absent', 'Unknown', 'NotApplicable'])
@pytest.mark.parametrize('prefix,aliases', [
    ('', {'K': 'atlas_brain.kernel.states.', 'terminal': 'typing.assert_never'}),
    ('s.', {'s': 'atlas_brain.kernel.states', 'terminal': 'typing.assert_never'}),
])
def test_exact_canonical_fact_and_assertion_witnesses(fact, prefix, aliases):
    name = prefix + fact if prefix else 'K'
    environment = dict(aliases)
    if not prefix:
        environment['K'] += fact
    tree = ast.parse(f'match value:\n case {name}(): pass\n case _ as missing: terminal(missing)')
    calls, facts = binding_proof(tree, environment, set())
    assert len(calls) == len(facts) == 1
    assert calls == frozenset(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert facts == frozenset(n for n in ast.walk(tree) if isinstance(n, ast.MatchClass))


@pytest.mark.parametrize('shadow', ['typing', 'typing.assert_never', 'typing.assert_never.extra'])
def test_assertion_shadow_refuses_exact_ancestor_and_descendant_bindings(shadow):
    tree = ast.parse('terminal(value)')
    assert binding_proof(tree, {'terminal': 'typing.assert_never'}, {shadow})[0] == frozenset()


@pytest.mark.parametrize('source', [
    'match value:\n case K(value=terminal): pass\n case _ as missing: terminal(missing)',
    'match value:\n case {"key": x, **terminal}: pass\n case _ as missing: terminal(missing)',
    'match value:\n case [*terminal]: pass\n case _ as missing: terminal(missing)',
])
def test_all_capture_forms_refuse_spoofed_terminal(source):
    assert binding_proof(ast.parse(source), {'terminal': 'typing.assert_never'}, set())[0] == frozenset()


@pytest.mark.parametrize('aliases,rebound', [
    ({}, set()),
    ({'K': 'other.Known'}, set()),
    ({'K': 'atlas_brain.kernel.states.Known'}, {'atlas_brain.kernel.states'}),
    ({'K': 'atlas_brain.kernel.states.Known'}, {'atlas_brain.kernel.states.Known'}),
])
def test_unproven_or_shadowed_fact_name_is_not_a_witness(aliases, rebound):
    tree = ast.parse('match value:\n case K(): pass')
    assert binding_proof(tree, aliases, rebound)[1] == frozenset()


@pytest.mark.parametrize('expression,aliases', [
    ('U()', {'U': 'atlas_brain.kernel.states.Unknown'}),
    ('s.Unknown()', {'s': 'atlas_brain.kernel.states'}),
    ('atlas_brain.kernel.states.Unknown()', {}),
])
def test_canonical_unknown_calls_are_separate_from_terminal_assertions(expression, aliases):
    tree = ast.parse(expression)
    calls, facts = binding_proof(tree, aliases, set(), call_target='atlas_brain.kernel.states.Unknown')
    assert calls == frozenset(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    assert not facts
    assert not binding_proof(tree, aliases, set())[0]


@pytest.mark.parametrize('rebound', [
    {'atlas_brain'}, {'atlas_brain.kernel.states'},
    {'atlas_brain.kernel.states.Unknown'}, {'atlas_brain.kernel.states.Unknown.extra'},
])
def test_unknown_call_witness_refuses_every_rebinding_level(rebound):
    tree = ast.parse('U()')
    assert not binding_proof(tree, {'U': 'atlas_brain.kernel.states.Unknown'}, rebound,
                             call_target='atlas_brain.kernel.states.Unknown')[0]


@pytest.mark.parametrize('source,aliases', [
    ('Unknown()', {}),
    ('U()', {'U': 'other.Unknown'}),
    ('match value:\n case U: pass\nU()', {'U': 'atlas_brain.kernel.states.Unknown'}),
    ('match value:\n case {"x": x, **U}: pass\nU()', {'U': 'atlas_brain.kernel.states.Unknown'}),
    ('match value:\n case [*U]: pass\nU()', {'U': 'atlas_brain.kernel.states.Unknown'}),
])
def test_unproven_unknown_and_pattern_capture_cannot_certify_refusal(source, aliases):
    assert not binding_proof(ast.parse(source), aliases, set(), call_target='atlas_brain.kernel.states.Unknown')[0]
