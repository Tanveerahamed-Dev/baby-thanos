import ast

import pytest

from atlas_brain.kernel.lints import contains_name, resolved_name, resolved_tail


@pytest.mark.parametrize('source,aliases,qualified', [
    ('item', {}, 'item'),
    ('K', {'K': 'atlas_brain.kernel.states.Known'}, 'atlas_brain.kernel.states.Known'),
    ('rx.ASCII', {'rx': 're'}, 're.ASCII'),
    ('table[key]', {'table': 'module.values'}, 'module.values'),
    ('factory()', {}, ''),
    ('42', {}, ''),
])
def test_lint_name_resolution_preserves_unknowns_and_qualifies_aliases(source, aliases, qualified):
    node = ast.parse(source, mode='eval').body
    assert resolved_name(node, aliases) == qualified
    assert resolved_tail(node, aliases) == qualified.split('.')[-1]


@pytest.mark.parametrize('source,aliases,names,found', [
    ('Wrapper[K]', {'K': 'atlas_brain.kernel.states.Known'}, ('Known',), True),
    ('O[int]', {'O': 'typing.Optional'}, ('Optional',), True),
    ('Wrapper[K]', {}, ('Known',), False),
    ('"Known"', {}, ('Known',), False),
])
def test_lint_name_search_uses_ast_names_and_import_bindings(source, aliases, names, found):
    assert contains_name(ast.parse(source, mode='eval').body, names, aliases) is found
