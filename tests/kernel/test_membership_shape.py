import ast

import pytest

from atlas_brain.kernel.token_lints import finite_subject, guarded_lookup


@pytest.mark.parametrize('source,subject', [
    ('raw == "up"', 'raw'), ('"up" == packet.state', 'packet.state'),
    ('raw != "up"', ''), ('raw == other', ''), ('raw == "up" == other', ''),
])
def test_finite_equality_requires_one_literal_and_one_named_input(source, subject):
    assert finite_subject(ast.parse(source, mode='eval').body) == subject


@pytest.mark.parametrize('condition,lookup,inverse,proven', [
    ('raw in states', 'states[raw]', False, True),
    ('packet.state not in states', 'states[packet.state]', True, True),
    ('"state" in fields', 'fields["state"]', False, True),
    ('raw not in states', 'states[raw]', False, False),
    ('raw in states', 'other[raw]', False, False),
    ('raw in states', 'states[other]', False, False),
    ('raw in states', 'states[raw] or "up"', False, False),
])
def test_membership_witness_binds_polarity_mapping_key_and_direct_return(condition, lookup, inverse, proven):
    test = ast.parse(condition, mode='eval').body
    body = tuple(ast.parse('return ' + lookup).body)
    assert guarded_lookup(test, body, inverse=inverse) is proven
