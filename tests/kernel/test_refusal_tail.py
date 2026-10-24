import ast

import pytest

from atlas_brain.kernel.token_lints import refusal_tail


@pytest.mark.parametrize('source,subject,trusted,proven', [
    ('', 'raw', False, False),
    ('raise ValueError("unmapped")', '', False, True),
    ('return Unknown()', '', True, True),
    ('return Unknown()', '', False, False),
    ('return "up"', 'raw', False, False),
    ('if raw == "down": return "down"\nraise ValueError("unmapped")', 'raw', False, True),
    ('if "down" == raw: return "down"\nraise ValueError("unmapped")', 'raw', False, True),
    ('if raw == "down": raise ValueError("bad")\nraise ValueError("unmapped")', 'raw', False, True),
    ('if raw == "mystery": raw = "down"\nif raw == "down": return "down"\nraise ValueError("unmapped")', 'raw', False, False),
    ('if packet.state == "mystery": packet.state = "down"\nif packet.state == "down": return "down"\nraise ValueError("unmapped")', 'packet.state', False, False),
    ('if raw == "mystery":\n raw = "down"\n return "down"\nraise ValueError("unmapped")', 'raw', False, False),
    ('if other == "down": return "down"\nraise ValueError("unmapped")', 'raw', False, False),
    ('if raw == "down": return "down"\nelse: return "up"\nraise ValueError("unmapped")', 'raw', False, False),
])
def test_refusal_tail_requires_terminal_stable_input_arms_and_trusted_unknown(source, subject, trusted, proven):
    tree = ast.parse(source)
    unknowns = frozenset(node for node in ast.walk(tree) if isinstance(node, ast.Call)) if trusted else frozenset()
    assert refusal_tail(tuple(tree.body), subject, unknowns) is proven
