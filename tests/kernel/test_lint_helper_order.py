"""The scanner's own helper must satisfy the ordinary iteration guard."""
import ast
from pathlib import Path

from atlas_brain.kernel.lints import binding_environment, unordered_iterations


def test_fallback_helper_has_no_unordered_set_iteration():
    path = 'atlas_brain/kernel/token_lints.py'
    tree = ast.parse(Path(path).read_text(encoding='utf-8'))
    assert not unordered_iterations(tree, binding_environment(tree)[0])
