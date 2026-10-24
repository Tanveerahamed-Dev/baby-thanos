import ast

import pytest

from atlas_brain.kernel.token_lints import statement_context


@pytest.mark.parametrize('source,protected', [
    ('def mapped(raw):\n if raw == "up": return "up"\n raise ValueError("unmapped")', False),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except ValueError: return "up"', True),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n finally: return "up"', True),
    ('def mapped(raw):\n with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', True),
    ('async def mapped(raw):\n async with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', True),
    ('def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except* ValueError: pass', True),
    ('def mapped(raw):\n try: pass\n except ValueError: pass\n else:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', False),
    ('def mapped(raw):\n try: pass\n except ValueError:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', True),
    ('def mapped(raw):\n try: raise ValueError("entered")\n except ValueError:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', False),
    ('def mapped(raw):\n try: raise KeyError("entered")\n except ValueError:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except KeyError: return "up"', True),
    ('def mapped(raw):\n try: raise ValueError("entered")\n except ValueError: pass\n else:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', True),
    ('def mapped(raw):\n return "up"\n if raw == "up": return "up"\n raise ValueError("unmapped")', True),
    ('def mapped(raw):\n try:\n  try:\n   if raw == "up": return "up"\n   raise ValueError("unmapped")\n  finally: pass\n except ValueError: return "up"', True),
    ('with manager:\n def mapped(raw):\n  if raw == "up": return "up"\n  raise ValueError("unmapped")', False),
])
def test_exception_and_finalization_context_is_retained_across_statement_blocks(source, protected):
    tree = ast.parse(source)
    following, intercepted = statement_context(tree)
    branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If))
    assert isinstance(following[branch][-1], ast.Raise)
    assert (branch in intercepted) is protected


def test_successor_inventory_is_bound_to_each_exact_statement_list():
    tree = ast.parse('if ready:\n first()\n second()\nelse:\n other()\nafter()')
    following, intercepted = statement_context(tree)
    branch = tree.body[0]
    assert isinstance(branch, ast.If)
    assert following[branch] == (tree.body[1],)
    assert following[branch.body[0]] == (branch.body[1],)
    assert following[branch.orelse[0]] == ()
    assert branch not in intercepted and tree.body[1] not in intercepted
    assert intercepted == frozenset(node for statement in branch.body + branch.orelse for node in ast.walk(statement))


@pytest.mark.parametrize('source', [
    'def mapped(key):\n for item in ():\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")',
    'def mapped(key):\n while ready:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")',
    'async def mapped(key):\n async for item in rows:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")',
    'def mapped(key):\n if ready:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")',
    'def mapped(key):\n for item in rows: break\n else:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")',
    'def mapped(key):\n while ready: break\n else:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")',
])
def test_optional_blocks_preserve_local_successors_without_certifying_execution(source):
    following, unproven = statement_context(ast.parse(source))
    branch = next(node for node in following if isinstance(node, ast.If) and isinstance(node.test, ast.Compare))
    assert isinstance(following[branch][-1], ast.Raise)
    assert branch in unproven


def test_a_defined_function_has_its_own_execution_scope_inside_an_optional_block():
    tree = ast.parse('for item in ():\n def mapped(key=states[raw]):\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")')
    following, unproven = statement_context(tree)
    branch = next(node for node in following if isinstance(node, ast.If))
    assert isinstance(following[branch][-1], ast.Raise)
    assert branch not in unproven
    assert next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)) in unproven
    assert next(node for node in ast.walk(tree) if isinstance(node, ast.Subscript)) in unproven


@pytest.mark.parametrize('earlier', [
    'if ready: return "up"',
    'for item in rows:\n   if ready: return "up"',
    'try:\n   if ready: return "up"\n  finally: pass',
])
def test_entered_handler_does_not_prove_execution_after_a_conditional_return(earlier):
    source = ('def mapped(raw, ready):\n try: raise ValueError("entered")\n except ValueError:\n  '
              + earlier + '\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")')
    following, unproven = statement_context(ast.parse(source))
    guard = next(node for node in following if isinstance(node, ast.If) and isinstance(node.test, ast.Compare))
    assert isinstance(following[guard][-1], ast.Raise)
    assert guard in unproven


def test_a_nested_functions_return_does_not_skip_the_enclosing_handlers_guard():
    source = ('def mapped(raw):\n try: raise ValueError("entered")\n except ValueError:\n'
              '  def other(): return "up"\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")')
    following, unproven = statement_context(ast.parse(source))
    guard = next(node for node in following if isinstance(node, ast.If))
    assert isinstance(following[guard][-1], ast.Raise)
    assert guard not in unproven
