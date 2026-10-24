import ast

import pytest

from atlas_brain.kernel.token_lints import (
    binding_proof,
    bound_names,
    fallback_node,
    fallback_nodes,
)


@pytest.mark.parametrize('source', [
    'tokens.get(token, "up")',
    'tokens.get(token) or "up"',
    'tokens.get(token)',
    'tokens.setdefault(token, "up")',
    'tokens.setdefault(token)',
    'tokens.pop(token, "up")',
    'dict.pop(tokens, token, "up")',
    'defaultdict(lambda: "up")',
    'collections.defaultdict(lambda: "up")',
    'value = states[raw] if raw in states else "up"',
    'value = states[raw.state] if raw.state in states else "up"',
    'if raw in states:\n value = states[raw]\nelse:\n value = "up"',
    'value = fields["state"] if "state" in fields else "up"',
    'def mapped(raw):\n if raw == "up": return 1\n else: return 2',
    'value = 1 if raw == "up" else 2',
    'def mapped(raw):\n if raw == "up": return "up"\n else: return "up" + ""',
    'def mapped(raw):\n if raw == "up": raise ValueError("refused")\n else: return "up" + ""',
    'def map_state(raw):\n if raw == "up": return "up"\n else: pass\n return "up"',
    'def map_state(raw):\n if raw == "up": return "up"\n if raw == "down": return "down"\n return "up"',
    'def map_state(raw):\n value = "up"\n if raw == "down": value = "down"\n return value',
    'class Known(str): pass\nmatch raw:\n case Known(): value = "up"',
    'if raw == "up": value = "up"\nelse: value = "up" + ""',
    'value = "up" if raw == "up" else "up" + ""',
    'def assert_never(value): pass\ndef mapped(raw):\n match raw:\n  case _ as missing: assert_never(missing)\n return "up"',
    'match raw:\n case _ as missing: assert_never(missing)',
    'match raw:\n case _: value = "up"',
    'match raw:\n case other: value = "up"',
    'match raw:\n case str(): value = "up"',
    'match raw:\n case _ as missing:\n  assert_never(missing)\n  value = "up"',
    'match raw:\n case _ as missing: assert_never(other)',
    '"up" if token not in tokens else tokens[token]',
    'if token in tokens:\n value = tokens[token]\nelse:\n value = "up"',
    'match token:\n case "up": value = 1\n case _: value = 1',
    'match token:\n case "up": value = 1\n case other: value = 1',
    'match token:\n case object(): value = "up"',
    'match token:\n case builtins.object(): value = "up"',
    'match token:\n case str(): value = "up"',
    'match raw:\n case "up": value = 1\n case object(): value = 1',
    'match raw:\n case object(): value = "up"',
    'match token:\n case "up" | _: value = 1',
])
def test_fallback_shapes_are_refused(source):
    assert any(fallback_node(node) for node in ast.walk(ast.parse(source)))


@pytest.mark.parametrize('source', [
    'value = tokens[token]',
    'stack.pop()',
    'stack.pop(0)',
    'value = states[raw]',
    'value = values[0] if valid else 0',
    'if valid:\n value = values[0]\nelse:\n value = 0',
    'index += 2 if pattern[index] == "\\\\" else 1',
    'def parse(pattern, index):\n if pattern[index] == "x": return index + 1\n return index',
    'if raw == "invalid": raise ValueError("refused")',
    'match state:\n case "up": value = 1\n case "down": value = 0',
    'match fact:\n case Known(value=state): pass\n case _ as missing: assert_never(missing)',
    'match token:\n case "up": value = 1\n case "down": value = 0',
    'match token:\n case "up" | "ready": value = 1\n case "down": value = 0',
    'match fact:\n case Known(): pass\n case _ as impossible: assert_never(impossible)',
    'if valid:\n value = 1\nelse:\n value = 2',
])
def test_explicit_mapping_and_fact_dispatch_remain_valid(source):
    tree = ast.parse(source)
    # These fragments declare a real assertion and an unhandled context;
    # the public entry point separately proves both from whole source.
    assertions = frozenset(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                           and isinstance(node.func, ast.Name) and node.func.id == 'assert_never')
    facts = frozenset(node for node in ast.walk(tree) if isinstance(node, ast.MatchClass))
    assert not any(fallback_node(node, assertions=assertions, facts=facts, allow_refusal=True) for node in ast.walk(tree))


def test_import_resolved_factory_alias_is_refused():
    node = ast.parse('DD(lambda: "up")').body[0].value
    assert fallback_node(node, 'collections.defaultdict')


def test_pattern_binding_inventory_covers_all_capture_forms():
    tree = ast.parse('match value:\n case {"key": local, **rest}: pass\n case [*tail]: pass')
    assert bound_names(tree) == frozenset({'local', 'rest', 'tail'})


def test_canonical_binding_proof_rejects_import_and_capture_shadows():
    tree = ast.parse('match fact:\n case K(): pass\n case _ as missing: terminal(missing)')
    aliases = {'K': 'atlas_brain.kernel.states.Known', 'terminal': 'typing.assert_never'}
    calls, facts = binding_proof(tree, aliases, set())
    assert len(calls) == len(facts) == 1
    assert binding_proof(tree, aliases, {'typing'})[0] == frozenset()
    assert binding_proof(tree, aliases, {'atlas_brain.kernel.states'})[1] == frozenset()
    shadowed = ast.parse('match fact:\n case K(value=terminal): pass\n case _ as missing: terminal(missing)')
    assert binding_proof(shadowed, aliases, set())[0] == frozenset()


@pytest.mark.parametrize('ending', [
    'raise UnknownToken(raw)',
    'return atlas_brain.kernel.states.Unknown(reason=reason, detail="unmapped", evidence=(), candidates=(), next_evidence=())',
])
@pytest.mark.parametrize('branches', [
    ' if raw == "up": return "up"\n',
    ' if raw == "up": return "up"\n if raw == "down": return "down"\n',
])
def test_following_explicit_refusal_remains_valid(ending, branches):
    source = 'import atlas_brain.kernel.states\ndef map_state(raw):\n' + branches + ' ' + ending
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'def mapped(raw):\n if raw == "up": pass\n return "up"',
    'def mapped(raw):\n if raw == "mystery": raw = "down"\n if raw == "down": return "down"\n raise ValueError("unmapped")',
    'def mapped(raw):\n if raw == "mystery":\n  raw = "down"\n  pass\n if raw == "down": return "down"\n raise ValueError("unmapped")',
    'def normalize(packet): packet.state = "down"\ndef mapped(packet):\n if packet.state == "mystery": normalize(packet)\n if packet.state == "down": return "down"\n raise ValueError("unmapped")',
    'def mapped(packet):\n if packet.state == "mystery": packet.state = "down"\n if packet.state == "down": return "down"\n raise ValueError("unmapped")',
    'def mapped(raw):\n if raw == "up": return "up"\n if raw == "mystery": raw = "down"\n if raw == "down": return "down"\n raise ValueError("unmapped")',
    'def mapped(packet):\n if packet.state == "up": return "up"\n if packet.state == "mystery": packet.state = "down"\n if packet.state == "down": return "down"\n raise ValueError("unmapped")',
    'def mapped(raw):\n if raw == "bad": raise UnknownToken(raw)\n return "up"',
    'def mapped(raw):\n if raw != "up": return "up"\n raise UnknownToken(raw)',
    'def mapped(raw, other):\n if raw == "up": return "up"\n if other == "down": return "up"\n raise UnknownToken(raw)',
    'def Unknown(*args): return "up"\ndef mapped(raw):\n if raw == "up": return "up"\n return Unknown(raw)',
    'def mapped(raw):\n if raw == "up": return "up"\n return "up"\n raise UnknownToken(raw)',
])
def test_following_healthy_or_unproven_default_is_refused(source):
    assert fallback_nodes(ast.parse(source), {}, set())


def test_following_unknown_witness_rejects_rebinding():
    tree = ast.parse('import atlas_brain.kernel.states\ndef mapped(raw):\n if raw == "up": return "up"\n return atlas_brain.kernel.states.Unknown()')
    assert fallback_nodes(tree, {}, {'atlas_brain.kernel.states.Unknown'})


@pytest.mark.parametrize('source', [
    'def map_state(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n except ValueError:\n  return "up"',
    'def mapped(raw):\n try:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n finally:\n  return "up"',
    'import atlas_brain.kernel.states\ndef mapped(raw):\n try:\n  if raw == "up": return "up"\n  return atlas_brain.kernel.states.Unknown()\n finally:\n  return "up"',
    'def mapped(raw):\n with manager:\n  if raw == "up": return "up"\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n try:\n  try:\n   if raw == "up": return "up"\n   raise ValueError("unmapped")\n  finally: pass\n except ValueError: return "up"',
])
def test_enclosing_control_flow_cannot_turn_refusal_into_health(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'def mapped(raw):\n try: pass\n except ValueError: pass\n else:\n  if raw == "up": return "up"\n  raise UnknownToken(raw)',
    'def mapped(raw):\n with manager:\n  def local(raw):\n   if raw == "up": return "up"\n   raise UnknownToken(raw)\n return local(raw)',
    'def mapped(raw):\n try: raise ValueError("entered")\n except ValueError:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n try: raise ValueError("entered")\n except ValueError:\n  def other(): return "up"\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")',
    'def mapped(raw):\n value = states[raw]\n return value',
    'def mapped(raw):\n if raw == "up":\n  value = states[raw]\n  return value\n raise ValueError("unmapped")',
])
def test_uncaught_refusal_in_else_and_separate_function_remains_valid(source):
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'import typing\ndef mapped(raw):\n try:\n  match raw:\n   case "up": return "up"\n   case _ as missing: typing.assert_never(missing)\n except AssertionError: return "up"',
    'def mapped(raw):\n match raw:\n  case "up": return "up"\n  case "down": return "down"\n return "up"',
    'def mapped(raw):\n try:\n  match raw:\n   case "up": return "up"\n  raise ValueError("unmapped")\n except ValueError: return "up"',
    'import atlas_brain.kernel.states\ndef mapped(fact):\n match fact:\n  case atlas_brain.kernel.states.Known(): return "up"\n return "up"',
    'import typing\ndef mapped(raw):\n match raw:\n  case _ as missing if False: typing.assert_never(missing)\n return "up"',
    'import typing\ndef mapped(raw):\n match raw:\n  case "up" as missing: typing.assert_never(missing)\n return "up"',
    'import typing\ndef mapped(raw):\n match raw:\n  case str() as missing: typing.assert_never(missing)\n return "up"',
    'import typing\ndef mapped(raw):\n match raw:\n  case ("up" | "down") as missing: typing.assert_never(missing)\n return "up"',
])
def test_match_refusals_must_escape_and_literal_arms_cannot_hide_fallthrough(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('ending', ['raise UnknownToken(raw)', 'return atlas_brain.kernel.states.Unknown()'])
def test_literal_match_with_explicit_uncaught_unknown_remains_valid(ending):
    source = 'import atlas_brain.kernel.states\ndef mapped(raw):\n match raw:\n  case "up": return "up"\n ' + ending
    assert not fallback_nodes(ast.parse(source), {}, set())


def test_unhandled_exhaustive_assertion_allows_a_known_fact_branch_to_continue():
    source = 'import typing\nimport atlas_brain.kernel.states\ndef mapped(fact):\n match fact:\n  case atlas_brain.kernel.states.Known(): pass\n  case _ as missing: typing.assert_never(missing)\n return "up"'
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('pattern', ['_ as missing', 'missing', '(_ as first) as missing', '(1 | _) as missing'])
def test_only_irrefutable_terminal_assertion_patterns_are_default_proofs(pattern):
    source = 'import typing\ndef mapped(raw):\n match raw:\n  case ' + pattern + ': typing.assert_never(missing)\n return "up"'
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'states = {"up": "up"}\ndef map_state(raw: str) -> str:\n if raw in states: return states[raw]\n return "up"',
    'def mapped(entry):\n if entry in table: return table[entry]\n return "up" + ""',
    'def mapped(packet):\n value = "up"\n if packet.code in registry: value = registry[packet.code]\n return value',
    'def mapped(key):\n if key in mapping: return mapping[key]\n if valid: return "up"\n raise ValueError("unmapped")',
    'def mapped(key):\n try:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n except ValueError: return "up"',
    'def mapped(key):\n with manager:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(key):\n try:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n finally: return "up"',
])
def test_sequential_lookup_without_proven_refusal_is_refused(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('ending', ['raise ValueError("unmapped")', 'return atlas_brain.kernel.states.Unknown()'])
def test_guarded_lookup_with_uncaught_explicit_refusal_remains_valid(ending):
    source = 'import atlas_brain.kernel.states\ndef mapped(key):\n if key in mapping: return mapping[key]\n ' + ending
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'states = {"up": "up"}\ndefaults = {"healthy": "up"}\ndef map_state(raw: str) -> str:\n if raw not in states: return defaults["healthy"]\n raise ValueError("unmapped")',
    'def mapped(key):\n if key in mapping: return other[key]\n raise ValueError("unmapped")',
    'def mapped(key, other):\n if key in mapping: return mapping[other]\n raise ValueError("unmapped")',
    'def mapped(key):\n if key not in mapping: return "up"\n return mapping[key]',
    'def mapped(key):\n if key in mapping:\n  return "up"\n  return mapping[key]\n raise ValueError("unmapped")',
    'def mapped(key):\n if key in mapping: return mapping[key] or "up"\n raise ValueError("unmapped")',
])
def test_membership_refusal_requires_matching_polarity_key_map_and_direct_lookup(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('ending', ['raise ValueError("unmapped")', 'return atlas_brain.kernel.states.Unknown()'])
@pytest.mark.parametrize('key', ['key', 'packet.code', '"state"'])
def test_matching_inverted_membership_with_explicit_unknown_remains_valid(ending, key):
    source = 'import atlas_brain.kernel.states\ndef mapped(key, packet):\n if ' + key + ' not in mapping: ' + ending + '\n return mapping[' + key + ']'
    assert not fallback_nodes(ast.parse(source), {}, set())


def test_matching_literal_membership_with_explicit_unknown_remains_valid():
    source = 'def mapped(fields):\n if "state" in fields: return fields["state"]\n raise ValueError("unmapped")'
    assert not fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'states = {"up": "up"}\ndef map_state(raw):\n for _ in ():\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(key):\n while ready:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"',
    'async def mapped(key):\n async for item in rows:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(key):\n if ready:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(key):\n for item in rows: break\n else:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(key):\n while ready: break\n else:\n  if key in mapping: return mapping[key]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n try: pass\n except ValueError:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n try: raise KeyError("entered")\n except ValueError:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n except KeyError: return "up"',
    'def mapped(raw):\n try: raise ValueError("entered")\n except ValueError: pass\n else:\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")\n return "up"',
    'def mapped(raw):\n value = "up"\n for _ in ():\n  value = states[raw]\n return value',
    'def mapped(raw):\n value: str = "up"\n for _ in ():\n  value: str = states[raw]\n return value',
    'def mapped(raw):\n value = 0\n for _ in ():\n  value += states[raw]\n return value',
    'def mapped(raw):\n value = "up"\n for _ in ():\n  (value := states[raw])\n return value',
    'def mapped(raw):\n return "up"\n if raw in states: return states[raw]\n raise ValueError("unmapped")',
    'def mapped(raw):\n value = "up"\n for _ in ():\n  def ignored(value=states[raw]): pass\n return value',
    'def mapped(raw):\n value = "up"\n for _ in ():\n  @states[raw]\n  def ignored(): pass\n return value',
])
def test_optional_execution_cannot_certify_a_function_refusal(source):
    assert fallback_nodes(ast.parse(source), {}, set())


def test_entered_handler_conditional_early_return_cannot_certify_later_membership():
    source = 'def mapped(raw, ready):\n try: raise ValueError("entered")\n except ValueError:\n  if ready: return "up"\n  if raw in states: return states[raw]\n  raise ValueError("unmapped")'
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'def mapped(raw, ready):\n if ready: return "up"\n if raw == "up": return "up"\n raise ValueError("unmapped")',
    'import atlas_brain.kernel.states\ndef mapped(raw, ready):\n if ready: return "up"\n if raw not in states: return atlas_brain.kernel.states.Unknown()\n return states[raw]',
])
def test_a_prior_unrelated_return_cannot_borrow_a_later_refusal(source):
    assert fallback_nodes(ast.parse(source), {}, set())


@pytest.mark.parametrize('source', [
    'def mapped(key):\n for item in ():\n  return mapping[key]\n return "up"',
    'def mapped(key):\n while ready:\n  return mapping[key]\n return "up"',
    'async def mapped(key):\n async for item in rows:\n  return mapping[key]\n return "up"',
])
def test_a_bare_lookup_in_an_optional_body_cannot_hide_healthy_fallthrough(source):
    assert fallback_nodes(ast.parse(source), {}, set())


def test_finite_nonloop_guard_still_proves_a_returned_lookup():
    source = 'def mapped(key):\n if key == "up": return mapping[key]\n raise ValueError("unmapped")'
    assert not fallback_nodes(ast.parse(source), {}, set())


def test_outer_finite_guard_cannot_certify_a_nested_functions_optional_lookup():
    source = 'def factory(label):\n if label == "ready":\n  def mapped(key):\n   for item in ():\n    return mapping[key]\n   return "up"\n  return mapped\n raise ValueError("unmapped")'
    assert fallback_nodes(ast.parse(source), {}, set())


def test_a_nested_functions_own_guard_remains_a_valid_proof():
    source = 'def factory(label):\n if label == "ready":\n  def mapped(key):\n   if key in mapping: return mapping[key]\n   raise ValueError("unmapped")\n  return mapped\n raise ValueError("unmapped")'
    assert not fallback_nodes(ast.parse(source), {}, set())
