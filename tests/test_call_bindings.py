"""An uncertain binding cannot erase a possible carrier or prove a scalar result."""
import ast

import pytest

from tools.call_bindings import (
    CallableBindings,
    declared_classes,
    ignored_argument_classes,
)


def expression(text):
    return ast.parse(text, mode="eval").body


@pytest.mark.parametrize("source, proven", [
    ("class Record:\n def __init__(self, value): self.name = 'record'", True),
    ("class Record:\n def __new__(cls, value): return value", False),
    ("class Record:\n __new__ = unknown", False),
    ("class Record:\n match passthrough:\n  case __new__: pass", False),
    ("class Record:\n match values:\n  case [*__new__]: pass", False),
    ("class Record:\n match values:\n  case {**__new__}: pass", False),
    ("class Record:\n from provider import allocate as __new__", False),
    ("class Record:\n import allocator as __new__", False),
    ("class Record:\n try: pass\n except Error as __new__: pass", False),
    ("class Record:\n class __new__: pass", False),
    ("class Record:\n if condition: pass", False),
    ("class Record:\n locals()['__new__'] = passthrough", False),
    ("class Record:\n namespace['allocator'] = value", False),
    ("class Record:\n namespace.allocator = value", False),
    ("class Record:\n label = 'record'\n def __init__(self, value): self.name = 'record'", True),
    ("class Record(Base): pass", False),
    ("class Record(metaclass=Meta): pass", False),
    ("@decorate\nclass Record: pass", False),
    ("class Record: pass\ndef Record(value): return value", False),
    ("def Record(value): return value\nclass Record: pass", False),
    ("class Record: pass\nclass Record:\n def __new__(cls, value): return value", False)])
def test_constructor_exception_requires_ordinary_instance_semantics(source, proven):
    tree = ast.parse(source)
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.predeclare(tree)
    classes = declared_classes(tree, "atlas_brain.example")
    assert ("atlas_brain.example.Record" in classes) is proven
    assert bindings.constructor_call(expression("Record(value)"), "", classes) is proven


@pytest.mark.parametrize("source, ignored", [
    ("class Record:\n def __init__(self, path): self.name = 'record'", True),
    ("class Record:\n def __init__(self, path): self.path = path", False),
    ("class Record:\n def __init__(self, path): self.name = transform(path)", False),
    ("class Record:\n @decorate\n def __init__(self, path): self.name = 'record'", False),
    ("class Record:\n def __init__(self, path): self.name = 'record'\n __init__ = unknown", False),
    ("class Record:\n def __init__(self, path): self.name = 'record'\n def __getattr__(self, name): return unknown", False),
    ("class Record:\n path = unknown", False),
    ("class Record:\n def __init__(self, path): self.name = 'record'\nRecord.__init__ = unknown", False),
    ("class Record:\n def __init__(self, path): self.name = 'record'\nclass Record:\n def __init__(self, path): self.path = path", False)])
def test_global_argument_omission_requires_closed_nonobserving_initializer(source, ignored):
    classes = ignored_argument_classes({"atlas_brain.records": ast.parse(source)})
    assert ("atlas_brain.records.Record" in classes) is ignored


def test_conditional_rebinding_joins_carrier_and_unknown_origins():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.assign("carrier", expression("iter"), "factory.")
    bindings.assign("carrier", expression("lambda values: values"), "factory.")
    assert bindings.origins(expression("carrier"), "factory.") == {"builtins.iter", None}
    assert bindings.has_carrier(expression("carrier"), "factory.")
    assert not bindings.primitive_call(expression("carrier(values)"), "factory.")


def test_all_alternatives_must_prove_primitive_and_parameters_shadow_builtins():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.assign("predicate", expression("isinstance"), "factory.")
    bindings.assign("predicate", expression("issubclass"), "factory.")
    assert bindings.primitive_call(expression("predicate(value, kind)"), "factory.")
    bindings.assign("predicate", expression("unknown"), "factory.")
    assert not bindings.primitive_call(expression("predicate(value, kind)"), "factory.")
    bindings.argument("len", "factory.")
    assert not bindings.primitive_call(expression("len(value)"), "factory.")


def test_nested_scope_keeps_outer_origins_and_conditional_choices():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.assign("carrier", expression("iter if flag else len"), "outer.")
    assert bindings.origins(expression("carrier"), "outer.inner.") == {"builtins.iter", "builtins.len"}
    assert not bindings.primitive_call(expression("carrier(value)"), "outer.inner.")


def test_rebound_attribute_cannot_keep_a_primitive_api_proof():
    bindings = CallableBindings("atlas_brain.example", {"json": "json"}, {"json": "json"}, set())
    assert bindings.primitive_call(expression("json.dumps(value)"), "")
    bindings.assign("json.dumps", expression("unknown"), "")
    assert not bindings.primitive_call(expression("json.dumps(value)"), "")


def test_declarations_exist_before_a_forward_call_is_analyzed():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    tree = ast.parse("def factory(): return helper()\ndef helper(): return 1")
    bindings.predeclare(tree)
    assert bindings.origins(expression("helper"), "factory.") == {"atlas_brain.example.helper"}
    assert len(bindings.definitions["atlas_brain.example.helper"]) == 1


@pytest.mark.parametrize("declaration, scope", [("global carrier", "factory."),
                                               ("nonlocal carrier", "outer.factory.")])
def test_explicit_scope_assignments_keep_the_runtime_binding_alternatives(declaration, scope):
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    body = "def factory():\n " + declaration + "\n carrier = len\n"
    tree = ast.parse("carrier = iter\n" + body if scope == "factory."
                     else "def outer():\n carrier = iter\n " + body.replace("\n", "\n "))
    bindings.predeclare(tree)
    bindings.assign("carrier", expression("iter"), "" if scope == "factory." else "outer.")
    bindings.assign("carrier", expression("len"), scope)
    assert bindings.origins(expression("carrier"), scope) == {"builtins.iter", "builtins.len", None}
    assert bindings.has_carrier(expression("carrier"), scope)
    assert not bindings.primitive_call(expression("carrier(values)"), scope)


def test_explicit_outer_attribute_binding_cannot_prove_a_scalar_result():
    bindings = CallableBindings("atlas_brain.example", {"json": "json"}, {"json": "json"}, set())
    bindings.predeclare(ast.parse("def factory():\n global json\n return json.dumps(value)"))
    assert not bindings.primitive_call(expression("json.dumps(value)"), "factory.")


@pytest.mark.parametrize("module_value, class_value", [("iter", "len"), ("len", "iter")])
def test_method_bare_name_skips_class_namespace(module_value, class_value):
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.predeclare(ast.parse("class Reader:\n def factory(): pass"))
    bindings.assign("carrier", expression(module_value), "")
    bindings.assign("carrier", expression(class_value), "Reader.")
    assert bindings.origins(expression("carrier"), "Reader.factory.") == {"builtins." + module_value}
    assert bindings.primitive_call(expression("carrier(values)"), "Reader.factory.") == (module_value == "len")
    assert "Reader.carrier" not in bindings.scope_keys("carrier", "Reader.factory.")


def test_method_keeps_enclosing_function_binding_while_skipping_classes():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.predeclare(ast.parse("def outer():\n class Reader:\n  class Nested:\n   def factory(): pass"))
    bindings.assign("carrier", expression("len"), "")
    bindings.assign("carrier", expression("iter"), "outer.")
    bindings.assign("carrier", expression("len"), "outer.Reader.")
    bindings.assign("carrier", expression("len"), "outer.Reader.Nested.")
    assert bindings.origins(expression("carrier"), "outer.Reader.Nested.factory.") == {"builtins.iter"}
    assert not bindings.primitive_call(expression("carrier(values)"), "outer.Reader.Nested.factory.")


def test_class_body_expression_scope_keeps_uncertainty_for_lambdas_and_comprehensions():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.predeclare(ast.parse("class Reader:\n factory = lambda: carrier(values)"))
    bindings.assign("carrier", expression("iter"), "")
    bindings.assign("carrier", expression("len"), "Reader.")
    assert bindings.has_carrier(expression("carrier"), "Reader.")
    assert not bindings.primitive_call(expression("carrier(values)"), "Reader.")


def test_explicit_outer_mutation_stays_uncertain_for_other_readers():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.predeclare(ast.parse("class Reader:\n global carrier\n carrier = iter\n def factory(): pass"))
    bindings.assign("carrier", expression("len"), "")
    bindings.assign("carrier", expression("iter"), "Reader.")
    assert bindings.has_carrier(expression("carrier"), "Reader.factory.")
    assert not bindings.primitive_call(expression("carrier(values)"), "Reader.factory.")


def test_class_function_scope_collision_cannot_erase_function_local_carrier():
    bindings = CallableBindings("atlas_brain.example", {}, {}, set())
    bindings.predeclare(ast.parse("class Reader: pass\ndef Reader():\n def factory(): pass"))
    bindings.assign("carrier", expression("len"), "")
    bindings.assign("carrier", expression("iter"), "Reader.")
    assert bindings.has_carrier(expression("carrier"), "Reader.factory.")
    assert not bindings.primitive_call(expression("carrier(values)"), "Reader.factory.")
