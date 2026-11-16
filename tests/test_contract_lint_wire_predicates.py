"""Exact wire-module admission; all other computation and trusted-binding plants stay refused."""
import ast
from textwrap import indent

import pytest

from tools.contract_lint import violations

# Reviewed candidate blob 640c5ccbce24e4e962960313f1acefe36b51e836; source text is never executed.
REVIEWED = r'''"""RFC 8785 bytes for the contract's integer-only I-JSON subset."""
import json
import re
from typing import cast

SAFE = re.compile(r"[\x20-\x21\x23-\x5b\x5d-\x7e]*")


def canonical(value: object) -> bytes:
    return _encode(value).encode("utf-8")


def _encode(value: object) -> str:
    kind = type(value)
    if kind is str:
        if SAFE.fullmatch(cast(str, value)):
            return f'"{value}"'
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if value is None or kind is bool:
        return json.dumps(value)
    if kind is int:
        if not -9007199254740991 <= cast(int, value) <= 9007199254740991:
            raise ValueError("integer_out_of_range")
        return str(value)
    if kind is list or kind is tuple:
        items = cast("list[object] | tuple[object, ...]", value)
        return f"[{','.join(map(_encode, items))}]"
    if kind is not dict:
        raise TypeError("non_json_type")
    entries = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in entries):
        raise TypeError("non_string_key")
    obj = cast(dict[str, object], value)
    keys = sorted(obj, key=lambda key: key.encode("utf-16be"))
    members = (f"{_encode(key)}:{_encode(obj[key])}" for key in keys)
    return f"{{{','.join(members)}}}"
'''


def test_exact_reviewed_codec_and_formatting_only_variations_pass():
    assert not violations(REVIEWED)
    formatted = "# comments and locations are not authority\n\n" + ast.unparse(ast.parse(REVIEWED)) + "\n"
    assert not violations(formatted)
    parentheses = REVIEWED.replace("kind = type(value)", "kind = (type(value))  # whitespace only")
    assert not violations(parentheses)


@pytest.mark.parametrize("before,after", [
    ("kind = type(value)", "kind = value"),
    ("import json", "import json as json"),
    ("import re", "import re as matcher"),
    ("from typing import cast", "from typing import cast as convert"),
    ('SAFE = re.compile(r"[\\x20-\\x21\\x23-\\x5b\\x5d-\\x7e]*")', 'SAFE = re.compile(".*")'),
    ("return _encode(value).encode(\"utf-8\")", "return _encode(value).encode(\"ascii\")"),
    ("kind = type(value)", "kind = type(value)\n    kind = str"),
    ("kind = type(value)", "kind = type(value)\n    value = None"),
    ("kind = type(value)", "global kind\n    kind = type(value)"),
    ("kind = type(value)", "kind = type(value)\n    del kind"),
    ("kind is str", "kind == str"),
    ("kind is str", "kind is bytes"),
    ("value is None or kind is bool", "kind is bool or value is None"),
    ("kind is list or kind is tuple", "kind is tuple or kind is list"),
    ("kind is not dict", "kind is dict"),
    ("-9007199254740991 <= cast", "-9007199254740990 <= cast"),
    ("<= 9007199254740991:", "<= 9007199254740992:"),
    ("<= cast(int, value)", "< cast(int, value)"),
    ("cast(int, value)", "cast(str, value)"),
    ("cast(str, value)", "cast(bytes, value)"),
    ('raise ValueError("integer_out_of_range")', 'raise ValueError("changed")'),
    ('raise TypeError("non_json_type")', 'raise TypeError("changed")'),
    ("return str(value)", "return value"),
    ("ensure_ascii=False", "ensure_ascii=True"),
    ("def _encode(value: object)", "def _encode(value: str)"),
    ("def _encode(value: object) -> str:", "def _encode(value: object) -> object:"),
    ("def _encode(value: object)", "def other(value: object)"),
    ("def _encode(value: object)", "async def _encode(value: object)"),
    ("kind = type(value)", "kind = type(value)\n    result = left + right"),
    ("kind = type(value)", "kind = type(value)\n    result = kind is str"),
    ("kind = type(value)", "kind = type(value)\n    result = getattr(value, 'compute')()"),
    ("kind = type(value)", "kind = type(value)\n    str = callback"),
    ("kind = type(value)", "kind = type(value)\n    cast = callback"),
    ("kind = type(value)", "kind = type(value)\n    import math"),
])
def test_any_semantic_codec_edit_loses_the_narrow_admission(before, after):
    assert REVIEWED.count(before) == 1
    changed = REVIEWED.replace(before, after, 1)
    assert changed != REVIEWED and violations(changed)


@pytest.mark.parametrize("plant", [
    "result = kind is str",
    "'extra module expression'",
    "pass",
    "result = value is None",
    "result = -9007199254740991 <= cast(int, value) <= 9007199254740991",
    "result = a is b",
    "result = a == b",
    "result = a < b",
    "result = left + right",
    "result = sum(rows)",
    "result = getattr(value, 'compute')()",
    "str = callback",
    "cast = callback",
    "import math",
])
def test_matching_codec_does_not_admit_unrelated_compares_or_unsafe_descendants(plant):
    suffix = REVIEWED + "\n" + plant + "\n"
    assert violations(suffix)


def test_same_compare_ast_in_another_function_is_not_the_approved_node():
    body = REVIEWED[REVIEWED.index("def _encode("):]
    clone = body.replace("def _encode(", "def unapproved(", 1)
    source = REVIEWED + "\n" + clone
    compares = {node.lineno for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Compare)}
    assert compares and compares <= set(violations(source))


@pytest.mark.parametrize("wrapper", ["def outer():", "class Outer:", "if True:", "try:"])
def test_exact_function_body_in_an_unapproved_scope_is_refused(wrapper):
    body = REVIEWED[REVIEWED.index("def _encode("):]
    imports = "import json\nimport re\nfrom typing import cast\n"
    source = imports + wrapper + "\n" + indent(body, "    ")
    if wrapper == "try:":
        source += "except Exception:\n    pass\n"
    compares = {node.lineno for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Compare)}
    assert compares and compares <= set(violations(source))


@pytest.mark.parametrize("binding", ["cast", "json", "_encode"])
@pytest.mark.parametrize("pattern", ["case {name}:", "case [*{name}]:", "case {{**{name}}}:"])
def test_pattern_captures_cannot_replace_trusted_wire_bindings(binding, pattern):
    capture = "    " + pattern.format(name=binding)
    source = "import json\nfrom typing import cast\ndef _encode(value):\n    return value\nmatch external:\n" + capture + "\n        pass\n"
    assert violations(source) == [source.splitlines().index(capture) + 1]


def test_current_original_structural_wire_predicates_stay_admitted():
    source = """def original(value):
    if type(value) not in (type(None), bool, int, str, list, tuple, dict):
        raise TypeError("non_json_type")
    if value not in range(-9007199254740991, 9007199254740992):
        raise ValueError("integer_out_of_range")
"""
    assert not violations(source)
