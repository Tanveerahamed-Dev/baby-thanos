"""Preserved contract computation plants and reflected-access refusals."""
import pytest

from tools.contract_lint import violations


@pytest.mark.parametrize("plant", ["x = a + b", "x += 1", "x = a * b",
    "x = -a", "x = a < b", "x = a == b", "x = sum(rows)",
    "x = min(rows)", "x = statistics.mean(rows)", "from operator import add",
    "import math", "f = sum", "from builtins import sum as fold",
    "x: a + b", "x: tuple[sum(rows)]", "type X = a + b", "x = ~a",
    "x = value.__add__(other)", "x = eval(source)", "x = ~1",
    "x = a in b", "x = a is b", "x = a not in b"])
def test_contract_lint_fires_on_each_planted_computation(plant):
    assert violations(plant)


def test_contract_tree_and_declarative_types_pass_lint():
    from pathlib import Path
    paths = list(Path("atlas_brain/contract").rglob("*.py"))
    assert paths
    for path in paths:
        assert not violations(path.read_text(encoding="utf-8")), path
    assert not violations("x: str | int\nLIMIT = -9007199254740991")


def test_planted_arithmetic_fails_real_lint_entrypoint(tmp_path):
    import subprocess
    import sys
    plant = tmp_path / "projection.py"
    plant.write_text("result = left + right", encoding="utf-8")
    result = subprocess.run([sys.executable, "tools/contract_lint.py", str(plant)],
        capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "computation refused" in result.stdout


@pytest.mark.parametrize("operation", ["add", "sub", "mul", "matmul", "truediv",
    "floordiv", "mod", "pow", "lshift", "rshift", "and", "or", "xor", "divmod"])
@pytest.mark.parametrize("prefix", ["", "r", "i"])
def test_arithmetic_protocol_family_is_refused(operation, prefix):
    assert violations(f"result = left.__{prefix}{operation}__(right)")
    assert violations(f"operation = left.__{prefix}{operation}__")


@pytest.mark.parametrize("operation", ["neg", "pos", "invert", "abs", "round", "divmod"])
def test_unary_and_numeric_protocol_calls_are_refused(operation):
    assert violations(f"result = value.__{operation}__()")


def test_workflow_concurrency_separates_main_pr_and_merge_group_heads():
    import re
    from pathlib import Path
    source = Path(".github/workflows/contract.yml").read_text(encoding="utf-8")
    group = re.search(r"^  group: (.+)$", source, re.MULTILINE).group(1)

    def distinct_heads(template):
        keys = {template.replace("${{ github.event_name }}", event).replace("${{ github.sha }}", sha)
            for event in ("push", "pull_request", "merge_group") for sha in ("head-a", "head-b")}
        return len(keys) == 6

    assert distinct_heads(group)
    assert not distinct_heads("ct-${{ github.workflow }}")  # Planted shared main key.
    assert not distinct_heads("ct-${{ github.sha }}")  # Planted cross-event collision.
    assert "  cancel-in-progress: false" in source
    assert "  pull_request:" in source and "  merge_group:" in source
    assert "  push:\n    branches: [main]" in source


@pytest.mark.parametrize("plant", [
    'left.__getattribute__("__add__")(right)',
    'object.__getattribute__(left, "__radd__")(right)',
    'type(left).__dict__["__add__"](left, right)',
    'vars(type(left))["__add__"](left, right)',
    'getattr(left, "__add__")(right)',
    'globals()["operation"](left, right)',
    'callbacks[0](left, right)',
    'factory()(left, right)',
    'from builtins import vars as reflect',
    'import inspect',
    'value._internal_operation(right)',
    'import _operator as ops\nresult = ops.add(left, right)',
    'from atlas_brain.kernel.states import callback\nresult = callback(left, right)',
    'result = value.bit_count()',
    'def project(str):\n    return str(left, right)',
    'str = callback\nresult = str(left, right)',
    'import json\njson.dumps = callback\nresult = json.dumps(value)',
    'from hashlib import sha256 as safe\nfrom atlas_brain.kernel.states import callback as safe\nresult = safe(left, right)',
    'from json import *\nresult = dumps(value)',
    'from atlas_brain.kernel.states import Known\nclass Row(Known):\n    pass',
    'class Row(metaclass=external):\n    pass',
    'from atlas_brain.kernel.states import callback\n@callback\nclass Row:\n    pass',
    'from hashlib import sha256 as safe\ntry:\n    pass\nexcept Exception as safe:\n    pass',
    'from hashlib import sha256 as safe\ndef safe():\n    pass',
    'from atlas_brain.kernel.states import callback\nresult = list(map(callback, values))',
    'from atlas_brain.kernel.states import callback\nresult = sorted(values, key=callback)',
    'result = sorted(values, **options)',
    'result = map(*options)',
    'result = list(map(map, operations, values))',
    'result = list(map(range, values))',
    'import json\nfrom atlas_brain.kernel.states import compute\nresult = json.dumps(value, default=compute)',
    'from json import dumps as write\nfrom atlas_brain.kernel.states import compute\nresult = write(value, default=compute)',
    'import dataclasses\nfrom atlas_brain.kernel.states import compute\nresult = dataclasses.asdict(value, dict_factory=compute)',
    'from dataclasses import asdict as project\nfrom atlas_brain.kernel.states import compute\nresult = project(value, dict_factory=compute)',
    'import json\nresult = json.dumps(value, **options)',
    'from dataclasses import asdict\nresult = asdict(value, **options)',
    'import json\nresult = json.dumps(value, cls=Encoder)',
    'from atlas_brain.kernel.states import compute\nresult = type("Carrier", (), {"encode": compute}).encode(value)',
    'from typing import Callable\nfrom dataclasses import dataclass\n@dataclass\nclass Carrier:\n    encode: Callable[[object], str]\ndef project(compute: Callable[[object], str], value: object) -> str:\n    return Carrier(compute).encode(value)',
    'from atlas_brain.kernel.states import compute\nclass Carrier:\n    __iter__ = compute\nresult = list(Carrier())',
    'ValueError = compute\nraise ValueError("bad")',
    'from atlas_brain.kernel.states import compute as ValueError\nraise ValueError("bad")',
    'def ValueError(message):\n    return compute(message)\nraise ValueError("bad")',
    'def project(TypeError):\n    raise TypeError("bad")',
    'match value:\n    case ValueError:\n        raise ValueError("bad")',
    'match value:\n    case [*TypeError]:\n        raise TypeError("bad")',
    'match value:\n    case {**ValueError}:\n        raise ValueError("bad")',
    'result = ValueError("bad")',
    'raise TypeError(value)',
    'raise ValueError(*options)',
    'raise ValueError(message="bad")',
    'result = list(map(ValueError, values))',
    'x: 1 | 2',
    'type X = 1 | 2',
    'def project(value: 1 | 2) -> str:\n    return "value"',
    'def project() -> 1 | 2:\n    return "value"',
    'x: str | (1 | 2)',
    'x: list[1] | tuple[2]',
    'x: left | right',
    'int = 1\nx: int | str',
    'match value:\n    case int:\n        x: int | str',
    'from atlas_brain.kernel.states import compute as int\nx: int | str',
])
def test_reflected_arithmetic_fails_real_lint_entrypoint(tmp_path, plant):
    import subprocess
    import sys
    path = tmp_path / "projection.py"
    path.write_text(plant, encoding="utf-8")
    result = subprocess.run([sys.executable, "tools/contract_lint.py", str(path)],
        capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "computation refused" in result.stdout


def test_structural_source_passes_real_lint_entrypoint(tmp_path):
    import subprocess
    import sys
    path = tmp_path / "projection.py"
    path.write_text('result = "".join(map(str, values))', encoding="utf-8")
    assert subprocess.run([sys.executable, "tools/contract_lint.py", str(path)],
        capture_output=True, check=False).returncode == 0


def test_missing_contract_tree_fails_closed(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    script = Path("tools/contract_lint.py").resolve()
    result = subprocess.run([sys.executable, str(script)], cwd=tmp_path,
        capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "contract sources missing" in result.stdout


@pytest.mark.parametrize("source", [
    'x: str | int',
    'type X = str | int | None',
    'x: list[str | int] | tuple[bytes, ...] | None',
    'def project(value: dict[str, int] | None) -> str | None:\n    return None',
    'raise ValueError("invalid_value")',
    'raise TypeError("invalid_type")',
    'import json\nresult = json.dumps(value, ensure_ascii=False, separators=(",", ":"))',
    'from dataclasses import dataclass\n@dataclass(frozen=True, slots=True, kw_only=True)\nclass Row:\n    value: str',
    'result = sorted(values, key=lambda item: item.encode("utf-16be"))',
    'result = sorted(values, key=None)',
    'import json as encoder\nresult = encoder.dumps(value)',
    'from hashlib import sha256 as digest\nresult = digest(value).hexdigest()',
    'import re\nNAME = re.compile("name")\nresult = NAME.fullmatch(value)',
    'from typing import cast\nresult = cast("str", value).encode("utf-8")',
    'def encode(value):\n    return str(value)\nresult = list(map(encode, values))',
    'from dataclasses import asdict, dataclass\n@dataclass(frozen=True, slots=True)\nclass Row:\n    value: str\nresult = asdict(Row("evidence"))',
])
def test_structural_capabilities_pass_real_lint_entrypoint(tmp_path, source):
    import subprocess
    import sys
    path = tmp_path / "projection.py"
    path.write_text(source, encoding="utf-8")
    assert subprocess.run([sys.executable, "tools/contract_lint.py", str(path)],
        capture_output=True, check=False).returncode == 0


def test_only_declared_contract_exports_are_callable(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    script = Path("tools/contract_lint.py").resolve()
    helper = tmp_path / "atlas_brain/contract/helpers.py"
    helper.parent.mkdir(parents=True)
    caller = tmp_path / "projection.py"
    callers = [
        "from atlas_brain.contract.helpers import apply\nresult = list(apply(callback, values))",
        "import atlas_brain.contract.helpers as operations\nresult = list(operations.apply(callback, values))",
    ]
    for body, expected in [
        ("apply = map\n", 1),
        ("def apply(callback, values):\n    return map(str, values)\n", 0),
    ]:
        helper.write_text(body, encoding="utf-8")
        for source in callers:
            caller.write_text(source, encoding="utf-8")
            result = subprocess.run([sys.executable, str(script), str(caller)],
                cwd=tmp_path, capture_output=True, text=True, check=False)
            assert result.returncode == expected
