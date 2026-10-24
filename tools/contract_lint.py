"""Reject computation; admit only structural calls and exact wire-validation predicates."""
import ast
import sys
from pathlib import Path

DENIED = {"sum", "min", "max", "len", "abs", "round", "pow", "divmod",
          "math", "operator", "statistics", "functools", "Counter", "count",
          "eval", "exec", "__import__", "getattr", "setattr", "delattr", "hasattr",
          "vars", "dir", "globals", "locals", "inspect", "importlib"}
SPELLING = {"mult": "mul", "matmult": "matmul", "div": "truediv"}
ARITHMETIC_METHODS = {f"__{prefix}{SPELLING.get(name, name)}__"
    for operation in ast.operator.__subclasses__()
    for name in (operation.__name__.lower().removeprefix("bit"),)
    for prefix in ("", "r", "i")}
ARITHMETIC_METHODS.update(f"__{name}__" for name in ("neg", "pos", "invert", "abs", "round"))
ARITHMETIC_METHODS.update(f"__{prefix}divmod__" for prefix in ("", "r", "i"))
DENIED.update(ARITHMETIC_METHODS)
# A closed structural capability policy, rather than an incomplete list of numeric helpers.
MODULE_CALLS = {"json": {"dumps"}, "re": {"compile"}, "hashlib": {"sha256"},
                "typing": {"cast", "final"}, "dataclasses": {"dataclass", "asdict"}}
OPTIONS = {"json.dumps": {"ensure_ascii", "separators"}, "dataclasses.dataclass": {"frozen", "slots", "kw_only"},
           "builtins.sorted": {"key", "reverse"}, "builtins.str": {"encoding", "errors"},
           "method.encode": {"encoding", "errors"}, "method.fullmatch": {"pos", "endpos"}}
DECLARATIVE = {"collections.abc", "__future__"}
BUILTIN_CALLS = {"type", "isinstance", "str", "range", "map", "sorted", "all", "tuple", "list", "dict"}
EXCEPTIONS = {"ValueError", "TypeError"}
TYPE_NAMES = {"str", "int", "bool", "bytes", "list", "tuple", "dict", "object", "type"}
METHOD_CALLS = {"encode", "join", "fullmatch", "hexdigest", "items", "keys", "values"}
STRUCTURAL = {ast.dump(ast.parse(text, mode="eval").body) for text in (
    "type(value) not in (type(None), bool, int, str, list, tuple, dict)",
    "value not in range(-9007199254740991, 9007199254740992)",
    '"result.json" not in files',
)}
VALIDATORS = {"all": ast.dump(ast.parse("all(isinstance(key, str) for key in entries)", mode="eval").body),
              "range": ast.dump(ast.parse("range(-9007199254740991, 9007199254740992)", mode="eval").body)}


def own_module(name):
    return name == "atlas_brain.contract" or name.startswith("atlas_brain.contract.")


def own_exports(module):
    if not own_module(module):
        return set()
    stem = Path(*module.split("."))
    source = next((p for p in (stem.with_suffix(".py"), stem / "__init__.py") if p.is_file()), None)
    if source is None:
        return set()
    tree = ast.parse(source.read_text(encoding="utf-8"))
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


def admitted_module(name):
    return name in MODULE_CALLS or name in DECLARATIVE or own_module(name) or name.startswith(("atlas_brain.kernel.", "atlas_brain.model."))


def violations(source: str) -> list[int]:
    tree = ast.parse(source)
    annotations, aliases, bindings, trusted = set(), {}, {}, set()
    local = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for node in ast.walk(tree):
        if isinstance(node, (ast.AnnAssign, ast.arg)) and node.annotation:
            annotations.update(ast.walk(node.annotation))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns:
            annotations.update(ast.walk(node.returns))
        if isinstance(node, ast.TypeAlias):
            annotations.update(ast.walk(node.value))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for entry in node.names:
                alias = entry.asname or entry.name.split(".")[0]
                bindings[alias] = bindings.get(alias, 0) + 1
                module = node.module or "" if isinstance(node, ast.ImportFrom) else ""
                aliases[alias] = f"{module}.{entry.name}" if module else entry.name if entry.asname else alias
                if module and entry.name in (own_exports(module) if own_module(module) else MODULE_CALLS.get(module, set())):
                    trusted.add(alias)
    members = {}
    for record in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        for member in record.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                members[member] = member.name
            for target in ([member.target] if isinstance(member, ast.AnnAssign) else member.targets if isinstance(member, ast.Assign) else []):
                members.update((n, n.id) for n in ast.walk(target) if isinstance(n, ast.Name))
    safe_names = BUILTIN_CALLS | trusted | local
    protected = safe_names | set(aliases) | EXCEPTIONS | TYPE_NAMES
    raises = {n.exc for n in ast.walk(tree) if isinstance(n, ast.Raise)}

    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, "")
        if isinstance(node, ast.Attribute):
            parent = qualified(node.value)
            return f"{parent}.{node.attr}" if parent else ""
        return ""

    def admitted_call(target):
        if isinstance(target, ast.Name):
            return target.id in safe_names
        if isinstance(target, ast.Attribute) and not target.attr.startswith("_"):
            module = qualified(target.value)
            return target.attr in (own_exports(module) if own_module(module) else MODULE_CALLS.get(module, set())) if module else target.attr in METHOD_CALLS
        return False

    def admitted_options(call):
        target = call.func  # This runs only after callee admission.
        if isinstance(target, ast.Name):
            identity = aliases.get(target.id, f"builtins.{target.id}" if target.id in BUILTIN_CALLS else "local")
        else:
            owner = qualified(target.value)
            identity = f"{owner}.{target.attr}" if owner else f"method.{target.attr}"
        if identity in {"local", "builtins.dict"} or own_module(identity):
            return True
        return all(k.arg in OPTIONS.get(identity, set()) for k in call.keywords)

    def literal_exception(call):
        return (call in raises and isinstance(call.func, ast.Name) and call.func.id in EXCEPTIONS
                and len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
                and type(call.args[0].value) is str and not call.keywords)

    def admitted_callback(callback):
        if isinstance(callback, ast.Lambda):
            return True  # Its body and bindings are inspected by the same walk.
        return admitted_call(callback) and not (isinstance(callback, ast.Name) and callback.id in {*VALIDATORS, "map", "sorted"})

    def structural_type(node):
        if isinstance(node, ast.Name):
            return node.id in TYPE_NAMES
        if isinstance(node, ast.Constant):
            return node.value is None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return structural_type(node.left) and structural_type(node.right)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in {"list", "tuple", "dict"}:
            parts = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
            return all(structural_type(part) or (node.value.id == "tuple" and isinstance(part, ast.Constant) and part.value is Ellipsis) for part in parts)
        return False  # Unknown names and literal operands cannot prove a type union.

    bad = []
    for node in ast.walk(tree):
        if node in annotations and isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr) and structural_type(node):
            continue
        arithmetic = isinstance(node, (ast.BinOp, ast.AugAssign))
        unary = isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert))
        literal = unary and isinstance(node.op, (ast.USub, ast.UAdd)) and isinstance(node.operand, ast.Constant) and type(node.operand.value) is int
        compare = isinstance(node, ast.Compare) and ast.dump(node) not in STRUCTURAL
        name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
        imported = isinstance(node, ast.Import) and any(not admitted_module(a.name) for a in node.names)
        imported_from = isinstance(node, ast.ImportFrom) and (node.level or not admitted_module(node.module or "") or any(a.name == "*" for a in node.names))
        private_or_write = isinstance(node, ast.Attribute) and (node.attr.startswith("_") or isinstance(node.ctx, (ast.Store, ast.Del)))
        call = isinstance(node, ast.Call) and not literal_exception(node) and (not admitted_call(node.func) or not admitted_options(node) or (isinstance(node.func, ast.Name) and node.func.id in VALIDATORS and ast.dump(node) != VALIDATORS[node.func.id]))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "type":
                call = call or len(node.args) != 1 or bool(node.keywords)
            if node.func.id == "map":
                call = call or not node.args or not admitted_callback(node.args[0])
            if node.func.id == "sorted":
                call = call or any(k.arg is None or (k.arg == "key" and not (isinstance(k.value, ast.Constant) and k.value.value is None) and not admitted_callback(k.value)) for k in node.keywords)
        shadow = (isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in protected) or (isinstance(node, ast.arg) and node.arg in protected)
        if isinstance(node, ast.alias):
            alias = node.asname or node.name.split(".")[0]
            shadow = bindings[alias] > 1 or alias in BUILTIN_CALLS | EXCEPTIONS | TYPE_NAMES or alias in local
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadow = node.name in BUILTIN_CALLS | EXCEPTIONS | TYPE_NAMES or node.name in aliases
            call = any(not admitted_call(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list)
        if isinstance(node, ast.ExceptHandler):
            shadow = node.name in protected
        if isinstance(node, (ast.MatchAs, ast.MatchStar)):
            shadow = node.name in EXCEPTIONS | TYPE_NAMES
        if isinstance(node, ast.MatchMapping):
            shadow = node.rest in EXCEPTIONS | TYPE_NAMES
        protocol_binding = node in members and (members[node].startswith("__") or members[node] in METHOD_CALLS)
        class_hook = isinstance(node, ast.ClassDef) and (bool(node.keywords) or any(not isinstance(base, ast.Name) or base.id != "object" for base in node.bases))
        if arithmetic or (unary and not literal) or compare or name in DENIED or imported or imported_from or private_or_write or call or shadow or class_hook or protocol_binding:
            bad.append(node.lineno)
    return sorted(set(bad))


if __name__ == "__main__":
    paths = list(map(Path, sys.argv[1:])) or list(Path("atlas_brain/contract").rglob("*.py"))
    if not paths:
        print("contract sources missing")
        raise SystemExit(2)
    failures = [(p, line) for p in paths for line in violations(p.read_text(encoding="utf-8"))]
    for path, line in failures:
        print(f"{path.as_posix()}:{line}: contract computation refused")
    raise SystemExit(int(bool(failures)))
