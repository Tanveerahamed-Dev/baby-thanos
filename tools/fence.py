"""Tracked paths, standard-library runtime dependencies, and denied engine imports."""
import ast
import importlib
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from functools import cache
from pathlib import Path, PurePosixPath

# Load the trusted tool sibling even for the isolated (-I) diagnostic CLI.
_binding_spec = importlib.util.spec_from_file_location("_fence_call_bindings", Path(__file__).with_name("call_bindings.py"))
_binding_module = importlib.util.module_from_spec(_binding_spec)
_binding_spec.loader.exec_module(_binding_module)
CallableBindings = _binding_module.CallableBindings
CALLABLE_VALUE = "$callable:"
CARRIER_RETURN = "$carrier:"
RESULT_VALUE = "$result:"

ROOTS = {"README.md", "LICENSE", ".gitattributes", ".gitignore",
         "pyproject.toml", "uv.lock", ".python-version"}
TREES = ("atlas_brain/", "tests/", "fixtures/", "docs/adr/", "docs/contract/",
         "tools/", "governance/", ".github/")
DENIED = {"plans", "prompts", "agents.md", "claude.md", ".claude", ".codex",
          ".agents", ".mcp.json", ".specify", "specs"}
PROCESS = re.compile(r"(?:^|[-_.])(boards?|agent[-_]?notes?)(?:$|[-_.])", re.ASCII)
# S3 3.3.1: dynamic importing requires an approved exact pack-loader path; none exists yet.
BANNED = ("tkinter", "curses", "webbrowser", "http.server", "wsgiref", "socketserver", "importlib", "builtins")
GOVERNANCE = {"governance/generators.json", "governance/review.schema.json", "governance/review-policy.json"}
DYNAMIC = {"exec", "eval", "compile", "__import__", "__builtins__", "globals", "locals", "vars",
           "getattr", "setattr", "delattr", "hasattr", "dir",
           "help", "breakpoint", "__loader__", "__spec__",
           "builtins.exec", "builtins.eval", "builtins.compile", "builtins.__import__", "sys.modules", "sys._getframe"}
CODE_ATTRIBUTES = {"__globals__", "__builtins__", "__code__", "__closure__", "__dict__", "__subclasses__",
                   "f_builtins", "f_globals", "f_locals", "gi_frame", "cr_frame", "ag_frame", "tb_frame"}
# ADR-0002: changes require an amendment, REV verdict and supervisor approval.
STDLIB_API = {
    "collections.abc.Mapping", "dataclasses.asdict", "dataclasses.dataclass", "enum.StrEnum",
    "hashlib.sha256", "json.dumps", "json.loads", "math.isfinite", "stat.S_ISDIR", "stat.S_ISREG",
    "pathlib.Path", "pathlib.PurePosixPath", "re.ASCII", "re.Pattern", "re.compile", "re.error",
    "re.fullmatch", "re.search", "typing.Literal", "typing.NewType", "typing.final", "typing.cast",
}
# ADR-0003 amends ADR-0002: exact AST endpoints at their actual using paths.
SCOPED_API = {
    "atlas_brain/kernel/token_lints.py": {
        "ast.In", "ast.NotIn",
        "ast.Eq", "ast.Raise", "ast.iter_fields",
        "ast.AnnAssign", "ast.Assign", "ast.Compare", "ast.Constant", "ast.Expr", "ast.MatchAs",
        "ast.MatchMapping", "ast.MatchStar", "ast.Return", "ast.stmt", "ast.Subscript",
        "ast.AST", "ast.Attribute", "ast.Call", "ast.If", "ast.IfExp", "ast.Match", "ast.MatchClass",
        "ast.MatchOr", "ast.MatchSingleton", "ast.MatchValue", "ast.Name", "ast.pattern", "ast.walk",
    },
    "atlas_brain/kernel/lints.py": {
        "ast.AnnAssign", "ast.arg", "ast.Assign", "ast.AST", "ast.AsyncFor", "ast.AsyncFunctionDef",
        "ast.Attribute", "ast.BinOp", "ast.BitOr", "ast.Call", "ast.ClassDef", "ast.comprehension",
        "ast.Constant", "ast.ExceptHandler", "ast.expr", "ast.For", "ast.FunctionDef", "ast.Import",
        "ast.ImportFrom", "ast.iter_child_nodes", "ast.Lambda", "ast.Load", "ast.Module", "ast.Name",
        "ast.NamedExpr", "ast.parse", "ast.Set", "ast.SetComp", "ast.Starred", "ast.stmt", "ast.Store", "ast.Subscript", "ast.walk",
    },
    "atlas_brain/evidence/parsekit/token_lint.py": {
        "ast.AnnAssign", "ast.arg", "ast.Assign", "ast.AST", "ast.AsyncFunctionDef", "ast.Attribute",
        "ast.Call", "ast.ClassDef", "ast.Compare", "ast.Constant", "ast.Dict", "ast.dump", "ast.ExceptHandler", "ast.expr",
        "ast.FunctionDef", "ast.If", "ast.IfExp", "ast.In", "ast.iter_child_nodes", "ast.Lambda", "ast.List",
        "ast.Match", "ast.MatchAs", "ast.Name", "ast.NotIn", "ast.parse", "ast.Raise", "ast.Return",
        "ast.Slice", "ast.Starred", "ast.stmt", "ast.Subscript", "ast.Tuple", "ast.walk",
    },
    "atlas_brain/evidence/parsekit/token_audit.py": {
        "ast.AST", "ast.AsyncFunctionDef", "ast.ClassDef", "ast.FunctionDef", "ast.get_source_segment",
        "ast.Lambda", "ast.Module", "ast.NodeVisitor", "ast.parse", "ast.walk",
    },
}


RUNTIME_API = {"atlas_brain/evidence/admission.py": {
    "pathlib.PurePosixPath.is_absolute", "pathlib.PurePosixPath.parts",
}}
RUNTIME_API["atlas_brain/evidence/archives.py"] = {
    "zipfile.ZipFile", "zipfile.BadZipFile", "zipfile.ZIP_STORED", "zipfile.ZIP_DEFLATED",
    "zlib.error", "zlib.decompressobj", "stat.S_IFMT", "zipfile.ZipFile.infolist",
    "zipfile.ZipFile.open", "pathlib.Path.suffix",
}
RUNTIME_API["atlas_brain/kernel/population.py"] = {"dataclasses.InitVar"}


def repository_path(path):
    parsed = PurePosixPath(path)
    return (not parsed.is_absolute() and ".." not in parsed.parts and "\\" not in path
            and not re.match(r"^[A-Za-z]:", path) and path == parsed.as_posix())


def allowed(path: str) -> bool:
    if not repository_path(path):
        return False
    parts = PurePosixPath(path).parts
    if any(p.lower() in DENIED or PROCESS.search(p.lower()) for p in parts):
        return False
    if path.startswith("governance/"):
        return path in GOVERNANCE
    return path in ROOTS or path.startswith(TREES)


def dependencies_allowed(config: dict) -> bool:
    project = config.get("project", {})
    extras = project.get("optional-dependencies", {})
    return project.get("dependencies") == [] and isinstance(extras, dict) and all(v == [] for v in extras.values())


def gate_data_allowed(path: str, data) -> bool:
    if not isinstance(data, dict):
        return False
    if path == "governance/generators.json":
        return bool(data) and all(
            isinstance(spec, dict) and set(spec) == {"command", "tool", "inputs"}
            and all(isinstance(spec[k], str) and spec[k] for k in ("command", "tool"))
            and isinstance(spec["inputs"], list) and spec["inputs"]
            and all(isinstance(item, str) and item for item in spec["inputs"])
            for spec in data.values()
        )
    if path == "governance/review.schema.json":
        return (data.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
                and data.get("type") == "object" and isinstance(data.get("properties"), dict)
                and isinstance(data.get("required"), list))
    if path == "governance/review-policy.json":
        return (set(data) == {"decision", "same_family_pairs", "unsigned_bootstrap"}
                and isinstance(data["decision"], str) and bool(data["decision"])
                and type(data["unsigned_bootstrap"]) is bool and isinstance(data["same_family_pairs"], list)
                and all(isinstance(pair, list) and len(pair) == 2 and all(isinstance(x, str) and x for x in pair)
                        for pair in data["same_family_pairs"]))
    return False


def origin_member(root, suffix):
    if root is None or root.startswith(CARRIER_RETURN):
        return root
    if root.startswith(RESULT_VALUE):
        endpoint = root[len(RESULT_VALUE):]
        apis = STDLIB_API | set().union(*SCOPED_API.values(), *RUNTIME_API.values())
        return endpoint + suffix if endpoint in constructor_members(frozenset(apis)) else root
    apis = STDLIB_API | set().union(*SCOPED_API.values(), *RUNTIME_API.values())
    endpoints = api_values(frozenset(apis))
    if suffix and root in endpoints and not callable(endpoints[root]):
        return RESULT_VALUE + root
    return root + suffix


def import_bindings(tree, path, ignored_arg_roots=None):
    aliases, exports, declarations = {}, {}, set()
    containers, callable_values = {}, {}
    calls = CallableBindings(path.removesuffix(".py").replace("/", ".").removesuffix(".__init__"), aliases, exports, declarations)
    calls.predeclare(tree)
    if ignored_arg_roots is None:
        module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        ignored_arg_roots = _binding_module.ignored_argument_classes({module: tree})
    def dotted(node):
        if isinstance(node, ast.Name):
            return node.id
        base = dotted(node.value) if isinstance(node, ast.Attribute) else ""
        return base + "." + node.attr if base else ""
    def reference(node, scope):
        name = dotted(node)
        if name:
            if scope + name in exports:
                return True, exports[scope + name]
            if scope + name in declarations:
                return False, None
            if name in exports:
                return True, exports[name]
            if isinstance(node, ast.Name):
                return (True, aliases[node.id]) if node.id in aliases else (False, None)
        if isinstance(node, ast.Attribute):
            known, base = reference(node.value, scope)
            def member(root):
                # A carrier describes possible contents, not an API namespace to extend.
                return origin_member(root, "." + node.attr)
            return known, (member(base) if isinstance(base, str) else
                           tuple(member(root) for root in base) if isinstance(base, tuple) else None)
        if isinstance(node, ast.Call):
            roots = returned(node, scope)
            return bool(roots), tuple(sorted(roots, key=lambda item: item or ""))
        if isinstance(node, ast.NamedExpr):
            return reference(node.value, scope)
        if isinstance(node, ast.IfExp):
            left, a = reference(node.body, scope)
            right, b = reference(node.orelse, scope)
            return left or right, a if left and right and a == b else None
        if isinstance(node, ast.BoolOp):
            values = [reference(value, scope) for value in node.values]
            origins = [origin for known, origin in values if known]
            return bool(origins), origins[0] if len(origins) == len(values) and all(o == origins[0] for o in origins) else None
        return False, None
    def opaque(value, scope):
        parents = {child: parent for parent in ast.walk(value) for child in ast.iter_child_nodes(parent)}
        roots = set()
        ambiguous = False
        for part in ast.walk(value):
            if not isinstance(part, (ast.Name, ast.Attribute)) or isinstance(parents.get(part), ast.Attribute):
                continue
            found, base = reference(part, scope)
            if found:
                items = base if isinstance(base, tuple) else (base,)
                ambiguous |= None in items
                roots.update(root for root in items if root is not None)
        return bool(roots or ambiguous), (None, *sorted(roots)) if ambiguous and roots else None if ambiguous else tuple(sorted(roots))
    scope_keys = calls.scope_keys
    def wrapper(value, scope):
        return calls.has_carrier(value, scope)
    def container(value, scope):
        if isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set, ast.DictComp,
                              ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return True
        if isinstance(value, ast.Call):
            return bool(wrapper(value.func, scope))
        if isinstance(value, ast.Name):
            key = next((key for key in scope_keys(value.id, scope) if key in exports or key in declarations), "")
            return key in containers
        return False
    def plain_type(value, scope):
        if isinstance(value, ast.Constant) and value.value is None:
            return True
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
            return plain_type(value.left, scope) and plain_type(value.right, scope)
        roots = calls.origins(value, scope)
        for root in roots:
            if (isinstance(root, str) and root.startswith("builtins.")
                    and isinstance(getattr(_binding_module.builtins, root.removeprefix("builtins."), None), type)):
                continue
            definitions = calls.definitions.get(root, ())
            if not definitions or any(not isinstance(node, ast.ClassDef) or node.bases or node.keywords or node.decorator_list
                                      for node, _ in definitions):
                return False
        return bool(roots)
    def assignment(target, value, scope, *, type_data=False):
        if isinstance(target, ast.Subscript):
            assignment(target.value, value, scope)
            if isinstance(target.value, ast.Name):
                containers.setdefault(scope + target.value.id, set()).update(returned(value, scope))
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if (isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts)
                    and not any(isinstance(item, ast.Starred) for item in target.elts)):
                for item, origin in zip(target.elts, value.elts, strict=True):
                    assignment(item, origin, scope)
            else:
                for item in ast.walk(target):
                    if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                        assignment(item, value, scope)
            return
        name = dotted(target)
        if not name:
            return
        key = scope + name
        if isinstance(target, (ast.Name, ast.Attribute)):
            carried = container(value, scope)
            calls.assign(name, value, scope)
            if carried or key in containers:
                containers.setdefault(key, set()).update(returned(value, scope))
        known, origin = reference(value, scope)
        if not known:
            known, origin = opaque(value, scope)
        if isinstance(value, ast.Call):
            targets = calls.origins(value.func, scope)
            module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__") + "."
            results = set().union(*(exports.get(target.removeprefix(module) + ".$return", ())
                                  for target in targets if target in calls.definitions))
            results.update({None} if any(target not in calls.definitions for target in targets) else ())
        else:
            results = returned(value, scope)
        values = callable_values.setdefault(key, set())
        values.update(root[len(CALLABLE_VALUE):] if isinstance(root, str) and root.startswith(CALLABLE_VALUE)
                      else root for root in results or {None})
        type_union = isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr) and plain_type(value, scope)
        functions = values.intersection(calls.definitions) if not type_data and not type_union else set()
        if functions:
            # Join callable values from both direct aliases and call results, preserving UNKNOWN.
            origins = tuple(CALLABLE_VALUE + root if root in functions else root
                            for root in sorted(values, key=lambda item: item or ""))
            exports[key] = origins[0] if len(origins) == 1 else origins
            declarations.discard(key)
            return
        if isinstance(value, ast.Call):
            result_roots = returned(value, scope)
            if result_roots:
                known, origin = True, tuple(sorted(result_roots, key=lambda item: item or ""))
            elif calls.primitive_call(value, scope):
                known, origin = False, None
        if not isinstance(value, ast.Call) and origin is None:
            _, possible = opaque(value, scope)
            if isinstance(possible, tuple):
                origin = (None, *possible)
        if known:
            if key in declarations or key in exports and exports[key] != origin:
                previous = exports.get(key)
                combined = (*previous,) if isinstance(previous, tuple) else (previous,)
                combined += origin if isinstance(origin, tuple) else (origin,)
                origin = (None, *sorted({root for root in combined if root is not None}))
            exports[key] = origin
            declarations.discard(key)
        elif key in exports:
            previous = exports[key]
            exports[key] = (None, *(previous if isinstance(previous, tuple) else (previous,)))
        else:
            declarations.add(key)
    def returned(value, scope):
        if isinstance(value, ast.Name):
            key = next((key for key in scope_keys(value.id, scope) if key in exports or key in declarations), "")
            if key in containers:
                return set(containers[key])
        if isinstance(value, (ast.Compare, ast.JoinedStr)) or isinstance(value, ast.UnaryOp) and isinstance(value.op, ast.Not):
            return set()
        if isinstance(value, (ast.NamedExpr, ast.Subscript)):
            return returned(value.value, scope)
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            return set().union(*(returned(part, scope) for part in value.elts))
        if isinstance(value, ast.IfExp):
            return returned(value.body, scope) | returned(value.orelse, scope)
        if isinstance(value, ast.BoolOp):
            return set().union(*(returned(part, scope) for part in value.values))
        if calls.primitive_call(value, scope):
            return set()
        if isinstance(value, ast.Call) and (wrapper(value.func, scope)
                or isinstance(value.func, ast.Attribute) and container(value.func.value, scope)):
            carried = [*value.args, *(item.value for item in value.keywords)]
            if isinstance(value.func, ast.Attribute):
                carried.append(value.func.value)
            return set().union(*(returned(part, scope) for part in carried))
        # A call returns its callee's result, not its arguments or tested classes.
        known, origin = reference(value.func if isinstance(value, ast.Call) else value, scope)
        if isinstance(value, ast.Call) and origin == "typing.cast":
            carried = value.args[1:] + [item.value for item in value.keywords if item.arg == "val"]
            return set().union(*(returned(part, scope) for part in carried))
        if not known:
            name = dotted(value.func if isinstance(value, ast.Call) else value)
            key = next((key for key in scope_keys(name, scope) if key in declarations), "")
            endpoint = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__") + "." + key
            if name and key and (isinstance(value, ast.Call) or endpoint in calls.definitions):
                origin, known = endpoint, True
        if isinstance(value, ast.Call):
            roots = {RESULT_VALUE + root if isinstance(root, str) else root
                     for root in (origin if isinstance(origin, tuple) else (origin,))} if known else set()
            targets = calls.origins(value.func, scope)
            ignores_input = bool(targets) and all(target in ignored_arg_roots for target in targets)
            parts = [*value.args, *(item.value for item in value.keywords)]
            callees = calls.origins(value.func, scope)
            if not callees or None in callees:
                parts.append(value.func)
            carried = set().union(*(returned(part, scope) for part in parts))
            # Global data precision requires a proved non-observing initializer, not allocation alone.
            roots.update(root if root.startswith(CARRIER_RETURN) else CARRIER_RETURN + root
                         for root in carried if isinstance(root, str)
                         and (not ignores_input or root.removeprefix(RESULT_VALUE) not in STDLIB_API))
            return roots
        if known:
            return set(origin if isinstance(origin, tuple) else (origin,))
        if isinstance(value, ast.Name):
            return {None}
        # Unknown non-call value carriers retain roots instead of becoming ordinary data.
        return set() if isinstance(value, ast.Call) else set().union(
            *(returned(child, scope) for child in ast.iter_child_nodes(value)))
    def walk(node, scope=""):
        pairs = []
        if isinstance(node, ast.Import):
            for item in node.names:
                pairs.append((item.asname or item.name.split(".")[0], item.name if item.asname else item.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if any(item.name == "*" for item in node.names):
                raise ValueError("wildcard import has no closed provenance")
            base = node.module or ""
            if node.level:
                anchor = PurePosixPath(path).parent.parts
                if node.level >= len(anchor) + 1:
                    raise ValueError("relative import leaves engine")
                base = ".".join((*anchor[:len(anchor) - node.level + 1], *([base] if base else [])))
            pairs = [(item.asname or item.name, f"{base}.{item.name}") for item in node.names]
        for name, target in pairs:
            if name in aliases and aliases[name] != target:
                raise ValueError("ambiguous import binding")
            aliases[name], exports[scope + name] = target, target
        if isinstance(node, ast.Assign):
            for target in node.targets:
                assignment(target, node.value, scope)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            assignment(node.target, node.value, scope)
        elif isinstance(node, ast.TypeAlias):
            assignment(node.name, node.value, scope, type_data=True)
        elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None:
            # Internal non-identifier key keeps return roots separate from locals.
            key = scope + "$return"
            exports[key] = tuple(set(exports.get(key, ())) | returned(node.value, scope))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            assignment(node.target, node.iter, scope)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            assignment(node.optional_vars, node.context_expr, scope)
        elif isinstance(node, ast.AugAssign):
            assignment(node.target, ast.Tuple(elts=[node.target, node.value], ctx=ast.Load()), scope)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                for pattern in ast.walk(case.pattern):
                    name = (pattern.name if isinstance(pattern, (ast.MatchAs, ast.MatchStar))
                            else pattern.rest if isinstance(pattern, ast.MatchMapping) else None)
                    if name:
                        assignment(ast.Name(id=name, ctx=ast.Store()), node.subject, scope)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            exports[scope + node.name] = None
        elif isinstance(node, ast.arg):
            calls.argument(node.arg, scope)
            declarations.add(scope + node.arg)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            calls.declare(node, scope)
            declarations.add(scope + node.name)
            scope += node.name + "."
        if (isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
                and (isinstance(node.ctx, ast.Del) or scope + node.id not in exports and scope + node.id not in declarations)):
            exports[scope + node.id] = None
        for child in ast.iter_child_nodes(node):
            walk(child, scope)
    walk(tree)
    return aliases, exports, declarations


class ImportIndex:
    def __init__(self, sources, forbidden=()):
        self.modules = {}
        self.forbidden = frozenset(forbidden)
        packages = set()
        trees = {path: ast.parse(source) for path, source in sources.items()}
        self.classes = set().union(*(_binding_module.declared_classes(tree,
            path.removesuffix(".py").replace("/", ".").removesuffix(".__init__"),
            lambda node: isinstance(node, ast.ClassDef)) for path, tree in trees.items()))
        self.ignored_arg_classes = _binding_module.ignored_argument_classes({
            path.removesuffix(".py").replace("/", ".").removesuffix(".__init__"): tree for path, tree in trees.items()})
        for path, tree in trees.items():
            module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
            if module in self.modules:
                raise ValueError("ambiguous engine module")
            self.modules[module] = import_bindings(tree, path, self.ignored_arg_classes)[1:]
            if path.endswith("/__init__.py"):
                packages.add(module)
        for module, (exports, declarations) in self.modules.items():
            if module not in packages and any(m.startswith(module + ".") for m in self.modules):
                raise ValueError("non-package module has descendants")
            if any(self.namespace(module + "." + key) and target != module + "." + key for key, target in exports.items()):
                raise ValueError("ambiguous imported module export")
            if any(self.namespace(module + "." + key) for key in declarations):
                raise ValueError("ambiguous declared module export")

    def namespace(self, name):
        return name in self.modules or any(module.startswith(name + ".") for module in self.modules)

    def foreign_roots(self, name, seen=frozenset(), *, callable_value=False, evaluate_return=True):
        """Trace known foreign API roots of exported data without running engine code."""
        if name is None or name in seen:
            return set()
        if name.startswith(RESULT_VALUE):
            callee = name[len(RESULT_VALUE):]
            roots = self.foreign_roots(callee, seen | {name}, callable_value=True)
            admitted = STDLIB_API | set().union(*SCOPED_API.values(), *RUNTIME_API.values())
            endpoints = api_values(frozenset(admitted))
            if callee.startswith("atlas_brain."):
                allowed = {api for api, target in endpoints.items() if callable(target)}
            else:
                allowed = set(constructor_members(frozenset(admitted)))
            return {root for root in roots if root.startswith(CARRIER_RETURN) or root in allowed}
        if name.startswith(CARRIER_RETURN):
            roots = self.foreign_roots(name[len(CARRIER_RETURN):], seen | {name}, callable_value=True)
            return {root if root.startswith(CARRIER_RETURN) else CARRIER_RETURN + root for root in roots}
        if name.startswith(CALLABLE_VALUE):
            return self.foreign_roots(name[len(CALLABLE_VALUE):], seen | {name},
                callable_value=callable_value, evaluate_return=evaluate_return)
        if not name.startswith("atlas_brain.") and name != "atlas_brain":
            return {name}
        module = max((m for m in self.modules if name.startswith(m + ".")), key=len, default="")
        if not module:
            return set()
        exports = self.modules[module][0]
        tail = name[len(module) + 1:]
        binding = max((key for key in exports if tail == key or tail.startswith(key + ".")), key=len, default="")
        returned = not binding
        if not binding:
            if not evaluate_return:
                return set()
            binding = tail + ".$return"
            if binding not in exports:
                if name in self.classes:
                    prefix = tail + "."
                    fields = [key for key in exports if key.startswith(prefix)
                              and "." not in key[len(prefix):] and not key[len(prefix):].startswith("_")]
                    fields += [tail + ".__new__.$return"] if tail + ".__new__.$return" in exports else []
                    roots = set().union(*(self.foreign_roots(module + "." + key, seen | {name}, callable_value=True)
                                          for key in fields))
                    return {root if root.startswith(CARRIER_RETURN) else CARRIER_RETURN + root for root in roots}
                return set()
        target = exports[binding]
        if isinstance(target, tuple):
            roots = set().union(*(self.foreign_roots(root, seen | {name}, callable_value=callable_value,
                evaluate_return=evaluate_return if isinstance(root, str) and root.startswith(CALLABLE_VALUE) else True)
                for root in target))
        else:
            endpoint = origin_member(target, tail[len(binding):])
            roots = self.foreign_roots(endpoint, seen | {name},
                callable_value=callable_value, evaluate_return=evaluate_return) if target is not None else set()
        if returned and not callable_value:
            # Only known class endpoints imply a returned instance, not primitive operations.
            admitted = STDLIB_API | set().union(*SCOPED_API.values(), *RUNTIME_API.values())
            classes = constructor_members(frozenset(admitted))
            roots = {root for root in roots if root.startswith(CARRIER_RETURN) or root in classes}
        return roots

    def origin(self, name, seen=frozenset()):
        if name.startswith(RESULT_VALUE):
            return self.origin(name[len(RESULT_VALUE):], seen | {name}) if name not in seen else None
        if name.startswith(CARRIER_RETURN):
            return self.origin(name[len(CARRIER_RETURN):], seen | {name}) if name not in seen else None
        if name.startswith(CALLABLE_VALUE):
            return self.origin(name[len(CALLABLE_VALUE):], seen | {name}) if name not in seen else None
        if any(name == module or name.startswith(module + ".") for module in self.forbidden):
            return None
        if not name.startswith("atlas_brain.") and name != "atlas_brain":
            return name
        if name in seen:
            return None
        if self.namespace(name):
            return name
        module = max((m for m in self.modules if name.startswith(m + ".")), key=len, default="")
        if not module:
            return None
        exports, declarations = self.modules[module]
        tail = name[len(module) + 1:]
        binding = max((key for key in exports if tail == key or tail.startswith(key + ".")), key=len, default="")
        if binding:
            target = exports[binding]
            if isinstance(target, tuple):
                if None in target:
                    return None
                roots = [self.origin(root, seen | {name}) for root in target]
                if not all(root is not None and (root.startswith("atlas_brain.") or root in STDLIB_API) for root in roots):
                    return None
                suffix = tail[len(binding):]
                if suffix and any(not root.startswith("atlas_brain.") for root in roots):
                    return roots[0] + suffix if len(roots) == 1 else None
                return name
            endpoint = origin_member(target, tail[len(binding):])
            return self.origin(endpoint, seen | {name}) if endpoint is not None else None
        return name if any(tail == key or tail.startswith(key + ".") for key in declarations) else None


@cache
def api_values(apis):
    """Inventory trusted admitted stdlib endpoints; never import consumer modules."""
    result = {}
    for api in sorted(apis):
        parts = api.split(".")
        if parts[0] not in sys.stdlib_module_names:
            raise ValueError("constructor inventory requires a stdlib namespace")
        for length in range(len(parts) - 1, 0, -1):
            module = ".".join(parts[:length])
            try:
                target = importlib.import_module(module)
            except ModuleNotFoundError as error:
                if error.name != module and not module.startswith(str(error.name) + "."):
                    raise
                continue
            for name in parts[length:]:
                target = getattr(target, name)
            result[api] = target
            break
        else:
            raise ValueError("admitted API has no closed stdlib namespace")
    return result


@cache
def constructor_members(apis):
    return {api: frozenset(name for name in dir(target) if name.isidentifier() and not name.startswith("_"))
            for api, target in api_values(apis).items() if isinstance(target, type)}


def source_refusals(source: str, sources=None, path="atlas_brain/probe.py") -> set[str]:
    tree = ast.parse(source)
    apis = STDLIB_API | SCOPED_API.get(path, set()) | RUNTIME_API.get(path, set())
    factories = constructor_members(frozenset(apis))
    all_factories = constructor_members(frozenset(STDLIB_API | set().union(*SCOPED_API.values(), *RUNTIME_API.values())))
    scoped_modules = {p.removesuffix(".py").replace("/", ".") for p in SCOPED_API}
    try:
        index = ImportIndex({path: source, **(sources or {})}, () if path in SCOPED_API else scoped_modules)
        aliases, exports, declarations = import_bindings(tree, path, index.ignored_arg_classes)
    except ValueError:
        return {"unresolved-provenance"}
    def admitted(name):
        if name is None or (path not in SCOPED_API and any(name == m or name.startswith(m + ".") for m in scoped_modules)):
            return False
        return (index.namespace(name) or name.startswith("atlas_brain.") or name in apis
                                     or any(api.startswith(name + ".") for api in apis))
    refused = {name for name in aliases.values() if not admitted(index.origin(name))}
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, "")
        base = qualified(node.value) if isinstance(node, ast.Attribute) else ""
        return base + "." + node.attr if base else ""
    def receiver_roots(value):
        roots = set()
        applied = any(isinstance(part, ast.Call) for part in ast.walk(value))
        for part in ast.walk(value):
            if isinstance(part, ast.Attribute) and (name := qualified(part)):
                roots.add((name, applied))
            if not isinstance(part, ast.Name):
                continue
            scope, ancestor = [], parents.get(part)
            while ancestor is not None:
                if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    scope.insert(0, ancestor.name)
                ancestor = parents.get(ancestor)
            if part.id in aliases:
                roots.add((aliases[part.id], applied))
            for length in range(len(scope), -1, -1):
                key = ".".join((*scope[:length], part.id))
                if key in exports:
                    target = exports[key]
                    if isinstance(target, tuple):
                        roots.update((root, True) for root in target if isinstance(root, str))
                    else:
                        roots.add((target, applied))
                    break
                if key in declarations:
                    roots.add((path.removesuffix(".py").replace("/", ".").removesuffix(".__init__") + "." + key, applied))
                    break
        return {(root, result) for root, result in roots if isinstance(root, str)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and not isinstance(node.func, ast.Attribute):
            for root, applied in receiver_roots(node.func):
                origins = index.foreign_roots(root, callable_value=True, evaluate_return=applied)
                if any(not admitted(origin.removeprefix(CARRIER_RETURN)) for origin in origins):
                    refused.add(root + "()")
        if isinstance(node, ast.Attribute) and (node.attr in CODE_ATTRIBUTES
                or node.attr.startswith("_") and node.attr not in {"__init__", "__init_subclass__"}):
            refused.add(node.attr)
        if isinstance(node, ast.Name) and node.id in DYNAMIC:
            refused.add(node.id)
        if isinstance(node, (ast.Name, ast.Attribute)):
            raw = qualified(node)
            if not raw:
                if isinstance(node, ast.Attribute):
                    # An opaque expression must not erase a known engine-export capability.
                    for root, _ in receiver_roots(node.value):
                        origins = index.foreign_roots(root)
                        for carried in (origin for origin in origins if origin.startswith(CARRIER_RETURN)):
                            target = carried[len(CARRIER_RETURN):]
                            if (not admitted(target) or node.attr in all_factories.get(target, ())
                                    and not admitted(target + "." + node.attr)):
                                refused.add(root + "." + node.attr)
                        if any(not admitted(factory + "." + node.attr) for factory in origins
                               if not factory.startswith(CARRIER_RETURN) and
                               (root.startswith(("atlas_brain.", RESULT_VALUE, CALLABLE_VALUE))
                                or node.attr in factories.get(factory, ()))):
                            refused.add(root + "." + node.attr)
                continue
            name = index.origin(raw)
            if not admitted(name):
                refused.add(raw)
                continue
            if index.namespace(name) or name not in apis and any(api.startswith(name + ".") for api in apis):
                parent = parents.get(node)
                if not isinstance(parent, ast.Attribute) or parent.value is not node:
                    refused.add(raw)
    return refused


def source_allowed(source: str, sources=None, path="atlas_brain/probe.py") -> bool:
    return not source_refusals(source, sources, path)


def main() -> int:
    paths = sys.argv[1:] or subprocess.check_output(
        ["git", "ls-files", "-z"],
    ).decode("utf-8").rstrip("\0").split("\0")
    failures = set()
    def refuse(path, kind, name):
        failures.add((path, kind))
        print(json.dumps({"path": path if repository_path(path) else "<non-repository-path>",
                          "class": kind, "name": name}, sort_keys=True))
    sources = {}
    for path in paths:
        if not allowed(path):
            refuse(path, "path", "unapproved-path")
            continue
        if path.startswith("atlas_brain/") and path.endswith(".py"):
            try:
                if Path(path).is_symlink():
                    refuse(path, "import", "source-link")
                    continue
                source = Path(path).read_text(encoding="utf-8")
                ast.parse(source)
                sources[path] = source
            except SyntaxError:
                refuse(path, "import", "invalid-syntax")
            except (OSError, ValueError):
                refuse(path, "import", "unreadable-source")
        if path.startswith("governance/"):
            try:
                if not gate_data_allowed(path, json.loads(Path(path).read_text(encoding="utf-8"))):
                    refuse(path, "machine-data", "invalid-shape")
            except (OSError, ValueError, TypeError):
                refuse(path, "machine-data", "invalid-data")
    for path, source in sources.items():
        for name in sorted(source_refusals(source, sources, path)):
            refuse(path, "import", name)
    try:
        if not dependencies_allowed(tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))):
            refuse("pyproject.toml", "dependency", "project.dependencies/optional-dependencies")
    except (OSError, ValueError, TypeError, AttributeError):
        refuse("pyproject.toml", "dependency", "invalid-data")
    print(f"scope fence: {len(failures)} refused paths, imports, dependencies or machine-data files")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
