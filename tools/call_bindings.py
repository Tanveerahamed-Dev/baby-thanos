"""Conservative callable-origin joins and narrow primitive-result proofs; no permissions."""
import ast
import builtins

BUILTINS = frozenset(vars(builtins))
SCALARS = frozenset({"bool", "int", "float", "complex", "str", "bytes", "bytearray", "isinstance", "issubclass", "callable", "len", "all", "any", "hash", "id", "repr", "ascii", "format", "bin", "oct", "hex", "ord", "chr"})
SCALAR_APIS = frozenset({"json.dumps", "math.isfinite", "stat.S_ISDIR", "stat.S_ISREG"})
CARRIERS = frozenset({"iter", "next", "aiter", "anext", "list", "tuple", "set", "frozenset", "dict", "reversed", "enumerate", "zip", "sorted"})


def ordinary_class(node):
    """Only a plain class with default allocation proves an ordinary instance."""
    if not isinstance(node, ast.ClassDef) or node.bases or node.keywords or node.decorator_list:
        return False
    # Unknown namespace statements (patterns, imports, control flow) can bind an allocator.
    for statement in node.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if all(isinstance(target, ast.Name) for target in targets):
                continue
            return False
        if isinstance(statement, (ast.Pass, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
            continue
        return False
    return not any(isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef)) and part.name == "__new__"
                   or isinstance(part, ast.Name) and part.id == "__new__"
                   or isinstance(part, ast.Attribute) and part.attr == "__new__" for part in ast.walk(node))


def ignores_arguments(node):
    """A closed constant initializer cannot retain constructor input objects."""
    if not ordinary_class(node):
        return False
    initializers = []
    for part in node.body:
        if isinstance(part, ast.FunctionDef) and part.name == "__init__" and not part.decorator_list:
            initializers.append(part)
        elif isinstance(part, (ast.Assign, ast.AnnAssign)):
            targets = part.targets if isinstance(part, ast.Assign) else [part.target]
            if (any(not isinstance(target, ast.Name) or target.id.startswith("_") for target in targets)
                    or part.value is not None and not isinstance(part.value, ast.Constant)):
                return False
        elif not (isinstance(part, ast.Pass) or isinstance(part, ast.Expr) and isinstance(part.value, ast.Constant)
                  and isinstance(part.value.value, str)):
            return False
    if len(initializers) != 1:
        return not initializers
    initializer = initializers[0]
    positional = initializer.args.posonlyargs + initializer.args.args
    if not positional:
        return False
    for part in initializer.body:
        if isinstance(part, ast.Pass) or isinstance(part, ast.Return) and part.value is None:
            continue
        if isinstance(part, ast.Expr) and isinstance(part.value, ast.Constant) and isinstance(part.value.value, str):
            continue
        if not isinstance(part, (ast.Assign, ast.AnnAssign)) or not isinstance(part.value, ast.Constant):
            return False
        targets = part.targets if isinstance(part, ast.Assign) else [part.target]
        if any(not isinstance(target, ast.Attribute) or not isinstance(target.value, ast.Name)
               or target.value.id != positional[0].arg or target.attr.startswith("_") for target in targets):
            return False
    return True


def declared_classes(tree, module, predicate=ordinary_class):
    result = {}
    def walk(node, scope=""):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            key = scope + node.name
            origin = module + "." + key
            result[origin] = result.get(origin, True) and predicate(node)
            scope = key + "."
        for child in ast.iter_child_nodes(node):
            walk(child, scope)
    walk(tree)
    return {origin for origin, proven in result.items() if proven}


def ignored_argument_classes(trees):
    if any(isinstance(node, ast.Attribute) and node.attr == "__init__" and isinstance(node.ctx, (ast.Store, ast.Del))
           for tree in trees.values() for node in ast.walk(tree)):
        return set()
    return set().union(*(declared_classes(tree, module, ignores_arguments) for module, tree in trees.items()))


class CallableBindings:
    def __init__(self, module, aliases, exports, declarations):
        self.module, self.aliases, self.exports, self.declarations = module, aliases, exports, declarations
        self.possible, self.values, self.definitions = {}, {}, {}
        self.external = set()
        self.external_roots, self.class_scopes = set(), set()
        self.function_scopes = set()

    def scope_keys(self, name, scope):
        parts = scope.rstrip(".").split(".") if scope else []
        prefixes = [".".join(parts[:length]) + ("." if length else "") for length in range(len(parts), -1, -1)]
        return [prefix + name for prefix in prefixes
                if prefix == scope or prefix not in self.class_scopes or prefix in self.function_scopes]

    def external_name(self, name, scope):
        root = name.split(".")[0]
        return root in self.external_roots or any(key in self.external for key in self.scope_keys(root, scope))

    def origins(self, value, scope):
        if isinstance(value, ast.Name):
            if self.external_name(value.id, scope) or scope in self.class_scopes:
                # Explicit outer bindings can be mutated outside this lexical walk.
                # Over-approximate named alternatives; never certify a scalar from them.
                roots = {None}
                if value.id in BUILTINS:
                    roots.add("builtins." + value.id)
                if value.id in self.aliases:
                    roots.add(self.aliases[value.id])
                for key, alternatives in self.possible.items():
                    if key.rsplit(".", 1)[-1] == value.id:
                        roots.update(alternatives)
                return frozenset(roots)
            for key in self.scope_keys(value.id, scope):
                if key in self.possible:
                    return frozenset(self.possible[key])
                if key in self.exports:
                    target = self.exports[key]
                    return frozenset({target if isinstance(target, str) else None})
                if key in self.declarations:
                    return frozenset({None})
            if value.id in self.aliases:
                return frozenset({self.aliases[value.id]})
            return frozenset({"builtins." + value.id if value.id in BUILTINS else None})
        if isinstance(value, ast.Attribute):
            def dotted(node):
                if isinstance(node, ast.Name):
                    return node.id
                base = dotted(node.value) if isinstance(node, ast.Attribute) else ""
                return base + "." + node.attr if base else ""
            for key in self.scope_keys(dotted(value), scope):
                if key in self.possible:
                    return frozenset(self.possible[key])
            return frozenset(root + "." + value.attr if root is not None else None
                             for root in self.origins(value.value, scope))
        if isinstance(value, ast.IfExp):
            return self.origins(value.body, scope) | self.origins(value.orelse, scope)
        if isinstance(value, ast.BoolOp):
            return frozenset().union(*(self.origins(part, scope) for part in value.values))
        return frozenset({None})

    def assign(self, name, value, scope):
        key = scope + name
        possible = self.origins(value, scope)
        self.possible.setdefault(key, set()).update(possible)
        self.values.setdefault(key, []).append((value, scope))

    def argument(self, name, scope):
        self.possible.setdefault(scope + name, set()).add(None)
        self.values.setdefault(scope + name, []).append((None, scope))

    def declare(self, node, scope):
        key, origin = scope + node.name, self.module + "." + scope + node.name
        self.possible.setdefault(key, set()).add(origin)
        definitions = self.definitions.setdefault(origin, [])
        if not any(previous is node for previous, _ in definitions):
            definitions.append((node, scope + node.name + "."))

    def predeclare(self, tree):
        def walk(node, scope=""):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                self.external.update(scope + name for name in node.names)
                self.external_roots.update(node.names)
            if isinstance(node, ast.ClassDef):
                self.class_scopes.add(scope + node.name + ".")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.function_scopes.add(scope + node.name + ".")
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                self.declare(node, scope)
                self.declarations.add(scope + node.name)
                scope += node.name + "."
            for child in ast.iter_child_nodes(node):
                walk(child, scope)
        walk(tree)

    def has_carrier(self, value, scope):
        return any(root in {"builtins." + name for name in CARRIERS} for root in self.origins(value, scope))

    def primitive_call(self, value, scope):
        if not isinstance(value, ast.Call):
            return False
        origins = self.origins(value.func, scope)
        root = value.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if scope in self.class_scopes or isinstance(root, ast.Name) and self.external_name(root.id, scope):
            return False
        scalar = SCALAR_APIS | {"builtins." + name for name in SCALARS}
        return bool(origins) and all(root in scalar for root in origins)

    def constructor_call(self, value, scope, classes):
        if not isinstance(value, ast.Call):
            return False
        local = {origin for origin, definitions in self.definitions.items()
                 if all(ordinary_class(node) for node, _ in definitions)}
        origins = self.origins(value.func, scope)
        return bool(origins) and all(root in classes or root in local for root in origins)
