"""Nested repetition shape support for the regex lint; no engine execution."""
import ast
import re


def nested_unbounded(pattern: str) -> bool:
    """Track groups, escaped characters and character classes before repeats."""
    stack: list[bool] = [False]
    last_group = False
    escaped = in_class = False
    for index, char in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            last_group = False
            continue
        if char == '[':
            in_class = True
            last_group = False
        if in_class:
            if char == ']':
                in_class = False
            continue
        if char == '(':
            stack.append(False)
        elif char == ')':
            last_group = stack.pop() if len(stack) > 1 else False
            stack[-1] |= last_group
            continue
        elif char in '*+' or (char == '{' and re.search(r'^\{\d+,\}', pattern[index:], re.ASCII)):
            if last_group:
                return True
            stack[-1] = True
        last_group = False
    return False


def resolved_name(node: ast.AST, aliases: dict[str, str]) -> str:
    """Resolve an AST name using the scanner's supplied import environment."""
    if isinstance(node, ast.Name):
        if node.id not in aliases:
            return node.id
        return aliases[node.id]
    if isinstance(node, ast.Attribute):
        return resolved_name(node.value, aliases) + '.' + node.attr
    if isinstance(node, ast.Subscript):
        return resolved_name(node.value, aliases)
    return ''


def resolved_tail(node: ast.AST, aliases: dict[str, str]) -> str:
    return resolved_name(node, aliases).split('.')[-1]


def contains_name(node: ast.AST, names: tuple[str, ...], aliases: dict[str, str]) -> bool:
    return any(resolved_tail(part, aliases) in names for part in ast.walk(node))


def binding_environment(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Collect imports; conflicting origins cannot certify a stable API binding."""
    bindings: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                bindings.append((item.asname or item.name.split('.')[0], item.name if item.asname else item.name.split('.')[0]))
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                bindings.append((item.asname or item.name, f'{node.module}.{item.name}'))
    aliases = dict(bindings)
    ambiguous = {origin for name, origin in bindings if any(
        name == other and origin != candidate for other, candidate in bindings)}
    rebound = {resolved_name(n, aliases) for n in ast.walk(tree) if isinstance(n, (ast.Name, ast.Attribute)) and isinstance(n.ctx, ast.Store)}
    for binding in ast.walk(tree):
        identifier = binding.arg if isinstance(binding, ast.arg) else binding.name if isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)) else ''
        if identifier:
            rebound.add(resolved_name(ast.Name(id=identifier, ctx=ast.Load()), aliases))
    return aliases, rebound | ambiguous


def unordered_iterations(tree: ast.AST, aliases: dict[str, str]) -> frozenset[ast.AST]:
    """Return the original rule-11 witnesses without changing its shape tests."""
    sets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and contains_name(node.annotation, ('set', 'frozenset'), aliases) and isinstance(node.target, ast.Name):
            sets.add(node.target.id)
        if isinstance(node, ast.arg) and node.annotation and contains_name(node.annotation, ('set', 'frozenset'), aliases):
            sets.add(node.arg)
        if isinstance(node, (ast.Assign, ast.NamedExpr)):
            value = node.value
            if isinstance(value, (ast.Set, ast.SetComp)) or (isinstance(value, ast.Call) and resolved_tail(value.func, aliases) in ('set', 'frozenset')):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                sets.update(t.id for t in targets if isinstance(t, ast.Name))
    findings: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            iterator = node.iter
            if isinstance(iterator, (ast.Set, ast.SetComp)) or (isinstance(iterator, ast.Name) and iterator.id in sets) or (isinstance(iterator, ast.Call) and resolved_tail(iterator.func, aliases) in ('set', 'frozenset')):
                findings.add(node)
    return frozenset(findings)
