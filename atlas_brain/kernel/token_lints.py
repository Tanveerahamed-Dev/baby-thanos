"""Conservative AST refusal of implicit defaults in enumerated token maps.

Missing tokens must take the explicit unknown path. Even one-argument get
silently manufactures None, so token maps must use checked subscription.
This is a static shape guard, complemented by the closed parse-kit token map.
"""
import ast
from typing import cast


def _tail(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    return node.attr if isinstance(node, ast.Attribute) else ''


def _lookup_value(node: ast.AST, type_nodes: frozenset[ast.AST] = frozenset()) -> bool:
    return any(isinstance(part, ast.Subscript) and part not in type_nodes and (
        isinstance(part.slice, (ast.Name, ast.Attribute)) or
        (isinstance(part.slice, ast.Constant) and type(part.slice.value) is str))
        for part in ast.walk(node))


def _lookup_branch(body: list[ast.stmt], type_nodes: frozenset[ast.AST]) -> bool:
    return any(_lookup_value(part.value, type_nodes)
               for statement in body for part in ast.walk(statement)
               if isinstance(part, (ast.Assign, ast.AnnAssign, ast.Return)) and part.value is not None)


def _statement_lookup(node: ast.AST, type_nodes: frozenset[ast.AST]) -> bool:
    if not isinstance(node, ast.stmt):
        return False
    for _, value in ast.iter_fields(node):
        children: tuple[ast.AST, ...] = ()
        if isinstance(value, ast.AST):
            children = (value,)
        elif isinstance(value, list):
            children = tuple(child for child in cast(list[object], value) if isinstance(child, ast.AST))
        if any(not isinstance(child, ast.stmt) and _lookup_value(child, type_nodes) for child in children):
            return True
    return False


def _may_return(node: ast.AST) -> bool:
    """Find a possible early return without entering a separately defined function."""
    pending = [node]
    while pending:
        part = pending.pop()
        if isinstance(part, ast.Return):
            return True
        fields = tuple(ast.iter_fields(part))
        if any(field == 'args' and isinstance(value, ast.AST) for field, value in fields):
            continue
        for _, value in fields:
            if isinstance(value, ast.AST):
                pending.append(value)
            elif isinstance(value, list):
                pending.extend(child for child in cast(list[object], value) if isinstance(child, ast.AST))
    return False


def statement_context(tree: ast.AST) -> tuple[dict[ast.stmt, tuple[ast.stmt, ...]], frozenset[ast.AST]]:
    """Bind local successors without certifying optional or intercepted execution.

    A single handler after an unconditional raise runs or failure escapes.
    Other handler entries are optional; a leaf-only try body proves else entry.
    A function body starts its own execution scope; finalizers may override exits.
    Test-controlled branches and loop bodies/else blocks may never execute.
    """
    following: dict[ast.stmt, tuple[ast.stmt, ...]] = {}
    intercepted: set[ast.AST] = set()
    pending: list[tuple[ast.AST, bool]] = [(tree, False)]
    while pending:
        owner, protected = pending.pop()
        fields = tuple(ast.iter_fields(owner))
        function_scope = any(field == 'args' and isinstance(value, ast.AST) for field, value in fields)
        if protected:
            intercepted.add(owner)
        catching = any(field == 'handlers' and bool(value) for field, value in fields)
        raising = any(field == 'body' and isinstance(value, list) and len(cast(list[object], value)) == 1
                      and isinstance(cast(list[object], value)[0], ast.Raise) for field, value in fields)
        single_handler = any(field == 'handlers' and isinstance(value, list) and len(cast(list[object], value)) == 1 for field, value in fields)
        leaf_body = any(field == 'body' and isinstance(value, list) and bool(cast(list[object], value)) and all(
            isinstance(child, ast.stmt) and not tuple(ast.iter_fields(child)) for child in cast(list[object], value)) for field, value in fields)
        finalizing = any(field == 'finalbody' and bool(value) for field, value in fields)
        managing = any(field == 'items' and bool(value) for field, value in fields)
        conditional = any(field in ('test', 'iter') and isinstance(value, ast.AST) for field, value in fields)
        for field, value in fields:
            children: tuple[ast.AST, ...] = ()
            if isinstance(value, ast.AST):
                children = (value,)
            elif isinstance(value, list):
                children = tuple(child for child in cast(list[object], value) if isinstance(child, ast.AST))
            block = tuple(child for child in children if isinstance(child, ast.stmt))
            following.update((statement, block[index + 1:]) for index, statement in enumerate(block))
            blocked = protected or (field == 'handlers' and not (raising and single_handler)) or (
                field == 'orelse' and catching and not leaf_body) or (field == 'body' and (catching or managing)) or (
                field in ('body', 'orelse', 'handlers') and finalizing) or (
                field in ('body', 'orelse') and conditional)
            blocked = blocked and not (function_scope and field == 'body')
            unreachable: set[ast.AST] = set()
            may_skip = False
            for statement in block:
                if may_skip:
                    unreachable.add(statement)
                may_skip = may_skip or isinstance(statement, ast.Raise) or _may_return(statement)
            pending.extend((child, blocked or child in unreachable) for child in children)
    return following, frozenset(intercepted)


def bound_names(node: ast.AST) -> frozenset[str]:
    return frozenset(part.name for part in ast.walk(node) if isinstance(part, (ast.MatchAs, ast.MatchStar)) and part.name) | frozenset(
        part.rest for part in ast.walk(node) if isinstance(part, ast.MatchMapping) and part.rest)


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        return node.id
    if isinstance(node, ast.Attribute):
        return _qualified(node.value, aliases) + '.' + node.attr
    return ''


def binding_proof(tree: ast.AST, aliases: dict[str, str], rebound: set[str], *, call_target: str = 'typing.assert_never') -> tuple[frozenset[ast.Call], frozenset[ast.MatchClass]]:
    """Verify names against the import/rebinding environment supplied by the scanner."""
    def symbol(identifier: str) -> str:
        if identifier in aliases:
            return aliases[identifier]
        return identifier

    shadowed = rebound | {symbol(k) for k in sorted(bound_names(tree))}

    def stable(name: str) -> bool:
        return not any(name == key or name.startswith(key + '.') or key.startswith(name + '.') for key in sorted(shadowed))

    calls = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.Call) and _qualified(n.func, aliases) == call_target and stable(_qualified(n.func, aliases)))
    closed = tuple('atlas_brain.kernel.states.' + state for state in ('Known', 'Absent', 'Unknown', 'NotApplicable'))
    facts = frozenset(n for n in ast.walk(tree) if isinstance(n, ast.MatchClass) and _qualified(n.cls, aliases) in closed and stable(_qualified(n.cls, aliases)))
    return calls, facts


def _irrefutable(pattern: ast.pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _irrefutable(pattern.pattern)
    return isinstance(pattern, ast.MatchOr) and any(_irrefutable(part) for part in pattern.patterns)


def _terminal_assertion(pattern: ast.pattern, body: list[ast.stmt], assertions: frozenset[ast.Call]) -> bool:
    bound = bound_names(pattern)
    if not _irrefutable(pattern) or len(body) != 1 or not isinstance(body[0], ast.Expr):
        return False
    call = body[0].value
    return (isinstance(call, ast.Call) and call in assertions and
            len(call.args) == 1 and not call.keywords and
            isinstance(call.args[0], ast.Name) and call.args[0].id in bound)


def _literal_pattern(pattern: ast.pattern, facts: frozenset[ast.MatchClass] = frozenset()) -> bool:
    if isinstance(pattern, (ast.MatchValue, ast.MatchSingleton)):
        return True
    return (isinstance(pattern, ast.MatchClass) and pattern in facts) or (
        isinstance(pattern, ast.MatchOr) and all(_literal_pattern(p, facts) for p in pattern.patterns))


def _enum_comparison(node: ast.AST) -> bool:
    return any(isinstance(part, ast.Compare) and
        not any(isinstance(value, ast.Subscript) for value in ast.walk(part)) and any(
        isinstance(value, ast.Constant) and type(value.value) is str
        for value in ast.walk(part)) for part in ast.walk(node))


def _value_branch(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Assign, ast.AnnAssign, ast.Return))


def _returned_default(body: list[ast.stmt]) -> bool:
    while len(body) == 1 and isinstance(body[0], ast.If):
        body = body[0].orelse
    return bool(body) and isinstance(body[-1], ast.Return)


def _finite_arm(node: ast.If) -> str:
    if not node.body or not isinstance(node.body[-1], (ast.Return, ast.Raise)):
        return ''
    return finite_subject(node.test)


def fallback_node(node: ast.AST, called: str = '', *, assertions: frozenset[ast.Call] = frozenset(), facts: frozenset[ast.MatchClass] = frozenset(), following: tuple[ast.stmt, ...] = (), unknowns: frozenset[ast.Call] = frozenset(), allow_refusal: bool = False, type_nodes: frozenset[ast.AST] = frozenset()) -> bool:
    """Refuse defaults; assertion call witnesses require whole-module binding proof."""
    if isinstance(node, ast.Call):
        short = (called or _tail(node.func)).rsplit('.', 1)[-1]
        return short in ('get', 'setdefault', 'defaultdict') or (
            short == 'pop' and (len(node.args) > 1 or bool(node.keywords)))
    if isinstance(node, ast.IfExp):
        return (_lookup_value(node.body, type_nodes) or _lookup_value(node.orelse, type_nodes) or
                _enum_comparison(node.test))
    if isinstance(node, ast.If):
        lookup = _lookup_branch(node.body + node.orelse, type_nodes) or _lookup_branch(list(following), type_nodes)
        subject = finite_subject(node.test)
        if subject and len(following) > 1 and not _finite_arm(node) and refusal_tail(following, subject, unknowns):
            return True
        if allow_refusal and not node.orelse:
            if (_finite_arm(node) or guarded_lookup(node.test, tuple(node.body))) and refusal_tail(following, subject, unknowns):
                return False
            if guarded_lookup(node.test, following, inverse=True) and refusal_tail(tuple(node.body), '', unknowns):
                return False
        return (_enum_comparison(node.test) and (_returned_default(node.body) or _returned_default(node.orelse) or
                _returned_default(list(following)) or (_value_branch(node.body) and (not node.orelse or _value_branch(node.orelse))))) or lookup
    if isinstance(node, ast.Match):
        terminals = frozenset(case for case in node.cases if allow_refusal and case.guard is None
                             and _terminal_assertion(case.pattern, case.body, assertions))
        if any(not _literal_pattern(case.pattern, facts) and
               case not in terminals
               for case in node.cases):
            return True
        terminal = _returned_default(list(following)) or bool(following and isinstance(following[-1], ast.Raise))
        return terminal and not terminals and not (allow_refusal and refusal_tail(following, _qualified(node.subject, {}), unknowns))
    return False


def _type_nodes(tree: ast.AST, aliases: dict[str, str], rebound: set[str]) -> frozenset[ast.AST]:
    """Prove pure type syntax in annotations and canonical typing.cast arguments."""
    casts, _ = binding_proof(tree, aliases, rebound, call_target='typing.cast')
    shadowed = rebound | {_qualified(ast.Name(id=name), aliases) for name in sorted(bound_names(tree))}
    generics = ('list', 'tuple', 'dict', 'set', 'frozenset', 'type')
    scalars = ('object', 'str', 'bytes', 'int', 'bool')

    def stable(symbol: str) -> bool:
        return not any(symbol == key or symbol.startswith(key + '.') or key.startswith(symbol + '.')
                       for key in sorted(shadowed))

    def builtin(node: ast.AST, names: tuple[str, ...]) -> bool:
        symbol = _qualified(node, aliases)
        short = symbol.rsplit('.', 1)[-1]
        return short in names and symbol in (short, 'builtins.' + short) and all(
            stable(target) for target in (short, 'builtins.' + short))

    def type_expression(node: ast.AST) -> bool:
        if isinstance(node, ast.Subscript):
            return builtin(node.value, generics) and type_expression(node.slice)
        return isinstance(node, (ast.Name, ast.Attribute)) and (builtin(node, generics + scalars) or (
            _qualified(node, aliases) == 'ast.AST' and stable('ast.AST')))

    arguments = tuple(call.args[0] for call in ast.walk(tree) if isinstance(call, ast.Call) and call in casts
                      and len(call.args) == 2 and not call.keywords and type_expression(call.args[0]))
    annotations = tuple(value for owner in ast.walk(tree) for field, value in ast.iter_fields(owner)
                        if field in ('annotation', 'returns') and isinstance(value, ast.AST) and type_expression(value))
    return frozenset(part for root in arguments + annotations for part in ast.walk(root))


def fallback_nodes(tree: ast.AST, aliases: dict[str, str], rebound: set[str]) -> frozenset[ast.AST]:
    """Inspect statement successors and genuine Unknown bindings for whole-source use."""
    assertions, facts = binding_proof(tree, aliases, rebound)
    unknowns, _ = binding_proof(tree, aliases, rebound, call_target='atlas_brain.kernel.states.Unknown')
    type_nodes = _type_nodes(tree, aliases, rebound)
    following, intercepted = statement_context(tree)
    roots = tuple(branch for branch in following
        if isinstance(branch, ast.If) and branch not in intercepted and not branch.orelse
        and (_finite_arm(branch) or guarded_lookup(branch.test, tuple(branch.body)))
        and refusal_tail(following[branch], finite_subject(branch.test), unknowns))
    proven_guards = roots + tuple(later for branch in roots if finite_subject(branch.test)
                                     for later in following[branch][:-1])
    inverses = tuple(branch for branch in following
        if isinstance(branch, ast.If) and branch not in intercepted and not branch.orelse
        and guarded_lookup(branch.test, following[branch], inverse=True)
        and refusal_tail(tuple(branch.body), '', unknowns))
    proven_statements = frozenset(part for branch in proven_guards if isinstance(branch, ast.If)
                                 for part in branch.body) | frozenset(part for branch in inverses for part in following[branch])
    return frozenset(node for node in ast.walk(tree) if fallback_node(node,
        _qualified(node.func, aliases) if isinstance(node, ast.Call) else '', assertions=assertions, facts=facts,
        following=following[node] if isinstance(node, ast.stmt) and node in following else (), unknowns=unknowns,
        allow_refusal=node not in intercepted or node in proven_guards, type_nodes=type_nodes) or (
            node in intercepted and node not in proven_statements and _statement_lookup(node, type_nodes)))


def finite_subject(test: ast.AST) -> str:
    if isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1 and isinstance(test.ops[0], ast.Eq):
        left, right = test.left, test.comparators[0]
        if isinstance(right, ast.Constant) and type(right.value) is str:
            return _qualified(left, {})
        if isinstance(left, ast.Constant) and type(left.value) is str:
            return _qualified(right, {})
    return ''


def _same_operand(left: ast.AST, right: ast.AST) -> bool:
    if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
        return type(left.value) is type(right.value) and left.value == right.value
    name = _qualified(left, {})
    return bool(name) and name == _qualified(right, {})


def guarded_lookup(test: ast.AST, body: tuple[ast.stmt, ...], *, inverse: bool = False) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.NotIn if inverse else ast.In):
        return False
    if len(body) != 1 or not isinstance(body[0], ast.Return) or not isinstance(body[0].value, ast.Subscript):
        return False
    lookup = body[0].value
    return _same_operand(test.left, lookup.slice) and _same_operand(test.comparators[0], lookup.value)


def refusal_tail(following: tuple[ast.stmt, ...], subject: str, unknowns: frozenset[ast.Call]) -> bool:
    """Prove an escaping tail; the caller supplies canonical Unknown call witnesses."""
    if not following:
        return False
    last = following[-1]
    # Each same-input arm must exit; an arm that mutates and continues is unproven.
    if len(following) > 1 and (not subject or any(
            not isinstance(s, ast.If) or s.orelse or finite_subject(s.test) != subject
            or len(s.body) != 1 or not isinstance(s.body[0], (ast.Return, ast.Raise)) for s in following[:-1])):
        return False
    return isinstance(last, ast.Raise) or (isinstance(last, ast.Return) and isinstance(last.value, ast.Call) and last.value in unknowns)
