"""Conservative admission guard for every parse-kit regex (no runtime parsers)."""
import re

# These expressions inspect pattern syntax, never capture data.
_QUANTIFIERS = (
    re.compile(r"\{[0-9]++,[0-9]*+\}", re.ASCII),
    re.compile(r"\{[0-9]++\}", re.ASCII),
    re.compile(r"\{,[0-9]*+\}", re.ASCII),
)
_NAME = re.compile(r"\(\?P<[A-Za-z_][A-Za-z_0-9]*+>", re.ASCII)


def compile_pattern(pattern: str) -> re.Pattern[bytes]:
    """Refuse nested repeats, alternation and non-local constructs.

    Deliberately conservative: even a bounded repeat around a repeated group
    is refused. Patterns use ASCII syntax and match bytes, preserving offsets.
    Inline flags, lookarounds, conditional groups and backreferences are outside
    this rule-table grammar. Escapes and character classes remain opaque atoms.
    Every repeat must be possessive: no input-dependent split is reconsidered.
    Rules are refused rather than rewritten; authors must state that semantics.
    """
    try:
        compiled = re.compile(pattern.encode("ascii"), re.ASCII)
    except (UnicodeEncodeError, re.error) as exc:
        raise ValueError("invalid ASCII rule pattern") from exc
    # Each frame records whether any descendant repeats.
    frames: list[bool] = [False]
    atom = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if pattern[index + 1].isdigit():
                raise ValueError("backreferences are forbidden")
            index += 2
            atom = False
            continue
        if char == "[":
            index += 1
            if pattern[index] == "^":
                index += 1
            if pattern[index] == "]":
                index += 1
            while pattern[index] != "]":
                index += 2 if pattern[index] == "\\" else 1
            index += 1
            atom = False
            continue
        if char == "(":
            if pattern.startswith("(?:", index):
                index += 3
            elif pattern.startswith("(?", index):
                name = _NAME.match(pattern, index)
                if name is None:
                    raise ValueError("unsupported group construct")
                index = name.end()
            else:
                index += 1
            frames.append(False)
            atom = False
            continue
        if char == ")":
            atom = frames.pop()
            parent = frames[-1]
            frames[-1] = parent or atom
        elif char == "|":
            raise ValueError("express alternatives as separate ordered rules")
        else:
            quantifier = next((match for syntax in _QUANTIFIERS
                               if (match := syntax.match(pattern, index)) is not None), None)
            if char in "*+?" or quantifier is not None:
                if atom:
                    raise ValueError("nested repeat")
                frames[-1] = True
                index = quantifier.end() if quantifier is not None else index + 1
                if index >= len(pattern) or pattern[index] != "+":
                    raise ValueError("every repeat must be explicitly possessive")
                index += 1
                atom = True
                continue
            atom = False
        index += 1
    return compiled
