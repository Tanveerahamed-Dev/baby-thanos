"""RFC 8785 bytes for the contract's integer-only I-JSON subset."""
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
