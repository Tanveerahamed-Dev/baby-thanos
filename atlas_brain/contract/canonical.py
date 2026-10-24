"""RFC 8785 bytes for the contract's integer-only I-JSON subset."""
import json
from typing import cast


def canonical(value: object) -> bytes:
    return _encode(value).encode("utf-8")


def _encode(value: object) -> str:
    if type(value) not in (type(None), bool, int, str, list, tuple, dict):
        raise TypeError("non_json_type")
    if isinstance(value, (type(None), bool, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        if value not in range(-9007199254740991, 9007199254740992):
            raise ValueError("integer_out_of_range")
        return str(value)
    if isinstance(value, (list, tuple)):
        items = cast("list[object] | tuple[object, ...]", value)
        return f"[{','.join(map(_encode, items))}]"
    entries = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in entries):
        raise TypeError("non_string_key")
    obj = cast(dict[str, object], value)
    keys = sorted(obj, key=lambda key: key.encode("utf-16be"))
    members = (f"{_encode(key)}:{_encode(obj[key])}" for key in keys)
    return f"{{{','.join(members)}}}"
