"""Pure contract file bytes from projected objects and authoritative ordered row keys."""
import re
from collections.abc import Mapping
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.manifest import manifest

PACK = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", re.ASCII)
type Rows = Mapping[tuple[str, str], dict[str, object]]


def _key(value: object) -> None:
    if not isinstance(value, tuple):
        raise TypeError("record_key_pair_required")
    pair = cast("tuple[object, ...]", value)
    canonical(pair)  # Refuse custom tuple/string hooks before unpacking or sorting.
    left, right = pair
    if not isinstance(left, str) or not isinstance(right, str):
        raise TypeError("record_key_strings_required")


def _object_bytes(value: object) -> bytes:
    if not isinstance(value, dict):
        raise TypeError("record_object_required")
    return canonical(cast(dict[object, object], value))


def _name(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("group_name_required")
    canonical(value)
    return value


def json_lines(records: Rows) -> bytes:
    """Sort supplied (subject,fact-id) or (check,subject) keys; preserve row values."""
    for key in records:
        _key(key)
    return b"\n".join((*(_object_bytes(records[key]) for key in sorted(records)), b""))


def result_bundle(result: dict[str, object], *, facts: Mapping[str, Rows],
                  checks: Mapping[str, Rows]) -> dict[str, bytes]:
    files = {"result.json": _object_bytes(result)}
    for kind, records in facts.items():
        files[f"facts/{_name(kind)}.jsonl"] = json_lines(records)
    for pack, records in checks.items():
        name = _name(pack)
        if not PACK.fullmatch(name):
            raise ValueError("invalid_pack_id")
        files[f"checks/{name}.jsonl"] = json_lines(records)
    files["MANIFEST.sha256"] = manifest(files)
    return {name: files[name] for name in sorted(files)}
