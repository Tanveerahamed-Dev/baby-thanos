"""Generate draft 2020-12 schemas from contract dataclasses; no runtime dependency."""
import re
from dataclasses import fields, is_dataclass
from enum import Enum
from types import UnionType
from typing import (
    Literal,
    NewType,
    TypeAliasType,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

from atlas_brain.contract.canonical import canonical

NUMBER = r"(?:0|[1-9][0-9]*)"
PRE = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER = re.compile(rf"{NUMBER}\.{NUMBER}\.{NUMBER}(?:-{PRE}(?:\.{PRE})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", re.ASCII)


def schema_for(root: type, version: str) -> dict:
    if not SEMVER.fullmatch(version):
        raise ValueError("invalid_schema_version")
    definitions = {}
    owners = {}

    def describe(annotation):
        origin, args = get_origin(annotation), get_args(annotation)
        if isinstance(annotation, TypeAliasType):
            return describe(annotation.__value__)
        if isinstance(annotation, NewType):
            return describe(annotation.__supertype__)
        if annotation is int:
            return {"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}
        if annotation in (str, bool, type(None)):
            return {"type": {str: "string", bool: "boolean", type(None): "null"}[annotation]}
        if origin is Literal:
            canonical(list(args))  # Refuse unsupported literals too.
            return {"enum": list(args)}
        if origin in (Union, UnionType):
            return {"anyOf": [describe(arg) for arg in args]}
        if (origin is list and len(args) != 1) or (origin is dict and (len(args) != 2 or args[0] is not str)):
            raise TypeError("unsupported_contract_type")
        if origin is tuple and args[-1:] == (Ellipsis,) and len(args) != 2:
            raise TypeError("unsupported_contract_type")
        if origin is tuple and args[-1:] != (Ellipsis,):
            if not args:
                return {"type": "array", "maxItems": 0}
            return {"type": "array", "prefixItems": [describe(arg) for arg in args],
                "minItems": len(args), "maxItems": len(args)}
        if origin in (list, tuple) and (origin is list or args[-1:] == (Ellipsis,)):
            return {"type": "array", "items": describe(args[0])}
        if origin is dict and args[0] is str:
            return {"type": "object", "additionalProperties": describe(args[1])}
        if isinstance(annotation, type) and issubclass(annotation, Enum):
            values = [member.value for member in annotation]
            canonical(values)
            return {"enum": values}
        if isinstance(annotation, type) and is_dataclass(annotation):
            name = annotation.__name__
            if name in owners and owners[name] is not annotation:
                raise TypeError("schema_name_collision")
            if name not in definitions:
                owners[name], definitions[name] = annotation, {}
                hints = get_type_hints(annotation)
                definitions[name] = {"type": "object", "additionalProperties": False,
                    "properties": {f.name: describe(hints[f.name]) for f in fields(annotation)},
                    "required": [f.name for f in fields(annotation)]}
            return {"$ref": f"#/$defs/{name}"}
        raise TypeError("unsupported_contract_type")

    shape = describe(root)
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
        "x-schema-version": version, **shape, "$defs": definitions}


def verify_revision(previous: dict, current: dict) -> None:
    if canonical(previous) != canonical(current) and previous["x-schema-version"] == current["x-schema-version"]:
        raise ValueError("schema changed without schema_version change")
