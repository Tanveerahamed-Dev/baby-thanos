"""Development-only offline consumer for published contract schemas and wire bytes."""
import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from atlas_brain.contract.canonical import canonical


def _local_references(node: object) -> None:
    if isinstance(node, dict):
        for name, value in node.items():
            if name in {"$ref", "$dynamicRef", "$id"} and (
                    not isinstance(value, str) or not value.startswith("#")):
                raise ValueError("external_schema_reference")
            _local_references(value)
    elif isinstance(node, list):
        for value in node:
            _local_references(value)


def validate_wire(schema: dict, data: bytes, *, jsonl: bool = False) -> None:
    _local_references(schema)
    Draft202012Validator.check_schema(schema)  # Runs even for an empty JSONL stream.
    validator = Draft202012Validator(schema)
    if jsonl:
        if data and not data.endswith(b"\n"):
            raise ValueError("jsonl_lf_required")
        records = data.split(b"\n")[:-1] if data else []
    else:
        records = [data]
    for record in records:
        instance = json.loads(record)
        if canonical(instance) != record:
            raise ValueError("noncanonical_contract_bytes")
        validator.validate(instance)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--schema", type=Path, default=Path("docs/contract/header.schema.json"))
    parser.add_argument("--jsonl", action="store_true")
    args = parser.parse_args()
    try:
        validate_wire(json.loads(args.schema.read_bytes()), args.result.read_bytes(), jsonl=args.jsonl)
        return 0
    except (OSError, ValueError, TypeError, SchemaError, ValidationError) as error:
        print(f"contract validation refused ({type(error).__name__})")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
