"""Regenerate the header schema and bind changes to its real Git-base version."""
import argparse
import json
import subprocess
from pathlib import Path
from typing import get_args, get_type_hints

from atlas_brain.contract.canonical import canonical
from atlas_brain.contract.header import ResultHeader
from tools.contract_schema import schema_for, verify_revision

OUTPUT = Path("docs/contract/header.schema.json")
SOURCE = "atlas_brain/contract/header.py"


def generated_header() -> dict:
    (version,) = get_args(get_type_hints(ResultHeader)["schema_version"])
    return schema_for(ResultHeader, version)


def verify_base(current: dict, base: str) -> None:
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "--end-of-options",
        f"{base}^{{commit}}"], stderr=subprocess.DEVNULL).decode("ascii").strip()
    paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", commit,
        "--", OUTPUT.as_posix(), SOURCE]).decode("ascii").splitlines()
    if OUTPUT.as_posix() not in paths:
        if SOURCE in paths:
            raise ValueError("baseline_schema_missing")
        return  # First publication is allowed only before the header source exists.
    previous = json.loads(subprocess.check_output(
        ["git", "show", f"{commit}:{OUTPUT.as_posix()}"], stderr=subprocess.DEVNULL))
    verify_revision(previous, current)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--base")
    args = parser.parse_args()
    try:
        schema = generated_header()
        data = canonical(schema)
        if args.write:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_bytes(data)
        elif OUTPUT.read_bytes() != data:
            raise ValueError("generated_schema_stale")
        if args.base:
            verify_base(schema, args.base)
        return 0
    except (ValueError, TypeError, OSError, subprocess.CalledProcessError):
        print("contract schema publication refused")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
