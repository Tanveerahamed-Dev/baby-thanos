"""Manifest bytes over already-serialized result files, never operational receipts."""
import re
from collections.abc import Mapping
from hashlib import sha256

NAME = re.compile(r"(?:result\.json|facts/[a-z][a-z0-9_]*\.jsonl|checks/[a-z][a-z0-9_.]*\.jsonl)", re.ASCII)


def manifest(files: Mapping[str, bytes]) -> bytes:
    if "result.json" not in files:
        raise ValueError("missing_result")
    for name in files:
        if not NAME.fullmatch(name):
            raise ValueError("noncontract_path")
    lines = (f"{sha256(files[name]).hexdigest()}  {name}\n" for name in sorted(files))
    return "".join(lines).encode("utf-8")
