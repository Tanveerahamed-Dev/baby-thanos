"""Read-only AD-03/AD-07 guards and canonical review-diff hashing."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

MANIFEST = "governance/generators.json"
# Owner-approved plan PR 1 registration, limited to REV's accepted clean head (#7).
BOOTSTRAP = ("361efed5717610e226c1c41c2835f4019f4844ff", "a41f882902b40d698cf64ff058654a7149cf9c79")


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)


def blob(repo: Path, revision: str, path: str) -> bytes | None:
    for row in git(repo, "ls-tree", "-r", "-z", revision).split(b"\0"):
        if row:
            metadata, name = row.split(b"\t", 1)
            if name.decode("utf-8") == path:
                return git(repo, "cat-file", "blob", metadata.split()[2].decode("ascii"))
    return None


def resolve(repo: Path, revision: str) -> str:
    return git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").decode().strip()


def generated(repo: Path, base: str, head: str) -> tuple[str, ...]:
    before = json.loads(blob(repo, base, MANIFEST) or b"{}")
    after = json.loads(blob(repo, head, MANIFEST) or b"{}")
    if before != after:
        if (base, head) != BOOTSTRAP:
            raise ValueError("AD-03: generator changes require a separate owner-approved registration")
        before = after
    if not isinstance(before, dict) or any(
        not isinstance(path, str) or not re.fullmatch(r"[a-zA-Z0-9_.\-/]+", path, re.ASCII)
        or path.startswith("/") or ".." in path.split("/") for path in before
    ):
        raise ValueError("AD-03: invalid generator manifest")
    return tuple(sorted(before))


def excluded(path: str, outputs: tuple[str, ...]) -> bool:
    return path in outputs or path.startswith(("fixtures/", "tests/goldens/"))


def changes(repo: Path, base: str, head: str) -> list[tuple[bytes, bytes, str]]:
    rows = git(repo, "diff", "--numstat", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", base, head).split(b"\0")
    return [(a, d, p.decode("utf-8")) for row in rows if row for a, d, p in [row.split(b"\t", 2)]]


def diff_digest(repo: Path, base: str, head: str) -> str:
    # Published REV format; retain historical hashes instead of silently rebinding records.
    base, head = resolve(repo, base), resolve(repo, head)
    outputs = generated(repo, base, head)
    patch = git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", "--no-color",
                base, head, "--", ".", *[f":(exclude,literal){p}" for p in outputs])
    return hashlib.sha256(patch).hexdigest()


def adr_status(data: bytes) -> tuple[bytes, bytes, bytes]:
    markers = re.findall(rb"(?m)^[ \t]*Status:", data)
    match = re.search(rb"(?m)^Status: ([a-z][a-z0-9_-]*)(?=\r?$)", data)
    if len(markers) != 1 or match is None:
        raise ValueError("AD-07: ADR requires exactly one well-formed status line")
    return data[:match.start()], data[match.end():], match[1]


def audit(repo: Path, base: str, head: str) -> dict[str, int | str]:
    base, head = resolve(repo, base), resolve(repo, head)
    outputs, count, classes = generated(repo, base, head), 0, set()
    for added, deleted, path in changes(repo, base, head):
        if not excluded(path, outputs):
            if b"-" in (added, deleted):
                raise ValueError("AD-03: uncountable binary change")
            count += int(added) + int(deleted)
            parts = path.split("/")
            if parts[0] == "atlas_brain" and len(parts) > 1:
                depth = 4 if parts[1] == "packs" else 3 if parts[1] == "platform" else len(parts)
                classes.add("/".join(parts[:depth]))
        if path.startswith("docs/adr/"):
            old, new = blob(repo, base, path), blob(repo, head, path)
            text = new.decode("utf-8") if new is not None else ""
            if len(text.splitlines()) > 60 or len(text) > 4000:
                raise ValueError("AD-07: ADR exceeds 60 lines or 4000 characters")
            current = adr_status(new) if new is not None else None
            previous = adr_status(old) if old is not None else None
            if (previous is not None and previous[2] == b"accepted"
                    and (current is None or previous[:2] != current[:2])):
                raise ValueError("AD-07: accepted ADR is immutable except its status line")
    if count > 400 or len(classes) > 1:
        raise ValueError("AD-03: more than 400 changed lines or multiple production path classes")
    return {"counted_lines": count, "diff_sha256": diff_digest(repo, base, head),
            "base_sha": base, "head_sha": head}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()
    try:
        print(json.dumps(audit(Path.cwd(), args.base, args.head), sort_keys=True))
        return 0
    except (ValueError, TypeError, OSError, subprocess.CalledProcessError):
        print("governance audit refused; inspect AD-03/AD-07 self-tests and input commits")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
