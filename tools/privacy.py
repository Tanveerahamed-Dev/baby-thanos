"""Scan Git blobs as data; receipts contain only blob IDs and byte offsets."""
import argparse
import ast
import ipaddress
import itertools
import json
import os
import re
import subprocess

HOME = re.compile(rb"(?i:[a-z]:[\\/]+Users[\\/]+[^\\/\s\"'<>]+|/(?:home|Users)/[^/\s\"'<>]+)", re.ASCII)
SERIAL = re.compile(rb"\b[A-Z]{3}[0-9]{4}[A-Z0-9]{4}\b", re.ASCII | re.IGNORECASE)
IP = re.compile(rb"(?<![\w:.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])|(?<![\w:])[0-9a-fA-F:.]*:[0-9a-fA-F:.]*:[0-9a-fA-F:.]*(?![\w:])", re.ASCII)
DOCS = tuple(map(ipaddress.ip_network, ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")))
COMMENT = rb"\#[^\n]*|//[^\n]*|/\*.*?\*/"
LITERAL = re.compile(rb"(?P<comment>" + COMMENT + rb")|(?i:br|rb|fr|rf|tr|rt|[bruft])?(?:" + rb'"(?:\\.|[^"\\])*"' + rb"|'(?:\\.|[^'\\])*')", re.ASCII | re.DOTALL)
PIECE = re.compile(rb"\\(?:\r?\n|U[0-9a-fA-F]{8}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|.)|[^\\]", re.ASCII | re.DOTALL)


def literal_runs(data: bytes):
    chunks, offsets, previous = [], [], 0
    for match in LITERAL.finditer(data):
        if match["comment"] is not None:
            continue
        if re.fullmatch(rb"(?:[\s+()]|\\\r?\n|" + COMMENT + rb")*", data[previous:match.start()], re.ASCII | re.DOTALL) is None:
            yield b"".join(chunks), offsets
            chunks, offsets = [], []
        quote = next(i for i, char in enumerate(match[0]) if char in (34, 39))
        for piece in PIECE.finditer(match[0][quote + 1:-1]):
            raw = piece[0]
            try:
                value = ast.literal_eval('"' + raw.decode("ascii") + '"').encode() if raw.startswith(b"\\") and b"r" not in match[0][:quote].lower() else raw
            except (ValueError, SyntaxError, UnicodeError):
                value = raw
            chunks.append(value)
            offsets.extend([match.start() + quote + 1 + piece.start()] * len(value))
        previous = match.end()
    yield b"".join(chunks), offsets


def structural_offsets(data: bytes) -> set[int]:
    offsets = {m.start() for pattern in (HOME, SERIAL) for m in pattern.finditer(data)}
    for match in IP.finditer(data):
        try:
            address = ipaddress.ip_address(match[0].decode("ascii"))
        except ValueError:
            continue
        if address.is_private and not any(address in net for net in DOCS):
            offsets.add(match.start())
    return offsets


def scan(data: bytes, blob: str, markers: list[bytes]) -> list[dict[str, str | int]]:
    offsets = set()
    for content, positions in itertools.chain([(data, range(len(data)))], literal_runs(data)):
        found = structural_offsets(content)
        for marker in markers:
            for match in re.finditer(re.escape(marker), content, re.ASCII | re.IGNORECASE):
                found.add(match.start())
        offsets.update(positions[offset] for offset in found)
    return [{"blob": blob, "offset": offset} for offset in sorted(offsets)]


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--gate", action="store_true")
    args = parser.parse_args()
    try:
        markers = json.loads(os.environ["ATLAS_PRIVACY_MARKERS"]) if args.gate else []
        if args.gate and (not isinstance(markers, list) or not markers or
                          any(not isinstance(m, str) or not m for m in markers)):
            raise ValueError
        encoded = [m.encode("utf-8") for m in markers]
        # Scan every outgoing historical blob: removing a planted hit cannot erase it.
        if args.base:
            objects = git("rev-list", "--objects", "--no-object-names", f"{args.base}..{args.head}").decode("ascii").splitlines()
            blobs = {oid for oid in objects if git("cat-file", "-t", oid).strip() == b"blob"}
        else:
            records = git("ls-files", "--stage", "-z").split(b"\0")
            blobs = {r.split()[1].decode("ascii") for r in records if r}
        hits = [hit for blob in sorted(blobs) for hit in scan(git("cat-file", "blob", blob), blob, encoded)]
        print(json.dumps(hits, sort_keys=True))
        return int(bool(hits))
    except (KeyError, ValueError, TypeError, OSError, subprocess.CalledProcessError):
        print("privacy scan refused: invalid configuration or unreadable Git data")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
