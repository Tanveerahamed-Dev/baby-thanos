"""Declared raw-byte edits with unqualified receipts; no source tier is assigned."""
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType


@dataclass(frozen=True)
class Operator:
    tokens: frozenset[bytes]
    transitions: frozenset[tuple[bytes, bytes]]


def _pairs(*pairs: tuple[bytes, bytes]) -> Operator:
    transitions = frozenset((*pairs, *((b, a) for a, b in pairs)))
    return Operator(frozenset(t for pair in pairs for t in pair), transitions)


def _numbers(low: int, high: int) -> Operator:
    return Operator(frozenset(str(n).encode("ascii") for n in range(low, high + 1)), frozenset())


OPERATORS = MappingProxyType({
    "ospf-state": _pairs(*((b"FULL", s) for s in (b"EXSTART", b"EXCHANGE", b"INIT", b"2WAY"))),
    "duplex": _pairs((b"full", b"half"), (b"a-full", b"a-half"), (b"Full-duplex", b"Half-duplex")),
    "psu-state": _pairs((b"OK", b"Absent"), (b"Ok", b"Absent"), (b"OK", b"Not Present"),
                        (b"OK", b"failed"), (b"active", b"bad-input")),
    "native-vlan": _numbers(1, 4094),
    "err-disabled": _pairs((b"connected", b"err-disabled")),
    "admin-up-oper-down": _pairs((b"is up, line protocol is up", b"is up, line protocol is down"),
                                 (b"is up", b"is down")),
    "mtu": _numbers(68, 65535),
    "duplicate-address": Operator(frozenset(f"{net}.{n}".encode("ascii")
                                  for net in ("192.0.2", "198.51.100", "203.0.113")
                                  for n in range(1, 255)), frozenset()),
})


@dataclass(frozen=True)
class Capture:
    """Untrusted caller description; never admitted source or witness evidence."""
    fixture_id: str
    family: str
    train: str | None
    tier: str
    raw: bytes
    sha256: str
    provenance: str


def _capture(capture: Capture) -> None:
    if (capture.tier not in {"H", "L", "P"} or capture.family not in {"iosxe", "nxos"}
            or not capture.fixture_id or not isinstance(capture.train, str)
            or not capture.train.strip() or capture.train != capture.train.strip() or capture.train.lower() in {"unstated", "unknown"}
            or type(capture.raw) is not bytes or sha256(capture.raw).hexdigest() != capture.sha256
            or not capture.provenance or "\\" in capture.provenance or ":" in capture.provenance
            or PurePosixPath(capture.provenance).is_absolute()
            or any(p in {"", ".", ".."} for p in capture.provenance.split("/"))):
        raise ValueError("consistent declaration, known train, digest and relative link required")


def _span(raw: bytes, start: int, end: int) -> bytes:
    if type(raw) is not bytes or type(start) is not int or type(end) is not int or not 0 <= start < end <= len(raw):
        raise ValueError("nonempty byte span outside capture")
    # Refuse partial tokens, including full inside a-full or FULL inside FULLNESS.
    word = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
    if (start and raw[start - 1] in word) or (end < len(raw) and raw[end] in word):
        raise ValueError("span splits a token")
    return raw[start:end]


def apply_span(raw: bytes, operator: str, start: int, end: int, after: bytes) -> bytes:
    """One explicit field-token edit; this bare transform makes no provenance/tier claim."""
    if type(after) is not bytes or not isinstance(operator, str) or operator not in OPERATORS:
        raise ValueError("undeclared operator")
    spec = OPERATORS[operator]
    before = _span(raw, start, end)
    if (before not in spec.tokens or after not in spec.tokens or before == after
            or (spec.transitions and (before, after) not in spec.transitions)):
        raise ValueError("absent or undeclared token transition")
    return raw[:start] + after + raw[end:]


def mutate(parent: Capture, operator: str, start: int, end: int, after: bytes,
           witness: Capture, witness_start: int, witness_end: int) -> tuple[bytes, dict]:
    """Return bytes and an explicitly unqualified receipt; caller claims cannot assign M."""
    _capture(parent)
    _capture(witness)
    if (parent.family, parent.train) != (witness.family, witness.train):
        raise ValueError("token witness must have the same family and exact train")
    if _span(witness.raw, witness_start, witness_end) != after:
        raise ValueError("inserted token absent at witness span")
    output = apply_span(parent.raw, operator, start, end, after)
    receipt = {
        "qualification": "unqualified", "family": parent.family, "train": parent.train,
        "source": {
            "kind": "unqualified_text_edit", "parent_fixture": parent.fixture_id,
            "parent_sha256": parent.sha256, "parent_provenance": parent.provenance,
            "operator": operator,
            "token_witness": {"capture_id": witness.fixture_id, "sha256": witness.sha256,
                              "provenance": witness.provenance,
                              "span": [witness_start, witness_end]},
        },
        "edit": {"start": start, "end": end, "before_hex": parent.raw[start:end].hex(),
                 "after_hex": after.hex()},
        "sha256": sha256(output).hexdigest(),
    }
    identity = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    receipt["source"]["mutation_id"] = sha256(identity).hexdigest()
    return output, receipt
