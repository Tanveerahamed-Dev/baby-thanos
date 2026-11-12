"""Typed displayed STP root claims; trusted after owner finish, never fact admission or intended-root proof."""
import re
from dataclasses import dataclass

from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.stp import build
from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.runner.pack_runtime import Executed


def _need(condition: bool, code: str) -> None:
    k.require(condition, "stp_root_identity_" + code)


@dataclass(frozen=True, slots=True, kw_only=True)
class DisplayedRoot:
    """The displayed priority and case-preserved address, with no configured-base inference."""

    priority: int
    address: str

    def __post_init__(self) -> None:
        _need(type(self.priority) is int and 0 <= self.priority <= 65535
              and type(self.address) is str and re.fullmatch(stp.MAC, self.address) is not None, "value")


type RootIdentityClaims = tuple[tuple[stp.Row, DisplayedRoot | None, tuple[k.ByteSpan, ...]], ...]


def _sections(raw: bytes) -> tuple[dict[int, list[tuple[int, int]]],
                                    dict[tuple[bytes, int], list[int]], list[tuple[int, int]]]:
    sections: dict[int, list[tuple[int, int]]] = {}
    keys: dict[tuple[bytes, int], list[int]] = {}
    orphan: list[tuple[int, int]] = []
    current: int | None = None
    start = 0
    for piece in raw.split(b"\n"):
        end = start + len(piece)
        line = piece[:-1] if piece.endswith(b"\r") and end < len(raw) else piece
        stop = start + len(line)
        stripped = line.lstrip(b" \t")
        if re.fullmatch(rb"[ \t]*Port [0-9]+ \(.*", line) is not None:
            current = start
            sections[current] = []
            match = re.fullmatch(rb"[ \t]*Port [0-9]+ \(([^)\r\n]+)\) of VLAN([0-9]{4})(?:[ \t].*)?", line)
            if match is not None:
                key = (match[1], int(match[2]))
                keys.setdefault(key, []).append(start)
        elif (re.fullmatch(rb"[ \t]*[A-Za-z0-9_.:-]+[>#].*", line) is not None
              or stripped.lower() == b"show" or stripped.lower().startswith((b"show ", b"show\t"))):
            current = None
        elif stripped.startswith(b"Designated root"):
            if current is None:
                orphan.append((start, stop))
            else:
                sections[current].append((start, stop))
        start = end + 1
    return sections, keys, orphan


def _identity(row: stp.Row, record: stp.Record, raw: bytes) -> DisplayedRoot:
    names = ("root_priority", "root_mac")
    fields, cells = dict(row.fields), dict(record.fields)
    _need(len(record.fields) == len(cells) == 2 and set(cells) == set(names)
          and all(tuple(name for name, _ in row.fields).count(name) == 1
                  and fields[name] is cells[name] for name in names), "record")
    priority, address = tuple(cells[name] for name in names)
    _need(all(type(token.value) is str and token.value == token.raw and token.raw.isascii()
              for token in (priority, address))
          and priority.raw.isdigit() and len(priority.raw) <= 5
          and str(int(priority.raw)) == priority.raw and int(priority.raw) <= 65535
          and re.fullmatch(stp.MAC, address.raw) is not None, "witness")
    span = record.span
    _need(0 <= span.start < span.end <= len(raw)
          and (span.start == 0 or raw[span.start - 1] == 10)
          and (span.end == len(raw) or raw.startswith((b"\n", b"\r\n"), span.end)), "witness")
    line = raw[span.start:span.end]
    prefix = b"Designated root has priority "
    middle = b", address "
    _need(line.strip(b" \t") == prefix + priority.raw.encode("ascii") + middle + address.raw.encode("ascii"), "witness")
    first = span.start + len(line) - len(line.lstrip(b" \t"))
    for token, at in ((priority, first + len(prefix)),
                      (address, first + len(prefix) + len(priority.raw) + len(middle))):
        _need(token.span.start == at and token.span.end == at + len(token.raw)
              and raw[token.span.start:token.span.end] == token.raw.encode("ascii"), "witness")
    return DisplayedRoot(priority=int(priority.raw), address=address.raw)


def _source_claims[T](target: build.Target, output: Executed[T]) -> RootIdentityClaims:
    """Retain original rows and six original spans; no parser replay, facts or standalone source seal."""
    headers = build.reported_header_proofs(target, output)
    if not any(points for _, points in headers):
        return tuple((row, None, ()) for row, _ in headers)
    raw, parsed = output.receipt.capture.raw, output.value
    if type(parsed) is not stp.Result:
        raise ValueError("stp_root_identity_record")
    sections, keys, orphan = _sections(raw)
    _need(not orphan, "section")
    checked: list[tuple[stp.Row, DisplayedRoot | None, tuple[k.ByteSpan, ...]]] = []
    for row, points in headers:
        if not points:
            checked.append((row, None, ()))
            continue
        header, port, vlan = points[:3]
        _need(keys.get((row.port.encode("ascii"), row.vlan)) == [header.start], "section")
        roots = sections[header.start]
        _need(len(roots) <= 1, "section")
        records = tuple(record for record in parsed.parse.records if record.rule_id == "root"
                        and any(span is record.span for span in row.spans))
        fields = dict(row.fields)
        if not roots and not records and not any(name in fields for name in ("root_priority", "root_mac")):
            checked.append((row, None, ()))
            continue
        _need(len(roots) == len(records) == 1, "record")
        record, = records
        _need((record.span.start, record.span.end) == roots[0], "section")
        identity = _identity(row, record, raw)
        cells = dict(record.fields)
        checked.append((row, identity, (header, port, vlan, record.span,
                                       cells["root_priority"].span, cells["root_mac"].span)))
    return tuple(checked)


def reported_root_identity_proofs[T](target: build.Target, output: Executed[T]) -> RootIdentityClaims:
    """Construct raw claims; producer/profile admission remains the caller's responsibility."""
    return _source_claims(target, output)


def validate_root_identity_claims[T](
    target: build.Target, output: Executed[T], claims: RootIdentityClaims,
) -> RootIdentityClaims:
    """Bind submitted claim data to the same trusted post-owner source; return canonical claims, not a producer seal."""
    expected = _source_claims(target, output)
    _need(type(claims) is tuple and len(claims) == len(expected) and all(type(claim) is tuple
          and len(claim) == 3 and type(claim[2]) is tuple for claim in claims), "claims")
    for (row, root, spans), (original, wanted, points) in zip(claims, expected, strict=True):
        _need(row is original and len(spans) == len(points) and all(type(span) is k.ByteSpan and span is point
              for span, point in zip(spans, points, strict=True)), "claims")
        if wanted is None:
            _need(root is None, "claims")
        else:
            _need(root is not None, "claims")
            if root is not None:
                _need(type(root) is DisplayedRoot, "value")
                try:
                    priority, address = root.priority, root.address
                except AttributeError as error:
                    raise ValueError("stp_root_identity_value") from error
                _need(type(priority) is int and 0 <= priority <= 65535
                      and type(address) is str and re.fullmatch(stp.MAC, address) is not None
                      and priority == wanted.priority and address == wanted.address, "value")
    return expected
