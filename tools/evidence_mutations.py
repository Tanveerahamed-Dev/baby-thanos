"""Source-bound mutation candidates; never admitted bundles or Tier-M truth."""
import json
from hashlib import sha256
from pathlib import Path

from tools.mutations import _span, apply_span
from tools.provenance import parse, record, relative, validate_tree


def _snapshot(root: Path, provenance: str, expected_sha256: str) -> tuple[bytes, dict]:
    """Reuse V's schema and bind the returned bytes to an unchanged sidecar snapshot."""
    try:
        name = relative(provenance)
        if not name.startswith("fixtures/") or not name.endswith("/provenance.yaml"):
            raise ValueError("fixture provenance path required")
        path = root
        for part in ("", *name.split("/")):
            path = path / part
            if path.is_symlink() or path.is_junction():
                raise ValueError("linked fixture path")
        metadata = path.read_bytes()
        if validate_tree(path.parent):
            raise ValueError("fixture tree refused by shared gate")
        raw_path, fixture_id = record(path)
        data = parse(metadata.decode("utf-8").replace("\r\n", "\n"))
        raw = raw_path.read_bytes()
        digest = sha256(raw).hexdigest()
        if (path.read_bytes() != metadata or raw_path.name != data["file"]
                or fixture_id != data["fixture_id"] or digest != data["sha256"]
                or digest != expected_sha256):
            raise ValueError("stale or changing fixture snapshot")
        return raw, {
            "fixture_id": fixture_id, "provenance": name,
            "provenance_sha256": sha256(metadata).hexdigest(), "raw_sha256": digest,
            "declared_source_tier": data["tier"], "source": data["source"],
            "platform": data["platform"], "capture": data.get("capture"),
        }
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        raise ValueError("fixture snapshot refused") from error


def _candidate(operator: str, parent: dict, raw: bytes, cut: int,
               output: bytes | None, context: tuple[dict, ...]) -> dict:
    receipt = {
        "qualification": "unqualified", "operator": operator, "parent": parent,
        "capture_relationship": "not_verified", "retained_context": list(context),
        "edit": {"start": cut, "end": len(raw), "after_hex": "",
                 "removed_sha256": sha256(raw[cut:]).hexdigest()},
        "artifact": {"present": output is not None,
                     "sha256": None if output is None else sha256(output).hexdigest()},
    }
    if operator == "drop-form":
        receipt["derived_attempt"] = {"attempted": "unknown", "succeeded": "unknown"}
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    receipt["derivation_id"] = sha256(encoded).hexdigest()
    return receipt


def truncate(root: Path, provenance: str, expected_sha256: str, cut: int) -> tuple[bytes, dict]:
    """I3 candidate: retain exactly [0,cut), including an empty present artifact at zero."""
    raw, parent = _snapshot(root, provenance, expected_sha256)
    if type(cut) is not int or not 0 <= cut < len(raw):
        raise ValueError("cut must remove at least one byte")
    output = raw[:cut]
    return output, _candidate("truncate", parent, raw, cut, output, ())


def drop_form(root: Path, provenance: str, expected_sha256: str,
              retained: tuple[tuple[str, str], ...]) -> tuple[None, dict]:
    """I1 candidate: absent artifact plus unknown attempt, with explicit retained references."""
    raw, parent = _snapshot(root, provenance, expected_sha256)
    if not retained:
        raise ValueError("independently supplied retained context required")
    context = []
    ids, digests = {parent["fixture_id"]}, {parent["raw_sha256"]}
    origins = {tuple(sorted(parent["source"]["repository"].items()))}
    for reference, digest in retained:
        _, witness = _snapshot(root, reference, digest)
        origin = tuple(sorted(witness["source"]["repository"].items()))
        if witness["fixture_id"] in ids or witness["raw_sha256"] in digests or origin in origins:
            raise ValueError("duplicate or parent-alias context")
        context.append(witness)
        ids.add(witness["fixture_id"])
        digests.add(witness["raw_sha256"])
        origins.add(origin)
    stable = tuple(sorted(context, key=lambda item: item["provenance"]))
    return None, _candidate("drop-form", parent, raw, 0, None, stable)


def mutate_fixture(root: Path, parent: tuple[str, str], operator: str,
                   start: int, end: int, after: bytes, witness: tuple[str, str],
                   witness_start: int, witness_end: int) -> tuple[bytes, dict]:
    """Bind an unqualified state edit to two public-M0 fixture snapshots, not caller records."""
    raw, source = _snapshot(root, *parent)
    donor, token = _snapshot(root, *witness)
    left, right = source["platform"], token["platform"]
    if (any(ref["declared_source_tier"] not in {"P", "S"} for ref in (source, token))
            or left["family"] not in {"iosxe", "nxos"}
            or any(platform["version_basis"] == "unknown" or platform["version"].lower() in
                   {"unknown", "unstated"} for platform in (left, right))
            or (left["family"], left["version"]) != (right["family"], right["version"])):
        raise ValueError("matching stated public-M0 family/train declarations required")
    same_path = source["provenance"] == token["provenance"]
    if ((same_path and source != token) or (not same_path and
            (source["fixture_id"] == token["fixture_id"]
             or source["source"]["repository"] == token["source"]["repository"]))):
        raise ValueError("conflicting or aliased fixture identity")
    if _span(donor, witness_start, witness_end) != after:
        raise ValueError("replacement absent at complete witness token span")
    output = apply_span(raw, operator, start, end, after)
    receipt = {
        "qualification": "unqualified", "operator": operator, "parent": source,
        "witness_status": "lexical_only", "capture_relationship": "not_verified",
        "token_witness": {"snapshot": token, "span": [witness_start, witness_end],
                          "token_hex": after.hex()},
        "edit": {"start": start, "end": end, "before_hex": raw[start:end].hex(),
                 "after_hex": after.hex()},
        "sha256": sha256(output).hexdigest(),
    }
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    receipt["derivation_id"] = sha256(encoded).hexdigest()
    return output, receipt
