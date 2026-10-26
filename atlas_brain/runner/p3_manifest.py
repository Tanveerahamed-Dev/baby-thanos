"""P3 decoder validates declared structure and types, never network truth."""
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.runner import p3
from atlas_brain.runner.p3_manifest_custody import validate as validate_custody
from atlas_brain.runner.records import RunnerRefused

_KEYS = {"schema", "group", "variant_support", "interpretation", "scope", "timing", "base_registry_sha256",
         "registry_sha256", "nodes", "endpoints", "samples", "adjacencies", "findings", "coverage",
         "denominator", "catalogue_digest", "captures"}
_HOPS = ("peer_context", "ip_mtu", "sampled_persistence", "receiving_control", "candidate")
_TYPES: dict[str, type[object]] = {
    p3.discovery.DEVICE_ID: str, p3.discovery.REMOTE_PORT: str, p3.discovery.BRIDGE: bool,
    p3.link.PEER: str, p3.l2_mtu.MTU: int, p3.l3_mtu.MTU: int,
    p3.s.STATE: str, p3.s.ROLE: str, p3.s.NEIGHBOR_ID: str, p3.s.NEIGHBOR_ADDRESS: str,
    p3.s.ROUTER_ID: str, p3.s.ADDRESS: str, p3.s.PROCESS: int, p3.s.AREA: int,
    p3.s.NETWORK: str, p3.s.VRF: str, p3.s.IGNORE: bool, p3.s.CLOCK: str,
    p3.s.EARLIEST: int, p3.s.LATEST: int, p3.s.ADJACENCY: str, p3.s.INTERFACE: str,
    p3.s.CONTEXT: bool, p3.s.PERSISTENT: bool, p3.s.SPAN: int,
}
_DECLARED = {p3.s.CLOCK, p3.s.EARLIEST, p3.s.LATEST, p3.s.ADJACENCY, p3.s.INTERFACE}


def _need(condition: bool) -> None:
    if not condition:
        raise RunnerRefused("invalid_manifest")


def _mapping(value: object, keys: set[str] | None = None) -> dict[str, object]:
    _need(type(value) is dict)
    row = cast(dict[str, object], value)
    _need(keys is None or set(row) == keys)
    return row


def _rows(value: object) -> list[dict[str, object]]:
    _need(type(value) is list)
    return [_mapping(item) for item in cast(list[object], value)]


def _digest(value: object) -> None:
    _need(type(value) is str)
    try:
        k.digest(cast(str, value))
    except ValueError as error:
        raise RunnerRefused("invalid_manifest") from error


def _identities(rows: list[dict[str, object]], key: str) -> set[str]:
    _need(all(type(row.get(key)) is str and bool(row[key]) for row in rows))
    result = {cast(str, row[key]) for row in rows}
    _need(len(result) == len(rows))
    return result


def _state(value: object, expected: type[object], basis: str, *, allow_na: bool = False) -> dict[str, object]:
    row = _mapping(value)
    state = row.get("state")
    _need(type(row.get("evidence")) is list and bool(row["evidence"]))
    if state == "known":
        _need(set(row) == {"state", "basis", "value", "raw", "evidence"}
              and type(row["value"]) is expected and row["basis"] == basis
              and (row["raw"] is None or type(row["raw"]) is str))
    elif state == "unknown":
        _need(set(row) == {"state", "reason", "detail", "candidates", "next_evidence", "evidence"}
              and row["reason"] in tuple(str(item) for item in k.UnknownReason)
              and (row["detail"] is None or type(row["detail"]) is str)
              and type(row["candidates"]) is list and type(row["next_evidence"]) is list
              and bool(row["next_evidence"]))
        _need(all(type(item) is str for item in cast(list[object], row["candidates"])))
    elif state == "not_applicable" and allow_na:
        _need(set(row) == {"state", "reason", "evidence"}
              and row["reason"] in tuple(str(item) for item in k.NAReason))
    else:
        raise RunnerRefused("invalid_manifest")
    return row


def _facts(value: object, expected: set[str]) -> dict[str, object]:
    facts = _mapping(value, expected)
    for identifier, state in facts.items():
        basis = ("declared" if identifier in _DECLARED else "configured" if identifier == p3.s.IGNORE else
                 "derived" if identifier in p3.s.SETTLE.produces or identifier == p3.link.PEER else "observed")
        _state(state, _TYPES[identifier], basis)
    return facts


def _pair(row: dict[str, object]) -> tuple[str, str]:
    _need(type(row.get("node")) is str and type(row.get("port")) is str)
    return cast(str, row["node"]), cast(str, row["port"])


def validate(payload: object, evidence: object) -> None:
    _need(set(_TYPES) == set(p3.FACT_IDS) and len(_TYPES) == len(p3.FACT_IDS))
    row = _mapping(payload, _KEYS)
    _need(row["schema"] == p3.SCHEMA and row["variant_support"] == "allowlisted"
          and row["interpretation"] == p3.INTERPRETATION and row["scope"] == p3.SCOPE and row["timing"] == p3.TIMING)
    validate_custody(row)
    group = _mapping(row["group"], {"id", "semantic_group", "declaration"})
    _need(type(group["id"]) is str and group["semantic_group"] == "declared_synthetic")
    for name in ("registry_sha256", "base_registry_sha256", "catalogue_digest"):
        _digest(row[name])
    nodes, endpoints = _rows(row["nodes"]), _rows(row["endpoints"])
    samples, adjacencies, findings = _rows(row["samples"]), _rows(row["adjacencies"]), _rows(row["findings"])
    _identities(endpoints, "subject")
    adjacency_ids = _identities(adjacencies, "id")
    _identities(adjacencies, "subject")
    denominator = _mapping(row["denominator"], {"declared_adjacencies", "rounds", "expected_endpoint_samples"})
    _need(all(type(value) is int and value >= 0 for value in denominator.values()))
    _need(denominator == {"declared_adjacencies": len(adjacencies), "rounds": len(samples),
                          "expected_endpoint_samples": 2 * len(adjacencies) * len(samples)})
    coverage = _state(row["coverage"], str, "derived")
    _need(coverage["state"] == "unknown" and coverage["reason"] == "denominator_open")
    declared_points: set[tuple[str, str]] = set()
    for node in nodes:
        ports = node.get("ports")
        _need(type(ports) is list and all(type(port) is str and bool(port) for port in cast(list[object], ports)))
        names = cast(list[str], ports)
        _need(len(set(names)) == len(names))
        declared_points.update((cast(str, node["id"]), port) for port in names)
    base_points = {_pair(point): point["subject"] for point in endpoints}
    _need(len(base_points) == len(endpoints) and set(base_points) == declared_points)
    for point in endpoints:
        _facts(point.get("facts"), {str(fact) for fact in p3.BASE_FACTS})
    expected_points: dict[str, set[tuple[str, str]]] = {}
    adjacency_subjects: dict[str, str] = {}
    for adjacency in adjacencies:
        identifier = cast(str, adjacency["id"])
        declared = _mapping(adjacency.get("declaration"))
        refs = [ref for ref in _rows(declared["evidence"]) if ref.get("kind") == "registry"
                and ref.get("table") == "synthetic_p3.adjacencies" and ref.get("row_id") == identifier]
        _need(len(refs) == 1 and refs[0].get("table_digest") == row["registry_sha256"])
        declaration = _mapping(refs[0].get("value"), {"id", "domain", "area", "left", "right"})
        _need(declaration["id"] == identifier)
        pairs = {_pair(_mapping(declaration[name])) for name in ("left", "right")}
        _need(len(pairs) == 2 and len({node for node, _ in pairs}) == 2 and pairs <= set(base_points))
        expected_points[identifier] = pairs
        adjacency_subjects[identifier] = cast(str, adjacency["subject"])
        _facts(adjacency.get("facts"), {str(fact) for fact in p3.s.SETTLE.produces})
    all_subjects: set[str] = set()
    for sample in samples:
        points = _rows(sample.get("endpoints"))
        subjects = _identities(points, "subject")
        _need(len(points) == 2 * len(adjacencies) and not subjects & all_subjects)
        all_subjects.update(subjects)
        observed: dict[str, list[tuple[str, str]]] = {identifier: [] for identifier in adjacency_ids}
        for point in points:
            identifier = point.get("adjacency")
            _need(type(identifier) is str and identifier in adjacency_ids)
            identifier = cast(str, identifier)
            pair = _pair(point)
            observed[identifier].append(pair)
            _need(pair in expected_points[identifier])
            facts = _facts(point.get("facts"), {str(fact) for fact in p3.p3_pipeline.SAMPLE_FACTS})
            for fact, target in ((p3.s.ADJACENCY, adjacency_subjects[identifier]), (p3.s.INTERFACE, base_points[pair])):
                state = _mapping(facts[str(fact)])
                _need(state["state"] == "known" and state["value"] == target)
        _need(all(len(pairs) == 2 and set(pairs) == expected_points[identifier] for identifier, pairs in observed.items()))
    _need(_identities(findings, "adjacency") == adjacency_ids)
    for finding in findings:
        identifier = cast(str, finding["adjacency"])
        _need(finding.get("subject") == adjacency_subjects[identifier]
              and finding.get("check") == p3.p3_pipeline.r1.CHECK and finding.get("interpretation") == p3.INTERPRETATION
              and finding.get("state") in ("problem", "unknown", "not_applicable"))
        hops = _rows(finding.get("hops"))
        _need(1 <= len(hops) <= len(_HOPS) and tuple(hop.get("id") for hop in hops) == _HOPS[:len(hops)]
              and type(finding.get("evidence")) is list and bool(finding["evidence"])
              and type(finding.get("next_evidence")) is list)
        states = [_state(hop.get("state"), bool, "derived", allow_na=True) for hop in hops]
        _need(all(state["state"] == "known" and state["value"] is True for state in states[:-1]))
        state, last = finding["state"], states[-1]
        if state == "problem":
            _need(len(hops) == len(_HOPS) and last["state"] == "known" and last["value"] is True
                  and finding.get("reason") is None and bool(finding["next_evidence"]))
        else:
            _need(len(hops) < len(_HOPS) and last["state"] == state and last["reason"] == finding.get("reason"))
            _need(state != "unknown" or bool(finding["next_evidence"]))
        receiver = finding.get("receiving_endpoint")
        allowed = tuple(base_points[pair] for pair in expected_points[identifier])
        _need(receiver in allowed if len(hops) >= 3 else receiver is None)
        if len(hops) >= 4:
            controls: list[dict[str, object]] = []
            for control_ref in _rows(states[3]["evidence"]):
                if control_ref.get("kind") == "fact" and control_ref.get("fact") == p3.s.IGNORE:
                    controls.append(control_ref)
            expected_controls = {point["subject"] for sample in samples for point in _rows(sample["endpoints"])
                                 if point["adjacency"] == identifier and base_points[_pair(point)] == receiver}
            _need(len(controls) == len(samples) and {control["subject"] for control in controls} == expected_controls)
    captures = _rows(row["captures"])
    metadata = _mapping(evidence, {"digest", "files", "captures", "registry_sha256", "base_registry_sha256"})
    _need(type(metadata["files"]) is int and type(metadata["captures"]) is int
          and metadata["captures"] == len(captures) and metadata["files"] == len(captures) + 2)
    _need(all(metadata[name] == row[name] for name in ("registry_sha256", "base_registry_sha256")))
    entries = sorted(({"capture": capture["id"], "sha256": capture["sha256"]} for capture in captures),
                     key=lambda entry: cast(str, entry["capture"]))
    expected = {"captures": entries, "registry_sha256": row["registry_sha256"],
                "base_registry_sha256": row["base_registry_sha256"]}
    _need(metadata["digest"] == sha256(canonical(expected)).hexdigest())
    try:
        canonical(payload)
    except (TypeError, ValueError, UnicodeError) as error:
        raise RunnerRefused("invalid_manifest") from error
