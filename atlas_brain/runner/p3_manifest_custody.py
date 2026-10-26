"""Projected P3 custody consistency; no raw-byte authentication or R1 recomputation."""
import re
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import member_names
from atlas_brain.evidence.p3_records import OPERATIONS, SCHEMA
from atlas_brain.kernel import states as k
from atlas_brain.runner.records import RunnerRefused

type Row = dict[str, object]
_BASE = {"iosxe.show_cdp_neighbors_detail": "show cdp neighbors detail",
         "iosxe.show_lldp_neighbors_detail": "show lldp neighbors detail"}
_COMMANDS = _BASE | OPERATIONS
_SHAPES = {"group": {"id", "semantic_group", "declaration"},
    "node": {"id", "key", "discovery_id", "ports", "declaration"},
    "endpoint": {"node", "port", "subject", "facts"}, "sample": {"id", "declaration", "endpoints"},
    "point": {"adjacency", "node", "port", "subject", "facts"},
    "adjacency": {"id", "subject", "declaration", "facts"},
    "finding": {"check", "adjacency", "subject", "state", "reason", "interpretation", "receiving_endpoint",
                "hops", "evidence", "next_evidence"},
    "hop": {"id", "state"}, "capture": {"id", "source", "sample", "operation", "rendered", "sha256",
                "integrity", "read_scope", "view", "parse", "owner", "evidence"}}
_REG = {"kind", "table", "row_id", "table_digest", "citation", "value"}
_CAP = {"kind", "capture", "source", "path", "operation", "rendered", "role", "sha256",
        "capture_sha256", "integrity", "read_scope", "view", "locator"}
_NEED = {"node", "operation", "rendered", "params", "resolves", "reruns", "after_s", "unprintable"}


def _need(condition: bool) -> None:
    if not condition:
        raise RunnerRefused("invalid_manifest")


def _row(value: object, keys: set[str] | None = None) -> Row:
    _need(type(value) is dict)
    result = cast(Row, value)
    _need(keys is None or set(result) == keys)
    return result


def _rows(value: object, keys: set[str] | None = None) -> list[Row]:
    _need(type(value) is list)
    return [_row(item, keys) for item in cast(list[object], value)]


def _text(value: object) -> str:
    _need(type(value) is str and bool(value))
    return cast(str, value)


def _ipv4(value: object) -> str:
    token = _text(value)
    parts = token.split(".")
    _need(len(parts) == 4 and all(
        1 <= len(part) <= 3 and part.isascii() and part.isdigit()
        and int(part) <= 255 and str(int(part)) == part for part in parts))
    return token


def _identifier(value: object) -> str:
    value = _text(value)
    _need(re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value, re.ASCII) is not None)
    return value


def _hash(prefix: str, value: object) -> str:
    return prefix + sha256(canonical(value)).hexdigest()


def _same(left: object, right: object) -> bool:
    return canonical(left) == canonical(right)


class _Custody:
    def __init__(self, payload: object) -> None:
        self.payload = _row(payload)
        self.registry: dict[tuple[str, str], Row] = {}
        self.indices: dict[str, set[int]] = {}
        self.facts: dict[tuple[str, str], Row] = {}
        self.captures: dict[str, Row] = {}
        self.node_keys: dict[str, str] = {}
        self.participants: set[str] = set()

    def declaration(self, value: object, family: str, identifier: str, digest: object) -> object:
        state = _row(value, {"state", "basis", "value", "raw", "evidence"})
        _need(state["state"] == "known" and state["basis"] == "declared"
              and state["value"] == state["raw"] == identifier)
        refs = _rows(state["evidence"], _REG)
        _need(len(refs) == 1)
        ref = refs[0]
        table = "synthetic_p2." + family if family in ("groups", "nodes") else "synthetic_p3." + family
        _need(ref["kind"] == "registry" and ref["table"] == table
              and ref["row_id"] == identifier and ref["table_digest"] == digest)
        citation = _text(ref["citation"])
        if family == "groups":
            _need(citation == "/group" and ref["value"] == identifier)
        else:
            prefix = "/" + family + "/"
            token = citation.removeprefix(prefix)
            _need(citation.startswith(prefix) and len(token) <= 10 and token.isascii() and token.isdigit()
                  and str(int(token)) == token)
            indices = self.indices.setdefault(family, set())
            _need(int(token) not in indices)
            indices.add(int(token))
        key = table, identifier
        _need(key not in self.registry)
        self.registry[key] = ref
        return ref["value"]

    def register(self, row: Row) -> None:
        subject = _text(row["subject"])
        for identifier, state in _row(row["facts"]).items():
            key = identifier, subject
            _need(key not in self.facts)
            self.facts[key] = _row(state)

    def scope(self, value: object) -> tuple[object, ...]:
        point = _row(value, {"node", "port", "process", "router_id", "address", "vrf"})
        node = _identifier(point["node"])
        _need(node in self.node_keys and type(point["process"]) is int and 1 <= point["process"] <= 65535)
        router_id, address = _ipv4(point["router_id"]), _ipv4(point["address"])
        vrf = _text(point["vrf"])
        _need(vrf == "default")
        self.participants.add(self.node_keys[node])
        return self.node_keys[node], _text(point["port"]), point["process"], router_id, address, vrf

    def needs(self, value: object) -> None:
        for need in _rows(value, _NEED):
            operation = _text(need["operation"])
            _need(operation in _COMMANDS and need["rendered"] == _COMMANDS[operation] and need["params"] == [])
            _need(need["node"] in (tuple(self.node_keys.values()) if operation in _BASE else tuple(self.participants)))
            _need(need["after_s"] is None or type(need["after_s"]) is int and need["after_s"] >= 0)
            for field in ("resolves", "reruns", "unprintable"):
                _need(type(need[field]) is list)
                items = [_text(item) for item in cast(list[object], need[field])]
                _need(items == sorted(set(items)))

    def state(self, value: object, chain: tuple[tuple[str, str], ...] = ()) -> None:
        state = _row(value)
        shapes = {"known": {"state", "basis", "value", "raw", "evidence"},
                  "unknown": {"state", "reason", "detail", "candidates", "next_evidence", "evidence"},
                  "not_applicable": {"state", "reason", "evidence"}}
        label = _text(state.get("state"))
        _need(label in shapes and set(state) == shapes[label])
        if label == "unknown":
            self.needs(state["next_evidence"])
        self.proofs(state["evidence"], chain)

    def proofs(self, value: object, chain: tuple[tuple[str, str], ...] = ()) -> None:
        _need(len(chain) <= 32)
        for proof in _rows(value):
            if proof.get("kind") == "registry":
                _row(proof, _REG)
                key = _text(proof["table"]), _text(proof["row_id"])
                _need(key in self.registry and _same(proof, self.registry[key]))
            elif proof.get("kind") == "capture":
                identity = _text(proof.get("capture"))
                _need(identity in self.captures)
                expected = dict(self.captures[identity])
                role = proof.get("role")
                _need(role in tuple(str(item) for item in k.EvidenceRole) and (not chain or role == "subject"))
                expected["role"] = role
                if proof.get("locator") == "bytes":
                    _need(type(proof.get("start")) is int and type(proof.get("end")) is int
                          and 0 <= cast(int, proof["start"]) <= cast(int, proof["end"]))
                    k.digest(_text(proof.get("sha256")))
                    expected.update(locator="bytes", start=proof["start"], end=proof["end"], sha256=proof["sha256"])
                _need(_same(proof, expected))
            elif proof.get("kind") == "fact":
                _row(proof, {"kind", "fact", "subject", "state"})
                key = _text(proof["fact"]), _text(proof["subject"])
                _need(key in self.facts and key not in chain and _same(proof["state"], self.facts[key]))
                self.state(proof["state"], chain + (key,))
            else:
                raise RunnerRefused("invalid_manifest")

    def validate(self) -> None:
        payload = self.payload
        group = _row(payload.get("group"), _SHAPES["group"])
        group_id = _identifier(group["id"])
        base_digest, digest = _text(payload.get("base_registry_sha256")), _text(payload.get("registry_sha256"))
        k.digest(base_digest)
        k.digest(digest)
        self.declaration(group["declaration"], "groups", group_id, base_digest)
        nodes, adjacencies = _rows(payload.get("nodes"), _SHAPES["node"]), _rows(payload.get("adjacencies"), _SHAPES["adjacency"])
        samples = _rows(payload.get("samples"), _SHAPES["sample"])
        _need(1 <= len(nodes) <= 32 and 1 <= len(adjacencies) <= 16 and len(samples) <= 16)
        for node in nodes:
            identifier = _identifier(node["id"])
            _need(identifier not in self.node_keys and node["key"] == "node:" + group_id + ":" + identifier)
            self.node_keys[identifier] = _text(node["key"])
            _text(node["discovery_id"])
            declared = _row(self.declaration(node["declaration"], "nodes", identifier, base_digest), {"id", "discovery_id", "ports"})
            _need(declared["id"] == identifier and declared["discovery_id"] == node["discovery_id"])
            ports = [_text(port) for port in cast(list[object], declared["ports"])] if type(declared["ports"]) is list else []
            _need(1 <= len(ports) <= 128 and len(set(ports)) == len(ports) and sorted(ports) == node["ports"])
        for point in _rows(payload.get("endpoints"), _SHAPES["endpoint"]):
            node, port = _identifier(point["node"]), _text(point["port"])
            _need(node in self.node_keys and point["subject"] == _hash("interface:", (self.node_keys[node], port)))
            self.register(point)
        contexts: dict[str, tuple[object, ...]] = {}
        scopes: dict[str, dict[tuple[str, str], tuple[object, ...]]] = {}
        for adjacency in adjacencies:
            identifier = _identifier(adjacency["id"])
            value = _row(self.declaration(adjacency["declaration"], "adjacencies", identifier, digest),
                         {"id", "domain", "area", "left", "right"})
            _need(value["id"] == identifier and type(value["area"]) is int and 0 <= value["area"] <= 4294967295)
            left, right = self.scope(value["left"]), self.scope(value["right"])
            context = (SCHEMA, identifier, _identifier(value["domain"]), value["area"], left, right)
            _need(identifier not in contexts and adjacency["subject"] == _hash("ospf_adjacency:", context))
            contexts[identifier] = context
            scopes[identifier] = {(cast(str, point[0]), cast(str, point[1])): point for point in (left, right)}
            self.register(adjacency)
        expected: dict[str, tuple[Row, str, object]] = {}
        sample_ids: list[str] = []
        for sample in samples:
            identifier = _identifier(sample["id"])
            _need(identifier not in sample_ids)
            sample_ids.append(identifier)
            value = _row(self.declaration(sample["declaration"], "samples", identifier, digest), {"id", "time", "captures"})
            _need(value["id"] == identifier)
            if value["time"] is not None:
                time = _row(value["time"], {"unit", "clock", "earliest", "latest", "bound"})
                _need(time["unit"] == "unix_us" and time["bound"] == "collector_recorded"
                      and re.fullmatch(r"collector:[A-Za-z0-9_.:/-]{1,64}", _text(time["clock"]), re.ASCII) is not None
                      and type(time["earliest"]) is int and type(time["latest"]) is int
                      and 0 <= time["earliest"] <= time["latest"] <= 9007199254740991)
            pairs: set[tuple[str, str]] = set()
            for ref in _rows(value["captures"], {"path", "node", "operation", "sha256"}):
                pair = _identifier(ref["node"]), _text(ref["operation"])
                _need(pair not in pairs and pair[1] in OPERATIONS)
                pairs.add(pair)
                identity = _hash("cap:", (SCHEMA, digest, base_digest, identifier,
                    ref["node"], ref["path"], ref["operation"], ref["sha256"]))
                _need(identity not in expected)
                expected[identity] = ref, identifier, value["time"]
            for point in _rows(sample["endpoints"], _SHAPES["point"]):
                adjacency = _identifier(point["adjacency"])
                node = self.node_keys[_identifier(point["node"])]
                scope = scopes[adjacency][node, _text(point["port"])]
                _need(point["subject"] == _hash("ospf_sample:", contexts[adjacency] + (scope, identifier)))
                self.register(point)
        for family, count in (("nodes", len(nodes)), ("adjacencies", len(adjacencies)), ("samples", len(samples))):
            _need(self.indices.get(family, set()) == set(range(count)))
        seen: set[str] = set()
        paths, baseline = ["p2.json", "p3.json"], 0
        baseline_pairs: set[tuple[str, str]] = set()
        for capture in _rows(payload.get("captures"), _SHAPES["capture"]):
            identity = _text(capture["id"])
            proofs = _rows(capture["evidence"])
            _need(identity not in self.captures and len(proofs) == 1)
            proof = proofs[0]
            if identity in expected:
                ref, sample_id, collected = expected[identity]
                source = self.node_keys[_identifier(ref["node"])]
                seen.add(identity)
            else:
                _row(proof, _CAP)
                source = _text(proof["source"])
                node = next((identifier for identifier, key in self.node_keys.items() if key == source), None)
                ref = {"node": node, "path": proof["path"], "operation": proof["operation"], "sha256": proof["capture_sha256"]}
                _need(node is not None and ref["operation"] in _BASE
                      and identity == _hash("cap:", ("atlas-brain.synthetic-p2/1", group_id, base_digest,
                          ref["path"], node, ref["operation"], ref["sha256"])))
                pair = _text(node), _text(ref["operation"])
                _need(pair not in baseline_pairs)
                baseline_pairs.add(pair)
                sample_id, collected = None, None
                baseline += 1
            operation, path, raw_hash = _text(ref["operation"]), _text(ref["path"]), _text(ref["sha256"])
            k.digest(raw_hash)
            owner = ("l2.discovery/parse" if operation in _BASE else "l2.mtu/parse_samples"
                     if operation == "iosxe.show_interfaces" else "l3.mtu/parse_samples"
                     if operation == "iosxe.show_ip_interface" else "l3.ospf/parse_samples")
            _need(capture["owner"] == owner and capture["parse"] in ("complete", "partial")
                  and capture["integrity"] in tuple(str(item) for item in k.IntegrityState)
                  and capture["read_scope"] in tuple(str(item) for item in k.ReadScope)
                  and capture["view"] in tuple(str(item) for item in k.ViewConsistency))
            _need(operation in _COMMANDS and capture["source"] == source and capture["sample"] == sample_id
                  and capture["operation"] == operation and capture["rendered"] == _COMMANDS[operation] and capture["sha256"] == raw_hash)
            expected_proof: Row = {"kind": "capture", "capture": identity, "source": source, "path": path,
                "operation": operation, "rendered": _COMMANDS[operation], "role": "subject", "sha256": raw_hash,
                "capture_sha256": raw_hash, "integrity": capture["integrity"], "read_scope": capture["read_scope"],
                "view": capture["view"], "locator": "whole_capture"}
            if sample_id is not None:
                expected_proof.update(sample=sample_id, collected_utc=collected)
            _need(_same(proof, expected_proof))
            self.captures[identity] = expected_proof
            paths.append(path)
        _need(seen == set(expected) and len(expected) <= 64 and 1 <= baseline <= 64)
        member_names(paths)
        for key, state in self.facts.items():
            self.state(state, (key,))
        self.state(payload.get("coverage"))
        findings = _rows(payload.get("findings"), _SHAPES["finding"])
        _need(len(findings) == len(contexts) and {_text(item["adjacency"]) for item in findings} == set(contexts))
        for finding in findings:
            adjacency = _identifier(finding["adjacency"])
            _need(finding["subject"] == _hash("ospf_adjacency:", contexts[adjacency]))
            hops = _rows(finding["hops"], _SHAPES["hop"])
            for hop in hops:
                self.state(hop["state"])
            self.proofs(finding["evidence"])
            self.needs(finding["next_evidence"])
            if finding["state"] == "problem":
                _need(len(sample_ids) >= 2 and len(hops) == 5)
                refs = _rows(_row(hops[3]["state"])["evidence"], {"kind", "fact", "subject", "state"})
                _need(len(refs) == len(sample_ids) and all(ref["kind"] == "fact" and ref["fact"] == "l3.ospf.mtu_ignore"
                      and _row(ref["state"]).get("state") == "known" and _row(ref["state"]).get("value") is False
                      and _row(ref["state"]).get("raw") == "no ip ospf mtu-ignore" for ref in refs))
                subjects = {ref["subject"] for ref in refs}
                matches = [_hash("interface:", key) for key, scope in scopes[adjacency].items()
                    if subjects == {_hash("ospf_sample:", contexts[adjacency] + (scope, sample)) for sample in sample_ids}]
                _need(len(matches) == 1 and finding["receiving_endpoint"] == matches[0])


def validate(payload: object) -> None:
    try:
        _Custody(payload).validate()
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        raise RunnerRefused("invalid_manifest") from error
