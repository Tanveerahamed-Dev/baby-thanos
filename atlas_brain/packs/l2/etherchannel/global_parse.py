"""Production EtherChannel preparation for one trusted, declared-synthetic global parser run."""
import re
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration
from atlas_brain.packs.l2.etherchannel import build, parse_summary
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Handler, Parsed, Parser


class _Adapter(Parser[parse_summary.Result]):
    def __init__(self, targets: dict[k.CaptureId, build.Target]) -> None:
        self.targets = targets

    def parse(self, request: CaptureRequest) -> Parsed[parse_summary.Result]:
        target = self.targets[request.capture.id]
        value = parse_summary.parse_capture(request.capture, target.groups, target.ports)
        return value, value.parse


def _strings(value: object) -> tuple[str, ...]:
    if type(value) is not list:
        raise ValueError("etherchannel_folder_strings")
    items: list[object] = value
    k.require(all(type(item) is str for item in items), "etherchannel_folder_strings")
    return tuple(item for item in items if type(item) is str)


def _records(value: object, fields: tuple[str, ...], key: str) -> dict[str, tuple[int, dict[str, object]]]:
    if type(value) is not list:
        raise ValueError("etherchannel_folder_registry")
    items: list[object] = value
    rows: dict[str, tuple[int, dict[str, object]]] = {}
    for index, item in enumerate(items):
        row = record(item, fields)
        identity = string(row, key)
        k.require(identity not in rows, "etherchannel_folder_registry")
        rows[identity] = (index, row)
    return rows


def _reference(state: k.Known[str], table: str, identity: str, digest: str, pointer: str) -> None:
    ref = k.RegistryRef(table=table, row_id=identity, table_digest=digest, citation=pointer)
    k.require(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.raw == state.value == identity
              and state.evidence == (ref,), "etherchannel_folder_declaration")


def _integrity(raw: bytes) -> k.IntegrityState:
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError("etherchannel_folder_text") from error
    k.require(not any(ord(c) < 32 and c not in "\t\n" or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in text),
              "etherchannel_folder_text")
    lines = [line for line in text.split("\n") if line.strip(" \t")]
    opening = re.fullmatch(r"([A-Za-z0-9_.:-]+[>#]) ?(.+)", lines[0], re.ASCII) if lines else None
    missing = False
    if opening:
        k.require(opening[2] == parse_summary.COMMAND, "etherchannel_folder_frame")
        missing = lines[-1] != opening[1]
        lines = lines[1:] if missing else lines[1:-1]
    elif lines and lines[0] == parse_summary.COMMAND:
        lines = lines[1:]
    forbidden = (r"(?:[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*|(?:do[ \t]+)?sh(?:ow|o)?(?:[ \t].*)?|!|"
                 r"(?:end|exit|configure|building configuration|current configuration|banner|interface|router|vlan|"
                 r"hostname|spanning-tree|switchport|description|shutdown|no|default)(?:[ \t:].*)?)")
    k.require(not any(re.fullmatch(forbidden, line.strip().casefold(), re.ASCII) for line in lines), "etherchannel_folder_frame")
    if any(line.lstrip().startswith("%") or line.strip().casefold() in ("command authorization failed", "command authorization failed.") for line in lines):
        return k.IntegrityState.ERROR
    if any(line.strip().casefold() in ("--more--", "<--- more --->", "--(more)--") for line in lines):
        return k.IntegrityState.PAGING_ARTIFACTS
    if any(line.strip().casefold() in ("[truncated]", "<output truncated>") for line in lines):
        return k.IntegrityState.TRUNCATED
    k.require(not missing, "etherchannel_folder_frame")
    if not lines:
        return k.IntegrityState.EMPTY
    first = " ".join(part for part in lines[0].replace("\t", " ").split(" ") if part)
    legend = first in (
        "Flags: D - down P - bundled in port-channel", "I - stand-alone s - suspended",
        "H - Hot-standby (LACP only)", "R - Layer3 S - Layer2", "U - in use f - failed to allocate aggregator",
        "M - not in use, minimum links not met", "u - unsuitable for bundling", "w - waiting to be aggregated",
        "d - default port", "A - formed by Auto LAG",
    )
    return k.IntegrityState.COMPLETE if legend or re.fullmatch(r"Number of channel-groups in use:[ \t]*[0-9]+[ \t]*", lines[0], re.ASCII) else k.IntegrityState.UNKNOWN_FORMAT


def _scope(envelope: p4.Envelope, budgets: Budgets) -> tuple[
    tuple[p4.Target, ...], dict[k.CaptureId, build.Target], tuple[CaptureRequest, ...],
]:
    k.require(type(envelope) is p4.Envelope and type(envelope.raw) is bytes
              and type(envelope.base) is SyntheticGroup and type(envelope.base.raw) is bytes, "etherchannel_folder_registry")
    base, context = envelope.base, envelope.context
    p4_digest, base_digest = sha256(envelope.raw).hexdigest(), sha256(base.raw).hexdigest()
    side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
                  ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    registry = record(strict_json(base.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
    k.require(side["schema"] == p4.SCHEMA and side["semantic_group"] == "declared_synthetic" and side["context"] == context
              and side["base_sha256"] == base_digest and registry["group"] == base.id and registry["semantic_group"] == "declared_synthetic"
              and registry["schema"] == base.schema == BASE_SCHEMA, "etherchannel_folder_registry")
    _reference(base.declaration, "synthetic_p2.groups", base.id, base_digest, "/group")
    _reference(envelope.declaration, "synthetic_p4.context", context, p4_digest, "/context")
    node_rows = _records(registry["nodes"], ("id", "discovery_id", "ports"), "id")
    target_rows = _records(side["targets"], ("id", "node", "operation", "params"), "id")
    capture_rows = _records(side["captures"], ("target", "path", "sha256"), "path")
    k.require(type(base.nodes) is tuple and all(type(node) is Node for node in base.nodes), "etherchannel_folder_node")
    nodes = {node.id: node for node in base.nodes}
    k.require(set(nodes) == set(node_rows) and len(nodes) == len(base.nodes), "etherchannel_folder_node")
    k.require(type(envelope.targets) is tuple and all(type(item) is p4.Target for item in envelope.targets), "etherchannel_folder_target")
    declared = {item.id: item for item in envelope.targets}
    k.require(set(declared) == set(target_rows) and len(declared) == len(envelope.targets), "etherchannel_folder_target")
    targets: dict[str, build.Target] = {}
    owned_nodes: set[k.EntityKey] = set()
    for item in envelope.targets:
        index, row = target_rows[item.id]
        node_id = string(row, "node")
        k.require(node_id in nodes and item.node is nodes[node_id] and item.operation == row["operation"]
                  and type(item.params) is bytes and canonical(row["params"]) == item.params, "etherchannel_folder_target")
        _reference(item.declaration, "synthetic_p4.targets", item.id, p4_digest, f"/targets/{index}")
        if item.operation != parse_summary.OP:
            k.require(item.owner != build.STEP.id, "etherchannel_folder_target")
            continue
        node = item.node
        node_index, node_row = node_rows[node_id]
        k.require(item.owner == build.STEP.id and node.group == base.id and node.discovery_id == node_row["discovery_id"]
                  and tuple(sorted(_strings(node_row["ports"]))) == node.ports, "etherchannel_folder_node")
        _reference(node.declaration, "synthetic_p2.nodes", node_id, base_digest, f"/nodes/{node_index}")
        params = record(row["params"], ("groups", "ports"))
        k.require(node.key not in owned_nodes, "etherchannel_duplicate_target")
        owned_nodes.add(node.key)
        target = build.Target(context=context, node=node, groups=tuple(sorted(_strings(params["groups"]))), ports=tuple(sorted(_strings(params["ports"]))))
        targets[item.id] = target
    k.require(type(envelope.captures) is tuple and all(type(m) is p4.CaptureMember and type(m.raw) is bytes for m in envelope.captures)
              and {m.path for m in envelope.captures} == set(capture_rows) and len(envelope.captures) == len(capture_rows), "etherchannel_folder_member")
    requests: list[CaptureRequest] = []
    by_capture: dict[k.CaptureId, build.Target] = {}
    supplied: set[k.EntityKey] = set()
    for member in envelope.captures:
        _, row = capture_rows[member.path]
        identity, digest = string(row, "target"), sha256(member.raw).hexdigest()
        key = canonical((p4.SCHEMA, p4_digest, base_digest, context, identity, member.path, digest, envelope.registration_sha256))
        k.require(identity in declared and member.target is declared[identity] and digest == member.sha256 == row["sha256"]
                  and member.id == "cap:" + sha256(key).hexdigest(), "etherchannel_folder_member")
        if identity in targets:
            target = targets[identity]
            k.require(target.node.key not in supplied, "etherchannel_duplicate_target_capture")
            supplied.add(target.node.key)
            capture = Capture(id=member.id, source=target.node.key, operation=parse_summary.OP, rendered=parse_summary.COMMAND,
                              raw=member.raw, codec="utf-8", integrity=_integrity(member.raw), lines=text_lines(member.raw, "utf-8"),
                              read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)
            by_capture[member.id] = target
            requests.append(CaptureRequest(capture=capture, context=context))
    return tuple(item for item in envelope.targets if item.id in targets), by_capture, tuple(requests)


class SummaryPack[Peer](p4_pipeline.Pack[parse_summary.Result | Peer]):
    """Classify synthetic artifact framing; neither collector identity nor network health is established."""

    def __init__(self, budgets: Budgets) -> None:
        self.budgets = budgets
        self.attempted = False

    def declaration(self) -> PackDeclaration:
        return build.DECLARATION

    def prepare(self, envelope: p4.Envelope) -> p4_pipeline.Prepared[parse_summary.Result | Peer]:
        k.require(not self.attempted, "etherchannel_global_run")
        self.attempted = True
        targets, by_capture, requests = _scope(envelope, self.budgets)
        handler = Handler[parse_summary.Result | Peer](binding=build.BINDING, parser=_Adapter(by_capture))
        return p4_pipeline.Prepared[parse_summary.Result | Peer](targets=targets, handlers=(handler,), requests=requests)
