"""Production HSRP preparation and owned fact finishing for one declared-synthetic global run."""
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration
from atlas_brain.packs.l3.fhrp import build
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as hsrp
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import Executed, Handler


def _strings(value: object) -> tuple[str, ...]:
    if type(value) is not list:
        raise ValueError("hsrp_folder_strings")
    k.require(all(type(item) is str for item in cast(list[object], value)), "hsrp_folder_strings")
    return tuple(item for item in cast(list[object], value) if type(item) is str)


def _pairs(value: object) -> tuple[tuple[str, str], ...]:
    k.require(type(value) is list and all(type(pair) is list and len(cast(list[object], pair)) == 2
              and all(type(item) is str for item in cast(list[object], pair)) for pair in cast(list[object], value)),
              "hsrp_folder_groups")
    return tuple((cast(list[str], pair)[0], cast(list[str], pair)[1]) for pair in cast(list[object], value))


def _records(value: object, fields: tuple[str, ...], key: str) -> dict[str, tuple[int, dict[str, object]]]:
    if type(value) is not list:
        raise ValueError("hsrp_folder_registry")
    rows: dict[str, tuple[int, dict[str, object]]] = {}
    for index, item in enumerate(cast(list[object], value)):
        row = record(item, fields)
        identity = string(row, key)
        k.require(identity not in rows, "hsrp_folder_registry")
        rows[identity] = (index, row)
    return rows


def _reference(state: k.Known[str], table: str, identity: str, digest: str, pointer: str) -> None:
    ref = k.RegistryRef(table=table, row_id=identity, table_digest=digest, citation=pointer)
    k.require(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.raw == state.value == identity
              and state.evidence == (ref,), "hsrp_folder_declaration")


def _integrity(raw: bytes) -> k.IntegrityState:
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError("hsrp_folder_text") from error
    k.require(not any(ord(c) < 32 and c not in "\t\n" or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in text),
              "hsrp_folder_text")
    lines = [line for line in text.split("\n") if line.strip(" \t")]
    opening = re.fullmatch(r"([A-Za-z0-9_.:-]+[>#]) ?(.+)", lines[0], re.ASCII) if lines else None
    missing = False
    if opening:
        k.require(opening[2] == hsrp.COMMAND, "hsrp_folder_frame")
        missing = lines[-1] != opening[1]
        lines = lines[1:] if missing else lines[1:-1]
    elif lines and lines[0] == hsrp.COMMAND:
        lines = lines[1:]
    header = r"Interface[ \t]+Grp[ \t]+Pri[ \t]+P[ \t]+State[ \t]+Active[ \t]+Standby[ \t]+Virtual IP[ \t]*"
    forbidden = (r"(?:[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*|(?:do[ \t]+)?sh(?:ow|o)?(?:[ \t].*)?|!|"
                 r"(?:end|exit|configure|building configuration|current configuration|banner|interface|router|vlan|"
                 r"hostname|spanning-tree|switchport|standby|description|shutdown|no|default)(?:[ \t:].*)?)")
    k.require(not any(re.fullmatch(forbidden, line.strip().casefold(), re.ASCII)
                      for line in lines if re.fullmatch(header, line, re.ASCII) is None), "hsrp_folder_frame")
    if any(line.lstrip().startswith("%") or line.strip().casefold() in ("command authorization failed", "command authorization failed.") for line in lines):
        return k.IntegrityState.ERROR
    if any(line.strip().casefold() in ("--more--", "<--- more --->", "--(more)--") for line in lines):
        return k.IntegrityState.PAGING_ARTIFACTS
    if any(line.strip().casefold() in ("[truncated]", "<output truncated>") for line in lines):
        return k.IntegrityState.TRUNCATED
    k.require(not missing, "hsrp_folder_frame")
    if not lines:
        return k.IntegrityState.EMPTY
    first = " ".join(part for part in lines[0].replace("\t", " ").split(" ") if part)
    return k.IntegrityState.COMPLETE if first == "P indicates configured to preempt." else k.IntegrityState.UNKNOWN_FORMAT


def _scope(envelope: p4.Envelope, budgets: Budgets) -> tuple[
    tuple[p4.Target, ...], tuple[build.Target, ...], tuple[CaptureRequest, ...],
]:
    k.require(type(envelope) is p4.Envelope and type(envelope.raw) is bytes
              and type(envelope.base) is SyntheticGroup and type(envelope.base.raw) is bytes, "hsrp_folder_registry")
    base, context = envelope.base, envelope.context
    p4_digest, base_digest = sha256(envelope.raw).hexdigest(), sha256(base.raw).hexdigest()
    side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
                  ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    registry = record(strict_json(base.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
    k.require(side["schema"] == p4.SCHEMA and side["semantic_group"] == "declared_synthetic" and side["context"] == context
              and side["base_sha256"] == base_digest and registry["group"] == base.id and registry["semantic_group"] == "declared_synthetic"
              and registry["schema"] == base.schema == BASE_SCHEMA, "hsrp_folder_registry")
    _reference(base.declaration, "synthetic_p2.groups", base.id, base_digest, "/group")
    _reference(envelope.declaration, "synthetic_p4.context", context, p4_digest, "/context")
    node_rows = _records(registry["nodes"], ("id", "discovery_id", "ports"), "id")
    target_rows = _records(side["targets"], ("id", "node", "operation", "params"), "id")
    capture_rows = _records(side["captures"], ("target", "path", "sha256"), "path")
    k.require(type(base.nodes) is tuple and all(type(node) is Node for node in base.nodes), "hsrp_folder_node")
    nodes = {node.id: node for node in base.nodes}
    k.require(set(nodes) == set(node_rows) and len(nodes) == len(base.nodes), "hsrp_folder_node")
    k.require(type(envelope.targets) is tuple and all(type(item) is p4.Target for item in envelope.targets), "hsrp_folder_target")
    declared = {item.id: item for item in envelope.targets}
    k.require(set(declared) == set(target_rows) and len(declared) == len(envelope.targets), "hsrp_folder_target")
    targets: dict[str, build.Target] = {}
    owned_nodes: set[k.EntityKey] = set()
    for item in envelope.targets:
        index, row = target_rows[item.id]
        node_id = string(row, "node")
        k.require(node_id in nodes and item.node is nodes[node_id] and item.operation == row["operation"]
                  and type(item.params) is bytes and canonical(row["params"]) == item.params, "hsrp_folder_target")
        _reference(item.declaration, "synthetic_p4.targets", item.id, p4_digest, f"/targets/{index}")
        if item.operation != hsrp.OP:
            k.require(item.owner != build.STEP.id, "hsrp_folder_target")
            continue
        node = item.node
        node_index, node_row = node_rows[node_id]
        k.require(item.owner == build.STEP.id and node.group == base.id and node.discovery_id == node_row["discovery_id"]
                  and tuple(sorted(_strings(node_row["ports"]))) == node.ports, "hsrp_folder_node")
        _reference(node.declaration, "synthetic_p2.nodes", node_id, base_digest, f"/nodes/{node_index}")
        params = record(row["params"], ("groups",))
        k.require(node.key not in owned_nodes, "hsrp_duplicate_target")
        owned_nodes.add(node.key)
        target = build.Target(context=context, node=node, groups=tuple(sorted(_pairs(params["groups"]))))
        targets[item.id] = target
    k.require(type(envelope.captures) is tuple and all(type(m) is p4.CaptureMember and type(m.raw) is bytes for m in envelope.captures)
              and {m.path for m in envelope.captures} == set(capture_rows) and len(envelope.captures) == len(capture_rows), "hsrp_folder_member")
    requests: list[CaptureRequest] = []
    supplied: set[k.EntityKey] = set()
    for member in envelope.captures:
        _, row = capture_rows[member.path]
        identity, digest = string(row, "target"), sha256(member.raw).hexdigest()
        key = canonical((p4.SCHEMA, p4_digest, base_digest, context, identity, member.path, digest, envelope.registration_sha256))
        k.require(identity in declared and member.target is declared[identity] and digest == member.sha256 == row["sha256"]
                  and member.id == "cap:" + sha256(key).hexdigest(), "hsrp_folder_member")
        if identity in targets:
            target = targets[identity]
            k.require(target.node.key not in supplied, "hsrp_duplicate_capture")
            supplied.add(target.node.key)
            capture = Capture(id=member.id, source=target.node.key, operation=hsrp.OP, rendered=hsrp.COMMAND,
                              raw=member.raw, codec="utf-8", integrity=_integrity(member.raw), lines=text_lines(member.raw, "utf-8"),
                              read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)
            requests.append(CaptureRequest(capture=capture, context=context))
    return tuple(item for item in envelope.targets if item.id in targets), tuple(targets[name] for name in targets), tuple(requests)


@dataclass(frozen=True, slots=True, kw_only=True)
class _Run:
    envelope: p4.Envelope
    registration: str
    owner: build.StateOwner


class StandbyBriefPack[Peer](p4_pipeline.Pack[hsrp.Result | Peer]):
    """Prepare once and finish HSRP facts from the original global run.

    Artifact framing establishes neither collector identity nor network health.
    """

    def __init__(self, budgets: Budgets) -> None:
        self.budgets = budgets
        self.attempted = self.finished = False
        self.run: _Run | None = None

    @property
    def owner(self) -> build.StateOwner:
        run = self.run
        if run is None:
            raise ValueError("hsrp_global_run")
        return run.owner

    def declaration(self) -> PackDeclaration:
        return build.DECLARATION

    def prepare(self, envelope: p4.Envelope) -> p4_pipeline.Prepared[hsrp.Result | Peer]:
        k.require(not self.attempted, "hsrp_global_run")
        self.attempted = True
        targets, domains, requests = _scope(envelope, self.budgets)
        owner = build.StateOwner(envelope, self.budgets, domains, requests)
        handler = Handler[hsrp.Result | Peer](binding=build.BINDING, parser=owner)
        batch = p4_pipeline.Prepared[hsrp.Result | Peer](targets=targets, handlers=(handler,), requests=requests)
        self.run = _Run(envelope=envelope, registration=envelope.registration_sha256, owner=owner)
        return batch

    def finish(self, execution: p4_pipeline.Result[hsrp.Result | Peer]) -> build.Result:
        """Close every global receipt before materializing HSRP's original parsed values."""
        run = self.run
        if (self.finished or run is None or type(execution) is not p4_pipeline.Result
                or execution.envelope is not run.envelope or run.envelope.registration_sha256 != run.registration):
            raise ValueError("hsrp_global_run")
        envelope, owner = run.envelope, run.owner
        outputs = execution.executed
        k.require(type(outputs) is tuple and all(type(o) is Executed and type(o.receipt) is ParseReceipt
                  and type(o.receipt.capture) is Capture for o in outputs), "hsrp_global_receipt")
        members = {m.id: m for m in envelope.captures}
        k.require(len(outputs) == len(members) and {o.receipt.capture.id for o in outputs} == set(members), "hsrp_global_coverage")
        for output in outputs:
            receipt, capture = output.receipt, output.receipt.capture
            member = members[capture.id]
            k.require(receipt.owner == member.target.owner and receipt.context == envelope.context
                      and receipt.registration_sha256 == run.registration and capture.source == member.target.node.key
                      and capture.operation == member.target.operation and type(capture.raw) is bytes
                      and capture.raw == member.raw and capture.bytes_sha256 == member.sha256, "hsrp_global_receipt")
        owned = tuple(owner.own(output) for output in outputs if output.receipt.capture.operation == hsrp.OP)
        result = owner.finish(owned)
        self.finished = True
        return result


class VirtualIpPack[Peer](StandbyBriefPack[Peer]):
    """Fixed GLOBAL STATE+VIP declaration; no caller-selected profile."""

    def declaration(self) -> PackDeclaration:
        return build.VIP_DECLARATION

    @property
    def virtual_ip_owner(self) -> build.VirtualIpOwner:
        owner = self.owner
        if type(owner) is not build.VirtualIpOwner:
            raise ValueError("hsrp_vip_source")
        return owner

    def prepare(self, envelope: p4.Envelope) -> p4_pipeline.Prepared[hsrp.Result | Peer]:
        k.require(not self.attempted, "hsrp_global_run")
        self.attempted = True
        targets, domains, requests = _scope(envelope, self.budgets)
        owner = build.VirtualIpOwner(envelope, self.budgets, domains, requests)
        handler = Handler[hsrp.Result | Peer](binding=build.BINDING, parser=owner)
        batch = p4_pipeline.Prepared[hsrp.Result | Peer](targets=targets, handlers=(handler,), requests=requests)
        self.run = _Run(envelope=envelope, registration=envelope.registration_sha256, owner=owner)
        return batch
