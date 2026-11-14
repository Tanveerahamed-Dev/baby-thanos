"""Production HSRP preparation and owned fact finishing for one declared-synthetic global run."""
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import CompiledPackSet, PackDeclaration
from atlas_brain.packs.l3.fhrp import build, peer_profile
from atlas_brain.packs.l3.fhrp import parse_hsrp_all as all_hsrp
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as hsrp
from atlas_brain.packs.l3.fhrp import version_profile as profile
from atlas_brain.packs.l3.fhrp.version_inputs import (
    VersionInputs,
    prepare_version_request,
    retain_version_inputs,
    validate_fhrp_request_graph,
    validate_version_inputs,
    validate_version_state_graph,
)
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


def _state_version_budgets(budgets: Budgets) -> None:
    k.require(type(budgets) is Budgets and all(type(value) is int and value > 0 for value in
        (budgets.bundle_bytes, budgets.artifact_bytes, budgets.artifacts, budgets.nesting_depth,
         budgets.numeric_digits, budgets.compression_ratio, budgets.archive_index_bytes)), "hsrp_state_version_budget")


def _state_version_graph(envelope: p4.Envelope, budgets: Budgets) -> None:
    """Close current finite envelope graphs before any detached input comparison."""
    _state_version_budgets(budgets)
    k.require(type(envelope) is p4.Envelope and type(envelope.raw) is bytes
              and type(envelope.context) is str and type(envelope.registration_sha256) is str
              and type(envelope.base) is SyntheticGroup, "hsrp_state_version_graph")
    base = envelope.base
    k.require(type(base.raw) is bytes and type(base.id) is str and type(base.schema) is str
              and type(base.nodes) is tuple and type(base.captures) is tuple
              and type(envelope.targets) is tuple and type(envelope.captures) is tuple, "hsrp_state_version_graph")
    validate_version_state_graph(base.declaration)
    validate_version_state_graph(envelope.declaration)
    for node in base.nodes:
        k.require(type(node) is Node and all(type(value) is str for value in (node.group, node.id, node.discovery_id))
                  and type(node.ports) is tuple and all(type(port) is str for port in node.ports), "hsrp_state_version_graph")
        validate_version_state_graph(node.declaration)
    for capture in base.captures:
        validate_fhrp_request_graph(CaptureRequest(capture=capture, context=None))
    for target in envelope.targets:
        k.require(type(target) is p4.Target and all(type(value) is str for value in (target.id, target.operation, target.owner))
                  and type(target.params) is bytes and any(target.node is node for node in base.nodes), "hsrp_state_version_graph")
        validate_version_state_graph(target.declaration)
    for member in envelope.captures:
        k.require(type(member) is p4.CaptureMember and all(type(value) is str for value in (member.id, member.path, member.sha256))
                  and type(member.raw) is bytes and any(member.target is target for target in envelope.targets), "hsrp_state_version_graph")


def validate_state_version_correspondence(
    envelope: p4.Envelope, budgets: Budgets, inputs: VersionInputs,
) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    """Recheck current registry correspondence; supplied data is not admission or origin."""
    _state_version_graph(envelope, budgets)
    profile.compile_state_version_profile()
    validate_version_inputs(inputs)
    _, domains, _ = _scope(envelope, budgets)
    k.require(len(domains) == len(inputs.targets) and all(
        (target.context, target.node.key) in inputs.indexed
        and inputs.indexed[target.context, target.node.key].node is target.node
        and inputs.indexed[target.context, target.node.key].groups == target.groups for target in domains), "hsrp_state_version_population")
    brief = {target.node.key: target for target in envelope.targets if target.operation == hsrp.OP}
    declared: dict[k.EntityKey, p4.Target] = {}
    for target in envelope.targets:
        if target.operation == hsrp.OP:
            continue
        k.require(target.operation == all_hsrp.OP and target.owner == profile.STEP.id
                  and target.node.key not in declared and target.node.key in brief, "hsrp_state_version_target")
        params = record(strict_json(target.params, budgets.nesting_depth, budgets.numeric_digits), ("groups",))
        groups = tuple(sorted(_pairs(params["groups"])))
        domain = inputs.indexed[envelope.context, target.node.key]
        k.require(target.node is domain.node and groups == domain.groups, "hsrp_state_version_target")
        declared[target.node.key] = target
    members = {member.id: member for member in envelope.captures if member.target.operation == all_hsrp.OP}
    k.require(len(members) == len(inputs.requests) and set(members) == set(inputs.expected)
              and len({member.target.node.key for member in members.values()}) == len(members), "hsrp_state_version_capture")
    for request in inputs.requests:
        member, capture = members[request.capture.id], request.capture
        k.require(member.target is declared.get(capture.source) and capture.raw is member.raw
                  and capture.bytes_sha256 == member.sha256 and request.context == envelope.context, "hsrp_state_version_capture")
    result: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]] = {}
    for domain in inputs.targets:
        evidence = domain.node.declaration.evidence + envelope.declaration.evidence + brief[domain.node.key].declaration.evidence
        if domain.node.key in declared:
            evidence += declared[domain.node.key].declaration.evidence
        k.require(all(type(ref) is k.RegistryRef for ref in evidence), "hsrp_state_version_declaration")
        result[domain.context, domain.node.key] = cast(tuple[k.RegistryRef, ...], evidence)
    return result


def validate_brief_request(request: CaptureRequest) -> None:
    """Close only the current fixed BRIEF model; no body, admission or origin verdict."""
    validate_fhrp_request_graph(request)
    capture = request.capture
    k.require(capture.operation == "iosxe.show_standby_brief" and capture.rendered == "show standby brief"
              and capture.codec in ("utf-8", "ascii")
              and capture.scope == Scope(node=capture.source, plane="exec", context=None, vrf=None,
                  instance=None, vdc=None, tenant=None, afi=None), "hsrp_state_version_request")


@dataclass(frozen=True, slots=True, kw_only=True)
class StateVersionInputs:
    envelope: p4.Envelope
    budgets: Budgets
    compiled: CompiledPackSet
    targets: tuple[p4.Target, ...]
    domains: tuple[build.Target, ...]
    requests: tuple[CaptureRequest, ...]
    version: VersionInputs
    declarations: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]


def prepare_state_version_inputs(root: Path, budgets: Budgets) -> StateVersionInputs:
    """Admit the fixed FHRP-only two-operation inputs; return comparison data, not a seal."""
    k.require(isinstance(cast(object, root), Path), "hsrp_state_version_input")
    _state_version_budgets(budgets)
    compiled = profile.compile_state_version_profile()
    identity = compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256
    envelope = p4.admit_folder(root, budgets, declarations=(profile.STATE_VERSION_DECLARATION,))
    _state_version_graph(envelope, budgets)
    k.require(envelope.registration_sha256 == compiled.registration_sha256, "hsrp_state_version_registration")
    targets, domains, requests = _scope(envelope, budgets)
    for request in requests:
        validate_brief_request(request)
    all_requests = tuple(prepare_version_request(capture_id=member.id, source=member.target.node.key,
        context=envelope.context, raw=member.raw) for member in envelope.captures if member.target.operation == all_hsrp.OP)
    version = retain_version_inputs(domains, all_requests)
    declarations = validate_state_version_correspondence(envelope, budgets, version)
    fresh = profile.compile_state_version_profile()
    k.require(identity == (compiled.catalogue_bytes, compiled.registration_bytes, compiled.registration_sha256)
              == (fresh.catalogue_bytes, fresh.registration_bytes, fresh.registration_sha256)
              and envelope.registration_sha256 == identity[2], "hsrp_state_version_registration")
    for request in requests:
        validate_brief_request(request)
    return StateVersionInputs(envelope=envelope, budgets=budgets, compiled=compiled,
        targets=targets, domains=domains, requests=requests, version=version, declarations=declarations)


def validate_peer_state_version_context(envelope: p4.Envelope, budgets: Budgets) -> CompiledPackSet:
    """Close finite trusted peer metadata; this supplies no admission or execution seal."""
    _state_version_graph(envelope, budgets)
    compiled = peer_profile.compile_peer_state_version_profile()
    k.require(envelope.registration_sha256 == compiled.registration_sha256, "fhrp_peer_registration")
    return compiled


def validate_peer_state_version_correspondence(
    envelope: p4.Envelope, budgets: Budgets, inputs: VersionInputs,
) -> dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]]:
    """Recheck the full named peer context; no admission or ownership seal."""
    validate_peer_state_version_context(envelope, budgets)
    validate_version_inputs(inputs)
    _, domains, _ = _scope(envelope, budgets)
    k.require(len(domains) == len(inputs.targets) and all(
        (target.context, target.node.key) in inputs.indexed
        and inputs.indexed[target.context, target.node.key].node is target.node
        and inputs.indexed[target.context, target.node.key].groups == target.groups for target in domains), "hsrp_state_version_population")
    brief = {target.node.key: target for target in envelope.targets if target.operation == hsrp.OP}
    declared: dict[k.EntityKey, p4.Target] = {}
    owners = {"iosxe.show_spanning_tree_interface_detail": "l2.stp/parse_root_guard",
              "iosxe.show_etherchannel_summary": "l2.etherchannel/parse_protocol"}
    for target in envelope.targets:
        if target.operation == hsrp.OP:
            continue
        if target.operation in owners:
            k.require(target.owner == owners[target.operation], "fhrp_peer_target")
            continue
        k.require(target.operation == all_hsrp.OP and target.owner == profile.STEP.id
                  and target.node.key not in declared and target.node.key in brief, "hsrp_state_version_target")
        params = record(strict_json(target.params, budgets.nesting_depth, budgets.numeric_digits), ("groups",))
        groups = tuple(sorted(_pairs(params["groups"])))
        domain = inputs.indexed[envelope.context, target.node.key]
        k.require(target.node is domain.node and groups == domain.groups, "hsrp_state_version_target")
        declared[target.node.key] = target
    members = {member.id: member for member in envelope.captures if member.target.operation == all_hsrp.OP}
    k.require(len(members) == len(inputs.requests) and set(members) == set(inputs.expected)
              and len({member.target.node.key for member in members.values()}) == len(members), "hsrp_state_version_capture")
    for request in inputs.requests:
        member, capture = members[request.capture.id], request.capture
        k.require(member.target is declared.get(capture.source) and capture.raw is member.raw
                  and capture.bytes_sha256 == member.sha256 and request.context == envelope.context, "hsrp_state_version_capture")
    result: dict[tuple[str, k.EntityKey], tuple[k.RegistryRef, ...]] = {}
    for domain in inputs.targets:
        evidence = domain.node.declaration.evidence + envelope.declaration.evidence + brief[domain.node.key].declaration.evidence
        if domain.node.key in declared:
            evidence += declared[domain.node.key].declaration.evidence
        k.require(all(type(ref) is k.RegistryRef for ref in evidence), "hsrp_state_version_declaration")
        result[domain.context, domain.node.key] = cast(tuple[k.RegistryRef, ...], evidence)
    return result


def prepare_peer_state_version_inputs(envelope: p4.Envelope, budgets: Budgets) -> StateVersionInputs:
    """Prepare this pack's original models inside an already-owned full peer envelope."""
    compiled = validate_peer_state_version_context(envelope, budgets)
    targets, domains, requests = _scope(envelope, budgets)
    for request in requests:
        validate_brief_request(request)
    selected = tuple(target for target in envelope.targets if target.operation == all_hsrp.OP)
    all_requests = tuple(prepare_version_request(capture_id=member.id, source=member.target.node.key,
        context=envelope.context, raw=member.raw) for member in envelope.captures if member.target.operation == all_hsrp.OP)
    inputs = retain_version_inputs(domains, all_requests)
    declarations = validate_peer_state_version_correspondence(envelope, budgets, inputs)
    for request in requests:
        validate_brief_request(request)
    return StateVersionInputs(envelope=envelope, budgets=budgets, compiled=compiled,
        targets=targets + selected, domains=domains, requests=requests, version=inputs, declarations=declarations)
