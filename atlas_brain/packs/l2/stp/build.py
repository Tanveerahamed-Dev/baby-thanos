"""STP root-guard facts, with registry-backed subjects for declared synthetic folders."""
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture, Scope
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup, endpoint
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_writer
from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.runner import p4_pipeline
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import (
    Executed,
    Handler,
    Parsed,
    Parser,
    execute_parsers,
)

PACK = k.PackId("l2.stp")
ROOT_GUARD = k.FactId("l2.stp.root_guard")
STEP = StepSpec(id=StepId("l2.stp/parse_root_guard"), pack=PACK, kind="parse_build", scope="device",
                reads=(), produces=(ROOT_GUARD,), evaluator="l2.stp.build_root_guard")
BINDING = OperationBinding(operation=stp.OP, step=STEP.id)
DECLARATION = PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="stp_port_vlan", pack=PACK, root=False),),
    facts=(FactSpec(id=ROOT_GUARD, pack=PACK, subject="stp_port_vlan", value_type="boolean", step=STEP.id),),
    relations=(), steps=(STEP,), operations=(BINDING,))


@dataclass(frozen=True, slots=True, kw_only=True)
class Target:
    context: str
    node: Node
    port: str
    vlans: tuple[int, ...]

    def __post_init__(self) -> None:
        k.require(type(self.context) is str and bool(self.context) and type(self.node) is Node, "stp_target")
        stp.command(self.port)
        endpoint(self.node, self.port)
        k.require(type(self.vlans) is tuple and 1 <= len(self.vlans) <= 16
                  and all(type(v) is int and 1 <= v <= 4094 for v in self.vlans)
                  and len(set(self.vlans)) == len(self.vlans), "invalid_stp_vlans")
        declaration = self.node.declaration
        k.require(type(declaration) is k.Known and declaration.basis is k.Basis.DECLARED
                  and declaration.value == declaration.raw == self.node.id and len(declaration.evidence) == 1
                  and all(type(ref) is k.RegistryRef and ref.table == "synthetic_p2.nodes"
                          and ref.row_id == self.node.id and re.fullmatch(r"/nodes/(0|[1-9][0-9]*)", ref.citation)
                          is not None for ref in declaration.evidence), "stp_node_declaration")


def subject(target: Target, vlan: int) -> k.EntityKey:
    k.require(type(target) is Target and type(vlan) is int and vlan in target.vlans, "stp_subject_vlan")
    key = canonical(("atlas-brain.stp-port-vlan/1", target.context, target.node.key, target.port, vlan))
    return k.EntityKey("stp_port_vlan:" + sha256(key).hexdigest())


@dataclass(frozen=True, slots=True, kw_only=True)
class Row:
    target: Target
    vlan: int
    subject: k.EntityKey
    value: k.Known[bool] | k.Unknown


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    store: FactStore
    rows: tuple[Row, ...]
    executed: tuple[Executed[stp.Result], ...]


class _Adapter(Parser[stp.Result]):
    def __init__(self, targets: dict[k.CaptureId, Target], produced: dict[k.CaptureId, stp.Result] | None = None) -> None:
        self.targets = targets
        self.produced = produced

    def parse(self, request: CaptureRequest) -> Parsed[stp.Result]:
        target = self.targets[request.capture.id]
        if self.produced is not None:
            k.require(request.capture.id not in self.produced, "stp_global_value")
        result = stp.parse_capture(request.capture, target.port, target.vlans)
        if self.produced is not None:
            self.produced[request.capture.id] = result
        return result, result.parse


def _line(raw: bytes, span: k.ByteSpan) -> bytes:
    k.require(0 <= span.start < span.end <= len(raw) and (span.start == 0 or raw[span.start - 1] == 10)
              and (span.end == len(raw) or raw.startswith((b"\n", b"\r\n"), span.end)), "stp_proof_line")
    return raw[span.start:span.end]


def _observed(target: Target, row: stp.Row, output: Executed[stp.Result], provenance: tuple[k.Evidence, ...]) -> k.Known[bool]:
    capture = output.receipt.capture
    fields = dict(row.fields)
    names = tuple(name for name, _ in row.fields)
    k.require(all(names.count(name) == 1 for name in ("port", "vlan", "root_guard")), "stp_guard_fields")
    token = fields["root_guard"]
    k.require(token.value is stp.Switch.ENABLED or token.value is stp.Switch.DISABLED, "stp_guard_value")
    enabled = token.value is stp.Switch.ENABLED
    k.require(token.raw == ("enabled" if enabled else "disabled"), "stp_guard_value")
    records = output.receipt.parse.records
    guards = [r for r in records if r.rule_id == "root_guard" and r.span in row.spans]
    k.require(len(guards) == 1 and guards[0].fields == (("root_guard", token),), "stp_guard_record")
    guard = guards[0].span
    headers = [r for r in records if r.rule_id.startswith("header_") and r.span.start < guard.start]
    k.require(bool(headers), "stp_guard_header")
    nearest = max(headers, key=lambda record: record.span.start)
    k.require(nearest.span in row.spans, "stp_guard_header")
    header, header_fields = nearest.span, dict(nearest.fields)
    header_line = _line(capture.raw, header)
    words = header_line.split()
    k.require(len(words) == 8 and words[0] == b"Port" and words[1].isdigit()
              and words[2:6] == [b"(" + target.port.encode("ascii") + b")", b"of",
                                 f"VLAN{row.vlan:04d}".encode("ascii"), b"is"], "stp_guard_header")
    port, vid = fields["port"], fields["vlan"]
    before_port = b"Port " + words[1] + b" ("
    before_vlan = b"Port " + words[1] + b" " + words[2] + b" of VLAN"
    first = header.start + len(header_line) - len(header_line.lstrip(b" \t"))
    for name, field, expected, prefix_bytes in (("port", port, target.port, before_port),
                                                ("vlan", vid, f"{row.vlan:04d}", before_vlan)):
        k.require(name in header_fields and header_fields[name] == field and field.raw == field.value == expected
                  and field.span.start == first + len(prefix_bytes) and field.span.end == field.span.start + len(expected)
                  and field.span.end <= header.end and capture.raw[field.span.start:field.span.end] == expected.encode("ascii"),
                  "stp_guard_header")
    line = _line(capture.raw, guard)
    prefix = b"Root guard is "
    word = token.raw.encode("ascii")
    k.require(line.strip(b" \t") == prefix + word + b" on the port"
              and token.span.start == guard.start + len(line) - len(line.lstrip(b" \t")) + len(prefix)
              and token.span.end == token.span.start + len(word)
              and capture.raw[token.span.start:token.span.end] == word, "stp_guard_witness")
    refs = tuple(k.EvidenceRef(capture=capture.id, locator=s, role=k.EvidenceRole.SUBJECT,
                 excerpt_sha256=sha256(capture.raw[s.start:s.end]).hexdigest()) for s in (token.span, guard, port.span, vid.span, header))
    return k.Known(value=enabled, basis=k.Basis.OBSERVED, evidence=provenance + refs, raw=token.raw)


def _rows(target: Target, outputs: list[Executed[stp.Result]], declared: tuple[k.RegistryRef, ...]) -> tuple[Row, ...]:
    needs = (k.EvidenceNeed(node=target.node.key, operation=stp.OP, params=(("port", target.port),),
             resolves=(ROOT_GUARD,), reruns=(STEP.id,), after_s=None, unprintable=()),)
    provenance = target.node.declaration.evidence + declared
    evidence = provenance + tuple(k.EvidenceRef(capture=o.receipt.capture.id,
        locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS, excerpt_sha256=o.receipt.capture.bytes_sha256) for o in outputs)
    rows: list[Row] = []
    for index, vlan in enumerate(target.vlans):
        reason: k.UnknownReason | None = k.UnknownReason.NOT_COLLECTED
        if outputs:
            output, = outputs
            row = output.value.rows[index]
            reason = output.value.reason or row.reason
            if reason is None and output.value.parse.quality != "complete":
                reason = k.UnknownReason.PARSE_PARTIAL
            if reason is None and "root_guard" not in dict(row.fields):
                reason = k.UnknownReason.FIELD_NOT_PRINTED
            if reason is None:
                rows.append(Row(target=target, vlan=vlan, subject=subject(target, vlan), value=_observed(target, row, output, provenance)))
                continue
        value = k.Unknown(reason=reason, detail="stp_root_guard_unresolved", evidence=evidence, candidates=(), next_evidence=needs)
        rows.append(Row(target=target, vlan=vlan, subject=subject(target, vlan), value=value))
    return tuple(rows)


def build_root_guard(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Accept at most one capture per target and execute before projecting any subject."""
    return _local(_plan(targets, requests, None))


type _Key = tuple[str, k.EntityKey, str]
type _Proofs = dict[_Key, tuple[k.RegistryRef, ...]]


@dataclass(frozen=True, slots=True, kw_only=True)
class _Plan:
    indexed: dict[_Key, Target]
    by_capture: dict[k.CaptureId, Target]
    requests: tuple[CaptureRequest, ...]
    proofs: _Proofs | None


def _plan(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...], proofs: _Proofs | None) -> _Plan:
    k.require(type(targets) is tuple and all(type(t) is Target for t in targets), "stp_targets")
    k.require(type(requests) is tuple and all(type(r) is CaptureRequest for r in requests), "stp_requests")
    indexed: dict[tuple[str, k.EntityKey, str], Target] = {}
    for item in targets:
        item = Target(context=item.context, node=item.node, port=item.port, vlans=item.vlans)
        target = Target(context=item.context, node=item.node, port=item.port, vlans=tuple(sorted(item.vlans)))
        key = (target.context, target.node.key, stp.command(target.port))
        k.require(key not in indexed, "stp_duplicate_target")
        indexed[key] = target
    by_capture: dict[k.CaptureId, Target] = {}
    supplied: set[tuple[str, k.EntityKey, str]] = set()
    for request in requests:
        capture = request.capture
        key = (request.context or "", capture.source, capture.rendered)
        k.require(key in indexed and capture.operation == stp.OP, "stp_request_target")
        k.require(capture.codec in ("ascii", "utf-8"), "unsupported_stp_capture")
        expected = Scope(node=capture.source, plane="exec", vrf=None, context=None, vdc=None, tenant=None, afi=None, instance=None)
        k.require(capture.scope == expected, "stp_request_scope")
        k.require(key not in supplied, "stp_duplicate_target_capture")
        supplied.add(key)
        by_capture[capture.id] = indexed[key]
    return _Plan(indexed=indexed, by_capture=by_capture, requests=requests, proofs=proofs)


def _local(plan: _Plan) -> Result:
    handler = Handler(binding=BINDING, parser=_Adapter(plan.by_capture))
    return _materialize(plan, execute_parsers((DECLARATION,), (handler,), plan.requests))


def _materialize(plan: _Plan, executed: tuple[Executed[stp.Result], ...]) -> Result:
    indexed, by_capture, proofs = plan.indexed, plan.by_capture, plan.proofs
    grouped: dict[tuple[str, k.EntityKey, str], list[Executed[stp.Result]]] = {key: [] for key in indexed}
    for output in executed:
        target = by_capture[output.receipt.capture.id]
        k.require(type(output.value) is stp.Result and output.receipt.parse is output.value.parse, "stp_receipt_parse")
        k.require(type(output.value.rows) is tuple and all(type(r) is stp.Row and type(r.vlan) is int
                  and r.port == target.port for r in output.value.rows)
                  and tuple(r.vlan for r in output.value.rows) == target.vlans, "stp_parser_population")
        grouped[(target.context, target.node.key, stp.command(target.port))].append(output)
    rows = tuple(row for key in sorted(indexed) for row in _rows(indexed[key], grouped[key], () if proofs is None else proofs[key]))
    k.require(len({r.subject for r in rows}) == len(rows), "stp_subject_collision")
    store = FactStore()
    writer = bind_writer(store, step=STEP)
    for row in rows:
        writer.write(fact=ROOT_GUARD, subject=row.subject, value=row.value)
    return Result(store=store, rows=rows, executed=executed)


@dataclass(frozen=True, slots=True, kw_only=True)
class FolderResult:
    envelope: p4_admission.Envelope
    result: Result


def _reference(state: k.Known[str], table: str, identity: str, digest: str, pointer: str) -> k.RegistryRef:
    ref = k.RegistryRef(table=table, row_id=identity, table_digest=digest, citation=pointer)
    k.require(type(state) is k.Known and state.basis is k.Basis.DECLARED and state.raw == state.value == identity
              and state.evidence == (ref,), "stp_folder_declaration")
    return ref


def _records(value: object, fields: tuple[str, ...], key: str) -> dict[str, tuple[int, dict[str, object]]]:
    k.require(type(value) is list, "stp_folder_registry")
    indexed: dict[str, tuple[int, dict[str, object]]] = {}
    for i, item in enumerate(cast(list[object], value)):
        row = record(item, fields)
        identifier = string(row, key)
        k.require(identifier not in indexed, "stp_folder_registry")
        indexed[identifier] = (i, row)
    return indexed


def _integrity(raw: bytes, command: str) -> k.IntegrityState:
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeError as error:
        raise ValueError("stp_folder_text") from error
    k.require(not any(ord(c) < 32 and c not in "\t\n" or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in text),
              "stp_folder_text")
    lines = [line for line in text.split("\n") if line.strip(" \t")]
    opening = re.fullmatch(r"([A-Za-z0-9_.:-]+[>#]) ?(.+)", lines[0], re.ASCII) if lines else None
    missing_prompt = False
    if opening:
        k.require(opening[2] == command, "stp_folder_frame")
        missing_prompt = lines[-1] != opening[1]
        lines = lines[1:] if missing_prompt else lines[1:-1]
    elif lines and lines[0] == command:
        lines = lines[1:]
    forbidden = (r"(?:[a-z0-9_.:-]+(?:\([^)]*\))?[>#].*|(?:do[ \t]+)?sh(?:ow|o)?(?:[ \t].*)?|!|"
                 r"(?:end|exit|configure|building configuration|current configuration|banner|interface|router|vlan|"
                 r"hostname|spanning-tree|switchport|description|shutdown|no|default)(?:[ \t:].*)?)")
    k.require(not any(re.fullmatch(forbidden, line.strip().casefold(), re.ASCII) for line in lines), "stp_folder_frame")
    if any(line.lstrip().startswith("%") or line.strip().casefold() in ("command authorization failed", "command authorization failed.")
           for line in lines):
        return k.IntegrityState.ERROR
    if any(line.strip().casefold() in ("--more--", "<--- more --->", "--(more)--") for line in lines):
        return k.IntegrityState.PAGING_ARTIFACTS
    if any(line.strip().casefold() in ("[truncated]", "<output truncated>") for line in lines):
        return k.IntegrityState.TRUNCATED
    k.require(not missing_prompt, "stp_folder_frame")
    if not lines:
        return k.IntegrityState.EMPTY
    header = r"[ \t]*Port [0-9]+ \(" + stp.PORT + r"\) of VLAN[0-9]{4} is [a-z]+ [a-z]+[ \t]*"
    return k.IntegrityState.COMPLETE if re.fullmatch(header, lines[0], re.ASCII) else k.IntegrityState.UNKNOWN_FORMAT


def build_root_guard_folder(root: Path, budgets: Budgets) -> FolderResult:
    """Admit a singleton STP composition and resolve its declared subjects before execution."""
    envelope = p4_admission.admit_folder(root, budgets, declarations=(DECLARATION,))
    return FolderResult(envelope=envelope, result=_local(_scope(envelope, budgets, singleton=True)))


def _scope(envelope: p4_admission.Envelope, budgets: Budgets, *, singleton: bool) -> _Plan:
    k.require(type(envelope) is p4_admission.Envelope and type(envelope.raw) is bytes
              and type(envelope.base) is SyntheticGroup and type(envelope.base.raw) is bytes, "stp_folder_registry")
    registration = envelope.registration_sha256
    if singleton:
        k.require(registration == compile_packs((DECLARATION,)).registration_sha256, "stp_folder_registration")
    base, context = envelope.base, envelope.context
    p4_digest, base_digest = sha256(envelope.raw).hexdigest(), sha256(base.raw).hexdigest()
    side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
                  ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
    registry = record(strict_json(base.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
    k.require(side["schema"] == p4_admission.SCHEMA and side["semantic_group"] == "declared_synthetic"
              and side["context"] == context and side["base_sha256"] == base_digest and registry["group"] == base.id
              and registry["semantic_group"] == "declared_synthetic" and registry["schema"] == base.schema == BASE_SCHEMA,
              "stp_folder_registry")
    _reference(base.declaration, "synthetic_p2.groups", base.id, base_digest, "/group")
    context_ref = _reference(envelope.declaration, "synthetic_p4.context", context, p4_digest, "/context")
    node_rows = _records(registry["nodes"], ("id", "discovery_id", "ports"), "id")
    k.require(type(base.nodes) is tuple and all(type(node) is Node for node in base.nodes), "stp_folder_node")
    nodes = {node.id: node for node in base.nodes}
    k.require(set(nodes) == set(node_rows) and len(nodes) == len(base.nodes), "stp_folder_node")
    for node in base.nodes:
        node_id = node.id
        index, row = node_rows[node_id]
        ports = row["ports"]
        k.require(type(ports) is list and all(type(p) is str for p in cast(list[object], ports))
                  and node.group == base.id and node.discovery_id == row["discovery_id"]
                  and tuple(sorted(cast(list[str], ports))) == node.ports, "stp_folder_node")
        _reference(node.declaration, "synthetic_p2.nodes", node_id, base_digest, f"/nodes/{index}")

    target_rows = _records(side["targets"], ("id", "node", "operation", "params"), "id")
    k.require(type(envelope.targets) is tuple and all(type(t) is p4_admission.Target for t in envelope.targets),
              "stp_folder_target")
    declared = {item.id: item for item in envelope.targets}
    k.require(set(declared) == set(target_rows) and len(declared) == len(envelope.targets), "stp_folder_target")
    targets: dict[str, Target] = {}
    proofs: dict[tuple[str, k.EntityKey, str], tuple[k.RegistryRef, ...]] = {}
    for item in envelope.targets:
        identifier = item.id
        index, row = target_rows[identifier]
        node_id = string(row, "node")
        k.require(node_id in nodes and item.node is nodes[node_id] and item.operation == row["operation"]
                  and type(item.params) is bytes and canonical(row["params"]) == item.params, "stp_folder_target")
        target_ref = _reference(item.declaration, "synthetic_p4.targets", identifier, p4_digest, f"/targets/{index}")
        if item.operation != stp.OP:
            k.require(not singleton and item.owner != STEP.id, "stp_folder_target")
            continue
        k.require(item.owner == STEP.id, "stp_folder_target")
        params = record(row["params"], ("port", "vlans"))
        vlans = params["vlans"]
        k.require(type(vlans) is list, "invalid_stp_vlans")
        target = Target(context=context, node=item.node, port=string(params, "port"), vlans=tuple(cast(list[int], vlans)))
        targets[identifier] = target
        proofs[(context, target.node.key, stp.command(target.port))] = (context_ref, target_ref)

    capture_rows = _records(side["captures"], ("target", "path", "sha256"), "path")
    k.require(type(envelope.captures) is tuple and all(type(m) is p4_admission.CaptureMember and type(m.raw) is bytes
              for m in envelope.captures), "stp_folder_member")
    k.require({m.path for m in envelope.captures} == set(capture_rows)
              and len(envelope.captures) == len(capture_rows), "stp_folder_member")
    for member in envelope.captures:
        _, row = capture_rows[member.path]
        identifier = string(row, "target")
        digest = sha256(member.raw).hexdigest()
        key = canonical((p4_admission.SCHEMA, p4_digest, base_digest, context, identifier, member.path, digest, registration))
        k.require(identifier in declared and member.target is declared[identifier] and digest == member.sha256 == row["sha256"]
                  and member.id == "cap:" + sha256(key).hexdigest(), "stp_folder_member")
    requests: list[CaptureRequest] = []
    for member in envelope.captures:
        if member.target.id not in targets:
            continue
        target = targets[member.target.id]
        command = stp.command(target.port)
        capture = Capture(id=member.id, source=target.node.key, operation=stp.OP, rendered=command,
                          raw=member.raw, codec="utf-8", integrity=_integrity(member.raw, command),
                          lines=text_lines(member.raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)
        requests.append(CaptureRequest(capture=capture, context=context))
    return _plan(tuple(targets[name] for name in targets), tuple(requests), proofs)


@dataclass(frozen=True, slots=True, kw_only=True)
class GlobalFacts[Peer]:
    execution: p4_pipeline.Result[stp.Result | Peer]
    result: Result


class _GlobalSTP[Peer](p4_pipeline.Pack[stp.Result | Peer]):
    """One invocation retains its admitted plan and the values its own parser actually produced."""

    def __init__(self, budgets: Budgets) -> None:
        self.budgets = budgets
        self.envelope: p4_admission.Envelope | None = None
        self.registration = ""
        self.plan: _Plan | None = None
        self.produced: dict[k.CaptureId, stp.Result] = {}

    def declaration(self) -> PackDeclaration:
        return DECLARATION

    def prepare(self, envelope: p4_admission.Envelope) -> p4_pipeline.Prepared[stp.Result | Peer]:
        k.require(self.plan is None, "stp_global_run")
        plan = _scope(envelope, self.budgets, singleton=False)
        self.envelope, self.registration, self.plan = envelope, envelope.registration_sha256, plan
        handler = Handler[stp.Result | Peer](binding=BINDING, parser=_Adapter(plan.by_capture, self.produced))
        return p4_pipeline.Prepared[stp.Result | Peer](targets=tuple(t for t in envelope.targets if t.operation == stp.OP),
                                                       handlers=(handler,), requests=plan.requests)

    def finish(self, execution: p4_pipeline.Result[stp.Result | Peer]) -> Result:
        envelope, plan = self.envelope, self.plan
        if (envelope is None or plan is None or type(execution) is not p4_pipeline.Result
                or execution.envelope is not envelope or envelope.registration_sha256 != self.registration):
            raise ValueError("stp_global_run")
        outputs = execution.executed
        k.require(type(outputs) is tuple and all(type(o) is Executed and type(o.receipt) is ParseReceipt
                  and type(o.receipt.capture) is Capture for o in outputs), "stp_global_receipt")
        members = {m.id: m for m in envelope.captures}
        k.require(len(outputs) == len(members) and {o.receipt.capture.id for o in outputs} == set(members),
                  "stp_global_coverage")
        for output in outputs:
            receipt = output.receipt
            capture = receipt.capture
            member = members[capture.id]
            k.require(receipt.owner == member.target.owner and receipt.context == envelope.context
                      and receipt.registration_sha256 == self.registration and capture.source == member.target.node.key
                      and capture.operation == member.target.operation and type(capture.raw) is bytes
                      and capture.raw == member.raw and capture.bytes_sha256 == member.sha256, "stp_global_receipt")
        requests = {req.capture.id: req for req in plan.requests}
        k.require(set(self.produced) == set(requests), "stp_global_value")
        owned: list[Executed[stp.Result]] = []
        for output in outputs:
            receipt = output.receipt
            identity = receipt.capture.id
            if identity in requests:
                k.require(receipt.capture is requests[identity].capture, "stp_global_capture")
                value = self.produced[identity]
                k.require(output.value is value and receipt.parse is value.parse, "stp_global_value")
                owned.append(Executed(receipt=receipt, value=value))
        return _materialize(plan, tuple(owned))


def build_root_guard_global[Peer](
    root: Path, budgets: Budgets, *, peers: tuple[p4_pipeline.Pack[stp.Result | Peer], ...],
) -> GlobalFacts[Peer]:
    """Run a trusted composition once; only this invocation's original STP captures/values close facts.

    Peer values remain opaque and the complete global execution remains unchanged.
    """
    k.require(type(peers) is tuple, "stp_global_peers")
    owner = _GlobalSTP[Peer](budgets)
    packs: tuple[p4_pipeline.Pack[stp.Result | Peer], ...] = (owner, *peers)
    execution = p4_pipeline.execute_p4_folder(root, budgets, packs=packs)
    return GlobalFacts[Peer](execution=execution, result=owner.finish(execution))
