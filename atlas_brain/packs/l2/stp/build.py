"""Default guard/role facts and an explicit local profile for displayed STP root observations."""
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture, CaptureMetadata, Scope
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
from atlas_brain.model.store import FactReader, FactStore, bind_writer
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
REPORTED_ROLE = k.FactId("l2.stp.reported_role")
STEP = StepSpec(id=StepId("l2.stp/parse_root_guard"), pack=PACK, kind="parse_build", scope="device",
                reads=(), produces=tuple(sorted((ROOT_GUARD, REPORTED_ROLE))), evaluator="l2.stp.build_root_guard")
BINDING = OperationBinding(operation=stp.OP, step=STEP.id)
DECLARATION = PackDeclaration(pack=PACK, entity_kinds=(EntityKindSpec(id="stp_port_vlan", pack=PACK, root=False),),
    facts=(FactSpec(id=ROOT_GUARD, pack=PACK, subject="stp_port_vlan", value_type="boolean", step=STEP.id),
           FactSpec(id=REPORTED_ROLE, pack=PACK, subject="stp_port_vlan", value_type="text", step=STEP.id)),
    relations=(), steps=(STEP,), operations=(BINDING,))


REPORTED_ROOT_PRIORITY = k.FactId("l2.stp.reported_root_priority")
REPORTED_ROOT_MAC = k.FactId("l2.stp.reported_root_mac")
ROOT_STEP = StepSpec(id=StepId("l2.stp/parse_root_guard"), pack=PACK, kind="parse_build", scope="device",
    reads=(), produces=tuple(sorted((ROOT_GUARD, REPORTED_ROLE, REPORTED_ROOT_PRIORITY, REPORTED_ROOT_MAC))),
    evaluator="l2.stp.build_root_observations")
ROOT_DECLARATION = PackDeclaration(pack=PACK, entity_kinds=DECLARATION.entity_kinds,
    facts=DECLARATION.facts + (
        FactSpec(id=REPORTED_ROOT_PRIORITY, pack=PACK, subject="stp_port_vlan", value_type="integer", step=ROOT_STEP.id),
        FactSpec(id=REPORTED_ROOT_MAC, pack=PACK, subject="stp_port_vlan", value_type="text", step=ROOT_STEP.id)),
    relations=(), steps=(ROOT_STEP,), operations=(BINDING,))


@dataclass(frozen=True, slots=True, kw_only=True)
class _Producer:
    """One retained producer selected only by the fixed named builder APIs."""

    declaration: PackDeclaration
    binding: OperationBinding
    step: StepSpec
    roots: bool = False

    def __post_init__(self) -> None:
        legacy = not self.roots and self.declaration is DECLARATION and self.step is STEP
        extended = self.roots and self.declaration is ROOT_DECLARATION and self.step is ROOT_STEP
        k.require(type(self.roots) is bool and self.binding is BINDING and (legacy or extended), "stp_producer_profile")


def _legacy_producer() -> _Producer:
    return _Producer(declaration=DECLARATION, binding=BINDING, step=STEP)


def _root_producer() -> _Producer:
    producer = _Producer(declaration=ROOT_DECLARATION, binding=BINDING, step=ROOT_STEP, roots=True)
    expected = (("l2.stp.reported_role", "text"), ("l2.stp.reported_root_mac", "text"),
                ("l2.stp.reported_root_priority", "integer"), ("l2.stp.root_guard", "boolean"))
    step, declaration, binding = producer.step, producer.declaration, producer.binding
    k.require(step.id == "l2.stp/parse_root_guard" and step.pack == declaration.pack == "l2.stp"
        and step.kind == "parse_build" and step.scope == "device" and step.reads == ()
        and step.evaluator == "l2.stp.build_root_observations"
        and step.produces == tuple(fact for fact, _ in expected) and declaration.steps == (step,)
        and declaration.operations == (binding,) and binding.operation == stp.OP and binding.step == step.id
        and declaration.relations == () and len(declaration.entity_kinds) == 1
        and all(kind.id == "stp_port_vlan" and kind.pack == "l2.stp" and kind.root is False
                for kind in declaration.entity_kinds)
        and tuple(sorted((fact.id, fact.value_type) for fact in declaration.facts)) == expected
        and all(fact.pack == "l2.stp" and fact.subject == "stp_port_vlan" and fact.step == step.id
                for fact in declaration.facts), "stp_root_observation_metadata")
    return producer


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
    role: k.Known[str] | k.Unknown
    root_priority: k.Known[int] | k.Unknown | None = None
    root_mac: k.Known[str] | k.Unknown | None = None


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


def _guard_claims(target: Target, row: stp.Row, capture: Capture,
                  parsed: stp.ParseResult) -> tuple[bool, str, tuple[k.ByteSpan, ...], stp.Record, stp.Record]:
    fields = dict(row.fields)
    names = tuple(name for name, _ in row.fields)
    k.require(all(names.count(name) == 1 for name in ("port", "vlan", "root_guard")), "stp_guard_fields")
    token = fields["root_guard"]
    k.require(token.value is stp.Switch.ENABLED or token.value is stp.Switch.DISABLED, "stp_guard_value")
    enabled = token.value is stp.Switch.ENABLED
    k.require(token.raw == ("enabled" if enabled else "disabled"), "stp_guard_value")
    records = parsed.records
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
    return enabled, token.raw, (token.span, guard, port.span, vid.span, header), nearest, guards[0]


def _observed(target: Target, row: stp.Row, output: Executed[stp.Result], provenance: tuple[k.Evidence, ...]) -> k.Known[bool]:
    capture = output.receipt.capture
    enabled, raw, spans, _, _ = _guard_claims(target, row, capture, output.receipt.parse)
    refs = tuple(k.EvidenceRef(capture=capture.id, locator=s, role=k.EvidenceRole.SUBJECT,
                 excerpt_sha256=sha256(capture.raw[s.start:s.end]).hexdigest()) for s in spans)
    return k.Known(value=enabled, basis=k.Basis.OBSERVED, evidence=provenance + refs, raw=raw)


def _role_states(
    target: Target, outputs: list[Executed[stp.Result]], provenance: tuple[k.Evidence, ...],
    evidence: tuple[k.Evidence, ...], step: StepSpec,
) -> tuple[k.Known[str] | k.Unknown, ...]:
    needs = (k.EvidenceNeed(node=target.node.key, operation=stp.OP, params=(("port", target.port),),
             resolves=(REPORTED_ROLE,), reruns=(step.id,), after_s=None, unprintable=()),)
    proofs = reported_header_proofs(target, outputs[0]) if outputs else ()
    states: list[k.Known[str] | k.Unknown] = []
    for index, _ in enumerate(target.vlans):
        reason: k.UnknownReason | None = k.UnknownReason.NOT_COLLECTED
        if outputs:
            output, = outputs
            rich, spans = proofs[index]
            if spans:
                token = dict(rich.fields)["role"]
                role = token.value
                if type(role) is not stp.Role:
                    raise ValueError("stp_proof_header")
                refs = tuple(k.EvidenceRef(capture=output.receipt.capture.id, locator=span,
                    role=k.EvidenceRole.SUBJECT, excerpt_sha256=sha256(output.receipt.capture.raw[span.start:span.end]).hexdigest())
                    for span in spans)
                states.append(k.Known(value=role.value, basis=k.Basis.OBSERVED, raw=token.raw, evidence=provenance + refs))
                continue
            reason = output.value.reason or rich.reason
            capture = output.receipt.capture
            if reason is None and (capture.integrity is k.IntegrityState.ERROR
                    or capture.metadata is not None and capture.metadata.error is not None):
                reason = k.UnknownReason.CAPTURE_ERROR
            if reason is None and capture.integrity in (k.IntegrityState.TRUNCATED, k.IntegrityState.PAGING_ARTIFACTS):
                reason = k.UnknownReason.CAPTURE_TRUNCATED
            if reason is None and capture.integrity is k.IntegrityState.EMPTY:
                reason = k.UnknownReason.EMPTY_UNREGISTERED
            if reason is None:
                reason = (k.UnknownReason.FIELD_NOT_PRINTED if output.value.parse.quality == "complete"
                          and "role" not in dict(rich.fields) else k.UnknownReason.PARSE_PARTIAL)
        states.append(k.Unknown(reason=reason, detail="stp_reported_role_unresolved",
                                evidence=evidence, candidates=(), next_evidence=needs))
    return tuple(states)


def _rows(target: Target, outputs: list[Executed[stp.Result]], declared: tuple[k.RegistryRef, ...],
          step: StepSpec, *, roots: bool = False) -> tuple[Row, ...]:
    needs = (k.EvidenceNeed(node=target.node.key, operation=stp.OP, params=(("port", target.port),),
             resolves=(ROOT_GUARD,), reruns=(step.id,), after_s=None, unprintable=()),)
    provenance = target.node.declaration.evidence + declared
    evidence = provenance + tuple(k.EvidenceRef(capture=o.receipt.capture.id,
        locator=k.WholeCapture(), role=k.EvidenceRole.WITNESS, excerpt_sha256=o.receipt.capture.bytes_sha256) for o in outputs)
    values: list[k.Known[bool] | k.Unknown] = []
    for index, _ in enumerate(target.vlans):
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
                values.append(_observed(target, row, output, provenance))
                continue
        value = k.Unknown(reason=reason, detail="stp_root_guard_unresolved", evidence=evidence, candidates=(), next_evidence=needs)
        values.append(value)
    roles = _role_states(target, outputs, provenance, evidence, step)
    root_values: tuple[tuple[k.Known[int] | k.Unknown | None, k.Known[str] | k.Unknown | None], ...] = (
        _root_states(target, outputs, provenance, evidence, roles, step) if roots
        else tuple((None, None) for _ in target.vlans))
    return tuple(Row(target=target, vlan=vlan, subject=subject(target, vlan), value=value, role=role,
                     root_priority=priority, root_mac=mac)
                 for vlan, value, role, (priority, mac) in zip(target.vlans, values, roles, root_values, strict=True))


def _root_states(
    target: Target, outputs: list[Executed[stp.Result]], provenance: tuple[k.Evidence, ...],
    evidence: tuple[k.Evidence, ...], roles: tuple[k.Known[str] | k.Unknown, ...], step: StepSpec,
) -> tuple[tuple[k.Known[int] | k.Unknown, k.Known[str] | k.Unknown], ...]:
    # One fixed literal import resolves the owning build/proof module dependency.
    from atlas_brain.packs.l2.stp import root_identity

    needs = (k.EvidenceNeed(node=target.node.key, operation=stp.OP, params=(("port", target.port),),
        resolves=(REPORTED_ROOT_MAC, REPORTED_ROOT_PRIORITY), reruns=(step.id,), after_s=None, unprintable=()),)
    claims = root_identity.validate_root_identity_claims(target, outputs[0],
        root_identity.reported_root_identity_proofs(target, outputs[0])) if outputs else ()
    result: list[tuple[k.Known[int] | k.Unknown, k.Known[str] | k.Unknown]] = []
    for index, role in enumerate(roles):
        if outputs:
            rich, displayed, spans = claims[index]
            if displayed is not None:
                fields, output = dict(rich.fields), outputs[0]
                k.require(type(displayed.priority) is int and 0 <= displayed.priority <= 65535
                    and type(displayed.address) is str and re.fullmatch(stp.MAC, displayed.address) is not None
                    and fields["root_priority"].raw == str(displayed.priority)
                    and fields["root_mac"].raw == displayed.address, "stp_root_observation_value")
                refs = tuple(k.EvidenceRef(capture=output.receipt.capture.id, locator=span,
                    role=k.EvidenceRole.SUBJECT, excerpt_sha256=sha256(output.receipt.capture.raw[span.start:span.end]).hexdigest())
                    for span in spans)
                result.append((k.Known(value=displayed.priority, basis=k.Basis.OBSERVED,
                    raw=fields["root_priority"].raw, evidence=provenance + refs),
                    k.Known(value=displayed.address, basis=k.Basis.OBSERVED,
                    raw=fields["root_mac"].raw, evidence=provenance + refs)))
                continue
        reason = role.reason if type(role) is k.Unknown else k.UnknownReason.FIELD_NOT_PRINTED
        unknown = k.Unknown(reason=reason, detail="stp_reported_root_unresolved",
                            evidence=evidence, candidates=(), next_evidence=needs)
        result.append((unknown, unknown))
    return tuple(result)


def _root_pair(row: Row) -> tuple[k.Known[int] | k.Unknown, k.Known[str] | k.Unknown]:
    priority, mac = row.root_priority, row.root_mac
    if priority is None or mac is None:
        raise ValueError("stp_root_observation_population")
    return priority, mac


def build_root_guard(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Accept at most one capture per target and execute before projecting any subject."""
    return _local(_plan(targets, requests, None), _legacy_producer())


def build_root_observations(targets: tuple[Target, ...], requests: tuple[CaptureRequest, ...]) -> Result:
    """Run the fixed local four-fact profile; this is not folder/global projection admission."""
    return _local(_plan(targets, requests, None), _root_producer())


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


def _local(plan: _Plan, producer: _Producer) -> Result:
    produced: dict[k.CaptureId, stp.Result] | None = {} if producer.roots else None
    handler = Handler(binding=producer.binding, parser=_Adapter(plan.by_capture, produced))
    executed = execute_parsers((producer.declaration,), (handler,), plan.requests)
    if producer.roots:
        k.require(type(executed) is tuple and all(type(output) is Executed and type(output.receipt) is ParseReceipt
            and type(output.receipt.capture) is Capture and type(output.value) is stp.Result for output in executed),
            "stp_root_observation_source")
        requests = {request.capture.id: request for request in plan.requests}
        registration = compile_packs((producer.declaration,)).registration_sha256
        k.require(produced is not None and set(produced) == set(requests)
            and len(executed) == len(requests) and {output.receipt.capture.id for output in executed} == set(requests),
            "stp_root_observation_source")
        for output in executed:
            receipt = output.receipt
            request = requests[receipt.capture.id]
            k.require(receipt.registration_sha256 == registration and receipt.owner == producer.step.id,
                      "stp_root_observation_profile")
            target = plan.by_capture[receipt.capture.id]
            k.require(receipt.capture is request.capture and receipt.context == request.context == target.context
                and receipt.capture.source == target.node.key and receipt.capture.operation == stp.OP
                and receipt.capture.rendered == stp.command(target.port)
                and produced is not None and produced.get(receipt.capture.id) is output.value
                and receipt.parse is output.value.parse, "stp_root_observation_source")
    return _materialize(plan, executed, producer)


def _materialize(plan: _Plan, executed: tuple[Executed[stp.Result], ...], producer: _Producer) -> Result:
    indexed, by_capture, proofs = plan.indexed, plan.by_capture, plan.proofs
    grouped: dict[tuple[str, k.EntityKey, str], list[Executed[stp.Result]]] = {key: [] for key in indexed}
    for output in executed:
        target = by_capture[output.receipt.capture.id]
        k.require(type(output.value) is stp.Result and output.receipt.parse is output.value.parse, "stp_receipt_parse")
        k.require(type(output.value.rows) is tuple and all(type(r) is stp.Row and type(r.vlan) is int
                  and r.port == target.port for r in output.value.rows)
                  and tuple(r.vlan for r in output.value.rows) == target.vlans, "stp_parser_population")
        grouped[(target.context, target.node.key, stp.command(target.port))].append(output)
    rows = tuple(row for key in sorted(indexed) for row in _rows(
        indexed[key], grouped[key], () if proofs is None else proofs[key], producer.step, roots=producer.roots))
    k.require(len({r.subject for r in rows}) == len(rows), "stp_subject_collision")
    root_pairs = tuple(_root_pair(row) for row in rows) if producer.roots else ()
    store = FactStore()
    writer = bind_writer(store, step=producer.step)
    for index, row in enumerate(rows):
        writer.write(fact=ROOT_GUARD, subject=row.subject, value=row.value)
        writer.write(fact=REPORTED_ROLE, subject=row.subject, value=row.role)
        if producer.roots:
            priority, mac = root_pairs[index]
            writer.write(fact=REPORTED_ROOT_PRIORITY, subject=row.subject, value=priority)
            writer.write(fact=REPORTED_ROOT_MAC, subject=row.subject, value=mac)
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
    producer = _legacy_producer()
    envelope = p4_admission.admit_folder(root, budgets, declarations=(producer.declaration,))
    return FolderResult(envelope=envelope, result=_local(_scope(envelope, budgets, producer, singleton=True), producer))


def _scope(envelope: p4_admission.Envelope, budgets: Budgets, producer: _Producer, *,
           singleton: bool, capture_requests: bool = True) -> _Plan:
    k.require(type(envelope) is p4_admission.Envelope and type(envelope.raw) is bytes
              and type(envelope.base) is SyntheticGroup and type(envelope.base.raw) is bytes, "stp_folder_registry")
    registration = envelope.registration_sha256
    if singleton:
        k.require(registration == compile_packs((producer.declaration,)).registration_sha256, "stp_folder_registration")
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
            k.require(not singleton and item.owner != producer.step.id, "stp_folder_target")
            continue
        k.require(item.owner == producer.step.id, "stp_folder_target")
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
    if not capture_requests:
        return _plan(tuple(targets[name] for name in targets), (), proofs)
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

    def __init__(self, budgets: Budgets, *, roots: bool = False) -> None:
        k.require(type(roots) is bool, "stp_producer_profile")
        self.budgets = budgets
        self.producer = _root_producer() if roots else _legacy_producer()
        self.envelope: p4_admission.Envelope | None = None
        self.registration = ""
        self.plan: _Plan | None = None
        self.produced: dict[k.CaptureId, stp.Result] = {}

    def declaration(self) -> PackDeclaration:
        return self.producer.declaration

    def prepare(self, envelope: p4_admission.Envelope) -> p4_pipeline.Prepared[stp.Result | Peer]:
        k.require(self.plan is None, "stp_global_run")
        plan = _scope(envelope, self.budgets, self.producer, singleton=False)
        self.envelope, self.registration, self.plan = envelope, envelope.registration_sha256, plan
        handler = Handler[stp.Result | Peer](binding=self.producer.binding, parser=_Adapter(plan.by_capture, self.produced))
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
        return _materialize(plan, tuple(owned), self.producer)


def _root_guard_source_state(state: k.Known[bool] | k.Known[str] | k.Unknown,
                             wanted: k.Known[bool] | k.Known[str] | k.Unknown) -> None:
    if isinstance(wanted, k.Known):
        if type(state) is not k.Known:
            raise ValueError("stp_root_guard_source_value")
        k.require(type(state.value) is type(wanted.value) and type(state.raw) is type(wanted.raw)
                  and state.basis is wanted.basis, "stp_root_guard_source_value")
        k.Known(value=state.value, raw=state.raw, basis=state.basis, evidence=state.evidence)
    else:
        if type(state) is not k.Unknown:
            raise ValueError("stp_root_guard_source_value")
        k.require(type(state.candidates) is tuple and all(type(value) is str for value in state.candidates), "stp_root_guard_source_value")
        k.Unknown(reason=state.reason, detail=state.detail, evidence=state.evidence,
                  candidates=state.candidates, next_evidence=state.next_evidence)
        for need in state.next_evidence:
            k.require(all(type(values) is tuple and all(type(value) is str for value in values)
                          for values in (need.resolves, need.reruns, need.unprintable)), "stp_root_guard_source_value")
            k.EvidenceNeed(node=need.node, operation=need.operation, params=need.params, resolves=need.resolves,
                reruns=need.reruns, after_s=need.after_s, unprintable=need.unprintable)
    for ref in state.evidence:
        if type(ref) is k.RegistryRef:
            k.RegistryRef(table=ref.table, row_id=ref.row_id, table_digest=ref.table_digest, citation=ref.citation)
        elif type(ref) is k.EvidenceRef:
            locator = ref.locator
            if type(locator) is k.ByteSpan:
                k.ByteSpan(start=locator.start, end=locator.end)
            else:
                k.require(type(locator) is k.WholeCapture, "stp_root_guard_source_value")
            k.EvidenceRef(capture=ref.capture, locator=locator, role=ref.role, excerpt_sha256=ref.excerpt_sha256)
        else:
            raise ValueError("stp_root_guard_source_value")
    k.require(state == wanted, "stp_root_guard_source_value")


class RootGuardPack[Peer](_GlobalSTP[Peer]):
    """Fixed legacy STP staging; ordinary preparation does not finish or write facts."""

    def __init__(self, budgets: Budgets) -> None:
        super().__init__(budgets)

    def validate_root_guard_values(self, result: Result, reader: FactReader,
                                   outputs: tuple[Executed[stp.Result | Peer], ...]) -> tuple[Target, ...]:
        """Compare actual legacy owning values; callers still own whole-run/profile/proof closure."""
        envelope, plan, producer = self.envelope, self.plan, self.producer
        if envelope is None or plan is None:
            raise ValueError("stp_root_guard_source_run")
        k.require(type(self.budgets) is Budgets and all(type(value) is int and value > 0 for value in
            (self.budgets.bundle_bytes, self.budgets.artifact_bytes, self.budgets.artifacts, self.budgets.nesting_depth,
             self.budgets.numeric_digits, self.budgets.compression_ratio, self.budgets.archive_index_bytes)),
            "stp_root_guard_source_budget")
        k.require(type(envelope) is p4_admission.Envelope and type(plan) is _Plan
                  and type(self) is RootGuardPack and type(producer) is _Producer and producer.roots is False
                  and producer.declaration is DECLARATION and producer.step is STEP and producer.binding is BINDING,
                  "stp_root_guard_source_profile")
        contract = projection_contract()
        step = StepSpec(id=contract[0][2], pack=contract[0][1], kind="parse_build", scope="device", reads=(),
            produces=tuple(spec[0] for spec in contract), evaluator="l2.stp.build_root_guard")
        binding = OperationBinding(operation="iosxe.show_spanning_tree_interface_detail", step=step.id)
        literal = PackDeclaration(pack=step.pack, entity_kinds=(EntityKindSpec(id="stp_port_vlan", pack=step.pack, root=False),),
            facts=tuple(FactSpec(id=fact, pack=pack, subject=kind, value_type="boolean" if value is bool else "text",
                step=owner) for fact, pack, owner, kind, value in contract), relations=(), steps=(step,), operations=(binding,))
        runtime = PackDeclaration(pack=DECLARATION.pack, entity_kinds=DECLARATION.entity_kinds, facts=DECLARATION.facts,
            relations=DECLARATION.relations, steps=(producer.step,), operations=(producer.binding,))
        identities = tuple((item.catalogue_bytes, item.registration_bytes, item.registration_sha256)
            for item in (compile_packs((DECLARATION,)), compile_packs((runtime,)), compile_packs((literal,))))
        k.require(type(ROOT_GUARD) is str and type(REPORTED_ROLE) is str
                  and (REPORTED_ROLE, ROOT_GUARD) == step.produces and producer.step == step and producer.binding == binding
                  and identities[0] == identities[1] == identities[2],
                  "stp_root_guard_source_profile")
        k.require(type(self.registration) is str and self.registration == envelope.registration_sha256,
                  "stp_root_guard_source_run")
        base = envelope.base
        k.require(type(base) is SyntheticGroup and type(envelope.raw) is bytes and type(base.raw) is bytes
                  and all(type(value) is str for value in (base.id, base.schema, envelope.context)) and type(base.nodes) is tuple
                  and all(type(node) is Node and all(type(value) is str for value in (node.id, node.group, node.discovery_id))
                      and type(node.ports) is tuple and all(type(port) is str for port in node.ports) for node in base.nodes)
                  and type(envelope.targets) is tuple and all(type(target) is p4_admission.Target
                      and all(type(value) is str for value in (target.id, target.operation, target.owner))
                      and type(target.params) is bytes and any(target.node is node for node in base.nodes) for target in envelope.targets)
                  and type(envelope.captures) is tuple and all(type(member) is p4_admission.CaptureMember
                      and all(type(value) is str for value in (member.id, member.path, member.sha256))
                      and type(member.raw) is bytes and any(member.target is target for target in envelope.targets) for member in envelope.captures),
                  "stp_root_guard_source_graph")
        fresh = _scope(envelope, self.budgets, producer, singleton=False, capture_requests=False)
        k.require(type(plan.indexed) is dict and all(type(key) is tuple and len(key) == 3
                  and all(type(value) is str for value in key) for key in plan.indexed)
                  and set(plan.indexed) == set(fresh.indexed)
                  and plan.proofs == fresh.proofs and type(plan.requests) is tuple
                  and all(type(request) is CaptureRequest and type(request.capture) is Capture
                      and all(type(value) is str for value in (request.capture.id, request.capture.source,
                          request.capture.operation, request.capture.rendered, request.capture.codec))
                      and type(request.capture.raw) is bytes and type(request.capture.lines) is tuple
                      for request in plan.requests), "stp_root_guard_source_population")
        for key, target in plan.indexed.items():
            wanted = fresh.indexed[key]
            k.require(type(target) is Target and target.node is wanted.node and target == wanted, "stp_root_guard_source_population")
            Target(context=target.context, node=target.node, port=target.port, vlans=target.vlans)
        k.require(type(outputs) is tuple and all(type(output) is Executed and type(output.receipt) is ParseReceipt
                  and type(output.receipt.capture) is Capture and type(output.receipt.capture.operation) is str
                  for output in outputs), "stp_root_guard_source_receipt")
        own = tuple(output for output in outputs if output.receipt.capture.operation == stp.OP)
        k.require(all(all(type(value) is str for value in (output.receipt.capture.id, output.receipt.capture.source,
                  output.receipt.capture.rendered, output.receipt.owner, output.receipt.context,
                  output.receipt.registration_sha256)) for output in own), "stp_root_guard_source_receipt")
        requests = {request.capture.id: request for request in plan.requests}
        k.require(len(requests) == len(plan.requests) == len(own) and type(self.produced) is dict
                  and all(type(key) is str and type(value) is stp.Result for key, value in self.produced.items())
                  and set(requests) == set(self.produced) == {output.receipt.capture.id for output in own},
                  "stp_root_guard_source_population")
        grouped: dict[_Key, list[Executed[stp.Result]]] = {key: [] for key in fresh.indexed}
        checked: list[Executed[stp.Result]] = []
        for output in own:
            receipt, capture = output.receipt, output.receipt.capture
            value = self.produced[capture.id]
            k.require(type(value) is stp.Result and output.value is value and receipt.parse is value.parse
                      and capture is requests[capture.id].capture and receipt.owner == step.id
                      and receipt.context == requests[capture.id].context
                      and receipt.registration_sha256 == self.registration, "stp_root_guard_source_cache")
            key = (receipt.context or "", capture.source, capture.rendered)
            k.require(key in grouped, "stp_root_guard_source_population")
            narrowed = Executed(receipt=receipt, value=value)
            grouped[key].append(narrowed)
            checked.append(narrowed)
        expected_rows = tuple(row for key in sorted(fresh.indexed) for row in _rows(fresh.indexed[key], grouped[key],
            () if fresh.proofs is None else fresh.proofs[key], step, roots=False))
        k.require(type(result) is Result and type(result.store) is FactStore and type(result.rows) is tuple
                  and all(type(row) is Row and type(row.subject) is str and type(row.vlan) is int for row in result.rows)
                  and type(result.executed) is tuple and all(type(output) is Executed and type(output.receipt) is ParseReceipt
                      for output in result.executed) and len(result.executed) == len(checked)
                  and all(a.receipt is b.receipt and a.value is b.value for a, b in zip(result.executed, checked, strict=True))
                  and type(reader) is FactReader and reader.store is result.store, "stp_root_guard_source_store")
        owners = {fact: owner for fact, _, owner, _, _ in contract}
        references = {k.FactRef(fact=fact, subject=row.subject) for row in expected_rows for fact in owners}
        k.require(type(result.store.owners) is dict and result.store.owners == owners
                  and all(type(fact) is str and type(owner) is str for fact, owner in result.store.owners.items())
                  and type(result.store.values) is dict and all(type(ref) is k.FactRef
                      and type(ref.fact) is str and type(ref.subject) is str for ref in result.store.values)
                  and set(result.store.values) == references, "stp_root_guard_source_store")
        rows = {row.subject: row for row in result.rows}
        k.require(len(rows) == len(result.rows) == len(expected_rows)
                  and set(rows) == {row.subject for row in expected_rows}, "stp_root_guard_source_population")
        for wanted in expected_rows:
            row = rows[wanted.subject]
            k.require(type(row.target) is Target and row.target.node is wanted.target.node and row.target == wanted.target
                      and row.vlan == wanted.vlan, "stp_root_guard_source_population")
            Target(context=row.target.context, node=row.target.node, port=row.target.port, vlans=row.target.vlans)
            for fact, value in ((REPORTED_ROLE, wanted.role), (ROOT_GUARD, wanted.value)):
                actual_value = original_state(fact, row)
                k.require(reader.read(fact=fact, subject=row.subject) is actual_value, "stp_root_guard_source_store")
                _root_guard_source_state(actual_value, value)
        return tuple(plan.indexed[key] for key in sorted(plan.indexed))


def build_root_guard_global[Peer](
    root: Path, budgets: Budgets, *, peers: tuple[p4_pipeline.Pack[stp.Result | Peer], ...],
) -> GlobalFacts[Peer]:
    """Run once; STP facts need original captures/values from this invocation, and peers stay opaque."""
    k.require(type(peers) is tuple, "stp_global_peers")
    owner = _GlobalSTP[Peer](budgets)
    packs: tuple[p4_pipeline.Pack[stp.Result | Peer], ...] = (owner, *peers)
    execution = p4_pipeline.execute_p4_folder(root, budgets, packs=packs)
    return GlobalFacts[Peer](execution=execution, result=owner.finish(execution))


def build_root_observations_global[Peer](
    root: Path, budgets: Budgets, *, peers: tuple[p4_pipeline.Pack[stp.Result | Peer], ...],
) -> GlobalFacts[Peer]:
    """Own an extended run; callers still close every peer before consuming observations."""
    k.require(type(peers) is tuple, "stp_global_peers")
    owner = _GlobalSTP[Peer](budgets, roots=True)
    packs: tuple[p4_pipeline.Pack[stp.Result | Peer], ...] = (owner, *peers)
    execution = p4_pipeline.execute_p4_folder(root, budgets, packs=packs)
    return GlobalFacts[Peer](execution=execution, result=owner.finish(execution))


@dataclass(frozen=True, slots=True, kw_only=True)
class DeclaredRootGuard:
    source: p4_admission.Target
    target: Target
    evidence: tuple[k.RegistryRef, ...]


def declared_root_guard_targets(envelope: p4_admission.Envelope, budgets: Budgets) -> tuple[DeclaredRootGuard, ...]:
    """Trusted after composition-profile validation; not standalone profile admission."""
    plan = _scope(envelope, budgets, _legacy_producer(), singleton=False, capture_requests=False)
    proofs = plan.proofs
    if proofs is None:
        raise ValueError("stp_guard_policy_selector")
    sources = {source.id: source for source in envelope.targets}
    result: list[DeclaredRootGuard] = []
    for key, target in sorted(plan.indexed.items()):
        match target.node.declaration.evidence + proofs[key]:
            case (k.RegistryRef() as node_ref, k.RegistryRef() as context_ref,
                  k.RegistryRef(row_id=identifier) as target_ref):
                result.append(DeclaredRootGuard(source=sources[identifier], target=target,
                                                evidence=(node_ref, context_ref, target_ref)))
            case _:
                raise ValueError("stp_guard_policy_selector")
    return tuple(result)


def _proof_fields(fields: tuple[tuple[str, stp.Captured], ...]) -> bool:
    return type(fields) is tuple and all(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str
        and type(pair[1]) is stp.Captured and type(pair[1].raw) is str and type(pair[1].span) is k.ByteSpan for pair in fields)


def _header_claims(target: Target, row: stp.Row, header: stp.Record, raw: bytes) -> tuple[k.ByteSpan, k.ByteSpan]:
    names = ("number", "port", "vlan", "role", "state")
    fields, cells = dict(row.fields), dict(header.fields)
    k.require(len(cells) == len(header.fields) == len(names) and set(cells) == set(names)
              and all(tuple(name for name, _ in row.fields).count(name) == 1 and fields[name] is cells[name] for name in names)
              and any(span is header.span for span in row.spans), "stp_proof_header")
    number, port, vlan, role, state = tuple(cells[name] for name in names)
    rv, sv = role.value, state.value
    if type(rv) is not stp.Role or type(sv) is not stp.State:
        raise ValueError("stp_proof_header")
    k.require(all(token.raw.isascii() for token in cells.values())
              and all(type(token.value) is str and token.value == token.raw for token in (number, port, vlan))
              and number.raw.isdigit() and port.raw == target.port and vlan.raw == f"{row.vlan:04d}", "stp_proof_header")
    line = _line(raw, header.span)
    port_prefix = b"Port " + number.raw.encode("ascii") + b" ("
    vlan_prefix = port_prefix + target.port.encode("ascii") + b") of VLAN"
    prefix = vlan_prefix + f"{row.vlan:04d}".encode("ascii") + b" is "
    k.require(line.strip(b" \t") == prefix + role.raw.encode("ascii") + b" " + state.raw.encode("ascii"), "stp_proof_header")
    first = header.span.start + len(line) - len(line.lstrip(b" \t"))
    for token, expected, start in ((number, number.raw, first + len(b"Port ")),
                                   (port, target.port, first + len(port_prefix)),
                                   (vlan, f"{row.vlan:04d}", first + len(vlan_prefix)),
                                   (role, rv.value, first + len(prefix)),
                                   (state, sv.value, first + len(prefix) + len(role.raw) + 1)):
        k.require(token.raw == expected and token.span.start == start and token.span.end == start + len(expected)
                  and raw[token.span.start:token.span.end] == expected.encode("ascii"), "stp_proof_header")
    return role.span, state.span


def _proof_inputs[T](target: Target, output: Executed[T]) -> tuple[stp.Result, Capture, bool]:
    """Validate the existing trusted raw-proof boundary without constructing fact state."""
    if (type(target) is not Target or type(output) is not Executed or type(output.receipt) is not ParseReceipt
            or type(output.receipt.capture) is not Capture):
        raise ValueError("stp_proof_input")
    value, receipt = output.value, output.receipt
    if (type(value) is not stp.Result or type(value.parse) is not stp.ParseResult
            or receipt.parse is not value.parse):
        raise ValueError("stp_proof_input")
    try:
        Target(context=target.context, node=target.node, port=target.port, vlans=target.vlans)
    except ValueError as error:
        raise ValueError("stp_proof_input") from error
    capture, parsed = receipt.capture, value.parse
    k.require(type(capture.id) is str and bool(capture.id) and type(capture.raw) is bytes and type(capture.lines) is tuple
              and type(capture.integrity) is k.IntegrityState
              and type(capture.read_scope) is k.ReadScope and type(capture.view) is k.ViewConsistency
              and (capture.metadata is None or type(capture.metadata) is CaptureMetadata), "stp_proof_input")
    k.require(receipt.owner == STEP.id and receipt.context == target.context and capture.source == target.node.key
              and capture.operation == stp.OP and capture.rendered == stp.command(target.port)
              and capture.codec in ("ascii", "utf-8"), "stp_proof_binding")
    metadata = capture.metadata
    if metadata is not None:
        expected = Scope(node=target.node.key, plane="exec", vrf=None, context=None, vdc=None, tenant=None, afi=None, instance=None)
        k.require(type(metadata.scope) is Scope and metadata.scope == expected, "stp_proof_binding")
    k.require(type(value.rows) is tuple and all(type(row) is stp.Row and type(row.port) is str
              and row.port == target.port and type(row.vlan) is int for row in value.rows)
              and tuple(row.vlan for row in value.rows) == tuple(sorted(target.vlans)), "stp_proof_population")
    k.require(parsed.quality in ("complete", "partial") and (value.reason is None or type(value.reason) is k.UnknownReason)
              and _proof_fields(parsed.tokens) and type(parsed.records) is tuple and all(type(record) is stp.Record and type(record.span) is k.ByteSpan
                  and type(record.rule_id) is str and _proof_fields(record.fields) for record in parsed.records)
              and all(_proof_fields(row.fields) and type(row.spans) is tuple and all(type(span) is k.ByteSpan for span in row.spans)
                  and (row.reason is None or type(row.reason) is k.UnknownReason) for row in value.rows), "stp_proof_input")
    eligible = (value.reason is None and parsed.quality == "complete" and capture.integrity is k.IntegrityState.COMPLETE
                and (metadata is None or metadata.error is None)
                and not any(isinstance(token.value, k.Unknown) for _, token in parsed.tokens))
    return value, capture, eligible


def reported_root_guard_proofs[T](target: Target, output: Executed[T]) -> tuple[tuple[stp.Row, tuple[k.ByteSpan, ...]], ...]:
    """Raw reported guard/header claims only; trusted after composition/owner finish, not a producer seal."""
    value, capture, eligible = _proof_inputs(target, output)
    parsed = value.parse
    checked: list[tuple[stp.Row, tuple[k.ByteSpan, ...]]] = []
    for row in value.rows:
        spans: tuple[k.ByteSpan, ...] = ()
        if (eligible and row.reason is None and "root_guard" in dict(row.fields)
                and not any(name in ("root_guard", "role", "state") and isinstance(token.value, k.Unknown) for name, token in row.fields)):
            _, _, guard_spans, header, guard = _guard_claims(target, row, capture, parsed)
            k.require(guard.fields[0][1] is dict(row.fields)["root_guard"]
                      and any(span is guard.span for span in row.spans), "stp_proof_header")
            spans = tuple(sorted(guard_spans + _header_claims(target, row, header, capture.raw), key=lambda point: (point.start, point.end)))
        checked.append((row, spans))
    return tuple(checked)


def reported_header_proofs[T](target: Target, output: Executed[T]) -> tuple[tuple[stp.Row, tuple[k.ByteSpan, ...]], ...]:
    """Raw reported header claims, independent of guard printout; not fact admission or a producer seal."""
    value, capture, eligible = _proof_inputs(target, output)
    checked: list[tuple[stp.Row, tuple[k.ByteSpan, ...]]] = []
    for row in value.rows:
        spans: tuple[k.ByteSpan, ...] = ()
        if (eligible and row.reason is None and row.fields
                and not any(isinstance(token.value, k.Unknown) for _, token in row.fields)):
            headers = tuple(record for record in value.parse.records if record.rule_id.startswith("header_")
                            and any(span is record.span for span in row.spans))
            k.require(len(headers) == 1, "stp_proof_header")
            record, = headers
            role, state = _header_claims(target, row, record, capture.raw)
            fields = dict(row.fields)
            spans = tuple(sorted((record.span, fields["port"].span, fields["vlan"].span, role, state),
                                 key=lambda point: (point.start, point.end)))
        checked.append((row, spans))
    return tuple(checked)


type ProjectionSpec = tuple[k.FactId, k.PackId, StepId, str, type[bool | str]]


def projection_contract() -> tuple[ProjectionSpec, ...]:
    """Trusted literal expectations, independent of the declaration metadata under validation."""
    return ((k.FactId("l2.stp.reported_role"), k.PackId("l2.stp"), StepId("l2.stp/parse_root_guard"), "stp_port_vlan", str),
            (k.FactId("l2.stp.root_guard"), k.PackId("l2.stp"), StepId("l2.stp/parse_root_guard"), "stp_port_vlan", bool))


def original_state(fact: k.FactId, row: Row) -> k.Known[bool] | k.Known[str] | k.Unknown:
    """Return the original owning state, independently of projection tuples or Store."""
    if type(fact) is not str or fact not in (k.FactId("l2.stp.root_guard"), k.FactId("l2.stp.reported_role")):
        raise ValueError("stp_projection_fact")
    if type(row) is not Row:
        raise ValueError("stp_projection_rows")
    return row.value if fact == k.FactId("l2.stp.root_guard") else row.role


def requires_all(fact: k.FactId) -> bool:
    """Trusted literal leaf policy; unregistered facts have no projection permission."""
    if type(fact) is not str or fact not in (k.FactId("l2.stp.root_guard"), k.FactId("l2.stp.reported_role")):
        raise ValueError("stp_projection_fact")
    return fact == k.FactId("l2.stp.reported_role")


def fact_rows(result: Result) -> tuple[tuple[k.FactId, Row, k.Known[bool] | k.Known[str] | k.Unknown], ...]:
    """Expose original owning rows/states for trusted projection, not result admission."""
    if type(result) is not Result or type(result.rows) is not tuple or not all(type(row) is Row for row in result.rows):
        raise ValueError("stp_projection_rows")
    return tuple((k.FactId("l2.stp.reported_role"), row, row.role) for row in result.rows) + tuple(
        (k.FactId("l2.stp.root_guard"), row, row.value) for row in result.rows)


def projection_leaves[T](fact: k.FactId, domain: Target, vlan: int, output: Executed[T]) -> tuple[
    frozenset[k.ByteSpan], frozenset[k.ByteSpan], frozenset[k.ByteSpan]
]:
    """Legacy cell-local permission metadata only; not byte authentication or fact admission."""
    if fact not in tuple(spec[0] for spec in projection_contract()):
        raise ValueError("stp_projection_fact")
    if (type(domain) is not Target or type(vlan) is not int or vlan not in domain.vlans
            or type(output) is not Executed):
        raise ValueError("stp_projection_scope")
    value = output.value
    if type(value) is not stp.Result:
        raise ValueError("stp_projection_scope")
    rows = tuple(row for row in value.rows if row.port == domain.port and row.vlan == vlan)
    if len(rows) != 1:
        raise ValueError("stp_projection_scope")
    row, = rows
    if fact == k.FactId("l2.stp.reported_role"):
        points = next(points for rich, points in reported_header_proofs(domain, output) if rich is row)
        claims = frozenset(points)
        anchors: frozenset[k.ByteSpan] = frozenset((dict(row.fields)["role"].span,)) if points else frozenset()
        return claims, anchors, claims
    spans: frozenset[k.ByteSpan] = frozenset((*row.spans, *(token.span for _, token in row.fields))) if row.fields else frozenset()
    complete = (value.reason is None and row.reason is None and output.receipt.capture.integrity is k.IntegrityState.COMPLETE
                and output.receipt.parse.quality == "complete")
    tokens = tuple(token for name, token in row.fields if name == "root_guard")
    positive: frozenset[k.ByteSpan] = frozenset((tokens[0].span,)) if complete and len(tokens) == 1 else frozenset()
    return spans, positive, frozenset()


type RootProjectionSpec = tuple[k.FactId, k.PackId, StepId, str, type[bool | int | str]]


def root_projection_contract() -> tuple[RootProjectionSpec, ...]:
    return tuple(sorted(projection_contract() + (
        (k.FactId("l2.stp.reported_root_mac"), k.PackId("l2.stp"), StepId("l2.stp/parse_root_guard"), "stp_port_vlan", str),
        (k.FactId("l2.stp.reported_root_priority"), k.PackId("l2.stp"), StepId("l2.stp/parse_root_guard"), "stp_port_vlan", int)),
        key=lambda spec: spec[0]))


def root_original_state(fact: k.FactId, row: Row) -> k.Known[bool] | k.Known[int] | k.Known[str] | k.Unknown:
    if type(fact) is not str:
        raise ValueError("stp_projection_fact")
    if fact in (k.FactId("l2.stp.root_guard"), k.FactId("l2.stp.reported_role")):
        return original_state(fact, row)
    if type(row) is not Row:
        raise ValueError("stp_projection_rows")
    if fact == k.FactId("l2.stp.reported_root_priority"):
        return _root_pair(row)[0]
    if fact == k.FactId("l2.stp.reported_root_mac"):
        return _root_pair(row)[1]
    raise ValueError("stp_projection_fact")


def root_fact_rows(result: Result) -> tuple[tuple[k.FactId, Row, k.Known[bool] | k.Known[int] | k.Known[str] | k.Unknown], ...]:
    legacy = fact_rows(result)
    return legacy + tuple((fact, row, value) for row in result.rows
        for fact, value in ((REPORTED_ROOT_PRIORITY, _root_pair(row)[0]), (REPORTED_ROOT_MAC, _root_pair(row)[1])))


def root_projection_leaves[T](fact: k.FactId, domain: Target, vlan: int, output: Executed[T]) -> tuple[
    frozenset[k.ByteSpan], frozenset[k.ByteSpan], frozenset[k.ByteSpan]
]:
    if type(fact) is not str:
        raise ValueError("stp_projection_fact")
    if fact in (ROOT_GUARD, REPORTED_ROLE):
        return projection_leaves(fact, domain, vlan, output)
    if fact not in (REPORTED_ROOT_PRIORITY, REPORTED_ROOT_MAC):
        raise ValueError("stp_projection_fact")
    if (type(domain) is not Target or type(vlan) is not int or vlan not in domain.vlans
            or type(output) is not Executed):
        raise ValueError("stp_projection_scope")
    from atlas_brain.packs.l2.stp import root_identity

    claims = root_identity.validate_root_identity_claims(domain, output,
        root_identity.reported_root_identity_proofs(domain, output))
    selected = tuple((root, points) for row, root, points in claims if row.vlan == vlan)
    k.require(len(selected) == 1, "stp_projection_scope")
    root, points = selected[0]
    granted = frozenset(points)
    anchor: frozenset[k.ByteSpan] = frozenset((points[-2 if fact == REPORTED_ROOT_PRIORITY else -1],)) if root is not None else frozenset()
    return granted, anchor, granted


def validate_root_observation_values[Peer](source: GlobalFacts[Peer], budgets: Budgets, reader: FactReader) -> None:
    """Own value-to-source validation after caller-owned run/profile closure; emit no facts or verdicts."""
    k.require(type(source.result) is Result and type(source.result.store) is FactStore
        and type(source.result.rows) is tuple and all(type(row) is Row for row in source.result.rows)
        and type(reader) is FactReader, "stp_root_observation_population")
    plan = _scope(source.execution.envelope, budgets, _root_producer(), singleton=False, capture_requests=False)
    grouped: dict[_Key, list[Executed[stp.Result]]] = {key: [] for key in plan.indexed}
    for output in source.execution.executed:
        if output.receipt.capture.operation == stp.OP:
            value, receipt = output.value, output.receipt
            k.require(type(value) is stp.Result, "stp_root_observation_source")
            if type(value) is stp.Result:
                key = (receipt.context or "", receipt.capture.source, receipt.capture.rendered)
                k.require(key in grouped, "stp_root_observation_source")
                grouped[key].append(Executed(receipt=receipt, value=value))
    expected = tuple(row for key in sorted(plan.indexed) for row in _rows(plan.indexed[key], grouped[key],
        () if plan.proofs is None else plan.proofs[key], ROOT_STEP, roots=True))
    actual = {row.subject: row for row in source.result.rows}
    k.require(len(source.result.rows) == len(actual) == len(expected) and set(actual) == {row.subject for row in expected}
              and reader.store is source.result.store, "stp_root_observation_population")
    for wanted in expected:
        row = actual[wanted.subject]
        k.require(row.target == wanted.target and row.vlan == wanted.vlan, "stp_root_observation_source")
        for fact in (ROOT_GUARD, REPORTED_ROLE, REPORTED_ROOT_PRIORITY, REPORTED_ROOT_MAC):
            if fact == ROOT_GUARD:
                value = wanted.value
            elif fact == REPORTED_ROLE:
                value = wanted.role
            elif fact == REPORTED_ROOT_PRIORITY:
                value = wanted.root_priority
            else:
                value = wanted.root_mac
            state = reader.read(fact=fact, subject=row.subject)
            if isinstance(value, k.Known):
                k.require(type(state) is k.Known and type(state.value) is type(value.value)
                    and state.basis is value.basis and type(state.raw) is str and state == value,
                    "stp_root_observation_value")
            else:
                k.require(type(state) is k.Unknown and isinstance(value, k.Unknown)
                    and state.reason is value.reason and state == value, "stp_root_observation_value")


def root_requires_all(fact: k.FactId) -> bool:
    if type(fact) is not str:
        raise ValueError("stp_projection_fact")
    return True if fact in (REPORTED_ROOT_PRIORITY, REPORTED_ROOT_MAC) else requires_all(fact)
