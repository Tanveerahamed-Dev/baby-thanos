"""Bound leaf proofs for trusted completed STP/EC runs; no fact values, state or output projection."""
from dataclasses import dataclass
from hashlib import sha256
from typing import cast

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.p4_admission import SCHEMA as P4_SCHEMA
from atlas_brain.evidence.p4_admission import CaptureMember, Envelope, Target
from atlas_brain.evidence.synthetic import SCHEMA as BASE_SCHEMA
from atlas_brain.evidence.synthetic import Node, SyntheticGroup
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner.pack_receipts import ParseReceipt
from atlas_brain.runner.pack_runtime import Executed
from atlas_brain.runner.records import RunnerRefused

type Value = stp.stp.Result | ec.parse_summary.Result


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p4_projection_" + code)


def _rows(value: object, fields: tuple[str, ...]) -> tuple[dict[str, object], ...]:
    _need(type(value) is list, "registry")
    return tuple(record(row, fields) for row in cast(list[object], value))


def _strings(value: object) -> tuple[str, ...]:
    _need(type(value) is list and all(type(v) is str for v in cast(list[object], value)), "registry")
    return tuple(v for v in cast(list[object], value) if type(v) is str)


def _declared(state: k.Known[str], identity: str, ref: k.RegistryRef) -> None:
    _need(type(state) is k.Known and state.basis is k.Basis.DECLARED
          and state.value == state.raw == identity and state.evidence == (ref,), "registry")


@dataclass(frozen=True, slots=True, kw_only=True)
class Scope:
    reference: k.FactRef
    target: Target
    labels: tuple[tuple[str, str | int], ...]
    declarations: tuple[k.RegistryRef, ...]
    spans: frozenset[tuple[k.CaptureId, k.ByteSpan]]
    positive: frozenset[tuple[k.CaptureId, k.ByteSpan]]
    required: frozenset[tuple[k.CaptureId, k.ByteSpan]] = frozenset()


def _table(value: object, fields: tuple[str, ...], table: str,
           name: str, digest: str) -> dict[str, tuple[k.RegistryRef, dict[str, object]]]:
    result: dict[str, tuple[k.RegistryRef, dict[str, object]]] = {}
    for index, row in enumerate(_rows(value, fields)):
        identity = string(row, "id")
        _need(identity not in result, "registry")
        ref = k.RegistryRef(table=table, row_id=identity, table_digest=digest, citation=f"/{name}/{index}")
        result[identity] = (ref, row)
    return result


class ProofIndex:
    """Require admitted/completed owner inputs; check metadata and cell scope, not execution origin or fact values."""

    def __init__(self, execution: pipe.Result[Value], budgets: Budgets) -> None:
        _need(type(execution) is pipe.Result and type(execution.envelope) is Envelope, "capture")
        self.execution, self.budgets = execution, budgets
        envelope = execution.envelope
        _need(type(envelope.raw) is bytes and type(envelope.base) is SyntheticGroup
              and type(envelope.base.raw) is bytes, "registry")
        _need(envelope.registration_sha256 == compile_packs((stp.DECLARATION, ec.DECLARATION)).registration_sha256,
              "profile")
        self.registry_sha256, self.base_registry_sha256 = sha256(envelope.raw).hexdigest(), sha256(envelope.base.raw).hexdigest()
        base = record(strict_json(envelope.base.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "group", "nodes", "captures"))
        side = record(strict_json(envelope.raw, budgets.nesting_depth, budgets.numeric_digits),
                      ("schema", "semantic_group", "context", "base_sha256", "targets", "captures"))
        _need(base["schema"] == envelope.base.schema == BASE_SCHEMA and side["schema"] == P4_SCHEMA
              and base["semantic_group"] == side["semantic_group"] == "declared_synthetic"
              and base["group"] == envelope.base.id and side["context"] == envelope.context
              and side["base_sha256"] == self.base_registry_sha256, "registry")
        _declared(envelope.base.declaration, envelope.base.id, k.RegistryRef(table="synthetic_p2.groups",
            row_id=envelope.base.id, table_digest=self.base_registry_sha256, citation="/group"))
        nodes = _table(base["nodes"], ("id", "discovery_id", "ports"), "synthetic_p2.nodes", "nodes", self.base_registry_sha256)
        targets = _table(side["targets"], ("id", "node", "operation", "params"), "synthetic_p4.targets", "targets", self.registry_sha256)
        context = k.RegistryRef(table="synthetic_p4.context", row_id=envelope.context, table_digest=self.registry_sha256, citation="/context")
        _declared(envelope.declaration, envelope.context, context)
        self.records = {ref: canonical(row) for table in (nodes, targets) for ref, row in table.values()}
        self.records[context] = canonical(envelope.context)
        _need(type(envelope.base.nodes) is tuple and all(type(n) is Node for n in envelope.base.nodes)
              and {n.id for n in envelope.base.nodes} == set(nodes) and len(envelope.base.nodes) == len(nodes), "registry")
        _need(type(envelope.targets) is tuple and all(type(t) is Target for t in envelope.targets)
              and {t.id for t in envelope.targets} == set(targets) and len(envelope.targets) == len(targets), "registry")
        self.declarations: dict[str, tuple[k.RegistryRef, ...]] = {}
        for target in envelope.targets:
            _need(target.node.id in nodes and any(target.node is node for node in envelope.base.nodes), "registry")
            node_ref, node = nodes[target.node.id]
            target_ref, row = targets[target.id]
            _need(target.node.group == envelope.base.id and target.node.discovery_id == node["discovery_id"]
                  and tuple(sorted(_strings(node["ports"]))) == target.node.ports and row["node"] == target.node.id
                  and row["operation"] == target.operation and type(target.params) is bytes and canonical(row["params"]) == target.params, "registry")
            _declared(target.node.declaration, target.node.id, node_ref)
            _declared(target.declaration, target.id, target_ref)
            self.declarations[target.id] = (node_ref, context, target_ref)
        _need(type(envelope.captures) is tuple and all(type(m) is CaptureMember and type(m.raw) is bytes for m in envelope.captures)
              and type(execution.executed) is tuple and all(type(o) is Executed and type(o.receipt) is ParseReceipt
                  and type(o.receipt.capture) is Capture for o in execution.executed), "capture")
        self.members = {m.id: m for m in envelope.captures}
        self.snapshots = {o.receipt.capture.id: o.receipt.capture for o in execution.executed}
        self.receipts = {o.receipt.capture.id: o.receipt for o in execution.executed}
        _need(len(self.members) == len(envelope.captures) and len(self.snapshots) == len(execution.executed)
              and set(self.members) == set(self.snapshots), "capture")
        rows = _rows(side["captures"], ("target", "path", "sha256"))
        captures = {string(row, "path"): row for row in rows}
        _need(len(captures) == len(rows) == len(self.members) and set(captures) == {m.path for m in envelope.captures}, "capture")
        self.hashes = {m.id: sha256(m.raw).hexdigest() for m in envelope.captures}
        self.by_target: dict[str, list[Executed[Value]]] = {t.id: [] for t in envelope.targets}
        for output in execution.executed:
            receipt, capture = output.receipt, output.receipt.capture
            member = self.members[capture.id]
            row = captures[member.path]
            identity = canonical((P4_SCHEMA, self.registry_sha256, self.base_registry_sha256, envelope.context,
                                  member.target.id, member.path, self.hashes[capture.id], envelope.registration_sha256))
            _need(any(member.target is t for t in envelope.targets) and row["target"] == member.target.id
                  and row["sha256"] == member.sha256 == self.hashes[capture.id] and capture.id == "cap:" + sha256(identity).hexdigest()
                  and receipt.owner == member.target.owner and receipt.context == envelope.context
                  and receipt.registration_sha256 == envelope.registration_sha256 and capture.source == member.target.node.key
                  and capture.operation == member.target.operation and capture.raw == member.raw, "capture")
            valid = capture.operation == stp.stp.OP and type(output.value) is stp.stp.Result or (
                capture.operation == ec.parse_summary.OP and type(output.value) is ec.parse_summary.Result)
            _need(valid and receipt.parse is output.value.parse, "capture")
            self.by_target[member.target.id].append(output)
        self.bound: dict[k.FactRef, Scope] = {}
        for target in envelope.targets:
            _bind(self, target, targets[target.id][1]["params"])
        self.ordered = tuple(self.bound[key] for key in sorted(self.bound, key=lambda key: (key.fact, key.subject)))

    @property
    def scopes(self) -> tuple[Scope, ...]:
        return self.ordered

    @property
    def captures(self) -> tuple[Capture, ...]:
        return tuple(self.snapshots[key] for key in sorted(self.snapshots))

    def scope(self, fact: k.FactId, subject: k.EntityKey) -> Scope:
        reference = k.FactRef(fact=fact, subject=subject)
        _need(reference in self.bound, "scope")
        return self.bound[reference]

    def resolve(self, scope: Scope, evidence: tuple[k.Evidence, ...], *, positive: bool = False) -> list[dict[str, object]]:
        """Positive requests mean any Known observation, including Known(False), never the fact's truthiness."""
        _need(type(scope) is Scope and type(scope.reference) is k.FactRef and type(positive) is bool, "scope")
        _need(self.scope(scope.reference.fact, scope.reference.subject) is scope, "scope")
        _need(type(evidence) is tuple and all(type(ref) in (k.RegistryRef, k.EvidenceRef) for ref in evidence), "reference")
        _need(tuple(ref for ref in evidence if type(ref) is k.RegistryRef) == scope.declarations, "registry")
        result: list[dict[str, object]] = []
        for ref in evidence:
            if type(ref) is k.RegistryRef:
                _need(ref in self.records, "registry")
                result.append({"kind": "registry", "table": ref.table, "row_id": ref.row_id, "table_digest": ref.table_digest,
                    "citation": ref.citation, "value": strict_json(self.records[ref], self.budgets.nesting_depth, self.budgets.numeric_digits)})
            elif type(ref) is k.EvidenceRef:
                result.append(_capture_leaf(self, ref, scope, positive, None))
            else:
                raise RunnerRefused("p4_projection_reference")
        _need(not positive or any(type(ref) is k.EvidenceRef and ref.role is k.EvidenceRole.SUBJECT
                  and type(ref.locator) is k.ByteSpan and (ref.capture, ref.locator) in scope.positive for ref in evidence), "positive")
        supplied = {(ref.capture, ref.locator) for ref in evidence if type(ref) is k.EvidenceRef
                    and ref.role is k.EvidenceRole.SUBJECT and type(ref.locator) is k.ByteSpan}
        _need(not positive or scope.required <= supplied, "positive")
        return result

    def metadata_evidence(self, identity: k.CaptureId, evidence: tuple[k.Evidence, ...]) -> list[dict[str, object]]:
        """Resolve capture-local SUBJECT byte/whole leaves, with no subject or positive request."""
        _need(identity in self.members, "capture")
        _need(type(evidence) is tuple and all(type(ref) is k.EvidenceRef for ref in evidence), "reference")
        return [_capture_leaf(self, ref, None, False, identity) for ref in evidence if type(ref) is k.EvidenceRef]


def _bind(resolver: ProofIndex, target: Target, value: object) -> None:
    if target.operation == stp.stp.OP:
        params = record(value, ("port", "vlans"))
        _need(type(params["vlans"]) is list and target.owner == stp.STEP.id, "scope")
        domain = stp.Target(context=resolver.execution.envelope.context, node=target.node, port=string(params, "port"),
                            vlans=tuple(cast(list[int], params["vlans"])))
        cases = tuple((k.FactRef(fact=stp.ROOT_GUARD, subject=stp.subject(domain, vlan)),
            (("context", domain.context), ("node", domain.node.id), ("port", domain.port), ("target", target.id), ("vlan", vlan))) for vlan in domain.vlans)
    elif target.operation == ec.parse_summary.OP:
        params = record(value, ("groups", "ports"))
        _need(target.owner == ec.STEP.id, "scope")
        channel = ec.Target(context=resolver.execution.envelope.context, node=target.node, groups=_strings(params["groups"]), ports=_strings(params["ports"]))
        cases = tuple((k.FactRef(fact=fact, subject=ec.subject(channel, group)),
            (("context", channel.context), ("group", group), ("node", channel.node.id), ("target", target.id)))
            for group in channel.groups for fact in (ec.REPORTED_PROTOCOL, ec.REPORTED_MEMBER_TOKENS))
    else:
        raise RunnerRefused("p4_projection_scope")
    for reference, labels in cases:
        match reference:
            case k.FactRef(fact=selected_fact):
                roster = selected_fact == ec.REPORTED_MEMBER_TOKENS
            case _:
                raise RunnerRefused("p4_projection_scope")
        spans: set[tuple[k.CaptureId, k.ByteSpan]] = set()
        positive: set[tuple[k.CaptureId, k.ByteSpan]] = set()
        required: set[tuple[k.CaptureId, k.ByteSpan]] = set()
        for output in resolver.by_target[target.id]:
            data = dict(labels)
            if isinstance(output.value, stp.stp.Result):
                rows = tuple(r for r in output.value.rows if r.port == data["port"] and r.vlan == data["vlan"])
                field = "root_guard"
            else:
                rows = tuple(r for r in output.value.rows if r.group == data["group"])
                field = "protocol"
            _need(len(rows) == 1, "scope")
            row, identity = rows[0], output.receipt.capture.id
            if row.fields:
                spans.update((identity, span) for span in row.spans)
                spans.update((identity, token.span) for _, token in row.fields)
            complete = (output.value.reason is None and row.reason is None
                        and output.receipt.capture.integrity is k.IntegrityState.COMPLETE
                        and output.receipt.parse.quality == "complete")
            if isinstance(row, ec.parse_summary.Row) and roster:
                claims = {span for member in row.members for span in (member.port.span, member.flag.span, member.span)}
                spans.update((identity, span) for span in claims)
                headers = tuple(tuple(token for name, token in row.fields if name == field) for field in ("group", "channel"))
                if complete and row.members and all(len(tokens) == 1 for tokens in headers):
                    positive.add((identity, row.members[0].port.span))
                    required.update((identity, span) for span in claims | set(row.spans) | {tokens[0].span for tokens in headers})
            else:
                tokens = tuple(token for name, token in row.fields if name == field)
                if complete and len(tokens) == 1:
                    positive.add((identity, tokens[0].span))
        _need(reference not in resolver.bound, "population")
        resolver.bound[reference] = Scope(reference=reference, target=target, labels=labels,
            declarations=resolver.declarations[target.id], spans=frozenset(spans), positive=frozenset(positive), required=frozenset(required))


def _capture_leaf(index: ProofIndex, ref: k.EvidenceRef, scope: Scope | None, positive: bool,
                  identity: k.CaptureId | None) -> dict[str, object]:
    _need(ref.capture in index.members and type(ref.role) is k.EvidenceRole, "scope")
    member, capture = index.members[ref.capture], index.snapshots[ref.capture]
    _need(member.target is scope.target if scope is not None else ref.capture == identity, "scope")
    _need(not positive or capture.integrity is k.IntegrityState.COMPLETE
              and index.receipts[ref.capture].parse.quality == "complete", "capture")
    leaf: dict[str, object] = {"kind": "capture", "capture": str(capture.id), "source": str(capture.source),
        "target": member.target.id, "path": member.path, "operation": capture.operation, "rendered": capture.rendered,
        "role": str(ref.role), "sha256": ref.excerpt_sha256, "capture_sha256": index.hashes[capture.id]}
    if type(ref.locator) is k.ByteSpan:
        _need(ref.role is k.EvidenceRole.SUBJECT, "role")
        span = ref.locator
        _need(type(span.start) is int and type(span.end) is int and 0 <= span.start < span.end <= len(capture.raw), "span")
        _need(scope is None or (ref.capture, span) in scope.spans, "scope")
        actual = sha256(capture.raw[span.start:span.end]).hexdigest()
        leaf.update(locator="bytes", start=span.start, end=span.end)
    elif type(ref.locator) is k.WholeCapture:
        _need(ref.role is (k.EvidenceRole.WITNESS if scope is not None else k.EvidenceRole.SUBJECT), "role")
        _need(not positive, "reference")
        actual = index.hashes[capture.id]
        leaf["locator"] = "whole_capture"
    else:
        raise RunnerRefused("p4_projection_reference")
    _need(actual == ref.excerpt_sha256, "span")
    return leaf
