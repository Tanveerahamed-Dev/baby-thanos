"""Pure partial P4 observation bundles; no CLI routing, checks or health qualification."""
from dataclasses import asdict
from pathlib import Path

from atlas_brain.contract.bundle import result_bundle
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner.p4_refs import ProofIndex, Scope
from atlas_brain.runner.records import RunnerRefused

SCHEMA = "atlas-brain.p4-observations/1"
PROJECT = StepSpec(id=StepId("l2.stp/project_p4_observations"), pack=stp.PACK, kind="derive", scope="estate",
                   reads=tuple(sorted((stp.ROOT_GUARD, ec.REPORTED_PROTOCOL))), produces=(), evaluator="l2.stp.project_p4_observations")
type State = k.Known[bool] | k.Known[str] | k.Unknown
type Owner = stp.Result | ec.Result
type Spec = tuple[k.FactId, k.PackId, StepId, str, type[bool | str]]


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RunnerRefused("p4_observations_" + code)


def _unknown(value: k.Unknown, evidence: list[dict[str, object]]) -> dict[str, object]:
    return {"state": "unknown", "reason": str(value.reason), "detail": value.detail,
        "candidates": list(value.candidates), "evidence": evidence,
        "next_evidence": [{"node": str(need.node), "operation": need.operation,
            "params": [list(pair) for pair in need.params], "resolves": list(need.resolves),
            "reruns": list(need.reruns), "after_s": need.after_s, "unprintable": list(need.unprintable)}
            for need in value.next_evidence]}


def _state(index: ProofIndex, scope: Scope, value: State, expected: type[bool | str]) -> dict[str, object]:
    _need(type(value) in (k.Known, k.Unknown), "state")
    if isinstance(value, k.Known):
        _need(type(value.value) is expected, "value")
        evidence = index.resolve(scope, value.evidence, positive=True)
        return {"state": "known", "basis": str(value.basis), "value": value.value, "raw": value.raw, "evidence": evidence}
    return _unknown(value, index.resolve(scope, value.evidence, positive=False))


def _spec(fact: k.FactId) -> Spec:
    _need(fact in PROJECT.reads, "spec")
    declaration, subject, value_type = ((stp.DECLARATION, "stp_port_vlan", "boolean") if fact == stp.ROOT_GUARD
                                      else (ec.DECLARATION, "etherchannel_group", "text"))
    match declaration:
        case PackDeclaration(pack=pack, facts=(FactSpec(id=fid, pack=fpack, subject=subj, value_type=vtype, step=step),),
                             entity_kinds=(EntityKindSpec(id=kind, pack=kpack, root=False),)):
            _need(fid == fact and pack == fpack == kpack and subj == kind == subject and vtype == value_type
                  and step == (stp.STEP.id if fact == stp.ROOT_GUARD else ec.STEP.id), "spec")
            return fid, pack, step, subj, bool if vtype == "boolean" else str
        case _:
            raise RunnerRefused("p4_observations_spec")


def _facts(index: ProofIndex, owner: Owner, spec: Spec) -> dict[tuple[str, str], dict[str, object]]:
    fact, pack, step, _, value_type = spec
    expected = {scope.reference.subject: scope for scope in index.scopes if scope.reference.fact == fact}
    owner_type = stp.Result if fact == stp.ROOT_GUARD else ec.Result
    row_type = stp.Row if fact == stp.ROOT_GUARD else ec.Row
    _need(type(owner) is owner_type and type(owner.store) is FactStore and type(owner.rows) is tuple
          and all(type(row) is row_type for row in owner.rows), "owner")
    _need(len(owner.rows) == len(expected) and {row.subject for row in owner.rows} == set(expected), "population")
    _need(type(owner.store.owners) is dict and type(owner.store.values) is dict
          and owner.store.owners == {fact: step}
          and set(owner.store.values) == {k.FactRef(fact=fact, subject=subject) for subject in expected}, "store")
    reader = bind_reader(owner.store, step=PROJECT)
    result: dict[tuple[str, str], dict[str, object]] = {}
    for row in owner.rows:
        scope = expected[row.subject]
        _need(row.target.node is scope.target.node and row.target.context == index.execution.envelope.context, "scope")
        _need(reader.read(fact=fact, subject=row.subject) is row.value, "store")
        result[(str(row.subject), str(fact))] = {"pack": str(pack), "fact": str(fact),
            "subject": str(row.subject), **dict(scope.labels), **_state(index, scope, row.value, value_type)}
    return result


def _metadata(index: ProofIndex) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for capture in index.captures:
        receipt = index.receipts[capture.id]
        member = index.members[capture.id]
        metadata = capture.resolved_metadata
        collected = metadata.collected_utc
        if type(collected) is not k.Unknown:
            raise RunnerRefused("p4_observations_time")
        time = _unknown(collected, index.metadata_evidence(capture.id, collected.evidence))
        result.append({"id": str(capture.id), "source": str(capture.source), "target": member.target.id, "path": member.path,
            "operation": capture.operation, "rendered": capture.rendered, "codec": capture.codec, "sha256": index.hashes[capture.id],
            "owner": str(receipt.owner), "context": receipt.context, "registration_sha256": receipt.registration_sha256, "parse": receipt.parse.quality,
            "channel": str(metadata.channel), "envelope": metadata.envelope, "integrity": str(capture.integrity), "scope": asdict(metadata.scope),
            "read_scope": str(capture.read_scope), "view": str(capture.view), "error": str(metadata.error) if metadata.error is not None else None,
            "integrity_evidence": index.metadata_evidence(capture.id, metadata.integrity_evidence),
            "read_scope_evidence": index.metadata_evidence(capture.id, metadata.read_scope_evidence), "collected_utc": time})
    return result


def analyse_folder(root: Path, budgets: Budgets) -> dict[str, bytes]:
    """Close both owners before estate projection; return canonical bytes without writing files."""
    channel = SummaryPack[stp.stp.Result](budgets)
    tree = stp.build_root_guard_global(root, budgets, peers=(channel,))
    finished = channel.finish(tree.execution)
    index = ProofIndex(tree.execution, budgets)
    tree_spec, channel_spec = _spec(stp.ROOT_GUARD), _spec(ec.REPORTED_PROTOCOL)
    trees = _facts(index, tree.result, tree_spec)
    channels = _facts(index, finished, channel_spec)
    _need(tree_spec[3] != channel_spec[3], "spec")
    result: dict[str, object] = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "scope": "observations_only",
        "checks": "not_implemented", "variant_support": "allowlisted", "group": index.execution.envelope.base.id,
        "context": index.execution.envelope.context, "registration_sha256": index.execution.envelope.registration_sha256,
        "registry_sha256": index.registry_sha256, "base_registry_sha256": index.base_registry_sha256,
        "capture_scope": "p4_members_only", "base_capture_scope": "admitted_discovery_context_only",
        "denominator": {str(stp.PACK): len(trees), str(ec.PACK): len(channels)}, "captures": _metadata(index)}
    return result_bundle(result, facts={tree_spec[3]: trees, channel_spec[3]: channels}, checks={})
