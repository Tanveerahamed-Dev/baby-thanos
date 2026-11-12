"""Pure three-pack P4 observations; no checks or health qualification."""
from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

from atlas_brain.contract.bundle import result_bundle
from atlas_brain.evidence.admission import Budgets, record, strict_json, string
from atlas_brain.evidence.synthetic import Node
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import PackDeclaration
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.model.store import FactStore, bind_reader
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack
from atlas_brain.runner.p4_refs import ProofIndex, Scope, Value
from atlas_brain.runner.records import RunnerRefused

SCHEMA = "atlas-brain.p4-observations/1"
PROJECT = StepSpec(id=StepId("l2.stp/project_p4_observations"), pack=stp.PACK, kind="derive", scope="estate",
                   reads=tuple(sorted(tuple(spec[0] for spec in stp.projection_contract()) + ec.STEP.produces + fhrp.STEP.produces)),
                   produces=(), evaluator="l2.stp.project_p4_observations")
type State = k.Known[bool] | k.Known[str] | k.Unknown
type Owner = stp.Result | ec.Result | fhrp.Result
type Spec = tuple[k.FactId, k.PackId, StepId, str, type[bool | str]]
type Item = tuple[k.FactId, stp.Row | ec.Row | fhrp.Row, State]
type Family = Literal["stp", "etherchannel", "hsrp"]


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


def _state(index: ProofIndex[Value], scope: Scope, value: State, expected: type[bool | str]) -> dict[str, object]:
    _need(type(value) in (k.Known, k.Unknown), "state")
    if isinstance(value, k.Known):
        _need(type(value.value) is expected, "value")
        evidence = index.resolve(scope, value.evidence, positive=True)
        return {"state": "known", "basis": str(value.basis), "value": value.value, "raw": value.raw, "evidence": evidence}
    return _unknown(value, index.resolve(scope, value.evidence, positive=False))


def _spec(fact: k.FactId) -> Spec:
    _need(fact in PROJECT.reads, "spec")
    contracts = stp.projection_contract()
    if any(spec[0] == fact for spec in contracts):
        found: dict[k.FactId, Spec] = {}
        match stp.STEP, stp.DECLARATION:
            case (StepSpec(id=owner, pack=pack, produces=outputs),
                  PackDeclaration(pack=dpack, facts=facts, entity_kinds=(EntityKindSpec(id=kind, pack=kpack, root=False),))):
                _need(outputs == tuple(sorted(spec[0] for spec in contracts)), "spec")
                for item in facts:
                    match item:
                        case FactSpec(id=fid, pack=fpack, subject=subj, value_type=vtype, step=step):
                            wanted = tuple(spec for spec in contracts if spec[0] == fid)
                            _need(len(wanted) == 1 and fid not in found, "spec")
                            expected, = wanted
                            _need(pack == dpack == kpack == fpack == expected[1] and owner == step == expected[2]
                                  and kind == subj == expected[3] and expected[4] in (bool, str)
                                  and vtype == ("boolean" if expected[4] is bool else "text"), "spec")
                            found[fid] = expected
                        case _:
                            raise RunnerRefused("p4_observations_spec")
                _need(tuple(sorted(found)) == outputs and fact in found, "spec")
                return found[fact]
            case _:
                raise RunnerRefused("p4_observations_spec")
    channel = fact in ec.STEP.produces
    producer = ec.STEP if channel else fhrp.STEP
    declaration = ec.DECLARATION if channel else fhrp.DECLARATION
    subject = "etherchannel_group" if channel else "fhrp_local"
    match producer, declaration:
        case (StepSpec(id=owner, pack=pack, produces=outputs),
              PackDeclaration(pack=dpack, facts=facts, entity_kinds=(EntityKindSpec(id=kind, pack=kpack, root=False),))):
            _need(pack == dpack == kpack and kind == subject
                  and (ec.REPORTED_PROTOCOL in outputs if channel else outputs == (fhrp.REPORTED_STATE,)), "spec")
            found = {}
            for item in facts:
                match item:
                    case FactSpec(id=fid, pack=fpack, subject=subj, value_type=vtype, step=step):
                        _need(fid not in found and fpack == pack and subj == subject and vtype == "text" and step == owner, "spec")
                        found[fid] = (fid, pack, step, subj, str)
                    case _:
                        raise RunnerRefused("p4_observations_spec")
            _need(tuple(sorted(found)) == outputs and fact in found, "spec")
            return found[fact]
        case _:
            raise RunnerRefused("p4_observations_spec")


def _strings(value: object) -> tuple[str, ...]:
    _need(type(value) is list and all(type(v) is str for v in cast(list[object], value)), "population")
    return tuple(v for v in cast(list[object], value) if type(v) is str)


def _groups(value: object) -> tuple[tuple[str, str], ...]:
    _need(type(value) is list and all(type(pair) is list and len(cast(list[object], pair)) == 2
          and all(type(item) is str for item in cast(list[object], pair)) for pair in cast(list[object], value)), "population")
    return tuple((cast(list[str], pair)[0], cast(list[str], pair)[1]) for pair in cast(list[object], value))


def _subjects(index: ProofIndex[Value]) -> tuple[set[k.EntityKey], set[k.EntityKey], set[k.EntityKey]]:
    envelope = index.execution.envelope
    trees: set[k.EntityKey] = set()
    channels: set[k.EntityKey] = set()
    gateways: set[k.EntityKey] = set()
    for target in envelope.targets:
        params = strict_json(target.params, index.budgets.nesting_depth, index.budgets.numeric_digits)
        if target.operation == stp.stp.OP:
            fields = record(params, ("port", "vlans"))
            values = fields["vlans"]
            _need(type(values) is list and all(type(v) is int for v in cast(list[object], values)), "population")
            domain = stp.Target(context=envelope.context, node=target.node, port=string(fields, "port"),
                                vlans=tuple(v for v in cast(list[object], values) if type(v) is int))
            step, selected = stp.STEP.id, trees
            subjects = {stp.subject(domain, vlan) for vlan in domain.vlans}
        elif target.operation == ec.parse_summary.OP:
            fields = record(params, ("groups", "ports"))
            channel = ec.Target(context=envelope.context, node=target.node, groups=_strings(fields["groups"]), ports=_strings(fields["ports"]))
            step, selected = ec.STEP.id, channels
            subjects = {ec.subject(channel, group) for group in channel.groups}
        elif target.operation == fhrp.hsrp.OP:
            fields = record(params, ("groups",))
            local = fhrp.Target(context=envelope.context, node=target.node, groups=_groups(fields["groups"]))
            step, selected = fhrp.STEP.id, gateways
            subjects = {fhrp.subject(local, interface, group) for interface, group in local.groups}
        else:
            raise RunnerRefused("p4_observations_profile")
        _need(target.owner == step and not selected & subjects, "population")
        selected |= subjects
    return trees, channels, gateways


def _cell(row: stp.Row | ec.Row | fhrp.Row) -> tuple[k.EntityKey, Node, str, State]:
    match row:
        case (stp.Row(subject=subject, target=stp.Target(node=node, context=context), value=value)
              | ec.Row(subject=subject, target=ec.Target(node=node, context=context), value=value)
              | fhrp.Row(subject=subject, target=fhrp.Target(node=node, context=context), value=value)):
            return subject, node, context, value
        case _:
            raise RunnerRefused("p4_observations_row")


def _facts(index: ProofIndex[Value], owner: Owner, family: Family,
           subjects: set[k.EntityKey]) -> tuple[str, dict[tuple[str, str], dict[str, object]]]:
    tree, channel = family == "stp", family == "etherchannel"
    baseline = _spec(stp.ROOT_GUARD if tree else ec.REPORTED_PROTOCOL if channel else fhrp.REPORTED_STATE)
    identities = tuple(spec[0] for spec in stp.projection_contract()) if tree else ec.STEP.produces if channel else fhrp.STEP.produces
    specs = tuple(_spec(fact) for fact in identities)
    owner_type, row_type = (stp.Result, stp.Row) if tree else (ec.Result, ec.Row) if channel else (fhrp.Result, fhrp.Row)
    _need(type(owner) is owner_type and type(owner.store) is FactStore and type(owner.rows) is tuple
          and all(type(row) is row_type for row in owner.rows), "owner")
    _need(len(owner.rows) == len(subjects) and {_cell(row)[0] for row in owner.rows} == subjects, "population")
    expected = {k.FactRef(fact=fact, subject=subject) for fact in identities for subject in subjects}
    operation = stp.stp.OP if tree else ec.parse_summary.OP if channel else fhrp.hsrp.OP
    _need(type(index.scopes) is tuple and all(type(scope) is Scope and type(scope.reference) is k.FactRef for scope in index.scopes), "population")
    _need(all(any(scope.target is target for target in index.execution.envelope.targets)
              and index.scope(scope.reference.fact, scope.reference.subject) is scope for scope in index.scopes), "population")
    scopes = tuple(scope for scope in index.scopes if scope.target.operation == operation)
    _need(len(scopes) == len(expected) and {scope.reference for scope in scopes} == expected, "population")
    items: tuple[Item, ...]
    if isinstance(owner, stp.Result):
        items = stp.fact_rows(owner)
    elif isinstance(owner, ec.Result):
        items = ec.fact_rows(owner)
    else:
        items = fhrp.fact_rows(owner)
    _need(type(items) is tuple and all(type(item) is tuple and len(item) == 3 for item in items), "row")
    _need(len(items) == len(expected), "population")
    _need(type(owner.store.owners) is dict and type(owner.store.values) is dict
          and owner.store.owners == {spec[0]: spec[2] for spec in specs}
          and set(owner.store.values) == expected, "store")
    originals = {_cell(row)[0]: row for row in owner.rows}
    reader = bind_reader(owner.store, step=PROJECT)
    result: dict[tuple[str, str], dict[str, object]] = {}
    for fact, row, value in items:
        _need(type(fact) is str and fact in identities and type(row) is row_type, "row")
        subject, node, context, _ = _cell(row)
        _need(originals.get(subject) is row, "row")
        reference = k.FactRef(fact=fact, subject=subject)
        _need(reference in expected and (str(subject), str(fact)) not in result, "population")
        scope = index.scope(fact, subject)
        _need(node is scope.target.node and context == index.execution.envelope.context, "scope")
        if tree:
            if not isinstance(row, stp.Row):
                raise RunnerRefused("p4_observations_row")
            try:
                original = stp.original_state(fact, row)
            except ValueError as error:
                raise RunnerRefused("p4_observations_store") from error
            _need(original is value, "store")
        _need(reader.read(fact=fact, subject=subject) is value, "store")
        _, declared_pack, _, kind, value_type = next(spec for spec in specs if spec[0] == fact)
        _need(kind == baseline[3], "spec")
        result[(str(subject), str(fact))] = {"pack": str(declared_pack), "fact": str(fact),
            "subject": str(subject), **dict(scope.labels), **_state(index, scope, value, value_type)}
    return baseline[3], result


def _metadata(index: ProofIndex[Value]) -> list[dict[str, object]]:
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
    """Close all three owners before estate projection; return canonical bytes without writing files."""
    channel = SummaryPack[stp.stp.Result | fhrp.hsrp.Result](budgets)
    standby = StandbyBriefPack[stp.stp.Result | ec.parse_summary.Result](budgets)
    tree = stp.build_root_guard_global(root, budgets, peers=(channel, standby))
    finished = channel.finish(tree.execution)
    local = standby.finish(tree.execution)
    index = ProofIndex(tree.execution, budgets)
    _need(index.execution is tree.execution, "profile")
    tree_subjects, channel_subjects, local_subjects = _subjects(index)
    tree_kind, trees = _facts(index, tree.result, "stp", tree_subjects)
    channel_kind, channels = _facts(index, finished, "etherchannel", channel_subjects)
    local_kind, locals_out = _facts(index, local, "hsrp", local_subjects)
    _need(len({tree_kind, channel_kind, local_kind}) == 3, "spec")
    result: dict[str, object] = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "scope": "observations_only",
        "checks": "not_implemented", "variant_support": "allowlisted", "group": index.execution.envelope.base.id,
        "context": index.execution.envelope.context, "registration_sha256": index.execution.envelope.registration_sha256,
        "registry_sha256": index.registry_sha256, "base_registry_sha256": index.base_registry_sha256,
        "capture_scope": "p4_members_only", "base_capture_scope": "admitted_discovery_context_only",
        "denominator": {str(stp.PACK): len(tree_subjects), str(ec.PACK): len(channel_subjects), str(fhrp.PACK): len(local_subjects)},
        "captures": _metadata(index)}
    return result_bundle(result, facts={tree_kind: trees, channel_kind: channels, local_kind: locals_out}, checks={})
