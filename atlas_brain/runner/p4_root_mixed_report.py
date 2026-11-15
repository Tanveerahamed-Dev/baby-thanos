"""Fresh Root9 HEX observations from one owning run; no health, peer, origin or acceptance claim."""
from hashlib import sha256
from pathlib import Path

from atlas_brain.contract.bundle import result_bundle
from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets, strict_json
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import mixed_component as owning
from atlas_brain.packs.l3.fhrp import root_mixed_profile as profile
from atlas_brain.packs.l3.fhrp.mixed_execution import RootMixedExecution
from atlas_brain.runner import p4_root_mixed_records as records
from atlas_brain.runner.p4_mixed_refs import RootMixedProofIndex

SCHEMA = "atlas-brain.p4-root-mixed-observations/1"
KINDS = records.KINDS


def _need(condition: bool, code: str) -> None:
    k.require(condition, "p4_root_mixed_report_" + code)


def _epoch(run: owning.RootMixedComponentRun, source: RootMixedExecution,
    component: owning.RootMixedComponent, budgets: Budgets,
) -> None:
    _need(owning.RootMixedComponentRun.current_component(run) is component
        and run.source is source and run.result is component and run.budgets is budgets, "epoch")


def _labels(result: owning.RootMixedComponent) -> dict[k.FactRef, dict[str, object]]:
    labels: dict[k.FactRef, dict[str, object]] = {}
    for tree in result.tree.rows:
        for fact in owning.stp.ROOT_STEP.produces:
            labels[k.FactRef(fact=fact, subject=tree.subject)] = {"protocol": "stp", "node": tree.target.node.key,
                "port": tree.target.port, "vlan": tree.vlan}
    for channel in result.channel.rows:
        for fact in owning.ec.STEP.produces:
            labels[k.FactRef(fact=fact, subject=channel.subject)] = {"protocol": "etherchannel",
                "node": channel.target.node.key, "group": channel.group}
    for state in result.state.rows:
        labels[k.FactRef(fact=owning.build.REPORTED_STATE, subject=state.subject)] = {
            "protocol": "hsrp", "node": state.target.node.key, "interface": state.interface, "group": state.group}
    for version in result.version.rows:
        labels[k.FactRef(fact=owning.version_profile.REPORTED_PROTOCOL_VERSION, subject=version.subject)] = {
            "protocol": "hsrp", "node": version.target.node.key, "interface": version.interface, "group": version.group}
    for vrrp in result.vrrp.rows:
        labels[k.FactRef(fact=owning.vrrp_profile.REPORTED_VRRP_STATE, subject=vrrp.subject)] = {
            "protocol": "vrrp", "node": vrrp.target.node.key, "interface": vrrp.interface, "group": vrrp.group}
    return labels


def analyse_root_mixed_folder(root: Path, budgets: Budgets) -> dict[str, bytes]:
    run = owning.RootMixedComponentRun(root, budgets)
    component = owning.RootMixedComponentRun.build(run)
    source, envelope = component.source, component.source.execution.envelope
    _epoch(run, source, component, budgets)
    plan, hsrp, vrrp = source.tree.plan, source.fhrp.hsrp, source.fhrp.vrrp_inputs
    if plan is None or hsrp is None or vrrp is None:
        raise ValueError("p4_root_mixed_report_epoch")
    tables: dict[str, list[dict[str, object]]] = {"raws": [], "captures": [], "registry_records": []}
    result: dict[str, object] = {"schema": SCHEMA, "semantic_group": "declared_synthetic",
        "scope": "observations_only", "qualification": "synthetic_observations_only", "checks": "not_implemented",
        "group": envelope.base.id, "context": envelope.context, "registration_sha256": envelope.registration_sha256,
        "root_scope": "local_reported_priority_and_mac_not_intended_root",
        "denominator": {"stp": {"kind": KINDS[0], "declared": sum(len(target.vlans) for target in plan.indexed.values())},
            "etherchannel": {"kind": KINDS[1], "declared": sum(len(target.groups) for target in source.channel.owner.plan.indexed.values())},
            "hsrp": {"kind": KINDS[2], "declared": sum(len(target.groups) for target in hsrp.version.targets)},
            "vrrp": {"kind": KINDS[2], "declared": len(vrrp.subjects)}}}
    result.update(tables)
    inputs = (envelope.base.raw, envelope.raw) + tuple(cap.raw for cap in envelope.base.captures) + tuple(member.raw for member in envelope.captures)
    budget = records.RecordBudget(inputs, source.limits, result)
    blobs = records.raw_blobs(inputs)
    for digest, raw in sorted(blobs.items()):
        records.append_record(tables["raws"], {"sha256": digest, "bytes": len(raw), "encoding": "hex"}, budget, ("data", raw))
    result["registries"] = [{"layer": layer, "raw": sha256(raw).hexdigest()}
        for layer, raw in (("p2", envelope.base.raw), ("p4", envelope.raw))]
    budget.add("result.json", len(canonical("registries")) + 2 + len(canonical(result["registries"])))
    for capture in sorted(envelope.base.captures, key=lambda cap: cap.id):
        records.append_record(tables["captures"], records.capture_record(capture, "p2", sha256(capture.raw).hexdigest()), budget)
    outputs = {out.receipt.capture.id: out for out in source.execution.executed}
    for member in sorted(envelope.captures, key=lambda cap: cap.id):
        receipt = outputs[member.id].receipt
        row = records.capture_record(receipt.capture, "p4", member.sha256)
        row.update(path=member.path, target=member.target.id, owner=receipt.owner, context=receipt.context,
            registration_sha256=receipt.registration_sha256, parse_quality=receipt.parse.quality,
            params=strict_json(member.target.params, budgets.nesting_depth, budgets.numeric_digits))
        records.append_record(tables["captures"], row, budget)
    index = RootMixedProofIndex(run)
    proofs = RootMixedProofIndex.resolve_all(index)
    labels = _labels(component)
    _need(len(proofs) == len(labels) and {proof.reference for proof in proofs} == set(labels), "value")
    specs = {fact.id: fact for declaration in profile.DECLARATIONS for fact in declaration.facts}
    facts: dict[str, dict[tuple[str, str], dict[str, object]]] = {kind: {} for kind in KINDS}
    registry_ids: dict[k.RegistryRef, tuple[str, bytes]] = {}
    scalar_types: dict[str, type[bool | int | str]] = {"boolean": bool, "integer": int, "text": str}
    for proof in proofs:
        reference, value = proof.reference, proof.state
        spec = specs[reference.fact]
        registry = [records.registry_record_id(leaf.reference, leaf.registry_raw, leaf.canonical_value,
            blobs, registry_ids, tables["registry_records"], budget) for leaf in proof.registry_leaves]
        state = records.state_record(value, scalar_types[spec.value_type])
        row = {"fact": reference.fact, "subject": reference.subject, "local": labels[reference], "value": state,
            "registry": registry, "evidence": [records.evidence_record(leaf.reference, "p4") for leaf in proof.capture_leaves]}
        budget.add(f"facts/{spec.subject}.jsonl", len(canonical(row)) + 1)
        facts[spec.subject][reference.subject, reference.fact] = row
    files = result_bundle(result, facts=facts, checks={})
    records.verify_bundle(files, budget)
    _epoch(run, source, component, budgets)
    return files
