"""Trusted projection of conditional guard reports; original pinned evidence is required."""
from dataclasses import asdict
from hashlib import sha256

from atlas_brain.contract.bundle import Rows, result_bundle
from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import BudgetExceeded, Budgets, strict_json
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.stp import build
from atlas_brain.packs.l2.stp import guard_check as check
from atlas_brain.packs.l2.stp import guard_policy as policy
from atlas_brain.runner.p4_refs import ProofIndex, Value

SCHEMA = "atlas-brain.p4-guard-report/1"
POLICY_FILE = "declared_guard_policy.json"
REPORT_FILES = ("checks/l2.stp.jsonl", POLICY_FILE, "facts/stp_port_vlan.jsonl", "result.json")


def _need(condition: bool, code: str) -> None:
    k.require(condition, "stp_guard_report_" + code)


def _registry(ref: k.RegistryRef, value: object) -> dict[str, object]:
    return {"kind": "registry", **asdict(ref), "value": value}


def _record(row: policy.GuardComparison) -> dict[str, object]:
    return {"id": row.policy_id, "domain": row.domain, "expectation": "same_reported_root_guard",
        "participants": [{"target_id": point.target.id, "vlan": point.vlan, "declared_mode": point.declared_mode,
            "position": point.position, "node": point.target.node.id, "port": point.port, "subject": str(point.subject),
            "declarations": [asdict(ref) for ref in point.evidence]} for point in row.participants]}


def _resolve(refs: tuple[k.Evidence, ...], registry: dict[k.RegistryRef, dict[str, object]],
             facts: Rows, allowed: tuple[k.RegistryRef, ...], subjects: tuple[k.EntityKey, ...]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for ref in refs:
        if isinstance(ref, k.FactRef):
            key = (str(ref.subject), str(ref.fact))
            _need(ref.fact in (build.ROOT_GUARD, build.REPORTED_ROLE) and ref.subject in subjects and key in facts, "reference")
            fact = facts[key]
            _need("fact" in fact and "subject" in fact and fact["fact"] == str(ref.fact)
                  and fact["subject"] == str(ref.subject), "reference")
            out.append({"kind": "fact", "fact": str(ref.fact), "subject": str(ref.subject), "value": fact})
        elif isinstance(ref, k.RegistryRef):
            _need(ref in allowed and ref in registry, "reference")
            out.append(registry[ref])
        else:
            _need(False, "reference")
    return out


def _state(value: check.Premise, evidence: list[dict[str, object]]) -> dict[str, object]:
    match value:
        case k.Known():
            return {"state": "known", "basis": str(value.basis), "value": value.value, "raw": value.raw, "evidence": evidence}
        case k.Unknown():
            return {"state": "unknown", "reason": str(value.reason), "detail": value.detail, "evidence": evidence,
                    "candidates": list(value.candidates), "next_evidence": [asdict(need) for need in value.next_evidence]}
        case k.NotApplicable():
            return {"state": "not_applicable", "reason": str(value.reason), "evidence": evidence}
        case _:
            raise ValueError("stp_guard_report_input")


def project_declared(plan: policy.GuardPlan, result: check.Result, index: ProofIndex[Value], kind: str,
                     facts: Rows, captures: list[dict[str, object]], budgets: Budgets) -> dict[str, bytes]:
    """Project application-owned closure, not caller-built snapshots or detached evidence."""
    _need(plan.envelope is index.execution.envelope and kind == "stp_port_vlan"
          and result.denominator == plan.denominator and result.coverage is plan.coverage, "input")
    _need(len(result.rows) == len(plan.rows) and len({row.policy_id for row in plan.rows}) == len(plan.rows), "input")
    envelope = index.execution.envelope
    _need(plan.context == envelope.context and plan.registration_sha256 == envelope.registration_sha256
          and plan.registry_sha256 == sha256(envelope.raw).hexdigest()
          and plan.base_registry_sha256 == sha256(envelope.base.raw).hexdigest(), "policy")
    records = [_record(row) for row in plan.rows]
    expected = {"schema": policy.SCHEMA, "semantic_group": "declared_synthetic", "context": plan.context,
        "registration_sha256": plan.registration_sha256, "registry_sha256": plan.registry_sha256,
        "base_registry_sha256": plan.base_registry_sha256, "policies": records}
    _need(canonical(expected) == plan.raw and sha256(plan.raw).hexdigest() == plan.sha256, "policy")
    registry: dict[k.RegistryRef, dict[str, object]] = {}
    for i, row in enumerate(plan.rows):
        ref = k.RegistryRef(table=policy.TABLE, row_id=row.policy_id, table_digest=plan.sha256, citation=f"/policies/{i}")
        _need(row.declaration.evidence == (ref,) and row.declaration.basis is k.Basis.DECLARED
              and row.declaration.value == row.declaration.raw == row.policy_id, "policy")
        registry[ref] = _registry(ref, records[i])
    if not plan.rows:
        for ref in plan.envelope.declaration.evidence:
            _need(type(ref) is k.RegistryRef and ref in index.records, "policy")
            if isinstance(ref, k.RegistryRef):
                registry[ref] = _registry(ref, strict_json(index.records[ref], budgets.nesting_depth, budgets.numeric_digits))
    rows: dict[tuple[str, str], dict[str, object]] = {}
    for finding, row in zip(result.rows, plan.rows, strict=True):
        subjects = tuple(point.subject for point in row.participants)
        _need(finding.policy_id == row.policy_id and (finding.left, finding.right) == subjects
              and finding.check == check.CHECK and finding.conditional is True and finding.gaps == row.gaps, "input")
        allowed = tuple(ref for ref in row.declaration.evidence if isinstance(ref, k.RegistryRef))
        hops = [{"id": hop.id, "state": _state(hop.state, _resolve(hop.state.evidence, registry, facts, allowed, subjects))}
                for hop in finding.hops]
        rows[(finding.check, finding.policy_id)] = {"check": finding.check, "policy_id": finding.policy_id,
            "left": str(finding.left), "right": str(finding.right), "state": finding.state,
            "reason": str(finding.reason) if finding.reason is not None else None, "conditional": finding.conditional,
            "gaps": list(finding.gaps), "hops": hops,
            "evidence": _resolve(finding.evidence, registry, facts, allowed, subjects), "next_evidence": [asdict(need) for need in finding.next_evidence]}
    coverage = _resolve(result.coverage.evidence, registry, facts, tuple(registry), ())
    header: dict[str, object] = {"schema": SCHEMA, "semantic_group": "declared_synthetic", "scope": "conditional_reported_guard_comparisons",
        "fact_scope": "stp_operands_only", "capture_scope": "p4_members_only", "source_required": "original_pinned_evidence_folder",
        "variant_support": "allowlisted", "context": plan.context, "registration_sha256": plan.registration_sha256,
        "registry_sha256": plan.registry_sha256, "base_registry_sha256": plan.base_registry_sha256,
        "policy_registry": {"path": POLICY_FILE, "sha256": plan.sha256, "basis": "declared"},
        "denominator": dict(result.denominator), "coverage": _state(result.coverage, coverage), "captures": captures}
    files = result_bundle(header, facts={kind: facts}, checks={str(build.PACK): rows})
    files[POLICY_FILE] = plan.raw
    del files["MANIFEST.sha256"]
    _need(set(files) == set(REPORT_FILES), "input")
    files["MANIFEST.sha256"] = b"".join(
        f"{sha256(files[name]).hexdigest()}  {name}\n".encode("ascii") for name in sorted(files))
    envelope = plan.envelope
    inputs = (envelope.raw, envelope.base.raw) + tuple(member.raw for member in envelope.captures) + tuple(cap.raw for cap in envelope.base.captures)
    if (len(inputs) + len(files) > budgets.artifacts or sum(map(len, inputs)) + sum(map(len, files.values())) > budgets.bundle_bytes
            or any(len(raw) > budgets.artifact_bytes for raw in files.values())):
        raise BudgetExceeded("guard_report")
    return {name: files[name] for name in sorted(files)}
