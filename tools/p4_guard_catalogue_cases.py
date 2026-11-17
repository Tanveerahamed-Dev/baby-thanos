"""Project-owned EI-R04 retained twins; synthetic comparisons, never historical or field qualification."""
import json
from hashlib import sha256

from atlas_brain.contract.canonical import canonical
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l2.stp import guard_policy as policy
from atlas_brain.packs.l3.fhrp import build as fhrp
from tools import p4_guard_cases as old

CATALOGUE, ALIAS, GENERATOR = "baby-thanos.p4.synthetic/1", "EI-R04", "p4_guard_catalogue_cases/1"
ROLE, GUARD, STEP = "l2.stp.reported_role", "l2.stp.root_guard", "l2.stp/parse_root_guard"
CHECK_STEP = "l2.stp/check_root_guard"
# Literal input recipe, damage, expected state/reason/last hop. Priority is not inferred from output.
CASES = {
    "F01": ("mismatch", "", "problem", None, "reported_root_guard"),
    "C01": ("role_excludes", "", "not_applicable", "role_excludes", "reported_role"),
    "C02": ("equal_untimed", "", "unknown", "as_of_missing", "reported_root_guard"),
    "U01": ("omitted_guard", "", "unknown", "field_not_printed", "reported_root_guard"),
    "U01-both": ("omitted_guard", "both", "unknown", "field_not_printed", "reported_root_guard"),
    "U02": ("mismatch", "missing", "unknown", "not_collected", "reported_role"),
    "C01-missing": ("role_excludes", "missing", "not_applicable", "role_excludes", "reported_role"),
    "C01-partial": ("role_excludes", "partial", "not_applicable", "role_excludes", "reported_role"),
    "U03-partial": ("mismatch", "partial", "unknown", "parse_partial", "reported_role"),
    "U03-error": ("mismatch", "error", "unknown", "capture_error", "reported_role"),
    "U03-truncated": ("mismatch", "truncated", "unknown", "capture_truncated", "reported_role"),
    "U03-unmodelled": ("mismatch", "unmodelled", "unknown", "parse_unsupported_variant", "reported_role"),
    "U03-applicability": ("mismatch", "mst", "unknown", "analysis_gap", "declared_scope"),
    "U03-scope-exclusion": ("role_excludes", "scope", "unknown", "analysis_gap", "declared_scope"),
}
DAMAGE = {"partial": ("parse_partial", "complete"), "error": ("capture_error", "error"),
          "truncated": ("capture_truncated", "truncated"),
          "unmodelled": ("parse_unsupported_variant", "unknown_format")}


def need(value, code):
    if not value:
        raise ValueError("p4_guard_catalogue_" + code)


def members(case):
    need(type(case) is str and case in CASES, "case")
    original, damage, *_ = CASES[case]
    files = old.members(canonical, original)
    side = json.loads(files["p4.json"])
    if damage == "both":
        files["left.txt"] = files["left.txt"].splitlines(keepends=True)[0]
    elif damage == "missing":
        files.pop("right.txt")
        side["captures"] = [row for row in side["captures"] if row["target"] != "right"]
    elif damage in ("partial", "scope"):
        files["right.txt"] += b"Unmodelled row\n"
        if case == "U03-partial":
            files["left.txt"] = files["left.txt"].splitlines(keepends=True)[0]
    elif damage == "error":
        files["right.txt"] = b"% Command failed\n"
    elif damage == "truncated":
        files["right.txt"] += b"[truncated]\n"
    elif damage == "unmodelled":
        files["right.txt"] = b"Unmodelled STP response\n"
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    return files


def caller_policy(case):
    need(type(case) is str and case in CASES, "case")
    damage = CASES[case][1]
    return (policy.GuardPolicy(id="same_guard", domain=None if damage == "scope" else "demo",
        expectation="same_reported_root_guard", participants=tuple(policy.GuardParticipant(
            target_id=name, vlan=1, declared_mode="mst" if damage == "mst" else "pvst",
            position="designated_downstream") for name in ("left", "right"))),)


def _oracle(case):
    """Construct all five expected artifacts only from the literal recipes and original bytes."""
    inputs = members(case)
    base, side = json.loads(inputs["p2.json"]), json.loads(inputs["p4.json"])
    base_hash, side_hash = sha256(inputs["p2.json"]).hexdigest(), sha256(inputs["p4.json"]).hexdigest()
    profile = compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256
    damage = CASES[case][1]
    gaps = ["mode_unsupported"] if damage == "mst" else ["domain_missing"] if damage == "scope" else []
    nodes = {row["id"]: (i, row) for i, row in enumerate(base["nodes"])}
    supplied = {row["target"]: row for row in side["captures"]}
    facts, captures, participants, operands = {}, [], [], []
    for target_index, target in enumerate(side["targets"]):
        name, node_id = target["id"], target["node"]
        node_index, node_record = nodes[node_id]
        node = "node:" + base["group"] + ":" + node_id
        subject = "stp_port_vlan:" + sha256(canonical(
            ("atlas-brain.stp-port-vlan/1", side["context"], node, old.PORT, 1))).hexdigest()
        declarations = [{"table": table, "row_id": identity, "table_digest": digest, "citation": pointer}
            for table, identity, digest, pointer in (("synthetic_p2.nodes", node_id, base_hash, f"/nodes/{node_index}"),
                ("synthetic_p4.context", side["context"], side_hash, "/context"),
                ("synthetic_p4.targets", name, side_hash, f"/targets/{target_index}"))]
        registry = [{"kind": "registry", **ref, "value": value}
            for ref, value in zip(declarations, (node_record, side["context"], target), strict=True)]
        member = supplied.get(name)
        reason, integrity = (DAMAGE["partial" if damage == "scope" else damage]
            if name == "right" and (damage in DAMAGE or damage == "scope") else (None, "complete"))
        role, guard, role_spans, guard_spans = None, None, (), ()
        witness = []
        if member is None:
            reason = "not_collected"
        else:
            raw = inputs[member["path"]]
            identifier = "cap:" + sha256(canonical((side["schema"], side_hash, base_hash, side["context"],
                name, member["path"], sha256(raw).hexdigest(), profile))).hexdigest()
            capture = {"id": identifier, "source": node, "target": name, "path": member["path"], "operation": old.OP,
                "rendered": f"show spanning-tree interface {old.PORT} detail", "codec": "utf-8",
                "sha256": sha256(raw).hexdigest(), "owner": STEP, "context": side["context"],
                "registration_sha256": profile, "parse": "partial" if reason else "complete",
                "channel": "cli", "envelope": None, "integrity": integrity, "read_scope": "unknown", "view": "unknown",
                "error": None, "scope": {"node": node, "context": None, "vrf": None, "instance": None,
                    "vdc": None, "tenant": None, "afi": None, "plane": "exec"}}
            whole = [old._leaf(capture, raw)]
            capture.update(integrity_evidence=whole, read_scope_evidence=[],
                collected_utc=old._unknown("as_of_missing", "no_collector_time", whole, []))
            captures.append(capture)
            witness = [old._leaf(capture, raw, role="witness")]
            if reason is None:
                role, guard, role_spans, guard_spans = old._source(raw)
        labels = {"pack": "l2.stp", "subject": subject, "context": side["context"], "node": node_id,
            "port": old.PORT, "target": name, "vlan": 1}
        role_state = (old._unknown(reason, "stp_reported_role_unresolved", registry + witness,
            [old._next(node, (ROLE,), STEP, ())]) if reason else old._known(role, "observed",
                registry + [old._leaf(capture, raw, span) for span in role_spans], role))
        guard_state = (old._unknown(reason or "field_not_printed", "stp_root_guard_unresolved", registry + witness,
            [old._next(node, (GUARD,), STEP, ())]) if reason or guard is None else old._known(guard == "enabled",
                "observed", registry + [old._leaf(capture, raw, span) for span in guard_spans], guard))
        for fact, value in ((ROLE, role_state), (GUARD, guard_state)):
            facts[subject, fact] = {**labels, "fact": fact, **value}
        participants.append({"target_id": name, "vlan": 1, "declared_mode": "mst" if damage == "mst" else "pvst",
            "position": "designated_downstream", "node": node_id, "port": old.PORT,
            "subject": subject, "declarations": declarations})
        operands.append((node, subject, role_state, guard_state))
    policy_record = {"id": "same_guard", "domain": None if damage == "scope" else "demo",
        "expectation": "same_reported_root_guard", "participants": participants}
    policy_raw = canonical({"schema": "atlas-brain.declared-stp-guard-policy/1", "semantic_group": "declared_synthetic",
        "context": side["context"], "registration_sha256": profile, "registry_sha256": side_hash,
        "base_registry_sha256": base_hash, "policies": [policy_record]})
    scope = {"kind": "registry", "table": "declared_stp_guard_policies", "row_id": "same_guard",
        "table_digest": sha256(policy_raw).hexdigest(), "citation": "/policies/0", "value": policy_record}
    refs = {fact: [{"kind": "fact", "fact": fact, "subject": point[1], "value": facts[point[1], fact]}
        for point in operands] for fact in (ROLE, GUARD)}
    all_needs = [old._next(point[0], (ROLE, GUARD), CHECK_STEP,
        ("collector_recorded_time", "declared_guard_policy")) for point in operands]
    scope_state = (old._unknown("analysis_gap", "declared_guard_policy_gap", [scope], all_needs)
        if gaps else old._known(True, "declared", [scope]))
    hops = [{"id": "declared_scope", "state": scope_state}]
    wanted = CASES[case][2:]
    if not gaps:
        excluded = CASES[case][0] == "role_excludes"
        role_gap = next((p[2] for p in operands if p[2]["state"] == "unknown"), None)
        role_state = ({"state": "not_applicable", "reason": "role_excludes", "evidence": refs[ROLE]} if excluded
            else old._unknown(role_gap["reason"], role_gap["detail"], refs[ROLE], role_gap["next_evidence"])
            if role_gap else old._known(True, "derived", refs[ROLE]))
        hops.append({"id": "reported_role", "state": role_state})
        if not excluded and role_gap is None:
            guard_gap = next((p[3] for p in operands if p[3]["state"] == "unknown"), None)
            guard_state = (old._unknown(guard_gap["reason"], guard_gap["detail"], refs[GUARD], guard_gap["next_evidence"])
                if guard_gap else old._unknown("as_of_missing", "untimed_equal_guard_reports", refs[GUARD], all_needs)
                if case == "C02" else old._known(True, "derived", refs[GUARD]))
            hops.append({"id": "reported_root_guard", "state": guard_state})
    next_evidence = (hops[-1]["state"]["next_evidence"] if wanted[0] == "unknown"
        else all_needs if wanted[0] == "problem" else [])
    finding = {"check": "l2.stp.reported_root_guard_mismatch", "policy_id": "same_guard",
        "left": operands[0][1], "right": operands[1][1], "state": wanted[0], "reason": wanted[1],
        "conditional": True, "gaps": gaps, "hops": hops,
        "evidence": [ref for hop in hops for ref in hop["state"]["evidence"]], "next_evidence": next_evidence}
    header = {"schema": "atlas-brain.p4-guard-report/1", "semantic_group": "declared_synthetic",
        "scope": "conditional_reported_guard_comparisons", "fact_scope": "stp_operands_only", "capture_scope": "p4_members_only",
        "source_required": "original_pinned_evidence_folder", "variant_support": "allowlisted", "context": side["context"],
        "registration_sha256": profile, "registry_sha256": side_hash, "base_registry_sha256": base_hash,
        "policy_registry": {"path": old.POLICY, "sha256": sha256(policy_raw).hexdigest(), "basis": "declared"},
        "denominator": {"declared_policies": 1, "declared_participant_occurrences": 2},
        "coverage": old._unknown("denominator_open", "caller_declared_guard_policy_only", [scope], []),
        "captures": sorted(captures, key=lambda item: item["id"])}
    expected = {"result.json": canonical(header), old.FACTS: b"".join(canonical(facts[key]) + b"\n" for key in sorted(facts)),
        old.CHECKS: canonical(finding) + b"\n", old.POLICY: policy_raw}
    expected["MANIFEST.sha256"] = b"".join(f"{sha256(expected[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in sorted(expected))
    return expected


def _typed_files(files):
    need(type(files) is dict and all(type(name) is str and type(raw) is bytes for name, raw in files.items()), "files")


def validate(reports, inputs, case):
    """Compare trusted canonical bytes, including secondary gaps and bool/int distinctions."""
    _typed_files(reports)
    _typed_files(inputs)
    generated = members(case)
    need(inputs == generated, "source")
    expected = _oracle(case)
    need(reports == expected, "oracle")
    if case in ("F01", "C01", "C02", "U01"):
        old.validate(reports, inputs, CASES[case][0], canonical)
    return _record(case, inputs, reports)


def _record(case, inputs, reports):
    head = json.loads(reports["result.json"])
    return {"catalogue": CATALOGUE, "alias": ALIAS, "case": case, "generator": GENERATOR,
        "historical_mapping": "UNVERIFIED", "expected": dict(zip(("state", "reason", "last_hop"), CASES[case][2:], strict=True)),
        "original_inputs": {name: {"hex": raw.hex(), "sha256": sha256(raw).hexdigest()} for name, raw in sorted(inputs.items())},
        "policy": {"value": json.loads(reports[old.POLICY]), "hex": reports[old.POLICY].hex(),
            "sha256": sha256(reports[old.POLICY]).hexdigest()},
        "registration_sha256": head["registration_sha256"], "captures": head["captures"],
        "denominator": head["denominator"], "coverage": head["coverage"],
        "operands": [json.loads(line) for line in reports[old.FACTS].splitlines()],
        "findings": [json.loads(line) for line in reports[old.CHECKS].splitlines()],
        "reports": {name: {"hex": raw.hex(), "sha256": sha256(raw).hexdigest()} for name, raw in sorted(reports.items())}}


def validate_retained(value, case):
    expected = _record(case, members(case), _oracle(case))
    need(canonical(value) == canonical(expected), "retained")
