"""Generated guard cases and independent retained-evidence oracles; synthetic scope only."""
import json
from hashlib import sha256

PORT = "GigabitEthernet1/0/1"
OP = "iosxe.show_spanning_tree_interface_detail"
POLICY, FACTS, CHECKS = "declared_guard_policy.json", "facts/stp_port_vlan.jsonl", "checks/l2.stp.jsonl"
NAMES = {"result.json", FACTS, CHECKS, POLICY, "MANIFEST.sha256"}
EXPECTED = {"mismatch": ("problem", None, "reported_root_guard"),
    "omitted_guard": ("unknown", "field_not_printed", "reported_root_guard"),
    "equal_untimed": ("unknown", "as_of_missing", "reported_root_guard"),
    "role_excludes": ("not_applicable", "role_excludes", "reported_role")}


def need(condition, code):
    if not condition:
        raise ValueError("p4_guard_demo_" + code)


def members(canonical, case):
    need(case in EXPECTED, "case")
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic",
        "group": "guard_demo", "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [PORT]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    files = {"p2.json": base, "discovery.txt": discovery}
    for target, word, role in (("left", "disabled" if case == "equal_untimed" else "enabled",
                               "root" if case == "role_excludes" else "designated"),
                              ("right", None if case == "omitted_guard" else "disabled", "designated")):
        files[target + ".txt"] = (f"Port 1 ({PORT}) of VLAN0001 is {role} forwarding\n"
            + ("" if word is None else f"   Root guard is {word} on the port\n")).encode("ascii")
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "guard_demo",
        "base_sha256": sha256(base).hexdigest(), "targets": [{"id": name, "node": node, "operation": OP,
            "params": {"port": PORT, "vlans": [1]}} for name, node in (("left", "a"), ("right", "b"))],
        "captures": [{"target": name, "path": name + ".txt", "sha256": sha256(files[name + ".txt"]).hexdigest()}
                     for name in ("left", "right")]}
    return {**files, "p4.json": canonical(side)}



def _next(node, facts, step, unprintable):
    return {"node": node, "operation": OP, "params": [["port", PORT]], "resolves": list(facts),
            "reruns": [step], "after_s": None, "unprintable": list(unprintable)}


def _source(raw):
    header = raw.splitlines()[0]
    port, vlan = raw.index(PORT.encode("ascii")), raw.index(b"VLAN") + 4
    role = raw.index(b" is ") + 4
    state = raw.index(b" ", role) + 1
    fields = ((port, port + len(PORT)), (vlan, vlan + 4), (role, state - 1), (state, len(header)))
    role_claims = ((0, len(header)), *fields)
    role_word = raw[role:state - 1].decode("ascii")
    if len(raw.splitlines()) == 1:
        return role_word, None, role_claims, ()
    guard = len(header) + 1
    word = guard + len(b"   Root guard is ")
    end = raw.index(b" ", word)
    return role_word, raw[word:end].decode("ascii"), role_claims, ((word, end),
        (guard, len(raw) - 1), fields[0], fields[1], (0, len(header)))


def _known(value, basis, evidence, raw=None):
    return {"state": "known", "value": value, "basis": basis, "evidence": evidence, "raw": raw}


def _unknown(reason, detail, evidence, needs):
    return {"state": "unknown", "reason": reason, "detail": detail, "evidence": evidence,
            "candidates": [], "next_evidence": needs}


def _leaf(capture, raw, span=None, role="subject"):
    value = {"kind": "capture", "capture": capture["id"], "source": capture["source"], "target": capture["target"],
        "path": capture["path"], "operation": OP, "rendered": capture["rendered"], "role": role,
        "capture_sha256": capture["sha256"]}
    if span is None:
        return {**value, "locator": "whole_capture", "sha256": sha256(raw).hexdigest()}
    return {**value, "locator": "bytes", "start": span[0], "end": span[1], "sha256": sha256(raw[span[0]:span[1]]).hexdigest()}


def validate(reports, inputs, case, canonical):
    """Compare all expected canonical artifacts for exactly four generated synthetic cases."""
    from atlas_brain.model.pack_registration import compile_packs
    from atlas_brain.packs.l2.etherchannel import build as ec
    from atlas_brain.packs.l2.stp import build as stp
    from atlas_brain.packs.l3.fhrp import build as fhrp
    need(case in EXPECTED and inputs == members(canonical, case), "generated_source")
    base, side = json.loads(inputs["p2.json"]), json.loads(inputs["p4.json"])
    base_hash, side_hash = sha256(inputs["p2.json"]).hexdigest(), sha256(inputs["p4.json"]).hexdigest()
    profile = compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256
    facts, captures, participants, operands = {}, [], [], []
    for i, member in enumerate(side["captures"]):
        target = side["targets"][i]
        name, node = target["id"], "node:" + base["group"] + ":" + target["node"]
        raw = inputs[member["path"]]
        role, guard, role_spans, guard_spans = _source(raw)
        subject = "stp_port_vlan:" + sha256(canonical(("atlas-brain.stp-port-vlan/1", side["context"], node, PORT, 1))).hexdigest()
        identifier = "cap:" + sha256(canonical((side["schema"], side_hash, base_hash, side["context"],
            name, member["path"], sha256(raw).hexdigest(), profile))).hexdigest()
        capture = {"id": identifier, "source": node, "target": name, "path": member["path"], "operation": OP,
            "rendered": f"show spanning-tree interface {PORT} detail", "codec": "utf-8", "sha256": sha256(raw).hexdigest(),
            "owner": str(stp.STEP.id), "context": side["context"], "registration_sha256": profile, "parse": "complete",
            "channel": "cli", "envelope": None, "integrity": "complete", "read_scope": "unknown", "view": "unknown",
            "error": None, "scope": {"node": node, "context": None, "vrf": None, "instance": None,
                                   "vdc": None, "tenant": None, "afi": None, "plane": "exec"}}
        whole = [_leaf(capture, raw)]
        capture.update(integrity_evidence=whole, read_scope_evidence=[],
            collected_utc=_unknown("as_of_missing", "no_collector_time", whole, []))
        captures.append(capture)
        declarations = [{"table": table, "row_id": identity, "table_digest": digest, "citation": pointer}
            for table, identity, digest, pointer in (("synthetic_p2.nodes", target["node"], base_hash, f"/nodes/{i}"),
                ("synthetic_p4.context", side["context"], side_hash, "/context"),
                ("synthetic_p4.targets", name, side_hash, f"/targets/{i}"))]
        registry = [{"kind": "registry", **ref, "value": value} for ref, value in zip(
            declarations, (base["nodes"][i], side["context"], target), strict=True)]
        labels = {"pack": "l2.stp", "subject": subject, "context": side["context"], "node": target["node"],
                  "port": PORT, "target": name, "vlan": 1}
        role_state = _known(role, "observed", registry + [_leaf(capture, raw, span) for span in role_spans], role)
        guard_state = (_unknown("field_not_printed", "stp_root_guard_unresolved",
            registry + [_leaf(capture, raw, role="witness")], [_next(node, ("l2.stp.root_guard",), str(stp.STEP.id), ())])
            if guard is None else _known(guard == "enabled", "observed",
                registry + [_leaf(capture, raw, span) for span in guard_spans], guard))
        for fact, state in (("l2.stp.reported_role", role_state), ("l2.stp.root_guard", guard_state)):
            facts[subject, fact] = {**labels, "fact": fact, **state}
        participants.append({"target_id": name, "vlan": 1, "declared_mode": "pvst", "position": "designated_downstream",
            "node": target["node"], "port": PORT, "subject": subject, "declarations": declarations})
        operands.append((node, subject, role, guard))
    policy_record = {"id": "same_guard", "domain": "demo", "expectation": "same_reported_root_guard", "participants": participants}
    policy_raw = canonical({"schema": "atlas-brain.declared-stp-guard-policy/1", "semantic_group": "declared_synthetic",
        "context": side["context"], "registration_sha256": profile, "registry_sha256": side_hash,
        "base_registry_sha256": base_hash, "policies": [policy_record]})
    scope = {"kind": "registry", "table": "declared_stp_guard_policies", "row_id": "same_guard",
             "table_digest": sha256(policy_raw).hexdigest(), "citation": "/policies/0", "value": policy_record}
    derived = (("not_applicable", "role_excludes", "reported_role") if any(point[2] != "designated" for point in operands)
        else ("unknown", "field_not_printed", "reported_root_guard") if any(point[3] is None for point in operands)
        else ("unknown", "as_of_missing", "reported_root_guard") if operands[0][3] == operands[1][3]
        else ("problem", None, "reported_root_guard"))
    need(derived == EXPECTED[case], "source_tokens")
    refs = {fact: [{"kind": "fact", "fact": fact, "subject": subject, "value": facts[subject, fact]}
        for _, subject, _, _ in operands] for fact in ("l2.stp.reported_role", "l2.stp.root_guard")}
    needs = [_next(node, ("l2.stp.reported_role", "l2.stp.root_guard"), "l2.stp/check_root_guard",
                   ("collector_recorded_time", "declared_guard_policy")) for node, _, _, _ in operands]
    hops = [{"id": "declared_scope", "state": _known(True, "declared", [scope])}]
    role_state = ({"state": "not_applicable", "reason": "role_excludes", "evidence": refs["l2.stp.reported_role"]}
        if derived[0] == "not_applicable" else _known(True, "derived", refs["l2.stp.reported_role"]))
    hops.append({"id": "reported_role", "state": role_state})
    if derived[0] == "not_applicable":
        needs = []
    else:
        if derived[1] == "field_not_printed":
            needs = [_next(node, ("l2.stp.root_guard",), str(stp.STEP.id), ())
                     for node, _, _, guard in operands if guard is None]
        state = (_known(True, "derived", refs["l2.stp.root_guard"]) if derived[0] == "problem" else _unknown(
            derived[1], "stp_root_guard_unresolved" if derived[1] == "field_not_printed" else "untimed_equal_guard_reports",
            refs["l2.stp.root_guard"], needs))
        hops.append({"id": "reported_root_guard", "state": state})
    finding = {"check": "l2.stp.reported_root_guard_mismatch", "policy_id": "same_guard", "left": operands[0][1],
        "right": operands[1][1], "state": derived[0], "reason": derived[1], "conditional": True, "gaps": [],
        "hops": hops, "evidence": [ref for hop in hops for ref in hop["state"]["evidence"]], "next_evidence": needs}
    header = {"schema": "atlas-brain.p4-guard-report/1", "semantic_group": "declared_synthetic",
        "scope": "conditional_reported_guard_comparisons", "fact_scope": "stp_operands_only", "capture_scope": "p4_members_only",
        "source_required": "original_pinned_evidence_folder", "variant_support": "allowlisted", "context": side["context"],
        "registration_sha256": profile, "registry_sha256": side_hash, "base_registry_sha256": base_hash,
        "policy_registry": {"path": POLICY, "sha256": sha256(policy_raw).hexdigest(), "basis": "declared"},
        "denominator": {"declared_policies": 1, "declared_participant_occurrences": 2},
        "coverage": _unknown("denominator_open", "caller_declared_guard_policy_only", [scope], []),
        "captures": sorted(captures, key=lambda capture: capture["id"])}
    expected = {"result.json": canonical(header), FACTS: b"".join(canonical(facts[key]) + b"\n" for key in sorted(facts)),
        CHECKS: canonical(finding) + b"\n", POLICY: policy_raw}
    expected["MANIFEST.sha256"] = b"".join(f"{sha256(expected[name]).hexdigest()}  {name}\n".encode("ascii") for name in sorted(expected))
    need(reports == expected, "report")
    state, reason, hop = derived
    return {"state": state, "reason": reason, "last_hop": hop,
        "expected": {"state": state, "reason": reason, "last_hop": hop},
        "source": {name: sha256(raw).hexdigest() for name, raw in sorted(inputs.items())},
        "reports": {name: sha256(raw).hexdigest() for name, raw in sorted(reports.items())},
        "policy_sha256": sha256(policy_raw).hexdigest()}
