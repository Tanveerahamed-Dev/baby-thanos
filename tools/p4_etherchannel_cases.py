"""Original synthetic R10 cases and independent literal oracles; no admission authority.

Historical EI meanings remain UNVERIFIED. Expected-members/min-links predicates
are absent; these cases cover reported operands and conditional protocol checks.
"""
import json
from dataclasses import asdict
from hashlib import sha256

from atlas_brain.packs.l2.etherchannel.protocol_policy import ProtocolPolicy

CATALOGUE, ALIAS, GENERATOR = "baby-thanos.p4.synthetic/1", "EI-R10", "baby-thanos.p4.r10-cases/1"
OP, COMMAND, OWNER = "iosxe.show_etherchannel_summary", "show etherchannel summary", "l2.etherchannel/parse_protocol"
PROTOCOL, MEMBERS = "l2.etherchannel.reported_protocol", "l2.etherchannel.reported_member_tokens"
CHECK, CHECK_STEP = "l2.etherchannel.reported_protocol_mismatch", "l2.etherchannel/check_reported_protocol"
PORTS = ("Gi1/0/1", "Gi1/0/2", "Gi1/0/3")
CONFIG = {
    "F01": ("LACP", "PAgP", False, ()),
    "C01": ("LACP", "LACP", False, ()),
    "C02": ("LACP", "LACP", True, ()),
    "U01": ("-", "PAgP", False, ()),
    "U02_passive": ("passive", "PAgP", False, ()),
    "U02_on": ("on", "PAgP", False, ()),
    "U03_missing": ("LACP", "PAgP", False, ("right",)),
    "U03_two_missing": ("LACP", "PAgP", False, ("left", "right")),
    "U03_unknown_before_dash": ("-", "PAgP", False, ("right",)),
    "U02_two_gaps": ("passive", "PAgP", False, ("right",)),
}
OUTCOMES = {
    "F01": ("problem", None, "conditional_reported_protocol_difference", None),
    "C01": ("unknown", "as_of_missing", "untimed_equal_protocol_reports", None),
    "C02": ("unknown", "as_of_missing", "untimed_equal_protocol_reports", None),
    "U01": ("unknown", "not_observable", "negotiation_protocol_not_reported", None),
    "U02_passive": ("unknown", "parse_partial", "etherchannel_protocol_unresolved", "a"),
    "U02_on": ("unknown", "parse_partial", "etherchannel_protocol_unresolved", "a"),
    "U03_missing": ("unknown", "not_collected", "etherchannel_protocol_unresolved", "b"),
    "U03_two_missing": ("unknown", "not_collected", "etherchannel_protocol_unresolved", "a"),
    "U03_unknown_before_dash": ("unknown", "not_collected", "etherchannel_protocol_unresolved", "b"),
    "U02_two_gaps": ("unknown", "parse_partial", "etherchannel_protocol_unresolved", "a"),
}
CASES = tuple(CONFIG)
LEGEND = b"Flags: D - down P - bundled in port-channel\nI - stand-alone s - suspended\n"
HEADER = b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n--+--+--+--\n"


def policies():
    return (ProtocolPolicy(id="same_protocol", expectation="same_reported_protocol",
        participants=(("left", "1"), ("right", "1"))),)


def members(canonical, case):
    left, right, wrapped, missing = CONFIG[case]
    discovery = b"Device ID: synthetic-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "r10",
        "nodes": [{"id": node, "discovery_id": "synthetic-" + node, "ports": list(PORTS)} for node in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
            "sha256": sha256(discovery).hexdigest()}]})
    files = {"p2.json": base, "discovery.txt": discovery}
    for name, word in (("left", left), ("right", right)):
        if name not in missing:
            files[name + ".txt"] = LEGEND + HEADER + ("1 Po1(SU) " + word + " Gi1/0/1(P)\n").encode("ascii") + (
                b"   Gi1/0/2(s) Gi1/0/3(D)\n" if wrapped and name == "left" else b"")
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "r10",
        "base_sha256": sha256(base).hexdigest(), "targets": [
            {"id": name, "node": node, "operation": OP, "params": {"groups": ["2", "1"], "ports": list(PORTS)}}
            for name, node in (("left", "a"), ("right", "b"))],
        "captures": [{"target": name, "path": name + ".txt", "sha256": sha256(files[name + ".txt"]).hexdigest()}
            for name in ("left", "right") if name not in missing]}
    return {**files, "p4.json": canonical(side)}


def _plain(value):
    return json.loads(json.dumps(asdict(value)))


def _state(value):
    result = _plain(value)
    return {"state": "known" if "value" in result else "unknown", **result}


def _record(files, case):
    return {"schema": "baby-thanos.p4.r10-retained/1", "catalogue": CATALOGUE, "alias": ALIAS, "case": case,
        "case_id": ALIAS + "." + case, "generator_revision": GENERATOR, "historical_catalogue": "UNVERIFIED",
        "scope": "conditional_synthetic_reports_only",
        "assumptions": ["declared_same_reported_protocol", "untimed", "port_census_is_not_membership_intent"], "open_obligations": ["expected_members_min_links_predicate_absent"],
        "source": {name: {"sha256": sha256(raw).hexdigest(), "hex": raw.hex()} for name, raw in sorted(files.items())}}


def observe(evaluation, files, case):
    """Detach a completed ordinary evaluation for comparison; this authenticates nothing."""
    rows = evaluation.source.rows
    captures = []
    for output in evaluation.source.executed:
        receipt, capture = output.receipt, output.receipt.capture
        captures.append({"id": capture.id, "source": capture.source, "operation": capture.operation,
            "rendered": capture.rendered, "codec": capture.codec, "sha256": capture.bytes_sha256,
            "owner": receipt.owner, "context": receipt.context, "registration_sha256": receipt.registration_sha256,
            "integrity": capture.integrity.value, "read_scope": capture.read_scope.value, "view": capture.view.value,
            "metadata": _plain(capture.resolved_metadata), "parse": receipt.parse.quality})
    return {**_record(files, case), "policy": json.loads(evaluation.plan.raw), "policy_sha256": evaluation.plan.sha256,
        "denominator": [list(pair) for pair in evaluation.result.denominator], "coverage": _state(evaluation.result.coverage),
        "source_denominator": {"declared_group_subjects": len(rows), "owned_cells": len(evaluation.source.store.values)},
        "store_owners": dict(evaluation.source.store.owners), "captures": sorted(captures, key=lambda item: item["id"]),
        "operands": [{"context": row.target.context, "node": row.target.node.key, "group": row.group,
            "groups": list(row.target.groups), "ports": list(row.target.ports), "subject": row.subject,
            "protocol": _state(row.value), "members": _state(row.member_tokens)} for row in rows],
        "findings": [_plain(finding) for finding in evaluation.result.rows]}


def _need(node, fact, step=OWNER, unprintable=()):
    return {"node": "node:r10:" + node, "operation": OP, "params": [], "resolves": [fact], "reruns": [step],
        "after_s": None, "unprintable": list(unprintable)}


def _unknown(reason, detail, evidence, needs):
    return {"state": "unknown", "reason": reason, "detail": detail, "evidence": evidence,
        "candidates": [], "next_evidence": needs}


def oracle(canonical, case, registration):
    """Expected coordinates come only from this generator's literal bytes and case table."""
    files = members(canonical, case)
    side = json.loads(files["p4.json"])
    base_hash, side_hash = sha256(files["p2.json"]).hexdigest(), sha256(files["p4.json"]).hexdigest()
    def subject(node, group):
        return "etherchannel_group:" + sha256(canonical(("atlas-brain.etherchannel-group/1", "r10", "node:r10:" + node, group))).hexdigest()
    def registry(table, identity, digest, citation):
        return {"table": table, "row_id": identity, "table_digest": digest, "citation": citation}
    def leaf(identity, raw, span=None, role="subject"):
        return {"capture": identity, "locator": {} if span is None else {"start": span[0], "end": span[1]},
            "role": role, "excerpt_sha256": sha256(raw if span is None else raw[span[0]:span[1]]).hexdigest()}
    operands, captures = [], []
    left, right, wrapped, _missing = CONFIG[case]
    for index, (name, node, word) in enumerate((("left", "a", left), ("right", "b", right))):
        raw = files.get(name + ".txt")
        declarations = [registry("synthetic_p2.nodes", node, base_hash, f"/nodes/{index}"),
            registry("synthetic_p4.context", "r10", side_hash, "/context"),
            registry("synthetic_p4.targets", name, side_hash, f"/targets/{index}")]
        identity = None
        if raw is not None:
            digest = sha256(raw).hexdigest()
            identity = "cap:" + sha256(canonical((side["schema"], side_hash, base_hash, "r10", name,
                name + ".txt", digest, registration))).hexdigest()
            witness = leaf(identity, raw)
            metadata = {"channel": "cli", "scope": {"node": "node:r10:" + node, "vrf": None, "context": None,
                "vdc": None, "tenant": None, "afi": None, "instance": None, "plane": "exec"},
                "collected_utc": {"reason": "as_of_missing", "detail": "no_collector_time", "evidence": [witness],
                    "candidates": [], "next_evidence": []}, "error": None, "integrity_evidence": [witness],
                "read_scope_evidence": [], "envelope": None}
            captures.append({"id": identity, "source": "node:r10:" + node, "operation": OP, "rendered": COMMAND,
                "codec": "utf-8", "sha256": digest, "owner": OWNER, "context": "r10", "registration_sha256": registration,
                "integrity": "complete", "read_scope": "unknown", "view": "unknown", "metadata": metadata,
                "parse": "partial" if word in ("passive", "on") else "complete"})
        for group in ("1", "2"):
            reason = "not_collected" if raw is None else "parse_partial" if word in ("passive", "on") else (
                "subject_absent_from_capture" if group == "2" else None)
            evidence = declarations + ([] if raw is None else [leaf(identity, raw, role="witness")])
            if reason is not None:
                protocol = _unknown(reason, "etherchannel_protocol_unresolved", evidence, [_need(node, PROTOCOL)])
                member_state = _unknown(reason, "etherchannel_member_tokens_unresolved", evidence, [_need(node, MEMBERS)])
            else:
                start = len(LEGEND + HEADER)
                end = raw.index(b"\n", start)
                group_span, channel_span = (start, start + 1), (start + 2, start + 5)
                token_span = start + 10, start + 10 + len(word)
                protocol = {"state": "known", "value": {"LACP": "lacp", "PAgP": "pagp", "-": "none_reported"}[word],
                    "basis": "observed", "raw": word, "evidence": declarations + [
                        leaf(identity, raw, point) for point in (group_span, token_span, (start, end))]}
                text = "Gi1/0/1(P)" + (" Gi1/0/2(s) Gi1/0/3(D)" if wrapped and name == "left" else "")
                spans = {group_span, channel_span, (start, end)}
                if wrapped and name == "left":
                    spans.add((end + 1, len(raw) - 1))
                for token in text.split():
                    offset = raw.index(token.encode("ascii"))
                    port_end = offset + token.index("(")
                    spans.update(((offset, offset + len(token)), (offset, port_end), (port_end + 1, offset + len(token) - 1)))
                member_state = {"state": "known", "value": text, "basis": "derived", "raw": None,
                    "evidence": declarations + [leaf(identity, raw, point) for point in sorted(spans)]}
            operands.append({"context": "r10", "node": "node:r10:" + node, "group": group, "groups": ["1", "2"],
                "ports": list(PORTS), "subject": subject(node, group), "protocol": protocol, "members": member_state})
    participants = [{"target_id": name, "node": "node:r10:" + node, "group": "1", "subject": subject(node, "1")}
        for name, node in (("left", "a"), ("right", "b"))]
    policy = {"schema": "atlas-brain.declared-etherchannel-protocol-policy/1", "semantic_group": "declared_synthetic",
        "context": "r10", "registration_sha256": registration, "registry_sha256": side_hash, "base_registry_sha256": base_hash,
        "policies": [{"id": "same_protocol", "expectation": "same_reported_protocol", "participants": participants}]}
    policy_hash = sha256(canonical(policy)).hexdigest()
    policy_refs = [registry("declared_etherchannel_protocol_policies", "same_protocol", policy_hash, "/policies/0")]
    state, reason, detail, primary = OUTCOMES[case]
    needs = [_need(primary, PROTOCOL)] if primary else [_need(node, PROTOCOL, CHECK_STEP,
        ("explicit_negotiation_protocol",) if reason == "not_observable" else ("collector_recorded_time", "declared_protocol_policy"))
        for node in ("a", "b")]
    finding = {"check": CHECK, "policy_id": "same_protocol", "left": subject("a", "1"), "right": subject("b", "1"),
        "state": state, "reason": reason, "detail": detail, "conditional": True,
        "evidence": policy_refs + [{"fact": PROTOCOL, "subject": subject(node, "1")} for node in ("a", "b")],
        "next_evidence": needs}
    return {**_record(files, case), "policy": policy, "policy_sha256": policy_hash,
        "denominator": [["declared_policies", 1], ["declared_participant_occurrences", 2]],
        "coverage": _unknown("denominator_open", "caller_declared_protocol_pairs_only", policy_refs, []),
        "source_denominator": {"declared_group_subjects": 4, "owned_cells": 8},
        "store_owners": {PROTOCOL: OWNER, MEMBERS: OWNER}, "captures": sorted(captures, key=lambda item: item["id"]),
        "operands": operands, "findings": [finding]}


def validate_retained(record, canonical, case, registration):
    """Compare trusted canonical bytes; never admit a source, execution or proof."""
    try:
        actual = canonical(record)
    except (TypeError, ValueError) as error:
        raise ValueError("p4_r10_oracle") from error
    if actual != canonical(oracle(canonical, case, registration)):
        raise ValueError("p4_r10_oracle")
    return record
