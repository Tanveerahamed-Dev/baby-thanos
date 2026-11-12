"""Independent wire oracle for one generated three-pack observation estate and its twins."""
import json
from hashlib import sha256

PORT = "GigabitEthernet1/0/1"
STP, EC, HSRP = "iosxe.show_spanning_tree_interface_detail", "iosxe.show_etherchannel_summary", "iosxe.show_standby_brief"
CASES = ("baseline", "pagp", "missing")
PATHS = {"l2.stp": "facts/stp_port_vlan.jsonl", "l2.etherchannel": "facts/etherchannel_group.jsonl",
         "l3.fhrp": "facts/fhrp_local.jsonl"}
NAMES = {"result.json", "MANIFEST.sha256", *PATHS.values()}


def need(condition, code):
    if not condition:
        raise ValueError("p4_estate_demo_" + code)


def members(canonical, case):
    need(case in CASES, "generated_source")
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": node, "discovery_id": "fixture-" + node, "ports": [PORT, "Gi1/0/1", "Gi1/0/2"]} for node in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                      "sha256": sha256(discovery).hexdigest()}]})
    tree = b"".join(f"Port 1 ({PORT}) of VLAN{vlan:04d} is designated forwarding\n   Root guard is disabled on the port\n".encode("ascii")
                    for vlan in (1, 2))
    protocol = b"PAgP" if case == "pagp" else b"-"
    channel = (b"Number of channel-groups in use: 2\nNumber of aggregators: 2\nGroup Port-channel Protocol Ports\n"
               b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n2 Po2(SD) " + protocol + b" Gi1/0/2(D)\n")
    hsrp = (b"                     P indicates configured to preempt.\n                     |\n"
            b"Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
            b"Vl20        0    100   Init    unknown         unknown         203.0.113.1\n"
            b"Vl10        1    110 P Active  local           192.0.2.2       192.0.2.1\n"
            b"BD3329      129  90 P Standby 198.51.100.2    local           198.51.100.1\n")
    files = {"p2.json": base, "discovery.txt": discovery, "tree.txt": tree, "ec.txt": channel, "hsrp.txt": hsrp}
    targets = [{"id": "tree", "node": "a", "operation": STP, "params": {"port": PORT, "vlans": [3, 2, 1]}},
        {"id": "ec", "node": "b", "operation": EC, "params": {"groups": ["3", "2", "1"], "ports": ["Gi1/0/1", "Gi1/0/2"]}},
        {"id": "cold", "node": "a", "operation": EC, "params": {"groups": ["4"], "ports": []}},
        {"id": "hsrp", "node": "a", "operation": HSRP,
         "params": {"groups": [["Vl20", "0"], ["Vl10", "1"], ["BD3329", "129"], ["Vl99", "2"]]}},
        {"id": "hsrp-cold", "node": "b", "operation": HSRP, "params": {"groups": [["Vl30", "2"]]}}]
    captures = [{"target": name, "path": name + ".txt", "sha256": sha256(files[name + ".txt"]).hexdigest()}
                for name in ("tree", "ec", "hsrp") if case != "missing" or name == "tree"]
    if case == "missing":
        del files["ec.txt"], files["hsrp.txt"]
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "round",
            "base_sha256": sha256(base).hexdigest(), "targets": targets, "captures": captures}
    return {**files, "p4.json": canonical(side)}


def _known(value, basis, evidence, raw):
    return {"state": "known", "value": value, "basis": basis, "evidence": evidence, "raw": raw}


def _unknown(reason, detail, evidence, needs):
    return {"state": "unknown", "reason": reason, "detail": detail, "evidence": evidence,
            "candidates": [], "next_evidence": needs}


def _leaf(capture, raw, span=None, role="subject"):
    value = {"kind": "capture", "capture": capture["id"], "role": role, "capture_sha256": capture["sha256"],
             **{name: capture[name] for name in ("source", "target", "path", "operation", "rendered")}}
    return ({**value, "locator": "whole_capture", "sha256": sha256(raw).hexdigest()} if span is None else
            {**value, "locator": "bytes", "start": span[0], "end": span[1], "sha256": sha256(raw[span[0]:span[1]]).hexdigest()})


def _line(raw, prefix):
    start = 0
    for line in raw.splitlines():
        if line.startswith(prefix):
            cursor, spans = start, []
            for word in line.split():
                cursor = raw.index(word, cursor)
                spans.append((cursor, cursor + len(word)))
                cursor += len(word)
            return (start, start + len(line)), line.split(), spans
        start += len(line) + 1
    return None


def validate(reports, inputs, case, canonical):
    from atlas_brain.model.pack_registration import compile_packs
    from atlas_brain.packs.l2.etherchannel import build as ec
    from atlas_brain.packs.l2.stp import build as stp
    from atlas_brain.packs.l3.fhrp import build as fhrp
    need(case in CASES and inputs == members(canonical, case), "generated_source")
    base, side = json.loads(inputs["p2.json"]), json.loads(inputs["p4.json"])
    p2hash, p4hash = sha256(inputs["p2.json"]).hexdigest(), sha256(inputs["p4.json"]).hexdigest()
    profile = compile_packs((stp.DECLARATION, ec.DECLARATION, fhrp.DECLARATION)).registration_sha256
    definitions = {STP: ("l2.stp", str(stp.STEP.id), f"show spanning-tree interface {PORT} detail"),
        EC: ("l2.etherchannel", str(ec.STEP.id), "show etherchannel summary"),
        HSRP: ("l3.fhrp", str(fhrp.STEP.id), "show standby brief")}
    facts = {pack: {} for pack in PATHS}
    captures, recorded = [], {}
    for member in side["captures"]:
        target = next(target for target in side["targets"] if target["id"] == member["target"])
        _, owner, command = definitions[target["operation"]]
        raw, node = inputs[member["path"]], "node:demo:" + target["node"]
        identifier = "cap:" + sha256(canonical((side["schema"], p4hash, p2hash, side["context"], target["id"],
            member["path"], sha256(raw).hexdigest(), profile))).hexdigest()
        capture = {"id": identifier, "source": node, "target": target["id"], "path": member["path"],
            "operation": target["operation"], "rendered": command, "codec": "utf-8", "sha256": sha256(raw).hexdigest(),
            "owner": owner, "context": side["context"], "registration_sha256": profile, "parse": "complete",
            "channel": "cli", "envelope": None, "integrity": "complete", "read_scope": "unknown", "view": "unknown",
            "error": None, "scope": {"node": node, "context": None, "vrf": None, "instance": None,
                                   "vdc": None, "tenant": None, "afi": None, "plane": "exec"}}
        whole = [_leaf(capture, raw)]
        capture.update(integrity_evidence=whole, read_scope_evidence=[],
                       collected_utc=_unknown("as_of_missing", "no_collector_time", whole, []))
        captures.append(capture)
        recorded[target["id"]] = capture, raw
    for i, target in enumerate(side["targets"]):
        op, node = target["operation"], "node:demo:" + target["node"]
        pack, step, _ = definitions[op]
        capture, raw = recorded[target["id"]] if target["id"] in recorded else (None, b"")
        node_index = 0 if target["node"] == "a" else 1
        registry = [{"kind": "registry", "table": table, "row_id": identity, "table_digest": digest,
                     "citation": pointer, "value": value} for table, identity, digest, pointer, value in (
            ("synthetic_p2.nodes", target["node"], p2hash, f"/nodes/{node_index}", base["nodes"][node_index]),
            ("synthetic_p4.context", side["context"], p4hash, "/context", side["context"]),
            ("synthetic_p4.targets", target["id"], p4hash, f"/targets/{i}", target))]
        witness = registry + ([] if capture is None else [_leaf(capture, raw, role="witness")])
        items = target["params"]["vlans" if op == STP else "groups"]
        for key in ((item,) if op != HSRP else item for item in items):
            labels = {"context": side["context"], "node": target["node"], "target": target["id"]}
            spans, values = {}, {}
            if op == STP:
                vlan, = key
                labels.update(port=PORT, vlan=vlan)
                subject = "stp_port_vlan:" + sha256(canonical(("atlas-brain.stp-port-vlan/1", side["context"], node, PORT, vlan))).hexdigest()
                row = _line(raw, f"Port 1 ({PORT}) of VLAN{vlan:04d} ".encode("ascii"))
                identities = (("l2.stp.root_guard", "stp_root_guard_unresolved"), ("l2.stp.reported_role", "stp_reported_role_unresolved"))
                if row is not None:
                    header, words, tokens = row
                    port, vid = (tokens[2][0] + 1, tokens[2][1] - 1), (tokens[4][0] + 4, tokens[4][1])
                    guard = _line(raw[header[1] + 1:], b"   Root guard is ")
                    line, guard_words, positions = guard
                    shift = header[1] + 1
                    line = tuple(value + shift for value in line)
                    word = tuple(value + shift for value in positions[3])
                    spans = {identities[0][0]: (word, line, port, vid, header),
                             identities[1][0]: (header, port, vid, tokens[6], tokens[7])}
                    values = {identities[0][0]: (guard_words[3] == b"enabled", guard_words[3].decode("ascii"), "observed"),
                              identities[1][0]: (words[6].decode("ascii"), words[6].decode("ascii"), "observed")}
            elif op == EC:
                group, = key
                labels.update(group=group)
                subject = "etherchannel_group:" + sha256(canonical(("atlas-brain.etherchannel-group/1", side["context"], node, group))).hexdigest()
                row = _line(raw, group.encode("ascii") + b" ")
                identities = (("l2.etherchannel.reported_protocol", "etherchannel_protocol_unresolved"),
                              ("l2.etherchannel.reported_member_tokens", "etherchannel_member_tokens_unresolved"))
                if row is not None:
                    record, words, positions = row
                    channel = positions[1][0], positions[1][0] + len(words[1].split(b"(")[0])
                    token, member = words[3], positions[3]
                    port = member[0], member[0] + token.index(b"(")
                    flag = port[1] + 1, member[1] - 1
                    spans = {identities[0][0]: (positions[0], positions[2], record),
                             identities[1][0]: tuple(sorted({positions[0], channel, member, port, flag, record}))}
                    word = words[2].decode("ascii")
                    values = {identities[0][0]: ({"LACP": "lacp", "PAgP": "pagp", "-": "none_reported"}[word], word, "observed"),
                              identities[1][0]: (token.decode("ascii"), None, "derived")}
            else:
                interface, group = key
                labels.update(address_family="ipv4", protocol="hsrp", interface=interface, group=group)
                subject = "fhrp_local:" + sha256(canonical(("atlas-brain.fhrp-local/1", side["context"], node, interface, "ipv4", "hsrp", group))).hexdigest()
                row = _line(raw, interface.encode("ascii") + b" ")
                identities = (("l3.fhrp.reported_state", "hsrp_state_unresolved"),)
                if row is not None:
                    record, words, positions = row
                    need(words[1].decode("ascii") == group, "source_tokens")
                    state = 4 if len(words) == 8 else 3
                    addresses = [span for word, span in zip(words[-3:], positions[-3:], strict=True) if b"." in word]
                    spans = {identities[0][0]: tuple(sorted({record, positions[0], positions[1], positions[state], *addresses}))}
                    value = words[state].decode("ascii")
                    values = {identities[0][0]: (value.lower(), value, "observed")}
            for fact, detail in identities:
                params = [["port", PORT]] if op == STP else ([["group", group], ["interface", interface]] if op == HSRP else [])
                need_record = {"node": node, "operation": op, "params": params, "resolves": [fact],
                               "reruns": [step], "after_s": None, "unprintable": []}
                if row is None:
                    state = _unknown("not_collected" if capture is None else "subject_absent_from_capture", detail, witness, [need_record])
                else:
                    value, token, basis = values[fact]
                    state = _known(value, basis, registry + [_leaf(capture, raw, span) for span in spans[fact]], token)
                facts[pack][subject, fact] = {"pack": pack, "fact": fact, "subject": subject, **labels, **state}
    header = {"schema": "atlas-brain.p4-observations/1", "semantic_group": "declared_synthetic", "scope": "observations_only",
        "checks": "not_implemented", "variant_support": "allowlisted", "group": base["group"], "context": side["context"],
        "registration_sha256": profile, "registry_sha256": p4hash, "base_registry_sha256": p2hash,
        "capture_scope": "p4_members_only", "base_capture_scope": "admitted_discovery_context_only",
        "denominator": {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5},
        "captures": sorted(captures, key=lambda capture: capture["id"])}
    expected = {"result.json": canonical(header), **{PATHS[pack]: b"".join(canonical(rows[key]) + b"\n" for key in sorted(rows))
                                                   for pack, rows in facts.items()}}
    expected["MANIFEST.sha256"] = b"".join(f"{sha256(expected[name]).hexdigest()}  {name}\n".encode("ascii") for name in sorted(expected))
    need(reports == expected, "report")
    known = sum(row["state"] == "known" for rows in facts.values() for row in rows.values())
    need(sum(map(len, facts.values())) == 19 and known == (4 if case == "missing" else 11), "source_tokens")
    return {"qualification": "synthetic_observations_only", "denominator": header["denominator"], "facts": 19,
        "known": known, "unknown": 19 - known, "source": {name: sha256(raw).hexdigest() for name, raw in sorted(inputs.items())},
        "reports": {name: sha256(raw).hexdigest() for name, raw in sorted(reports.items())}}
