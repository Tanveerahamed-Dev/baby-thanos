"""Current mixed raw registry correspondence; typed copies are not admission or origin tokens."""
import json
from dataclasses import replace
from enum import StrEnum
from hashlib import sha256

import pytest
from test_parse_vrrp import BODY as VRRP
from test_peer_execution import forbidden
from test_peer_version_owner import folder
from test_state_owner import LIMITS

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactStore, FactWriter
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import mixed_profile as mixed
from atlas_brain.packs.l3.fhrp import peer_profile
from atlas_brain.runner import pack_runtime


def admitted(root, mode="normal"):
    def changing(side, files):
        side["targets"].append({"id": "vrrp", "node": "a", "operation": "iosxe.show_vrrp",
            "params": {"groups": [["Vlan61", "100"], ["Vl61", "101"]]}})
        files["vrrp.txt"] = VRRP
        side["captures"].append({"target": "vrrp", "path": "vrrp.txt"})
        if mode == "multi_tree":
            side["targets"].append({"id": "tree-extra", "node": "a", "operation": stp.stp.OP,
                "params": {"port": "Gi1/0/1", "vlans": [2]}})
        if mode in ("only_vrrp", "none"):
            selected = {"vrrp"} if mode == "only_vrrp" else {target["id"] for target in side["targets"]}
            side["targets"] = [target for target in side["targets"] if target["id"] in selected]
            removed = [row["path"] for row in side["captures"] if mode == "none" or row["target"] not in selected]
            side["captures"] = [] if mode == "none" else [row for row in side["captures"] if row["target"] in selected]
            for name in removed:
                files.pop(name)
        elif mode == "cold_vrrp":
            side["captures"] = [row for row in side["captures"] if row["target"] != "vrrp"]
            files.pop("vrrp.txt")
        elif mode == "opaque_params":
            next(target for target in side["targets"] if target["id"] == "vrrp")["params"] = {"future": ["not interpreted"]}
    files = folder(root, change=changing)
    for name in ("brief.txt", "all.txt", "tree.txt", "channel.txt", "vrrp.txt"):
        if name not in files:
            (root / name).unlink(missing_ok=True)
    envelope = p4.admit_folder(root, LIMITS, declarations=mixed.DECLARATIONS)
    assert preparation.validate_mixed_context(envelope, LIMITS) == mixed.compile_mixed_profile()
    return envelope, files


def refs(state, digest, citation=None):
    ref = state.evidence[0]
    return replace(state, evidence=(replace(ref, table_digest=digest, citation=ref.citation if citation is None else citation),))


def rebased(envelope, base=None, side=None):
    old_base, old_side = json.loads(envelope.base.raw), json.loads(envelope.raw)
    base, side = old_base if base is None else base, old_side if side is None else side
    raw_base = canonical(base)
    base_hash = sha256(raw_base).hexdigest()
    side["base_sha256"] = base_hash
    raw_side = canonical(side)
    side_hash = sha256(raw_side).hexdigest()
    nodes = tuple(replace(node, declaration=refs(node.declaration, base_hash)) for node in envelope.base.nodes)
    by_node = {node.id: node for node in nodes}
    rows = {row["id"]: (index, row) for index, row in enumerate(side["targets"])}
    targets = tuple(replace(target, node=by_node[target.node.id], params=canonical(rows[target.id][1]["params"]),
        declaration=refs(target.declaration, side_hash, f"/targets/{rows[target.id][0]}")) for target in envelope.targets if target.id in rows)
    by_target = {target.id: target for target in targets}
    discovery = []
    for index, capture in enumerate(envelope.base.captures):
        row = base["captures"][index] if index < len(base["captures"]) else old_base["captures"][index]
        identity = "cap:" + sha256(canonical((base["schema"], base["group"], base_hash, row["path"],
            row["node"], row["operation"], row["sha256"]))).hexdigest()
        discovery.append(replace(capture, id=identity))
    members = []
    old_indexes = {row["path"]: index for index, row in enumerate(old_side["captures"])}
    for member in envelope.captures:
        index = old_indexes[member.path]
        row = side["captures"][index] if index < len(side["captures"]) else old_side["captures"][index]
        if member.target.id not in by_target:
            continue
        identity = "cap:" + sha256(canonical((p4.SCHEMA, side_hash, base_hash, envelope.context,
            row["target"], row["path"], row["sha256"], envelope.registration_sha256))).hexdigest()
        members.append(replace(member, target=by_target[member.target.id], path=row["path"], id=identity, sha256=row["sha256"]))
    current_base = replace(envelope.base, raw=raw_base, nodes=nodes, captures=tuple(discovery),
        declaration=refs(envelope.base.declaration, base_hash))
    return replace(envelope, raw=raw_side, base=current_base, targets=targets, captures=tuple(members),
        declaration=refs(envelope.declaration, side_hash))


def freeze(monkeypatch):
    for module, name in ((preparation.hsrp, "parse_capture"), (preparation.all_hsrp, "parse_capture"),
            (mixed.stp.stp, "parse_capture"), (mixed.ec.parse_summary, "parse_capture"), (mixed.vrrp.parser, "parse_capture"),
            (pack_runtime, "execute_parsers"), (FactStore, "__init__"), (FactWriter, "write")):
        monkeypatch.setattr(module, name, forbidden)


@pytest.fixture
def case(tmp_path, monkeypatch):
    freeze(monkeypatch)
    envelope, files = admitted(tmp_path)
    assert preparation.validate_mixed_context(rebased(envelope), LIMITS) == mixed.compile_mixed_profile()
    return envelope, files


@pytest.mark.parametrize("mode", ["normal", "only_vrrp", "none", "cold_vrrp", "multi_tree", "opaque_params"])
def test_real_admitted_context_remains_metadata_only_for_cold_vrrp_and_legitimate_stp_scopes(tmp_path, monkeypatch, mode):
    freeze(monkeypatch)
    envelope, files = admitted(tmp_path, mode)
    result = preparation.validate_mixed_context(replace(envelope), LIMITS)
    assert result == mixed.compile_mixed_profile() and len(result.operations) == 5
    with pytest.raises(ValueError, match="^fhrp_peer_registration$"):
        preparation.validate_peer_state_version_context(envelope, LIMITS)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files
    if mode == "none":
        assert not envelope.captures and envelope.targets
    if mode == "only_vrrp":
        assert all(target.operation == "iosxe.show_vrrp" for target in envelope.targets) and len(envelope.base.nodes) == 2


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
@pytest.mark.parametrize("value", [False, [], 0, -1])
def test_every_budget_leaf_refuses_before_registry_work(case, monkeypatch, field, value):
    envelope, _ = case
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, value)
    monkeypatch.setattr(preparation, "strict_json", forbidden)
    with pytest.raises(ValueError, match="^hsrp_state_version_budget$"):
        preparation.validate_mixed_context(envelope, budgets)


@pytest.mark.parametrize("field", ["artifacts", "artifact_bytes", "bundle_bytes"])
def test_all_raw_material_including_both_manifests_is_budgeted_before_scope_framing(case, monkeypatch, field):
    envelope, _ = case
    raws = (envelope.base.raw, envelope.raw) + tuple(capture.raw for capture in envelope.base.captures) + tuple(member.raw for member in envelope.captures)
    limits = {"artifacts": len(raws), "artifact_bytes": max(map(len, raws)), "bundle_bytes": sum(map(len, raws))}
    assert preparation.validate_mixed_context(envelope, replace(LIMITS, **limits)) == mixed.compile_mixed_profile()
    monkeypatch.setattr(preparation, "_scope", forbidden)
    with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
        preparation.validate_mixed_context(envelope, replace(LIMITS, **{field: limits[field] - 1}))
    assert caught.value.member == "fhrp_mixed_context_raw_budget"


@pytest.mark.parametrize("field", ["schema", "semantic", "context", "base_hash", "side_raw", "base_raw", "registration"])
def test_raw_registry_and_profile_identity_cannot_be_substituted(case, field):
    envelope, _ = case
    side, base = json.loads(envelope.raw), json.loads(envelope.base.raw)
    if field == "registration":
        envelope = replace(envelope, registration_sha256=peer_profile.compile_peer_state_version_profile().registration_sha256)
    elif field == "side_raw":
        envelope = replace(envelope, raw=envelope.raw + b"\n")
    elif field == "base_raw":
        envelope = replace(envelope, base=replace(envelope.base, raw=envelope.base.raw + b"\n"))
    else:
        side["schema" if field == "schema" else "semantic_group" if field == "semantic" else "context" if field == "context" else "base_sha256"] = "other"
        envelope = rebased(envelope, base, side) if field != "base_hash" else replace(envelope, raw=canonical(side))
    code = "fhrp_mixed_context_registration" if field == "registration" else "hsrp_folder_declaration" if field == "side_raw" else "fhrp_mixed_context_registry"
    with pytest.raises(ValueError, match="^" + code + "$"):
        preparation.validate_mixed_context(envelope, LIMITS)


@pytest.mark.parametrize("mode", ["normal", "only_vrrp", "cold_vrrp"])
@pytest.mark.parametrize("field", ["group", "id", "discovery", "ports", "declaration", "registry_ref"])
def test_every_original_base_node_is_bound_to_raw_registry_even_without_hsrp_or_capture(tmp_path, mode, field):
    envelope, _ = admitted(tmp_path, mode)
    node = next(node for node in envelope.base.nodes if node.id == "b")
    obj, name, value = {"group": (node, "group", "other"), "id": (node, "id", "other"),
        "discovery": (node, "discovery_id", "other"), "ports": (node, "ports", ("Gi1/0/2",)),
        "declaration": (node.declaration, "raw", "other"),
        "registry_ref": (node.declaration.evidence[0], "citation", "/nodes/0")}[field]
    object.__setattr__(obj, name, value)
    code = "hsrp_folder_declaration" if field in ("declaration", "registry_ref") else "fhrp_mixed_context_node"
    with pytest.raises(ValueError, match="^" + code + "$"):
        preparation.validate_mixed_context(envelope, LIMITS)


@pytest.mark.parametrize("field", ["id", "source", "operation", "rendered", "raw", "drop", "duplicate", "row_hash", "row_operation"])
def test_original_discovery_capture_id_formula_full_census_and_raw_binding_are_not_ignored(case, field):
    envelope, _ = case
    capture = envelope.base.captures[0]
    if field in ("row_hash", "row_operation"):
        base = json.loads(envelope.base.raw)
        base["captures"][0]["sha256" if field == "row_hash" else "operation"] = "0" * 64 if field == "row_hash" else "iosxe.show_interfaces_trunk"
        envelope = rebased(envelope, base=base)
    elif field in ("drop", "duplicate"):
        envelope = replace(envelope, base=replace(envelope.base, captures=() if field == "drop" else envelope.base.captures + (capture,)))
    else:
        obj = replace(capture)
        object.__setattr__(obj, field, {"id": "cap:other", "source": "node:other:a", "operation": "iosxe.show_lldp_neighbors_detail",
            "rendered": "show lldp neighbors detail", "raw": capture.raw + b"\n"}[field])
        if field == "raw":
            object.__setattr__(obj, "lines", text_lines(obj.raw, obj.codec))
        envelope = replace(envelope, base=replace(envelope.base, captures=(obj,)))
    with pytest.raises(ValueError, match="^fhrp_mixed_context_" + ("graph" if field == "drop" else "capture") + "$"):
        preparation.validate_mixed_context(envelope, LIMITS)


@pytest.mark.parametrize("path", ["discovery.txt", "Discovery.txt", "p2.json", "p3.json", "p4.json", "manifest.json", "../unsafe", "folder//unsafe", "folder\\unsafe", "discovery.txt/child", "Discovery.txt/child"])
def test_discovery_and_side_paths_are_disjoint_normalized_and_never_reserved_or_prefix_colliding(case, path):
    envelope, _ = case
    side = json.loads(envelope.raw)
    side["captures"][0]["path"] = path
    changed = rebased(envelope, side=side)
    code = "unsafe_member_name" if ".." in path or "//" in path or chr(92) in path else "name_collision" if path in ("Discovery.txt", "Discovery.txt/child") else (
        "duplicate_member" if path in ("discovery.txt", "p2.json", "p4.json") else "fhrp_mixed_context_names")
    with pytest.raises(ValueError, match="^" + code + "$"):
        preparation.validate_mixed_context(changed, LIMITS)


@pytest.mark.parametrize("field", ["owner", "node", "params", "target_drop", "member_target", "member_id", "member_hash", "member_raw", "member_drop", "member_duplicate"])
def test_all_original_side_target_and_member_correspondence_is_closed(case, field):
    envelope, _ = case
    target, member = envelope.targets[0], envelope.captures[0]
    if field.startswith("member_"):
        if field in ("member_drop", "member_duplicate"):
            envelope = replace(envelope, captures=envelope.captures[:-1] if field == "member_drop" else envelope.captures + (member,))
        else:
            changes = {"member_target": {"target": replace(member.target)}, "member_id": {"id": "cap:other"},
                "member_hash": {"sha256": "0" * 64}, "member_raw": {"raw": member.raw + b"changed"}}[field]
            envelope = replace(envelope, captures=(replace(member, **changes), *envelope.captures[1:]))
    elif field == "target_drop":
        removed = envelope.targets[-1].id
        side = json.loads(envelope.raw)
        side["captures"] = [row for row in side["captures"] if row["target"] != removed]
        envelope = rebased(envelope, side=side)
        envelope = replace(envelope, targets=envelope.targets[:-1], captures=tuple(member for member in envelope.captures if member.target.id != removed))
    else:
        changed = replace(target, **{"owner": {"owner": "l3.fhrp/other"}, "node": {"node": replace(target.node)},
            "params": {"params": b"{}"}}[field])
        envelope = replace(envelope, targets=tuple(changed if old is target else old for old in envelope.targets))
        envelope = replace(envelope, captures=tuple(replace(old, target=changed) if old.target is target else old for old in envelope.captures))
    code = "hsrp_state_version_graph" if field in ("node", "member_target") else "fhrp_mixed_context_target" if field in ("owner", "target_drop") else (
        "fhrp_mixed_context_capture" if field in ("member_drop", "member_duplicate") else "hsrp_folder_target" if field == "params" else "hsrp_folder_member")
    with pytest.raises(ValueError, match="^" + code + "$"):
        preparation.validate_mixed_context(envelope, LIMITS)


@pytest.mark.parametrize("field", ["artifacts", "artifact_bytes", "bundle_bytes"])
def test_overbudget_real_unframed_brief_is_refused_before_its_existing_frame_guard(case, field):
    envelope, _ = case
    bad = b"show running-config\n"
    side = json.loads(envelope.raw)
    row = next(row for row in side["captures"] if row["target"] == "brief-a")
    row["sha256"] = sha256(bad).hexdigest()
    changed = rebased(envelope, side=side)
    changed = replace(changed, captures=tuple(replace(member, raw=bad) if member.target.id == "brief-a" else member for member in changed.captures))
    with pytest.raises(ValueError, match="^hsrp_folder_frame$"):
        preparation.validate_mixed_context(changed, LIMITS)
    with pytest.raises(BudgetExceeded, match="^budget_exceeded$") as caught:
        preparation.validate_mixed_context(changed, replace(LIMITS, **{field: 1}))
    assert caught.value.member == "fhrp_mixed_context_raw_budget"


@pytest.mark.parametrize("field", ["nodes", "targets", "base_captures", "members", "node_id", "target_id", "member_id", "node_declaration", "registry_digest", "registration_alias"])
def test_finite_current_graph_refuses_before_hashing_or_raw_decoder(case, monkeypatch, field):
    envelope, _ = case
    target, member, node = envelope.targets[0], envelope.captures[0], envelope.base.nodes[0]
    obj, name = {"nodes": (envelope.base, "nodes"), "targets": (envelope, "targets"),
        "base_captures": (envelope.base, "captures"), "members": (envelope, "captures"),
        "node_id": (node, "id"), "target_id": (target, "id"), "member_id": (member, "id"),
        "node_declaration": (node.declaration, "value"), "registry_digest": (node.declaration.evidence[0], "table_digest"),
        "registration_alias": (envelope, "registration_sha256")}[field]
    object.__setattr__(obj, name, [] if field != "registration_alias" else StrEnum("Alias", {"VALUE": envelope.registration_sha256}).VALUE)
    monkeypatch.setattr(preparation, "strict_json", forbidden)
    code = "fhrp_mixed_context_graph" if field in ("nodes", "targets", "base_captures", "members") else (
        "hsrp_version_inputs_state" if field == "node_declaration" else "invalid_digest" if field == "registry_digest" else "hsrp_state_version_graph")
    with pytest.raises(ValueError, match="^" + code + "$"):
        preparation.validate_mixed_context(envelope, LIMITS)


@pytest.mark.parametrize("field", ["discovery_id", "duplicate_ports", "bad_port", "node_id"])
def test_coherent_bad_raw_and_typed_cold_node_records_still_fail_the_node_anchor(tmp_path, field):
    envelope, _ = admitted(tmp_path, "only_vrrp")
    base = json.loads(envelope.base.raw)
    row = next(row for row in base["nodes"] if row["id"] == "b")
    name, value = ("discovery_id", "bad space") if field == "discovery_id" else ("id", "bad!") if field == "node_id" else (
        "ports", ["Gi1/0/1", "Gi1/0/1"] if field == "duplicate_ports" else ["bad port"])
    row[name] = value
    changed = rebased(envelope, base=base)
    node = next(node for node in changed.base.nodes if node.id == "b")
    object.__setattr__(node, name, tuple(value) if name == "ports" else value)
    with pytest.raises(ValueError, match="^fhrp_mixed_context_node$"):
        preparation.validate_mixed_context(changed, LIMITS)
