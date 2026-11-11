"""Authenticated declaration snapshots only; trusted post-profile API, no mode or fact claim."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_global_root_guard import LIMITS, P, scenario, write

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l3.fhrp import build as h
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack


def admitted(root, *, captures=True, vlans=(1, 2), declarations=None):
    files, side = scenario(raw=b"\xff\x00opaque\rbytes", tree_capture=captures)
    for target in side["targets"][:2]:
        target["params"]["vlans"] = list(vlans)
    side["targets"][2]["params"] = {"groups": ["1"], "ports": ["Gi1/0/1"]}
    side["targets"].append({"id": "alt", "node": "a", "operation": b.stp.OP, "params": {"port": "Gi1/0/2", "vlans": list(vlans)}})
    if not captures:
        side["captures"] = []
        files.pop("channel.txt")
    write(root, files, side)
    files["p4.json"] = canonical(side)
    envelope = p4.admit_folder(root, LIMITS, declarations=declarations or (b.DECLARATION, ec.DECLARATION, h.DECLARATION))
    return envelope, files


def declared_oracle(envelope, target_id):
    base, side = json.loads(envelope.base.raw), json.loads(envelope.raw)
    index, raw = next((i, raw) for i, raw in enumerate(side["targets"]) if raw["id"] == target_id)
    node_index = next(i for i, node in enumerate(base["nodes"]) if node["id"] == raw["node"])
    node = next(node for node in envelope.base.nodes if node.id == raw["node"])
    domain = b.Target(context=envelope.context, node=node, port=raw["params"]["port"], vlans=tuple(raw["params"]["vlans"]))
    refs = (
        k.RegistryRef(table="synthetic_p2.nodes", row_id=node.id, table_digest=sha256(envelope.base.raw).hexdigest(), citation=f"/nodes/{node_index}"),
        k.RegistryRef(table="synthetic_p4.context", row_id=envelope.context, table_digest=sha256(envelope.raw).hexdigest(), citation="/context"),
        k.RegistryRef(table="synthetic_p4.targets", row_id=raw["id"], table_digest=sha256(envelope.raw).hexdigest(), citation=f"/targets/{index}"),
    )
    return domain, refs


def test_original_targets_and_three_raw_registry_refs_survive_order_without_runtime_work(tmp_path, monkeypatch):
    envelope, _ = admitted(tmp_path)
    with monkeypatch.context() as patch:
        for module, names in ((b, ("Capture", "_integrity", "execute_parsers", "bind_writer")),
                              (b.stp, ("parse_capture",)), (b.p4_pipeline, ("execute_p4_folder",))):
            for name in names:
                patch.setattr(module, name, lambda *args, **kwargs: pytest.fail("snapshot crossed declared-only boundary"))
        snapshots = b.declared_root_guard_targets(envelope, LIMITS)
        permuted = replace(envelope, targets=tuple(reversed(envelope.targets)))
        assert b.declared_root_guard_targets(permuted, LIMITS) == snapshots
    assert type(snapshots) is tuple and len(snapshots) == 3 and {item.source.id for item in snapshots} == {"t0", "t1", "alt"}
    for item in snapshots:
        domain, refs = declared_oracle(envelope, item.source.id)
        assert type(item) is b.DeclaredRootGuard and item.source is next(target for target in envelope.targets if target.id == item.source.id)
        assert item.target == domain and item.target.node is item.source.node
        assert item.evidence == refs and len(refs) == 3 and all(type(ref) is k.RegistryRef for ref in refs)
    with pytest.raises(ValueError, match="^stp_folder_text$"):
        b.build_root_guard_global(tmp_path, LIMITS, peers=(SummaryPack(LIMITS), StandbyBriefPack(LIMITS)))


@pytest.mark.parametrize("plant", ["registry", "node", "target", "member_raw", "member_hash", "member_target", "member_id"])
def test_declared_only_scope_still_closes_original_registry_and_member_custody(tmp_path, plant):
    envelope, _ = admitted(tmp_path)
    if plant == "registry":
        envelope = replace(envelope, raw=envelope.raw + b" ")
    elif plant == "node":
        target = envelope.targets[0]
        changed = replace(target, node=replace(target.node, discovery_id="different"))
        envelope = replace(envelope, targets=(changed,) + envelope.targets[1:])
    elif plant == "target":
        target = envelope.targets[0]
        envelope = replace(envelope, targets=(replace(target, params=canonical({"port": P, "vlans": [3]})),) + envelope.targets[1:])
    else:
        member = next(member for member in envelope.captures if member.target.id == "t0")
        changed = replace(member, **({"raw": member.raw + b"x"} if plant == "member_raw" else {"sha256": "0" * 64} if plant == "member_hash" else
            {"target": next(target for target in envelope.targets if target.id == "t1")} if plant == "member_target" else {"id": k.CaptureId("cap:" + "0" * 64)}))
        envelope = replace(envelope, captures=tuple(changed if value is member else value for value in envelope.captures))
    with pytest.raises(ValueError):
        b.declared_root_guard_targets(envelope, LIMITS)


def test_missing_captures_preserve_target_census_but_not_raw_declaration_digests(tmp_path):
    envelope, _ = admitted(tmp_path)
    before = b.declared_root_guard_targets(envelope, LIMITS)
    empty = tmp_path / "empty"
    empty.mkdir()
    uncaptured, _ = admitted(empty, captures=False)
    after = b.declared_root_guard_targets(uncaptured, LIMITS)
    def census(values):
        return [(item.source.id, item.target.context, item.target.node.key, item.target.port, item.target.vlans) for item in values]
    assert census(before) == census(after) and len(after) == 3
    assert before[0].evidence != after[0].evidence and not uncaptured.captures
