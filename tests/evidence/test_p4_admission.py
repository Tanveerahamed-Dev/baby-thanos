"""Generated P4 operating folders; envelopes are declarations, never observed health."""
import json
from dataclasses import fields
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.evidence.admission import AdmissionRefused, BudgetExceeded, Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec

OP = "collect.future_fixture"
LIMITS = Budgets(1000000, 1000000, 1000)


def declarations(label="parse", name="future"):
    pack, owner = k.PackId("test." + name), StepId("test." + name + "/" + label)
    step = StepSpec(id=owner, pack=pack, kind="parse_build", scope="device", reads=(), produces=(), evaluator=pack + ".uninstalled")
    return (registration.PackDeclaration(pack=pack, entity_kinds=(), facts=(), relations=(), steps=(step,), operations=(registration.OperationBinding(operation=OP if name == "future" else "collect." + name, step=owner),)),)


def scenario(targets=2, captures=2):
    discovery = b"Device ID: fixture-b\n"
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
            "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": ["Gi1"]} for n in ("a", "b")],
            "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                          "sha256": sha256(discovery).hexdigest()}]}
    files = {"p2.json": canonical(base), "discovery.txt": discovery} | {"extra" + str(i) + ".txt": b"opaque fixture bytes\x00\n" for i in range(captures)}
    side = {"schema": p4.SCHEMA, "semantic_group": "declared_synthetic", "context": "round",
            "base_sha256": sha256(files["p2.json"]).hexdigest(),
            "targets": [{"id": "t" + str(i), "node": "a" if i % 2 == 0 else "b", "operation": OP,
                         "params": {"index": i, "flag": False}} for i in range(targets)],
            "captures": [{"target": "t0", "path": path, "sha256": sha256(raw).hexdigest()}
                         for path, raw in files.items() if path.startswith("extra")]}
    return files, side


def write(root, files, side):
    members = files | {"p4.json": json.dumps(side, ensure_ascii=True, separators=(",", ":")).encode()}
    for name, raw in members.items():
        (root / name).write_bytes(raw)
    return members


def admit(root, files, side, **options):
    write(root, files, side)
    return p4.admit_folder(root, LIMITS, declarations=options.get("declarations", declarations()))


def descriptor(envelope):
    return tuple((t.id, t.node.key, t.operation, t.owner, t.params) for t in envelope.targets)


def test_operating_folder_preserves_raw_provenance_and_supports_a_future_registered_operation(tmp_path):
    files, side = scenario()
    params = {str(i): i for i in range(31)} | {"kind": True}
    side["targets"][0]["params"] = params
    side["targets"][1].update(node="a", params=params | {"kind": 1})
    result = admit(tmp_path, files, side)
    assert result.raw == (tmp_path / "p4.json").read_bytes() and result.base.raw == files["p2.json"]
    assert result.context == "round" and result.registration_sha256 == registration.compile_packs(declarations()).registration_sha256
    context_ref, = result.declaration.evidence
    assert (result.declaration.value, result.declaration.raw, result.declaration.basis) == ("round", "round", k.Basis.DECLARED)
    assert (context_ref.table, context_ref.row_id, context_ref.citation, context_ref.table_digest) == ("synthetic_p4.context", "round", "/context", sha256(result.raw).hexdigest())
    assert len(result.targets) == len(result.captures) == 2
    assert result.captures[0].target is result.captures[1].target is result.targets[0]
    for target in result.targets:
        index = next(i for i, row in enumerate(side["targets"]) if row["id"] == target.id)
        assert target.node is next(node for node in result.base.nodes if node.id == side["targets"][index]["node"])
        assert target.owner == declarations()[0].steps[0].id and target.operation == OP
        assert target.params == canonical(side["targets"][index]["params"])
        declared = target.declaration
        assert declared.basis is k.Basis.DECLARED and declared.raw == declared.value == target.id
        ref, = declared.evidence
        assert (ref.table, ref.row_id, ref.table_digest, ref.citation) == ("synthetic_p4.targets", target.id, sha256(result.raw).hexdigest(), "/targets/" + str(index))
    for capture in result.captures:
        assert capture.raw == files[capture.path] and capture.sha256 == sha256(capture.raw).hexdigest()
        assert {field.name for field in fields(capture)} == {"id", "target", "path", "raw", "sha256"}
    assert len({capture.id for capture in result.captures}) == 2


@pytest.mark.parametrize("path,value,code", [
    (("schema",), "other", "p4_schema"), (("semantic_group",), "observed", "p4_schema"),
    (("context",), "", "p4_identifier"), (("targets", 1, "id"), "t0", "p4_duplicate_target"),
    (("targets", 1, "node"), "missing", "p4_target_node"), (("targets", 1, "operation"), "collect.unregistered", "p4_target_operation"),
    (("targets", 1, "owner"), "caller.owner", "invalid_record_fields"),
    (("targets", 1), {"id": "t1", "node": "a", "operation": OP, "params": {"flag": False, "index": 0}}, "p4_duplicate_target_definition"),
    (("captures", 1, "target"), "missing", "p4_capture_target"),
    (("captures", 1, "sha256"), "0" * 64, "p4_capture_hash"),
    (("captures", 1, "target"), "t0", "p4_duplicate_capture_id"),
    (("captures", 1, "path"), "p2.json", "p4_reserved_member"), (("captures", 1, "path"), "P4.JSON", "p4_missing_member"),
    (("captures", 1, "path"), "extra0.txt", "p4_duplicate_member"),
    (("captures", 1, "path"), "DISCOVERY.TXT", "p4_missing_member"),
    (("captures", 1, "rendered"), "show invented", "invalid_record_fields"), (("captures", 1, "integrity"), "complete", "invalid_record_fields"),
    (("captures", 1, "path"), "a/" * 16000 + "missing.txt", "p4_missing_member"),
])
def test_late_closed_metadata_fault_refuses_before_base_interpretation(tmp_path, monkeypatch, path, value, code):
    files, side = scenario()
    target = side
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    if code == "p4_duplicate_capture_id":
        monkeypatch.setattr(p4.k, "CaptureId", lambda value: "cap:forced_collision")
    original_names = p4.member_names
    monkeypatch.setattr(p4, "member_names", lambda names: pytest.fail("unbounded fake reference reached path walker") if any(len(name) > 1000 for name in names) else original_names(names))
    monkeypatch.setattr(p4, "admit_base", lambda *args: pytest.fail("base semantics before whole-envelope preflight"))
    with pytest.raises(AdmissionRefused, match="^" + code + "$"):
        admit(tmp_path, files, side)


@pytest.mark.parametrize("plant,code", [("missing", "p4_missing_member"), ("unlisted", "p4_unlisted_member"),
    ("base_hash", "p4_capture_hash"), ("schema2", "p4_base_schema"), ("trunk", "p4_base_operation"),
    ("config", "p4_base_operation"), ("base_node", "p4_base_node"), ("duplicate", "p4_base_duplicate"),
    ("reformatted", "p4_base_hash")])
def test_entire_partition_and_pinned_discovery_base_precede_callback(tmp_path, monkeypatch, plant, code):
    files, side = scenario()
    base = json.loads(files["p2.json"])
    if plant == "missing":
        files.pop("extra1.txt")
    elif plant == "unlisted":
        files["unlisted.txt"] = b"unowned"
    elif plant == "reformatted":
        files["p2.json"] += b"\n"
    else:
        row = base["captures"][0]
        if plant == "schema2":
            base["schema"] = "atlas-brain.synthetic-p2/2"
        elif plant == "duplicate":
            base["captures"].append(dict(row))
        else:
            row.update({"base_hash": {"sha256": "0" * 64}, "base_node": {"node": "missing"},
                        "trunk": {"operation": "iosxe.show_interfaces_trunk"},
                        "config": {"operation": "iosxe.show_running_config"}}[plant])
        files["p2.json"] = canonical(base)
        side["base_sha256"] = sha256(files["p2.json"]).hexdigest()
    monkeypatch.setattr(p4, "admit_base", lambda *args: pytest.fail("base semantics before whole-envelope preflight"))
    with pytest.raises(AdmissionRefused, match="^" + code + "$"):
        admit(tmp_path, files, side)


@pytest.mark.parametrize("params", [None, [], 1, {"x": 1.0}, {"x": 9007199254740992},
    {"x": "\ud800"}, {str(i): i for i in range(33)}])
def test_opaque_params_are_bounded_integer_json_without_coercion(tmp_path, monkeypatch, params):
    files, side = scenario()
    side["targets"][-1]["params"] = params
    monkeypatch.setattr(p4, "admit_base", lambda *args: pytest.fail("base semantics before whole-envelope preflight"))
    with pytest.raises(AdmissionRefused, match="^p4_params$"):
        admit(tmp_path, files, side)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts"])
def test_actual_whole_folder_budgets_precede_any_base_semantics(tmp_path, monkeypatch, field):
    files, side = scenario()
    members = write(tmp_path, files, side)
    sizes = {"bundle_bytes": sum(map(len, members.values())), "artifact_bytes": max(map(len, members.values())), "artifacts": len(members)}
    limits = Budgets(**({"bundle_bytes": 1000000, "artifact_bytes": 1000000, "artifacts": 1000} | {field: sizes[field] - 1}))
    monkeypatch.setattr(p4, "admit_base", lambda *args: pytest.fail("base semantics before whole-envelope preflight"))
    with pytest.raises(BudgetExceeded):
        p4.admit_folder(tmp_path, limits, declarations=declarations())


def test_actual_read_growth_is_rechecked_before_hashes_or_base_semantics(tmp_path, monkeypatch):
    files, side = scenario()
    members = write(tmp_path, files, side)
    limit = sum(map(len, members.values()))
    members["extra1.txt"] += b"grew"
    monkeypatch.setattr(p4, "folder_members", lambda *args: members)
    monkeypatch.setattr(p4, "admit_base", lambda *args: pytest.fail("base semantics before whole-envelope preflight"))
    with pytest.raises(BudgetExceeded) as error:
        p4.admit_folder(tmp_path, Budgets(limit, 1000000, 1000), declarations=declarations())
    assert error.value.member == "bundle"


def test_capture_deletion_preserves_declared_targets_and_reordering_preserves_descriptors(tmp_path):
    files, side = scenario()
    original = admit(tmp_path, files, side)
    side["captures"].pop()
    files.pop("extra1.txt")
    (tmp_path / "extra1.txt").unlink()
    removed = admit(tmp_path, files, side)
    assert descriptor(removed) == descriptor(original) and len(removed.captures) == 1
    assert original.captures[0].id != removed.captures[0].id
    side["targets"].reverse()
    reordered = admit(tmp_path, dict(reversed(tuple(files.items()))), side)
    assert descriptor(reordered) == descriptor(original)
    for target in reordered.targets:
        index = int(target.declaration.evidence[0].citation.rsplit("/", 1)[1])
        assert json.loads(reordered.raw)["targets"][index]["id"] == target.id
    side["context"] = "other"
    changed = admit(tmp_path, files, side)
    assert changed.captures[0].id != reordered.captures[0].id and changed.captures[0].raw == reordered.captures[0].raw


@pytest.mark.parametrize("targets,captures,code", [(0, 0, "p4_targets"), (129, 0, "p4_targets"),
    (1, 129, "p4_captures"), (1, 0, "duplicate_pack"), (128, 128, None), (128, 0, None)])
def test_population_and_registration_limits_precede_base_even_without_capture(tmp_path, monkeypatch, targets, captures, code):
    if code is not None:
        monkeypatch.setattr(p4, "admit_base", lambda *args: pytest.fail("base semantics before whole-envelope preflight"))
        error = ValueError if code == "duplicate_pack" else AdmissionRefused
        with pytest.raises(error, match="^" + code + "$"):
            admit(tmp_path, *scenario(targets, captures), declarations=declarations() * (2 if code == "duplicate_pack" else 1))
    else:
        result = admit(tmp_path, *scenario(targets, captures))
        assert (len(result.targets), len(result.captures)) == (targets, captures)


def test_registration_binds_ids_while_pack_order_preserves_identical_wire_bytes(tmp_path):
    files, side = scenario(captures=1)
    definitions = declarations() + declarations(name="other")
    first = admit(tmp_path, files, side, declarations=definitions)
    reordered = admit(tmp_path, files, side, declarations=tuple(reversed(definitions)))
    changed = admit(tmp_path, files, side, declarations=declarations("new") + declarations(name="other"))
    assert first.raw == reordered.raw == changed.raw and first.captures[0].id != changed.captures[0].id
    assert (first.captures, descriptor(first)) == (reordered.captures, descriptor(reordered))
