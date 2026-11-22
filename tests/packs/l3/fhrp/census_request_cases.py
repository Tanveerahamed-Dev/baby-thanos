"""Test fixtures and independent coordinate checks for named HSRP census preparation."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_gateway_source import LIMITS, folder

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission as p4
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as state
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census
from atlas_brain.packs.l3.fhrp.global_parse import StandbyBriefPack

REGISTRATION = "23ba8b6955b0a28309b22da3d7239aa60da96820edb85bdbaad6799fd242a975"


def census_row(census_id, node, source, interface):
    return {
        "id": census_id, "node": node, "operation": "synthetic.hsrp_ipv4_interface_census",
        "params": {"source_target": source, "interface": interface},
    }


def supply_member(side, files, target, path, raw):
    files[path] = raw
    side["captures"].append({"target": target, "path": path, "sha256": sha256(raw).hexdigest()})


def write_folder(root, side, files):
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (root / name).write_bytes(raw)


def input_folder(root, second=None, *, missing=None):
    files = folder(root, missing)
    side = json.loads(files["p4.json"])
    side["targets"][:0] = [census_row("census-b", "b", "hsrp-cold", "BD10"),
                           census_row("census-a", "a", "hsrp", "Vl10")]
    supply_member(side, files, "census-a", "census-a.txt", b"\xff\r\nrow")
    if second is not None:
        supply_member(side, files, "census-b", "census-b.txt", second)
    write_folder(root, side, files)
    return files, side


def forbid_observations(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("census preparation dispatched a parser or writer")

    for parser in (census, state.hsrp, stp.stp, ec.parse_summary):
        monkeypatch.setattr(parser, "parse_capture", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)


def observe_admission(monkeypatch):
    admitted = []
    admit = p4.admit_folder

    def admitting(*args, **kwargs):
        envelope = admit(*args, **kwargs)
        admitted.append(envelope)
        return envelope

    monkeypatch.setattr(p4, "admit_folder", admitting)
    return admitted


def assert_census_plan(plan, root, files, side, second):
    assert plan.budgets is LIMITS and plan.envelope.registration_sha256 == REGISTRATION
    assert tuple(item.target.id for item in plan.scopes) == ("census-a", "census-b")
    registry_digest = sha256(files["p4.json"]).hexdigest()
    base_digest = sha256(files["p2.json"]).hexdigest()

    for scope, source, node, interface, raw in zip(
        plan.scopes, ("hsrp", "hsrp-cold"), ("a", "b"), ("Vl10", "BD10"),
        (files["census-a.txt"], second), strict=True,
    ):
        target = next(item for item in plan.envelope.targets if item.id == scope.target.id)
        brief = next(item for item in plan.envelope.targets if item.id == source)
        assert scope.target is target and scope.source is brief and target.node is brief.node
        assert scope.interface == interface and scope.target.declaration.basis is k.Basis.DECLARED
        row_number = next(i for i, row in enumerate(side["targets"]) if row["id"] == scope.target.id)
        assert scope.target.declaration.evidence == (k.RegistryRef(
            table="synthetic_p4.targets", row_id=scope.target.id, table_digest=registry_digest,
            citation=f"/targets/{row_number}",
        ),)
        scope_token = ("atlas-brain.hsrp-census-scope/1", "atlas-brain.synthetic-p4/1",
                       REGISTRATION, registry_digest, base_digest, side["context"],
                       source, scope.target.id, "node:demo:" + node, interface, "ipv4", "hsrp", "all")
        assert scope.key == sha256(canonical(scope_token)).hexdigest()
        if raw is None:
            assert scope.member is scope.request is None
            continue
        member = next(item for item in plan.envelope.captures if item.target is target)
        capture = scope.request.capture
        assert scope.member is member and capture.raw is member.raw and capture.raw == raw
        capture_token = ("atlas-brain.synthetic-p4/1", registry_digest, base_digest, side["context"],
                         scope.target.id, member.path, sha256(raw).hexdigest(), REGISTRATION)
        assert capture.id == member.id == "cap:" + sha256(canonical(capture_token)).hexdigest()
        assert capture.bytes_sha256 == member.sha256
        assert capture.source == "node:demo:" + node and scope.request.context == side["context"]
        assert capture.scope.context is None
        anchor = next(item for item in plan.request_values if item[0] == capture.id)
        assert anchor[1] is scope.request and anchor[2] is capture
        assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
        assert capture.integrity is (k.IntegrityState.UNKNOWN_FORMAT if raw else k.IntegrityState.EMPTY)
    assert len(plan.request_values) == (1 if second is None else 2)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == files


def invalid_scope_folder(root, fault):
    files, side = input_folder(root)
    target = side["targets"][1]
    params = target["params"]
    if fault == "foreign_node":
        target["node"] = "b"
    elif fault == "foreign_operation":
        params["source_target"] = "census-b"
    elif fault == "unknown_source":
        params["source_target"] = "missing-target"
    elif fault == "wrong_case":
        params["interface"] = "vl10"
    elif fault == "physical_port":
        node = next(row for row in json.loads(files["p2.json"])["nodes"] if row["id"] == "a")
        source = next(row for row in side["targets"] if row["id"] == "hsrp")
        params["interface"] = next(port for port in node["ports"] if all(
            port != pair[0] for pair in source["params"]["groups"]))
    elif fault == "extra_field":
        params["protocol"] = "hsrp"
    elif fault == "missing_field":
        del params["source_target"]
    elif fault == "non_string":
        params["source_target"] = 17
    elif fault == "duplicate_scope":
        side["targets"].append(census_row("census-alias", "a", "hsrp", "Vl10"))
    else:
        supply_member(side, files, "census-a", "clone.txt", b"second reply")
    write_folder(root, side, files)


class OpenCarrier:
    def __getattribute__(self, name):
        pytest.fail(f"read open {name}")


class OpenPack(StandbyBriefPack):
    __slots__ = ()
    __getattribute__ = OpenCarrier.__getattribute__


class OpenText(str):
    def __eq__(self, _other):
        pytest.fail("compared open census text")

    def __hash__(self):
        raise AssertionError("hashed open census text")


def plant_brief_preparation(monkeypatch, plant):
    prepare, seen, restore = StandbyBriefPack.prepare, [], []

    def preparing(self, envelope):
        batch = prepare(self, envelope)
        seen.append(batch)
        handler, = batch.handlers
        if plant == "pack":
            object.__setattr__(self, "__class__", OpenPack)
        elif plant == "batch":
            return OpenCarrier()
        elif plant == "handlers":
            return replace(batch, handlers=())
        elif plant == "handler":
            return replace(batch, handlers=(OpenCarrier(),))
        elif plant == "binding":
            return replace(batch, handlers=(replace(handler, binding=replace(handler.binding)),))
        elif plant in ("operation", "step", "changed_operation", "changed_step"):
            coordinate = plant.removeprefix("changed_")
            old = getattr(handler.binding, coordinate)
            restore.append((handler.binding, coordinate, old))
            changed = "unexpected" if plant.startswith("changed_") else OpenText(old)
            object.__setattr__(handler.binding, coordinate, changed)
        elif plant == "owner":
            object.__setattr__(handler, "parser", OpenCarrier())
        elif plant == "targets":
            return replace(batch, targets=tuple(reversed(batch.targets)))
        elif plant == "target_copy":
            return replace(batch, targets=(replace(batch.targets[0]), *batch.targets[1:]))
        elif plant == "requests":
            cloned = tuple(request for request in batch.requests)
            assert cloned == batch.requests and cloned is not batch.requests
            return replace(batch, requests=cloned)
        return batch

    monkeypatch.setattr(StandbyBriefPack, "prepare", preparing)
    return seen, restore


INVALID_SCOPES = [
    ("foreign_node", "hsrp_census_source_target"),
    ("foreign_operation", "hsrp_census_source_target"),
    ("unknown_source", "hsrp_census_source_target"),
    ("wrong_case", "hsrp_census_interface"),
    ("physical_port", "hsrp_census_interface"),
    ("extra_field", "invalid_record_fields"),
    ("missing_field", "invalid_record_fields"),
    ("non_string", "invalid_string"),
    ("duplicate_scope", "p4_duplicate_target_definition"),
    ("duplicate_member", "hsrp_census_duplicate_member"),
]


BRIEF_PLANTS = [
    ("pack", "brief_prepared"), ("batch", "brief_prepared"), ("handler", "brief_handler"),
    ("handlers", "brief_handler"), ("binding", "brief_binding"), ("operation", "brief_binding"),
    ("step", "brief_binding"), ("changed_operation", "brief_binding"), ("changed_step", "brief_binding"),
    ("owner", "brief_owner"), ("targets", "brief_targets"), ("target_copy", "brief_targets"),
    ("requests", "brief_requests"),
]


MATERIALIZATION_PLANTS = [
    ("node", "hsrp_presence_context"), ("raw", "hsrp_presence_custody"),
]


def plant_later_member(monkeypatch, requests, admitted, plant):
    real_lines, seen = requests.text_lines, []

    def planted(raw, codec):
        seen.append(raw)
        if len(seen) == 1:
            member = next(row for row in admitted[0].captures if row.path == "census-b.txt")
            if plant == "node":
                object.__setattr__(member.target, "node", OpenCarrier())
            else:
                object.__setattr__(member, "raw", b"replacement")
        return real_lines(raw, codec)

    monkeypatch.setattr(requests, "text_lines", planted)
    return seen


def observe_brief_preparation(monkeypatch, *, forbid_owner=False):
    batches = []
    prepare = StandbyBriefPack.prepare

    def preparing(self, envelope):
        batch = prepare(self, envelope)
        batches.append(batch)
        return batch

    def forbid_dynamic_owner(_self):
        pytest.fail("census preparation followed a dynamic BRIEF owner")

    monkeypatch.setattr(StandbyBriefPack, "prepare", preparing)
    if forbid_owner:
        monkeypatch.setattr(StandbyBriefPack, "owner", property(forbid_dynamic_owner))
    return batches


def forbid_census_lines(monkeypatch, requests):
    def forbidden(*_args, **_kwargs):
        pytest.fail("census capture lines were allocated before preflight refusal")

    monkeypatch.setattr(requests, "text_lines", forbidden)


def plant_profile_declaration(monkeypatch, profile, admitted, plant):
    declaration = profile.declaration
    hits = []

    def declaring():
        value = declaration()
        if admitted:
            hits.append(value)
            if plant == "params":
                target = next(row for row in admitted[0].targets if row.id == "census-a")
                object.__setattr__(target, "params", canonical({"source_target": "hsrp", "interface": "Vl20"}))
            else:
                monkeypatch.setattr(census, "OP", OpenText(census.OP))
        return value

    monkeypatch.setattr(profile, "declaration", declaring)
    return hits


def plant_snapshot_batch_class(monkeypatch, custody, batches):
    snapshot = custody.capture_context
    hits = []

    def snapshotting(envelope, budgets):
        values = snapshot(envelope, budgets)
        if not hits:
            batch = batches[0]

            class OpenBatch(type(batch)):
                __slots__ = ()
                __getattribute__ = OpenCarrier.__getattribute__

            object.__setattr__(batch, "__class__", OpenBatch)
            hits.append(batch)
        return values

    monkeypatch.setattr(custody, "capture_context", snapshotting)
    return hits


def plant_earlier_census_request(monkeypatch, requests, plant):
    make = requests._request
    built = []

    def constructing(*args):
        request = make(*args)
        if len(built) == 1:
            first = built[0].capture
            if plant == "raw":
                raw = b"replacement\r\n"
                object.__setattr__(first, "raw", raw)
                object.__setattr__(first, "lines", requests.text_lines(raw, first.codec))
            elif plant == "raw_identity":
                copied = bytes(bytearray(first.raw))
                assert copied == first.raw and copied is not first.raw
                object.__setattr__(first, "raw", copied)
            elif plant == "open_context":
                object.__setattr__(built[0], "context", OpenText(built[0].context))
            elif plant == "view":
                object.__setattr__(first, "view", k.ViewConsistency.SINGLE_RESPONSE)
            elif plant == "codec":
                object.__setattr__(first, "codec", "ascii")
                object.__setattr__(first, "lines", requests.text_lines(first.raw, "ascii"))
            else:
                object.__setattr__(first, "metadata", first.resolved_metadata)
        built.append(request)
        return request

    monkeypatch.setattr(requests, "_request", constructing)
    return built


FOLDER_CASES = (
    pytest.param(None, None, id="missing"),
    pytest.param(b"", None, id="empty"),
    pytest.param(b"frame\n", "hsrp-cold", id="missing_brief"),
    pytest.param(None, "both", id="missing_both_brief"),
)


def plant_original_envelope_after_brief(monkeypatch):
    prepare = StandbyBriefPack.prepare
    seen = []

    def preparing(self, envelope):
        batch = prepare(self, envelope)
        target = next(row for row in envelope.targets if row.id == "census-a")
        object.__setattr__(target, "params", canonical({"source_target": "hsrp", "interface": "Vl20"}))
        seen.append(target)
        return batch

    monkeypatch.setattr(StandbyBriefPack, "prepare", preparing)
    return seen


def plant_final_request_snapshot(monkeypatch, requests):
    snapshot = requests.context.request_values
    seen = []

    def snapshotting(current):
        values = snapshot(current)
        for request in current:
            capture = request.capture
            if capture.operation == census.OP:
                lines = (replace(capture.lines[0], text="different"), *capture.lines[1:])
                object.__setattr__(capture, "lines", lines)
                seen.append(capture)
                break
        return values

    monkeypatch.setattr(requests.context, "request_values", snapshotting)
    return seen
