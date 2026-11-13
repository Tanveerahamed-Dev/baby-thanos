"""Real fixed FHRP admission/correspondence; carriers grant no parser or production authority."""
import json
from dataclasses import replace

import pytest
from test_state_owner import LIMITS
from test_state_version_correspondence import DETAIL, folder, forbid_execution

from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.packs.l3.fhrp import global_parse as gp
from atlas_brain.packs.l3.fhrp import version_inputs as vi
from atlas_brain.packs.l3.fhrp import version_profile as profile

prepare = gp.prepare_state_version_inputs


def test_real_whole_folder_fixed_registration_original_captures_and_declaration_witnesses(tmp_path, monkeypatch):
    files = folder(tmp_path)
    admit, records = gp.p4.admit_folder, []
    compile_profile, compilations = profile.compile_state_version_profile, []
    def compiling():
        value = compile_profile()
        compilations.append(value)
        return value
    def admitting(root, budgets, *, declarations):
        assert len(compilations) == 1 and declarations == (profile.STATE_VERSION_DECLARATION,)
        result = admit(root, budgets, declarations=declarations)
        records.append((root, budgets, declarations, result))
        return result
    monkeypatch.setattr(gp.p4, "admit_folder", admitting)
    monkeypatch.setattr(profile, "compile_state_version_profile", compiling)
    forbid_execution(monkeypatch)
    result = prepare(tmp_path, LIMITS)
    assert records == [(tmp_path, LIMITS, (profile.STATE_VERSION_DECLARATION,), result.envelope)]
    assert result.envelope is records[0][3] and result.budgets is LIMITS
    assert result.version.targets is result.domains and len(result.targets) == len(result.domains) == 2
    assert sum(len(target.groups) for target in result.domains) == 5 and len(result.requests) == len(result.version.requests) == 1
    compiled = compile_packs((profile.STATE_VERSION_DECLARATION,))
    assert len(compilations) == 3 and result.compiled is compilations[0]
    assert result.compiled == compiled and result.envelope.registration_sha256 == compiled.registration_sha256
    assert compiled.registration_sha256 not in (profile.compile_version_profile().registration_sha256, compile_packs((b.DECLARATION,)).registration_sha256)
    catalogue = json.loads(compiled.catalogue_bytes)
    assert {fact["id"] for fact in catalogue["facts"]} == {b.REPORTED_STATE, profile.REPORTED_PROTOCOL_VERSION}
    assert len(catalogue["entity_kinds"]) == 1 and not catalogue["relations"]
    for target, domain in zip(result.targets, result.domains, strict=True):
        assert target.node is domain.node and any(target is item for item in result.envelope.targets)
        expected = domain.node.declaration.evidence + result.envelope.declaration.evidence + target.declaration.evidence
        all_target = next(item for item in result.envelope.targets if item.node is domain.node and item.operation == gp.all_hsrp.OP)
        assert result.declarations[domain.context, domain.node.key] == expected + all_target.declaration.evidence
    for request in result.requests + result.version.requests:
        member = next(item for item in result.envelope.captures if item.id == request.capture.id)
        assert request.capture.raw is member.raw and request.capture.source == member.target.node.key and request.context == result.envelope.context
        assert request.capture.bytes_sha256 == member.sha256 and request.capture.rendered == (b.hsrp.COMMAND if member.target.operation == b.hsrp.OP else gp.all_hsrp.COMMAND)
    assert gp.validate_state_version_correspondence(replace(result.envelope), LIMITS, replace(result.version)) == result.declarations
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "no_captures", "unselected_b"])
def test_original_brief_domains_survive_missing_all_or_observed_inputs(tmp_path, mode):
    folder(tmp_path, mode=mode)
    result = prepare(tmp_path, LIMITS)
    assert len(result.domains) == len(result.version.targets) == (1 if mode == "unselected_b" else 2)
    assert sum(len(target.groups) for target in result.domains) == (4 if mode == "unselected_b" else 5)
    assert {key for key in result.version.indexed} == {(target.context, target.node.key) for target in result.domains}
    assert len(result.version.requests) == (0 if mode.startswith("no_all") or mode == "no_captures" else 1)
    assert all(len(refs) == (3 if mode == "no_all" else 3 if mode == "no_all_target" and key[1].endswith(":a") else 4) for key, refs in result.declarations.items())


@pytest.mark.parametrize("plant", ["orphan", "mismatch", "duplicate_all", "duplicate_brief", "duplicate_capture", "unknown_operation", "foreign_pack"])
def test_exact_all_target_capture_and_original_brief_correspondence_refuses(tmp_path, monkeypatch, plant):
    def changed(side, files):
        selected = next(row for row in side["targets"] if row["id"] == "all-a")
        if plant == "orphan":
            side["targets"] = [row for row in side["targets"] if row["id"] != "brief-a"]
            side["captures"] = [row for row in side["captures"] if row["target"] != "brief-a"]
            files.pop("brief.txt")
        elif plant == "mismatch":
            selected["params"]["groups"][0][0] = "Vlan20"
        elif plant in ("duplicate_all", "duplicate_brief"):
            target = selected if plant == "duplicate_all" else side["targets"][0]
            side["targets"].append(dict(target, id="extra", params={"groups": [["Vl20", "3"]]}))
        elif plant == "duplicate_capture":
            files["second.txt"] = files["all.txt"]
            side["captures"].append({"target": "all-a", "path": "second.txt"})
        else:
            selected["operation"] = "iosxe.show_clock" if plant == "unknown_operation" else "iosxe.show_spanning_tree"
    folder(tmp_path, change=changed)
    forbid_execution(monkeypatch)
    with pytest.raises(ValueError):
        prepare(tmp_path, LIMITS)


@pytest.mark.parametrize("plant", ["unlisted", "hash", "missing", "bundle", "artifact"])
def test_real_folder_member_hash_and_budget_admission_is_used(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    budgets = LIMITS
    if plant == "unlisted":
        (tmp_path / "extra.txt").write_bytes(b"unclaimed")
    elif plant == "hash":
        (tmp_path / "all.txt").write_bytes(DETAIL + b"changed")
    elif plant == "missing":
        (tmp_path / "all.txt").unlink()
    else:
        budgets = replace(LIMITS, **{("bundle_bytes" if plant == "bundle" else "artifact_bytes"): 1})
    forbid_execution(monkeypatch)
    with pytest.raises((ValueError, BudgetExceeded)):
        prepare(tmp_path, budgets)


@pytest.mark.parametrize("field", ["bundle_bytes", "artifact_bytes", "artifacts", "nesting_depth", "numeric_digits", "compression_ratio", "archive_index_bytes"])
@pytest.mark.parametrize("value", [False, []])
def test_budget_scalar_graph_refuses_before_generic_admission_or_detached_work(tmp_path, monkeypatch, field, value):
    budgets = replace(LIMITS)
    object.__setattr__(budgets, field, value)
    monkeypatch.setattr(gp.p4, "admit_folder", lambda *args, **kwargs: pytest.fail("malformed budget reached admission"))
    with pytest.raises(ValueError):
        prepare(tmp_path, budgets)


@pytest.mark.parametrize("field", ["envelope_raw", "base_raw", "node_ports", "node_declaration", "target_params",
    "target_declaration", "member_raw", "discovery_span", "context", "target_owner"])
def test_admitted_current_graph_refuses_before_any_target_or_request_snapshot(tmp_path, monkeypatch, field):
    folder(tmp_path)
    admit = gp.p4.admit_folder
    def altered(*args, **kwargs):
        result = admit(*args, **kwargs)
        if field == "envelope_raw":
            object.__setattr__(result, "raw", [])
        elif field == "base_raw":
            object.__setattr__(result.base, "raw", [])
        elif field in ("node_ports", "node_declaration"):
            node = result.base.nodes[0]
            object.__setattr__(node, "ports", []) if field == "node_ports" else object.__setattr__(node.declaration, "value", [])
        elif field in ("target_params", "target_declaration", "target_owner"):
            target = result.targets[0]
            if field == "target_declaration":
                object.__setattr__(target.declaration, "evidence", [])
            else:
                object.__setattr__(target, "params" if field == "target_params" else "owner", [])
        elif field == "member_raw":
            object.__setattr__(result.captures[0], "raw", bytearray(result.captures[0].raw))
        elif field == "context":
            object.__setattr__(result, "context", [])
        else:
            object.__setattr__(result.base.captures[0].lines[0].span, "start", [])
        return result
    monkeypatch.setattr(gp.p4, "admit_folder", altered)
    monkeypatch.setattr(vi, "asdict", lambda *args: pytest.fail("invalid graph reached snapshot"))
    monkeypatch.setattr(vi.custody, "asdict", lambda *args: pytest.fail("invalid graph reached snapshot"))
    with pytest.raises(ValueError):
        prepare(tmp_path, LIMITS)


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("which", ["first", "final", "both"])
@pytest.mark.parametrize("field", ["catalogue_bytes", "registration_bytes", "registration_sha256"])
def test_saved_first_compiled_bytes_survive_late_carrier_mutation_even_without_captures(tmp_path, monkeypatch, empty, which, field):
    folder(tmp_path, mode="no_captures" if empty else "normal")
    compile_profile, carriers = profile.compile_state_version_profile, []
    def compiling():
        carrier = compile_profile()
        carriers.append(carrier)
        if len(carriers) == 3:
            value = "0" * 64 if field == "registration_sha256" else b"corrupt"
            if which in ("first", "both"):
                object.__setattr__(carriers[0], field, value)
            if which in ("final", "both"):
                object.__setattr__(carrier, field, value)
        return carrier
    monkeypatch.setattr(profile, "compile_state_version_profile", compiling)
    with pytest.raises(ValueError):
        prepare(tmp_path, LIMITS)


@pytest.mark.parametrize("frame", ["body", "command", "prompt"])
def test_real_admission_uses_actual_all_preparation_without_judging_body_rows(tmp_path, monkeypatch, frame):
    raw = DETAIL if frame == "body" else b"show standby all\n" + DETAIL
    if frame == "prompt":
        raw = b"fixture#" + raw + b"fixture#\n"
    raw += b"unrecognised synthetic body\n" if frame == "body" else b""
    folder(tmp_path, detail=raw)
    forbid_execution(monkeypatch)
    result = prepare(tmp_path, LIMITS)
    request, = result.version.requests
    member = next(member for member in result.envelope.captures if member.target.operation == gp.all_hsrp.OP)
    assert request.capture.raw is member.raw and request.capture.integrity is k.IntegrityState.COMPLETE


@pytest.mark.parametrize("raw", [
    b"fixture#show standby\n" + DETAIL + b"fixture#\n",
    b"fixture#show standby all\n" + DETAIL,
    b"fixture#show standby all\n" + DETAIL + b"other#\n",
    DETAIL + b"show clock\n", DETAIL + b"configure terminal\n", DETAIL + b"!\n",
    DETAIL + b"\x00", DETAIL.replace(b"\n", b"\r"), b"\xff",
])
def test_actual_folder_preparation_retains_original_frame_refusal_wiring(tmp_path, monkeypatch, raw):
    folder(tmp_path, detail=raw)
    forbid_execution(monkeypatch)
    with pytest.raises(ValueError):
        prepare(tmp_path, LIMITS)


@pytest.mark.parametrize("extra", [{"envelope": object()}, {"compiled": object()}, {"rows": ()},
    {"store": object()}, {"mode": "other"}, {"profile": "other"}])
def test_preparation_does_not_accept_a_prepared_carrier_or_caller_profile(tmp_path, extra):
    with pytest.raises(TypeError):
        prepare(tmp_path, LIMITS, **extra)


@pytest.mark.parametrize("root", ["fixture", []])
def test_root_coordinates_are_validated_before_folder_access(monkeypatch, root):
    monkeypatch.setattr(gp.p4, "admit_folder", lambda *args, **kwargs: pytest.fail("invalid root reached admission"))
    with pytest.raises(ValueError):
        prepare(root, LIMITS)


@pytest.mark.parametrize("stage", ["before", "after"])
def test_initial_and_post_preparation_compiled_registration_mismatch_both_refuse(tmp_path, monkeypatch, stage):
    folder(tmp_path)
    compile_profile, calls = profile.compile_state_version_profile, []
    def compiling():
        value = compile_profile()
        calls.append(value)
        return replace(value, registration_sha256="0" * 64) if stage == "before" or len(calls) == 3 else value
    monkeypatch.setattr(profile, "compile_state_version_profile", compiling)
    forbid_execution(monkeypatch)
    with pytest.raises(ValueError):
        prepare(tmp_path, LIMITS)


@pytest.mark.parametrize("phase", ["before_call", "after_admission", "before_return"])
def test_fixed_brief_model_drift_refuses_at_the_actual_factory_boundaries(tmp_path, monkeypatch, phase):
    folder(tmp_path)
    admit, scope = gp.p4.admit_folder, gp._scope
    compile_profile, retain = profile.compile_state_version_profile, gp.retain_version_inputs
    original_requests, compilations = [], []
    def scoped(*args):
        result = scope(*args)
        if not original_requests:
            original_requests.append(result[2])
        return result
    def admitting(*args, **kwargs):
        result = admit(*args, **kwargs)
        if phase == "after_admission":
            monkeypatch.setattr(b.hsrp, "COMMAND", "show clock")
        return result
    def compiling():
        result = compile_profile()
        compilations.append(result)
        if phase == "before_return" and len(compilations) == 3:
            assert original_requests and len(original_requests[0]) == 1
            object.__setattr__(original_requests[0][0].capture, "rendered", "show clock")
        return result
    def retaining(*args):
        assert original_requests and all(request.capture.rendered == "show standby brief" for request in original_requests[0])
        return retain(*args)
    monkeypatch.setattr(gp, "_scope", scoped)
    monkeypatch.setattr(gp.p4, "admit_folder", admitting)
    monkeypatch.setattr(profile, "compile_state_version_profile", compiling)
    monkeypatch.setattr(gp, "retain_version_inputs", retaining)
    if phase == "before_call":
        monkeypatch.setattr(b.hsrp, "COMMAND", "show clock")
    forbid_execution(monkeypatch)
    with pytest.raises(ValueError):
        prepare(tmp_path, LIMITS)


@pytest.mark.parametrize("form", ["utf8", "ascii", "all", "other", "admin", "vrf", "rendered"])
def test_owning_brief_form_is_stricter_than_generic_model_graph_without_body_or_origin_claim(tmp_path, monkeypatch, form):
    folder(tmp_path)
    request = prepare(tmp_path, LIMITS).requests[0]
    sample = request.capture
    if form == "ascii":
        object.__setattr__(sample, "codec", "ascii")
    elif form in ("all", "other"):
        object.__setattr__(sample, "operation", gp.all_hsrp.OP if form == "all" else "iosxe.other")
    elif form in ("admin", "vrf"):
        metadata = sample.resolved_metadata
        scope = replace(metadata.scope, **({"plane": "admin"} if form == "admin" else {"vrf": "blue"}))
        object.__setattr__(sample, "metadata", replace(metadata, scope=scope))
    elif form == "rendered":
        object.__setattr__(sample, "rendered", "show clock")
    forbid_execution(monkeypatch)
    assert gp.validate_fhrp_request_graph(request) is None
    if form in ("utf8", "ascii"):
        assert gp.validate_brief_request(request) is None
    else:
        with pytest.raises(ValueError):
            gp.validate_brief_request(request)
