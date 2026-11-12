"""Actual synthetic P4 folders through the owning STP observation pipeline."""
from dataclasses import replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence import p4_admission
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.stp import build as b

P, Q = "GigabitEthernet1/0/1", "GigabitEthernet1/0/2"
HEADER = f"Port 1 ({P}) of VLAN0001 is designated forwarding\n".encode()
BODY = HEADER + b"   Root guard is enabled on the port\n"
OPEN = b"fixture#" + b.stp.command(P).encode() + b"\n"
LIMITS = Budgets(1000000, 1000000, 1000)
TABLES = {"synthetic_p2.nodes", "synthetic_p4.context", "synthetic_p4.targets"}


def scenario(raw=BODY):
    discovery = b"Device ID: fixture-b\n"
    base = {"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
            "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [P, Q]} for n in ("a", "b")],
            "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail",
                          "sha256": sha256(discovery).hexdigest()}]}
    files = {"p2.json": canonical(base), "discovery.txt": discovery, "stp.txt": raw}
    side = {"schema": p4_admission.SCHEMA, "semantic_group": "declared_synthetic", "context": "round",
            "base_sha256": sha256(files["p2.json"]).hexdigest(),
            "targets": [{"id": "t" + str(i), "node": n, "operation": b.stp.OP,
                         "params": {"port": P, "vlans": [2, 1] if i == 0 else [1]}}
                        for i, n in enumerate(("a", "b"))],
            "captures": [{"target": "t0", "path": "stp.txt", "sha256": sha256(raw).hexdigest()}]}
    return files, side


def write(root, files, side):
    for name, raw in (files | {"p4.json": canonical(side)}).items():
        (root / name).write_bytes(raw)


def run(root, files, side):
    write(root, files, side)
    return b.build_root_guard_folder(root, LIMITS)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["body", "command", "prompt", "marker_prompt"])
@pytest.mark.parametrize("state", ["enabled", "disabled"])
def test_real_folder_has_exact_custody_and_all_provenance_before_the_only_owner_writes(monkeypatch, tmp_path, ending, frame, state):
    raw = HEADER + f"   Root guard is {state} on the port\n".encode()
    if frame != "body":
        raw = b.stp.command(P).encode() + b"\n" + raw
    if frame in ("prompt", "marker_prompt"):
        prompt = b"fixture--more--#" if frame == "marker_prompt" else b"fixture#"
        raw = prompt + raw + prompt + b"\n"
    raw = raw.replace(b"\n", ending)
    calls, writes = [], []
    parser, writer = b.stp.parse_capture, FactWriter.write
    def observed(*args):
        calls.append(parser(*args))
        return calls[-1]
    def checked(self, **kwargs):
        value = kwargs["value"]
        assert TABLES <= {r.table for r in value.evidence if type(r) is k.RegistryRef}
        writes.append(value)
        return writer(self, **kwargs)
    monkeypatch.setattr(b.stp, "parse_capture", observed)
    monkeypatch.setattr(FactWriter, "write", checked)
    result = run(tmp_path, *scenario(raw))
    envelope, built = result.envelope, result.result
    member, output = envelope.captures[0], built.executed[0]
    capture = output.receipt.capture
    assert len(calls) == len(envelope.captures) == len(built.executed) == 1
    assert output.value is calls[0] and output.receipt.parse is output.value.parse
    assert envelope.raw == (tmp_path / "p4.json").read_bytes()
    assert capture.id == member.id and capture.raw == member.raw == raw and capture.bytes_sha256 == member.sha256
    assert capture.source == member.target.node.key and capture.operation == b.stp.OP and capture.rendered == b.stp.command(P)
    assert capture.scope.node == capture.source and capture.scope.plane == "exec" and capture.scope.context is None
    assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
    assert capture.collected_utc.reason is k.UnknownReason.AS_OF_MISSING and capture.integrity is k.IntegrityState.COMPLETE
    assert output.receipt.registration_sha256 == envelope.registration_sha256 == registration.compile_packs((b.DECLARATION,)).registration_sha256
    assert built.store.owners == {b.ROOT_GUARD: b.STEP.id, b.REPORTED_ROLE: b.STEP.id}
    assert writes == [state for row in built.rows for state in (row.value, row.role)]
    known, = [row for row in built.rows if type(row.value) is k.Known]
    assert known.value.value is (state == "enabled") and known.value.raw == state and known.value.basis is k.Basis.OBSERVED
    for row in built.rows:
        target = next(t for t in envelope.targets if t.node.key == row.target.node.key)
        refs = {r.table: r for r in row.value.evidence if type(r) is k.RegistryRef}
        assert refs["synthetic_p4.context"] == envelope.declaration.evidence[0]
        assert refs["synthetic_p4.targets"] == target.declaration.evidence[0]
        assert refs["synthetic_p2.nodes"] == row.target.node.declaration.evidence[0]
    refs = [r for r in known.value.evidence if type(r) is k.EvidenceRef]
    assert len(refs) == 5
    assert all(r.capture == member.id and sha256(raw[r.locator.start:r.locator.end]).hexdigest() == r.excerpt_sha256 for r in refs)


@pytest.mark.parametrize("raw,integrity,reason", [
    (b"", k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
    (b.stp.command(P).encode() + b"\n", k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
    (b"% Invalid input detected\n", k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY + b"--More--\n", k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (OPEN + BODY + b"--More--\n", k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
    (OPEN + BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED),
    (OPEN + b"% Invalid input detected\n", k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
    (BODY.replace(b"VLAN0001", b"MST0"), k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT),
    (HEADER + b"   Bpdu guard is enabled\n", k.IntegrityState.COMPLETE, k.UnknownReason.FIELD_NOT_PRINTED),
])
def test_transport_and_unprinted_guard_never_manufacture_false(tmp_path, raw, integrity, reason):
    result = run(tmp_path, *scenario(raw)).result
    assert result.executed[0].receipt.capture.integrity is integrity
    assert type(result.rows[0].value) is k.Unknown and result.rows[0].value.reason is reason
    assert all(TABLES <= {r.table for r in row.value.evidence if type(r) is k.RegistryRef} for row in result.rows)
    if integrity is not k.IntegrityState.COMPLETE:
        assert all(type(row.value) is k.Unknown and row.value.reason is reason for row in result.rows if row.target.node.key == result.executed[0].receipt.capture.source)


@pytest.mark.parametrize("raw,code", [
    (BODY + b"\xff", "stp_folder_text"), (BODY + b"\r", "stp_folder_text"),
    (BODY + b"\x00", "stp_folder_text"), (BODY + "\u0085".encode(), "stp_folder_text"),
    (BODY + "\u2028".encode(), "stp_folder_text"), (BODY + "\u2029".encode(), "stp_folder_text"),
    (b"other#show version\n" + BODY + b"other#\n", "stp_folder_frame"),
    (b"fixture#" + b.stp.command(P).encode() + b"\n" + BODY + b"other#\n", "stp_folder_frame"),
    (BODY + b"interface " + P.encode() + b"\n", "stp_folder_frame"),
    (b"other#show version\n% Invalid input\n", "stp_folder_frame"),
    (OPEN + BODY + b"--More--\nother#\n", "stp_folder_frame"),
    (OPEN + BODY, "stp_folder_frame"),
    (b"fixture--more--#" + b.stp.command(P).encode() + b"\n" + BODY, "stp_folder_frame"),
])
def test_late_bad_text_refuses_before_any_pack_parse_or_writer(tmp_path, monkeypatch, raw, code):
    files, side = scenario()
    files["later.txt"] = raw
    side["captures"].append({"target": "t1", "path": "later.txt", "sha256": sha256(raw).hexdigest()})
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("parser before all admission gates"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before all admission gates"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        run(tmp_path, files, side)


@pytest.mark.parametrize("plant,code", [("boolean", "invalid_stp_vlans"), ("port", "synthetic_undeclared_port"),
    ("extra", "invalid_record_fields"), ("scope", "stp_duplicate_target"), ("capture", "stp_duplicate_target_capture")])
def test_all_typed_params_and_effective_scopes_are_preflighted(tmp_path, monkeypatch, plant, code):
    files, side = scenario()
    params = side["targets"][1]["params"]
    changes = {"boolean": {"vlans": [True]}, "port": {"port": "GigabitEthernet99"}, "extra": {"rendered": "show version"}}
    if plant in changes:
        params.update(changes[plant])
    elif plant == "scope":
        side["targets"][1].update(node="a", params={"port": P, "vlans": [3]})
    else:
        files["second.txt"] = BODY
        side["captures"].append({"target": "t0", "path": "second.txt", "sha256": sha256(BODY).hexdigest()})
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("parser before typed population"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before typed population"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        run(tmp_path, files, side)


@pytest.mark.parametrize("plant,code", [("registration", "stp_folder_registration"), ("node", "stp_folder_target"),
    ("params", "stp_folder_target"), ("context", "stp_folder_declaration"), ("target", "stp_folder_declaration"),
    ("group", "stp_folder_declaration"), ("registry", "stp_folder_declaration"), ("raw", "stp_folder_member"), ("id", "stp_folder_member")])
def test_original_registry_bindings_survive_a_consistently_forged_loader(tmp_path, monkeypatch, plant, code):
    write(tmp_path, *scenario())
    definitions = (b.DECLARATION,)
    if plant == "registration":
        pack = k.PackId("test.future")
        step = StepSpec(id=StepId("test.future/parse"), pack=pack, kind="parse_build", scope="device", reads=(), produces=(), evaluator="test.future.uninstalled")
        definitions += (registration.PackDeclaration(pack=pack, entity_kinds=(), facts=(), relations=(), steps=(step,), operations=(registration.OperationBinding(operation="collect.future", step=step.id),)),)
    envelope = p4_admission.admit_folder(tmp_path, LIMITS, declarations=definitions)
    target, other = envelope.targets
    if plant in ("node", "params", "target"):
        target = replace(target, **({"node": envelope.base.nodes[1]} if plant == "node" else
            {"params": canonical({"port": Q, "vlans": [2, 1]})} if plant == "params" else
            {"declaration": replace(target.declaration, basis=k.Basis.OBSERVED)}))
        envelope = replace(envelope, targets=(target, other), captures=tuple(replace(m, target=target) for m in envelope.captures))
    elif plant == "context":
        envelope = replace(envelope, declaration=replace(envelope.declaration, basis=k.Basis.OBSERVED))
    elif plant == "group":
        envelope = replace(envelope, base=replace(envelope.base, declaration=replace(envelope.base.declaration, basis=k.Basis.OBSERVED)))
    elif plant == "registry":
        envelope = replace(envelope, raw=envelope.raw + b"\n")
    elif plant in ("raw", "id"):
        member, = envelope.captures
        envelope = replace(envelope, captures=(replace(member, **({"raw": BODY + b"changed\n"} if plant == "raw" else {"id": k.CaptureId("cap:forged")})),))
    monkeypatch.setattr(b.p4_admission, "admit_folder", lambda *args, **kwargs: envelope)
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("parser before registry custody"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before registry custody"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        b.build_root_guard_folder(tmp_path, LIMITS)


def test_removed_capture_keeps_typed_subjects_and_current_declared_proofs(tmp_path):
    files, side = scenario()
    original = run(tmp_path, files, side).result
    side["targets"].reverse()
    for target in side["targets"]:
        target["params"]["vlans"].reverse()
    reordered = run(tmp_path, files, side).result
    assert [(r.subject, r.value.value if type(r.value) is k.Known else r.value.reason) for r in reordered.rows] == [(r.subject, r.value.value if type(r.value) is k.Known else r.value.reason) for r in original.rows]
    side["captures"].clear()
    files.pop("stp.txt")
    (tmp_path / "stp.txt").unlink()
    removed = run(tmp_path, files, side)
    assert [row.subject for row in removed.result.rows] == [row.subject for row in original.rows]
    assert all(type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED for row in removed.result.rows)
    assert all(TABLES <= {r.table for r in row.value.evidence if type(r) is k.RegistryRef} for row in removed.result.rows)
