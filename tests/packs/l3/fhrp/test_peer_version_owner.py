"""Trusted full-peer context and original owning VERSION outcome; no product-Pack or source seal."""
import json
from dataclasses import replace
from hashlib import sha256

import pytest
from test_state_owner import LIMITS
from test_state_version_input_preparation import DETAIL
from test_state_version_input_preparation import folder as fhrp_folder
from test_version_values import reader_for

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import compile_packs
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as fhrp
from atlas_brain.packs.l3.fhrp import global_parse as preparation
from atlas_brain.packs.l3.fhrp import peer_profile, version_owner, version_profile
from atlas_brain.runner import p4_pipeline as pipeline
from atlas_brain.runner.pack_runtime import Handler

TREE = b"Port 1 (Gi1/0/1) of VLAN0001 is designated forwarding\n   Root guard is enabled on the port\n"
CHANNEL = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
    b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")


def folder(root, mode="normal", detail=DETAIL, change=None):
    files = fhrp_folder(root, mode=mode, detail=detail)
    side = json.loads(files["p4.json"])
    side["targets"] += [
        {"id": "tree", "node": "a", "operation": stp.stp.OP, "params": {"port": "Gi1/0/1", "vlans": [1]}},
        {"id": "channel", "node": "b", "operation": ec.parse_summary.OP, "params": {"groups": ["1"], "ports": ["Gi1/0/1"]}},
    ]
    files.update({"tree.txt": TREE, "channel.txt": CHANNEL})
    side["captures"] += [{"target": "tree", "path": "tree.txt"}, {"target": "channel", "path": "channel.txt"}]
    if change is not None:
        change(side, files)
    for row in side["captures"]:
        row["sha256"] = sha256(files[row["path"]]).hexdigest()
    files["p4.json"] = canonical(side)
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


class ContextPack(pipeline.Pack):
    """Test adapter for the public trusted context/owner, without a product finishing contract."""

    def declaration(self):
        return version_profile.STATE_VERSION_DECLARATION

    def prepare(self, envelope):
        self.inputs = preparation.prepare_peer_state_version_inputs(envelope, LIMITS)
        self.state = fhrp.StateOwner(envelope, LIMITS, self.inputs.domains, self.inputs.requests)
        self.owner = version_owner.PeerGlobalVersionOwner(envelope, LIMITS, self.inputs.domains, self.inputs.version.requests)
        return pipeline.Prepared(targets=self.inputs.targets,
            handlers=(Handler(binding=fhrp.BINDING, parser=self.state), Handler(binding=version_profile.BINDING, parser=self.owner)),
            requests=self.inputs.requests + self.inputs.version.requests)


def owning_run(root):
    pack = ContextPack()
    result = stp.build_root_guard_global(root, LIMITS, peers=(SummaryPack(LIMITS), pack))
    outputs = tuple(output for output in result.execution.executed if output.receipt.capture.operation == preparation.all_hsrp.OP)
    return result.execution, pack, outputs


def test_actual_full_envelope_owner_keeps_real_cache_receipts_registry_evidence_and_reader_cells(tmp_path, monkeypatch):
    files = folder(tmp_path)
    execute, calls = pipeline.execute_parsers, []
    def executing(declarations, handlers, requests):
        outputs = execute(declarations, handlers, requests)
        calls.append((declarations, handlers, requests, outputs))
        return outputs
    monkeypatch.setattr(pipeline, "execute_parsers", executing)
    execution, pack, outputs = owning_run(tmp_path)
    declarations, handlers, requests, ledger = calls[0]
    compiled = compile_packs(declarations)
    assert len(calls) == 1 and len(handlers) == len(requests) == len(ledger) == 4
    assert declarations == peer_profile.DECLARATIONS and compiled == peer_profile.compile_peer_state_version_profile()
    assert execution.executed is ledger and execution.envelope is pack.inputs.envelope is pack.owner.envelope
    assert compiled.registration_sha256 not in (version_profile.compile_version_profile().registration_sha256,
        version_profile.compile_state_version_profile().registration_sha256)
    assert pack.inputs.version.targets is pack.owner.inputs.source.targets
    for output in ledger:
        member = next(member for member in execution.envelope.captures if member.id == output.receipt.capture.id)
        request = next(request for request in requests if request.capture.id == member.id)
        assert output.receipt.capture is request.capture and request.capture.raw is member.raw
        assert output.receipt.registration_sha256 == compiled.registration_sha256 and output.receipt.owner == member.target.owner
        assert output.receipt.parse is output.value.parse
    owned = tuple(pack.owner.own(output) for output in outputs)
    assert all(output.value is original.value and output.receipt is original.receipt for output, original in zip(owned, outputs, strict=True))
    result = pack.owner.finish(outputs)
    assert result.registration_sha256 == compiled.registration_sha256 and len(result.rows) == 5
    assert {row.value.value for row in result.rows if type(row.value) is k.Known} == {"1", "2"}
    assert result.store.owners == {version_profile.REPORTED_PROTOCOL_VERSION: version_profile.STEP.id}
    for row in result.rows:
        assert result.store.values[k.FactRef(fact=version_profile.REPORTED_PROTOCOL_VERSION, subject=row.subject)] is row.value
        refs = pack.inputs.declarations[row.target.context, row.target.node.key]
        assert all(ref in row.value.evidence for ref in refs)
    def forbidden(*args, **kwargs):
        pytest.fail("owning Reader validation replayed a parser, dispatcher or Writer")
    monkeypatch.setattr(pipeline, "execute_parsers", forbidden)
    monkeypatch.setattr(FactWriter, "write", forbidden)
    for module in (stp.stp, ec.parse_summary, fhrp.hsrp, preparation.all_hsrp):
        monkeypatch.setattr(module, "parse_capture", forbidden)
    assert pack.owner.validate_values(result, reader_for(result.store)) is None
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files


@pytest.mark.parametrize("mode", ["no_all_target", "no_all_capture", "no_all", "no_brief_capture", "no_captures", "unselected_b"])
def test_trusted_peer_owner_preserves_all_original_brief_cells_when_all_evidence_is_missing(tmp_path, mode):
    folder(tmp_path, mode=mode)
    execution, pack, outputs = owning_run(tmp_path)
    result = pack.owner.finish(outputs)
    assert len(result.rows) == sum(len(target.groups) for target in pack.inputs.domains) == (4 if mode == "unselected_b" else 5)
    assert {output.receipt.capture.operation for output in execution.executed} >= {stp.stp.OP, ec.parse_summary.OP}
    for row in result.rows:
        if mode.startswith("no_all") or mode == "no_captures" or row.target.node.id == "b":
            assert type(row.value) is k.Unknown and row.value.reason is k.UnknownReason.NOT_COLLECTED
            need, = row.value.next_evidence
            assert need.node == row.target.node.key and need.operation == preparation.all_hsrp.OP
        assert any(type(ref) is k.RegistryRef for ref in row.value.evidence)
    assert pack.owner.validate_values(result, reader_for(result.store)) is None


@pytest.mark.parametrize("plant", ["stp_owner", "ec_owner", "extra_operation", "local_hash", "subset_hash", "cold_domain"])
def test_current_public_peer_context_refuses_coherent_lower_data_tampering(tmp_path, plant):
    folder(tmp_path)
    envelope = pipeline.p4.admit_folder(tmp_path, LIMITS, declarations=peer_profile.DECLARATIONS)
    inputs = preparation.prepare_peer_state_version_inputs(envelope, LIMITS)
    refs = preparation.validate_peer_state_version_correspondence(envelope, LIMITS, inputs.version)
    assert len(refs) == len(inputs.domains) == 2
    if plant in ("stp_owner", "ec_owner", "extra_operation"):
        operation = ec.parse_summary.OP if plant == "ec_owner" else stp.stp.OP
        target = next(target for target in envelope.targets if target.operation == operation)
        object.__setattr__(target, "operation" if plant == "extra_operation" else "owner",
                           "iosxe.show_clock" if plant == "extra_operation" else "l3.fhrp/wrong_owner")
    elif plant == "cold_domain":
        inputs.version.indexed.pop(next(key for key, target in inputs.version.indexed.items() if target.node.id == "b"))
    else:
        compiler = version_profile.compile_version_profile if plant == "local_hash" else version_profile.compile_state_version_profile
        object.__setattr__(envelope, "registration_sha256", compiler().registration_sha256)
    with pytest.raises(ValueError):
        preparation.validate_peer_state_version_correspondence(envelope, LIMITS, inputs.version)


@pytest.mark.parametrize("part", ["stp_step", "ec_binding", "stp_scalar", "ec_scalar", "root_alias", "tuple"])
def test_closed_full_peer_profile_refuses_live_and_captured_metadata_drift(monkeypatch, part):
    expected = peer_profile.compile_peer_state_version_profile()
    assert len(expected.operations) == 4
    if part == "stp_step":
        monkeypatch.setattr(stp, "STEP", replace(stp.STEP, id="l2.stp/wrong_owner"))
    elif part == "ec_binding":
        monkeypatch.setattr(ec, "BINDING", replace(ec.BINDING, operation="iosxe.show_clock"))
    elif part == "stp_scalar":
        monkeypatch.setattr(stp, "ROOT_GUARD", "l2.stp.wrong_guard")
    elif part == "ec_scalar":
        monkeypatch.setattr(ec, "REPORTED_PROTOCOL", "l2.etherchannel.wrong_protocol")
    elif part == "root_alias":
        declaration = stp.DECLARATION
        entity, = declaration.entity_kinds
        entity = replace(entity)
        object.__setattr__(entity, "root", 0)
        monkeypatch.setattr(stp, "DECLARATION", replace(declaration, entity_kinds=(entity,)))
    else:
        monkeypatch.setattr(peer_profile, "DECLARATIONS", (stp.DECLARATION, ec.DECLARATION, version_profile.DECLARATION))
    with pytest.raises(ValueError):
        peer_profile.compile_peer_state_version_profile()


@pytest.mark.parametrize("plant", ["capture", "value", "registration", "cold_domain"])
def test_actual_peer_owner_refuses_late_input_cache_and_full_registration_substitution_before_its_writer(tmp_path, monkeypatch, plant):
    folder(tmp_path)
    _, pack, outputs = owning_run(tmp_path)
    output, = outputs
    if plant == "cold_domain":
        pack.owner.inputs.source.indexed.pop(next(key for key, target in pack.owner.inputs.source.indexed.items() if target.node.id == "b"))
    elif plant == "capture":
        output = replace(output, receipt=replace(output.receipt, capture=replace(output.receipt.capture)))
    elif plant == "value":
        output = replace(output, value=replace(output.value))
    else:
        output = replace(output, receipt=replace(output.receipt, registration_sha256=version_profile.compile_state_version_profile().registration_sha256))
    monkeypatch.setattr(version_owner, "bind_writer", lambda *args, **kwargs: pytest.fail("owner wrote before current peer closure"))
    with pytest.raises(ValueError):
        pack.owner.finish((output,))
    assert pack.owner.production_attempted and pack.owner.production is None


@pytest.mark.parametrize("plant", ["local_hash", "subset_hash"])
def test_peer_owner_requires_original_full_registration_even_with_no_all_requests(tmp_path, plant):
    folder(tmp_path, mode="no_all")
    envelope = pipeline.p4.admit_folder(tmp_path, LIMITS, declarations=peer_profile.DECLARATIONS)
    inputs = preparation.prepare_peer_state_version_inputs(envelope, LIMITS)
    compiler = version_profile.compile_version_profile if plant == "local_hash" else version_profile.compile_state_version_profile
    object.__setattr__(envelope, "registration_sha256", compiler().registration_sha256)
    with pytest.raises(ValueError):
        version_owner.PeerGlobalVersionOwner(envelope, LIMITS, inputs.domains, ())


@pytest.mark.parametrize("plant", ["groups", "orphan", "duplicate_all", "duplicate_capture", "raw_copy"])
def test_current_peer_correspondence_keeps_exact_original_all_mapping(tmp_path, plant):
    folder(tmp_path)
    envelope = pipeline.p4.admit_folder(tmp_path, LIMITS, declarations=peer_profile.DECLARATIONS)
    inputs = preparation.prepare_peer_state_version_inputs(envelope, LIMITS)
    target = next(target for target in envelope.targets if target.operation == preparation.all_hsrp.OP)
    member = next(member for member in envelope.captures if member.target is target)
    if plant == "groups":
        object.__setattr__(target, "params", canonical({"groups": [["Vl20", "9"]]}))
    elif plant == "orphan":
        object.__setattr__(envelope, "targets", tuple(original for original in envelope.targets
            if original.operation != fhrp.hsrp.OP or original.node is not target.node))
    elif plant == "duplicate_all":
        object.__setattr__(envelope, "targets", (*envelope.targets, replace(target, id="extra-all")))
    elif plant == "duplicate_capture":
        object.__setattr__(envelope, "captures", (*envelope.captures, replace(member, id="cap:extra")))
    else:
        object.__setattr__(member, "raw", bytes(bytearray(member.raw)))
    with pytest.raises(ValueError):
        preparation.validate_peer_state_version_correspondence(envelope, LIMITS, inputs.version)
