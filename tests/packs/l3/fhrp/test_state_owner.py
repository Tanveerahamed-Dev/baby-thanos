"""Test-only trusted composition for the owning HSRP capsule; no public global-pack claim."""
import json
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from test_parse_hsrp_brief import BODY, capture
from test_reported_state_build import DISCOVERY, GROUPS, REGISTRY

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel.global_parse import SummaryPack
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import build as b
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Handler

LIMITS = Budgets(1000000, 1000000, 1000)
type Value = stp.stp.Result | ec.parse_summary.Result | b.hsrp.Result


def estate(root, mode="normal"):
    base = canonical(REGISTRY)
    tree = b"Port 1 (Gi1/0/1) of VLAN0001 is designated forwarding\n   Root guard is enabled on the port\n"
    channel = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
               b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")
    files = {"p2.json": base, "discovery.txt": DISCOVERY, "tree.txt": tree, "ec.txt": channel, "hsrp.txt": BODY}
    targets = [{"id": "tree", "node": "a", "operation": stp.stp.OP, "params": {"port": "Gi1/0/1", "vlans": [1]}},
        {"id": "ec", "node": "b", "operation": ec.parse_summary.OP, "params": {"groups": ["1"], "ports": ["Gi1/0/1"]}},
        {"id": "hsrp", "node": "a", "operation": b.hsrp.OP, "params": {"groups": [list(pair) for pair in GROUPS]}},
        {"id": "cold", "node": "b", "operation": b.hsrp.OP, "params": {"groups": [["Vl30", "2"]]}}]
    if mode == "no_targets":
        targets = targets[:2]
    names = ("tree", "ec") if mode in ("no_targets", "no_captures") else ("tree", "ec", "hsrp")
    side = {"schema": "atlas-brain.synthetic-p4/1", "semantic_group": "declared_synthetic", "context": "round",
        "base_sha256": sha256(base).hexdigest(), "targets": targets,
        "captures": [{"target": name, "path": name + ".txt", "sha256": sha256(files[name + ".txt"]).hexdigest()} for name in names]}
    for name in tuple(files):
        if name == "hsrp.txt" and "hsrp" not in names:
            files.pop(name)
    for name, raw in (files | {"p4.json": canonical(side)}).items():
        (root / name).write_bytes(raw)


class OwnerPack(pipe.Pack[Value]):
    def __init__(self, plant=None):
        self.plant, self.owner, self.envelope, self.domains, self.requests = plant, None, None, (), ()
    def declaration(self):
        return b.DECLARATION
    def prepare(self, envelope):
        owned = tuple(target for target in envelope.targets if target.operation == b.hsrp.OP)
        domains = tuple(b.Target(context=envelope.context, node=target.node,
            groups=tuple(tuple(pair) for pair in json.loads(target.params)["groups"])) for target in owned)
        requests = tuple(CaptureRequest(context=envelope.context, capture=replace(capture(member.raw), id=member.id,
            source=member.target.node.key)) for member in envelope.captures if member.target.operation == b.hsrp.OP)
        self.envelope, self.domains, self.requests = envelope, domains, requests
        if self.plant is not None:
            envelope, domains, requests = self.plant(envelope, domains, requests)
        self.owner = b.StateOwner(envelope, LIMITS, domains, requests)
        return pipe.Prepared[Value](targets=owned, handlers=(Handler[Value](binding=b.BINDING, parser=self.owner),), requests=requests)


def run(root, plant=None):
    pack = OwnerPack(plant)
    peer = SummaryPack[stp.stp.Result | b.hsrp.Result](LIMITS)
    tree = stp.build_root_guard_global(root, LIMITS, peers=(peer, pack))
    assert pack.owner is not None
    own = tuple(pack.owner.own(output) for output in tree.execution.executed if output.receipt.capture.operation == b.hsrp.OP)
    return pack, tree, own


def test_three_real_parsers_keep_global_identity_and_three_declarations_before_each_write(tmp_path, monkeypatch):
    estate(tmp_path)
    pack, tree, own = run(tmp_path)
    owner = pack.owner
    assert len(tree.execution.executed) == 3 and len(own) == 1
    original = next(output for output in tree.execution.executed if output.receipt.capture.operation == b.hsrp.OP)
    assert own[0].receipt is original.receipt and own[0].value is original.value and own[0].receipt.parse is original.value.parse
    direct = b.build_reported_state(pack.domains, pack.requests)
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: pytest.fail("owner replayed parser"))
    monkeypatch.setattr(b, "execute_parsers", lambda *args: pytest.fail("owner ran singleton dispatcher"))
    write, values = FactWriter.write, []
    def checked(self, **kwargs):
        if kwargs["fact"] == b.REPORTED_STATE:
            row = next((target, interface, group) for target in pack.domains for interface, group in target.groups if b.subject(target, interface, group) == kwargs["subject"])
            declared = next(target for target in pack.envelope.targets if target.operation == b.hsrp.OP and target.node is row[0].node)
            refs = tuple(ref for ref in kwargs["value"].evidence if type(ref) is k.RegistryRef)
            assert refs == row[0].node.declaration.evidence + pack.envelope.declaration.evidence + declared.declaration.evidence
            assert all(ref.table_digest == sha256(pack.envelope.base.raw if ref.table == "synthetic_p2.nodes" else pack.envelope.raw).hexdigest() for ref in refs)
            values.append(kwargs["value"])
        return write(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", checked)
    result = owner.finish(tuple(replace(output) for output in own))
    assert len(result.rows) == 5 and values == [row.value for row in result.rows]
    assert [(row.subject, row.value.value if type(row.value) is k.Known else row.value.reason) for row in result.rows] == [(row.subject, row.value.value if type(row.value) is k.Known else row.value.reason) for row in direct.rows]
    assert result.executed[0].receipt is original.receipt and result.executed[0].value is original.value
    assert len(b.fact_rows(result)) == len(result.rows) and {fact for fact, _, _ in b.fact_rows(result)} == {b.REPORTED_STATE}
    assert all(any(row is original_row for original_row in result.rows) and value is row.value for _, row, value in b.fact_rows(result))
    assert next(row for row in result.rows if row.target.node.id == "b").value.reason is k.UnknownReason.NOT_COLLECTED
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        owner.finish(own)


@pytest.mark.parametrize("plant", ["cold_context", "cold_groups", "missing", "node", "context_ref", "target_ref", "base", "member_raw", "member_hash", "member_target"])
def test_late_raw_registry_or_declared_census_fault_precedes_all_parsers_and_writers(tmp_path, monkeypatch, plant):
    estate(tmp_path)
    def changed(envelope, domains, requests):
        cold = next(domain for domain in domains if domain.node.id == "b")
        if plant in ("cold_context", "cold_groups", "missing", "node"):
            alternate = replace(cold, **({"context": "wrong"} if plant == "cold_context" else {"groups": (("Vl30", "3"),)} if plant == "cold_groups" else {"node": replace(cold.node, discovery_id="wrong")} if plant == "node" else {}))
            domains = tuple(domain for domain in domains if domain is not cold) if plant == "missing" else tuple(alternate if domain is cold else domain for domain in domains)
        elif plant == "context_ref":
            ref, = envelope.declaration.evidence
            envelope = replace(envelope, declaration=replace(envelope.declaration, evidence=(replace(ref, citation="/wrong"),)))
        elif plant == "target_ref":
            target = next(target for target in envelope.targets if target.id == "cold")
            ref, = target.declaration.evidence
            altered = replace(target, declaration=replace(target.declaration, evidence=(replace(ref, table_digest="0" * 64),)))
            envelope = replace(envelope, targets=tuple(altered if item is target else item for item in envelope.targets))
        elif plant.startswith("member_"):
            member = next(member for member in envelope.captures if member.target.operation == b.hsrp.OP)
            changes = {"member_raw": {"raw": member.raw + b"X"}, "member_hash": {"sha256": "0" * 64},
                "member_target": {"target": next(target for target in envelope.targets if target.id == "cold")}}[plant]
            altered = replace(member, **changes)
            envelope = replace(envelope, captures=tuple(altered if item is member else item for item in envelope.captures))
        else:
            envelope = replace(envelope, base=replace(envelope.base, raw=envelope.base.raw + b"\n"))
        return envelope, domains, requests
    for module in (b.hsrp, stp.stp, ec.parse_summary):
        monkeypatch.setattr(module, "parse_capture", lambda *args: pytest.fail("parser before owner provenance"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before owner provenance"))
    with pytest.raises(ValueError, match="^hsrp_global_provenance$"):
        run(tmp_path, changed)


@pytest.mark.parametrize("plant,code", [("capture", "hsrp_global_capture"), ("value", "hsrp_global_value"),
    ("parse", "hsrp_global_value"), ("owner", "hsrp_receipt_owner"), ("context", "hsrp_receipt_owner"),
    ("registration", "hsrp_receipt_owner"), ("missing", "hsrp_receipt_coverage"), ("duplicate", "hsrp_receipt_coverage")])
def test_failed_finish_can_retry_genuine_leaves_and_only_one_success_escapes(tmp_path, monkeypatch, plant, code):
    estate(tmp_path)
    pack, _, own = run(tmp_path)
    output = own[0]
    if plant == "capture":
        output = replace(output, receipt=replace(output.receipt, capture=replace(output.receipt.capture)))
    elif plant == "value":
        output = replace(output, value=replace(output.value))
    elif plant == "parse":
        output = replace(output, receipt=replace(output.receipt, parse=replace(output.receipt.parse)))
    elif plant in ("owner", "context", "registration"):
        change = {"owner": {"owner": stp.STEP.id}, "context": {"context": "wrong"}, "registration": {"registration_sha256": "0" * 64}}[plant]
        output = replace(output, receipt=replace(output.receipt, **change))
    bad = () if plant == "missing" else (output, output) if plant == "duplicate" else (output,)
    with monkeypatch.context() as guard:
        guard.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before leaf/receipt closure"))
        with pytest.raises(ValueError, match="^" + code + "$"):
            pack.owner.finish(bad)
    result = pack.owner.finish(own)
    assert len(result.rows) == 5 and result.executed[0].value is own[0].value
    with pytest.raises(ValueError, match="^hsrp_global_run$"):
        pack.owner.finish(own)


@pytest.mark.parametrize("mode", ["no_targets", "no_captures"])
def test_zero_own_population_and_uncaptured_locals_stay_declared_without_replay(tmp_path, monkeypatch, mode):
    estate(tmp_path, mode)
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: pytest.fail("uncaptured HSRP parsed"))
    pack, _, own = run(tmp_path)
    result = pack.owner.finish(own)
    assert own == result.executed == () and len(result.rows) == (0 if mode == "no_targets" else 5)
    assert all(row.value.reason is k.UnknownReason.NOT_COLLECTED and len(row.value.evidence) == 3 for row in result.rows)


def test_manual_parse_replay_and_failed_parse_leave_no_complete_cache(tmp_path, monkeypatch):
    estate(tmp_path)
    pack, _, _ = run(tmp_path)
    with pytest.raises(ValueError, match="^hsrp_global_value$"):
        pack.owner.parse(pack.requests[0])
    fresh = b.StateOwner(pack.envelope, LIMITS, pack.domains, pack.requests)
    monkeypatch.setattr(b.hsrp, "parse_capture", lambda *args: (_ for _ in ()).throw(ValueError("planted_parse_failure")))
    with pytest.raises(ValueError, match="^planted_parse_failure$"):
        fresh.parse(pack.requests[0])
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before complete parse cache"))
    with pytest.raises(ValueError, match="^hsrp_global_value$"):
        fresh.finish(())


WITNESS = '''from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.packs.l2.etherchannel import parse_summary as ec
from atlas_brain.packs.l3.fhrp import build as hsrp
from atlas_brain.runner.pack_runtime import Executed, Handler
type Value = stp.Result | ec.Result | hsrp.hsrp.Result
def client(owner: hsrp.StateOwner, outputs: tuple[Executed[Value], ...]) -> tuple[Handler[Value], hsrp.Result]:
    owned = tuple(owner.own(e) for e in outputs if e.receipt.capture.operation == hsrp.hsrp.OP)
    return Handler[Value](binding=hsrp.BINDING, parser=owner), owner.finish(owned)
def planted(output: Executed[Value]) -> str:
    return output.value
'''


def test_strict_closed_three_pack_union_narrows_without_payload_erasure(tmp_path):
    (tmp_path / "witness.py").write_text(WITNESS, encoding="utf-8")
    config = {"include": ["witness.py"], "extraPaths": [str(Path(__file__).resolve().parents[4])],
        "pythonVersion": "3.14", "typeCheckingMode": "strict", "enableTypeIgnoreComments": False, "reportUnnecessaryTypeIgnoreComment": "error"}
    (tmp_path / "pyrightconfig.json").write_text(json.dumps(config), encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "pyright", "--outputjson", "--project", "pyrightconfig.json"],
                            cwd=tmp_path, capture_output=True, text=True, check=False, timeout=60)
    report = json.loads(result.stdout)
    assert result.returncode == 1 and report["summary"]["errorCount"] == len(report["generalDiagnostics"]) == 1, report
    diagnostic, = report["generalDiagnostics"]
    assert (diagnostic["severity"], diagnostic["rule"]) == ("error", "reportReturnType")
    assert Path(diagnostic["file"]).resolve() == (tmp_path / "witness.py").resolve()
    assert diagnostic["range"]["start"]["line"] == WITNESS.splitlines().index("    return output.value")
