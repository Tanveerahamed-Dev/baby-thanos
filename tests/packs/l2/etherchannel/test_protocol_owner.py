import json
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.runner import p4_pipeline as pipe

P = "GigabitEthernet1/0/1"
LIMITS = gp.Budgets(1000000, 1000000, 1000)
BODY = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
        b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")
TREE = f"Port 1 ({P}) of VLAN0001 is designated forwarding\n   Root guard is enabled on the port\n".encode()


def scenario(root, raw=BODY):
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [P, "Gi1/0/1", "Gi1/0/2"]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(discovery).hexdigest()}]})
    side = {"schema": ec.p4.SCHEMA, "semantic_group": "declared_synthetic", "context": "round", "base_sha256": sha256(base).hexdigest(),
        "targets": [{"id": "tree", "node": "a", "operation": stp.stp.OP, "params": {"port": P, "vlans": [1]}},
                    {"id": "ec", "node": "b", "operation": ec.parse_summary.OP, "params": {"groups": ["2", "1"], "ports": ["Gi1/0/1", "Gi1/0/2"]}},
                    {"id": "cold", "node": "a", "operation": ec.parse_summary.OP, "params": {"groups": ["4"], "ports": []}}],
        "captures": [{"target": name, "path": name + ".txt", "sha256": sha256(data).hexdigest()} for name, data in (("tree", TREE), ("ec", raw))]}
    for name, data in {"p2.json": base, "discovery.txt": discovery, "tree.txt": TREE, "ec.txt": raw}.items():
        (root / name).write_bytes(data)
    (root / "p4.json").write_bytes(canonical(side))
    return side


class Peer(pipe.Pack[ec.parse_summary.Result | stp.stp.Result]):
    def __init__(self):
        self.summary = gp.SummaryPack[stp.stp.Result](LIMITS)

    def declaration(self):
        return self.summary.declaration()

    def prepare(self, envelope):
        prepared = self.summary.prepare(envelope)
        domains = tuple(ec.Target(context=envelope.context, node=t.node, groups=tuple(json.loads(t.params)["groups"]),
                                  ports=tuple(json.loads(t.params)["ports"])) for t in prepared.targets)
        self.owner = ec.ProtocolOwner(envelope, LIMITS, domains, prepared.requests)
        return pipe.Prepared[ec.parse_summary.Result | stp.stp.Result](targets=prepared.targets, handlers=(pipe.Handler[ec.parse_summary.Result | stp.stp.Result](binding=ec.BINDING, parser=self.owner),), requests=prepared.requests)


def build(root):
    peer = Peer()
    return peer, stp.build_root_guard_global(root, LIMITS, peers=(peer,))


def finish(peer, execution):
    owner = peer.owner
    return owner.finish(tuple(owner.own(e) for e in execution.executed if e.receipt.capture.operation == ec.parse_summary.OP))


@pytest.mark.parametrize("word,expected", [(b"LACP", "lacp"), (b"PAgP", "pagp"), (b"-", "none_reported")])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["bare", "command", "prompt"])
def test_two_real_owners_keep_global_identity_and_declared_proofs_at_ec_write(tmp_path, monkeypatch, word, expected, ending, frame):
    raw = BODY.replace(b"LACP", word)
    raw = raw if frame == "bare" else (b"fixture#" + ec.parse_summary.COMMAND.encode() + b"\n" + raw + b"fixture#\n" if frame == "prompt" else ec.parse_summary.COMMAND.encode() + b"\n" + raw)
    raw = raw.replace(b"\n", ending)
    side, seen, writes, subjects = scenario(tmp_path, raw), {}, [], {}
    peer = Peer()
    def watch(obj, name, tag):
        original = getattr(obj, name)
        def traced(*args, **kwargs):
            value = original(*args, **kwargs)
            seen.setdefault(tag, []).append(value)
            return value
        monkeypatch.setattr(obj, name, traced)
    for obj, name, tag in ((peer, "declaration", "declaration"), (peer, "prepare", "prepare"),
        (gp.p4_pipeline, "execute_p4_folder", "run"), (gp.p4_pipeline.p4, "admit_folder", "admit"),
        (ec.parse_summary, "parse_capture", "ec"), (stp.stp, "parse_capture", "stp")):
        watch(obj, name, tag)
    writer = FactWriter.write
    def checked(self, **kwargs):
        if kwargs["fact"] == ec.REPORTED_PROTOCOL:
            refs = [r for r in kwargs["value"].evidence if type(r) is k.RegistryRef]
            envelope = seen["run"][0].envelope
            target = subjects[kwargs["subject"]]
            assert tuple(refs) == target.node.declaration.evidence + envelope.declaration.evidence + target.declaration.evidence
            assert all(r.table_digest == sha256((tmp_path / "p2.json").read_bytes() if r.table == "synthetic_p2.nodes" else canonical(side)).hexdigest() for r in refs)
            if type(kwargs["value"]) is k.Known:
                witnesses = [r for r in kwargs["value"].evidence if type(r) is k.EvidenceRef]
                capture = next(e.receipt.capture for e in seen["run"][0].executed if e.receipt.owner == ec.STEP.id)
                assert len(witnesses) == 3 and all(r.capture == capture.id and r.excerpt_sha256 == sha256(raw[r.locator.start:r.locator.end]).hexdigest() for r in witnesses)
            writes.append(kwargs["value"])
        return writer(self, **kwargs)
    monkeypatch.setattr(FactWriter, "write", checked)
    monkeypatch.setattr(ec, "execute_parsers", lambda *args: pytest.fail("singleton EC execution"))
    out = stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    for target in (t for t in out.execution.envelope.targets if t.operation == ec.parse_summary.OP):
        params = json.loads(target.params)
        domain = ec.Target(context=out.execution.envelope.context, node=target.node, groups=tuple(params["groups"]), ports=tuple(params["ports"]))
        subjects.update((ec.subject(domain, group), target) for group in domain.groups)
    facts = finish(peer, out.execution)
    assert all(len(items) == 1 for items in seen.values()) and set(seen) == {"declaration", "prepare", "run", "admit", "ec", "stp"}
    assert out.execution is seen["run"][0] and out.execution.envelope is seen["admit"][0]
    own, = facts.executed
    original = next(e for e in out.execution.executed if e.receipt.capture.operation == ec.parse_summary.OP)
    assert own.receipt is original.receipt and own.value is original.value is seen["ec"][0] and own.receipt.parse is own.value.parse
    assert own.receipt.registration_sha256 == out.execution.envelope.registration_sha256 == out.result.executed[0].receipt.registration_sha256
    assert facts.store.owners == {ec.REPORTED_PROTOCOL: ec.STEP.id} and out.result.store.owners == {stp.ROOT_GUARD: stp.STEP.id}
    cold, known, absent = facts.rows
    assert cold.value.reason is k.UnknownReason.NOT_COLLECTED
    assert known.value.value == expected and known.value.raw == word.decode() and known.value.basis is k.Basis.OBSERVED and own.value.missing_ports == ("Gi1/0/2",)
    assert absent.value.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE and writes == [r.value for r in facts.rows]


def test_removed_ec_capture_preserves_population_and_an_ec_free_run_is_empty(tmp_path, monkeypatch):
    side = scenario(tmp_path)
    peer, out = build(tmp_path)
    before = finish(peer, out.execution)
    side["captures"] = [r for r in side["captures"] if r["target"] != "ec"]
    (tmp_path / "ec.txt").unlink()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("uncaptured EC parsed"))
    peer, out = build(tmp_path)
    missing = finish(peer, out.execution)
    assert [r.subject for r in missing.rows] == [r.subject for r in before.rows]
    assert all(r.value.reason is k.UnknownReason.NOT_COLLECTED and {"synthetic_p2.nodes", "synthetic_p4.context", "synthetic_p4.targets"} == {p.table for p in r.value.evidence if type(p) is k.RegistryRef} for r in missing.rows)
    assert all(p.table_digest == sha256((tmp_path / "p2.json").read_bytes() if p.table == "synthetic_p2.nodes" else canonical(side)).hexdigest() for row in missing.rows for p in row.value.evidence if type(p) is k.RegistryRef)
    side["targets"] = side["targets"][:1]
    (tmp_path / "p4.json").write_bytes(canonical(side))
    peer, out = build(tmp_path)
    assert finish(peer, out.execution).rows == ()


@pytest.mark.parametrize("plant,code", [("missing", "etherchannel_receipt_coverage"), ("duplicate", "etherchannel_receipt_coverage"),
    ("extra", "etherchannel_global_capture"), ("foreign", "etherchannel_global_capture"), ("capture", "etherchannel_global_capture"),
    *[(p, "etherchannel_global_value") for p in ("value", "parse", "coherent")],
    *[(p, "etherchannel_receipt_owner") for p in ("owner", "context", "registration")], ("shape", "etherchannel_global_receipt")])
def test_owned_evidence_barrier_precedes_ec_writes_and_failed_finish_can_retry(tmp_path, monkeypatch, plant, code):
    scenario(tmp_path)
    peer, out = build(tmp_path)
    owner = peer.owner
    own = next(e for e in out.execution.executed if e.receipt.capture.operation == ec.parse_summary.OP)
    entries, item = (own,), own
    if plant in ("missing", "duplicate", "extra", "foreign", "shape"):
        extra = replace(own, receipt=replace(own.receipt, capture=replace(own.receipt.capture, id=k.CaptureId("cap:extra"))))
        entries = {"missing": (), "duplicate": (own, own), "extra": (own, extra),
            "foreign": tuple(e for e in out.execution.executed if e is not own), "shape": [own]}[plant]
    elif plant in ("owner", "context", "registration", "capture"):
        changes = {"owner": {"owner": stp.STEP.id}, "context": {"context": "wrong"},
            "registration": {"registration_sha256": "0" * 64}, "capture": {"capture": replace(own.receipt.capture)}}[plant]
        item = replace(own, receipt=replace(own.receipt, **changes))
        entries = (item,)
    else:
        parsed = replace(own.value.parse, quality="partial") if plant == "coherent" else own.value.parse
        value = replace(own.value, parse=parsed) if plant != "parse" else own.value
        item = replace(own, value=value, receipt=replace(own.receipt, parse=parsed if plant == "coherent" else replace(parsed)) if plant != "value" else own.receipt)
        entries = (item,)
    writer = ec.bind_writer
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("EC writer before owned evidence closure"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        owner.finish(entries)
    monkeypatch.setattr(ec, "bind_writer", writer)
    built = owner.finish((owner.own(own),))
    assert len(built.rows) == 3 and built.executed[0].receipt is own.receipt and built.executed[0].value is own.value
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        owner.finish((owner.own(own),))


@pytest.mark.parametrize("plant", ["empty", "context", "groups", "declaration", "proofs", "unparsed"])
def test_public_capsule_authenticates_declared_population_and_cannot_borrow_an_unparsed_value(tmp_path, monkeypatch, plant):
    scenario(tmp_path)
    peer, out = build(tmp_path)
    facts = finish(peer, out.execution)
    own, envelope = facts.executed[0], out.execution.envelope
    domains = tuple({row.target.node.key: row.target for row in facts.rows}.values())
    targets = () if plant == "empty" else (replace(domains[0], **({"context": "wrong"} if plant == "context" else {"groups": ("3",)} if plant == "groups" else {})),) + domains[1:]
    requests = () if plant == "empty" else (ec.CaptureRequest(context=own.receipt.context, capture=own.receipt.capture),)
    if plant == "declaration":
        envelope = replace(envelope, declaration=replace(envelope.declaration, basis=k.Basis.OBSERVED))
    elif plant == "proofs":
        own_targets = tuple(t for t in envelope.targets if t.operation == ec.parse_summary.OP)
        envelope = replace(envelope, targets=tuple(replace(t, declaration=own_targets[1 if t is own_targets[0] else 0].declaration) if t.operation == ec.parse_summary.OP else t for t in envelope.targets))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("parser before capsule provenance"))
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before capsule provenance/cache closure"))
    with pytest.raises(ValueError, match="^etherchannel_global_" + ("value" if plant == "unparsed" else "provenance") + "$"):
        capsule = ec.ProtocolOwner(envelope, LIMITS, targets, requests)
        capsule.finish((own,))


@pytest.mark.parametrize("stage", ["parse", "replay"])
def test_capsule_parser_failure_keeps_cache_incomplete_and_duplicate_parse_is_refused(tmp_path, monkeypatch, stage):
    scenario(tmp_path)
    peer = Peer()
    def failed(*args):
        raise RuntimeError("EC parser failed")
    if stage == "parse":
        monkeypatch.setattr(ec.parse_summary, "parse_capture", failed)
        with pytest.raises(RuntimeError, match="^EC parser failed$"):
            stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
        monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("writer after incomplete parser cache"))
        with pytest.raises(ValueError, match="^etherchannel_global_value$"):
            peer.owner.finish(())
    else:
        out = stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
        own = next(e for e in out.execution.executed if e.receipt.capture.operation == ec.parse_summary.OP)
        monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("duplicate request reached parser"))
        with pytest.raises(ValueError, match="^etherchannel_global_value$"):
            peer.owner.parse(ec.CaptureRequest(context=own.receipt.context, capture=own.receipt.capture))


WITNESS = '''from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.runner.pack_runtime import Executed, Handler
type Value = stp.Result | ec.parse_summary.Result
def client(owner: ec.ProtocolOwner, outputs: tuple[Executed[Value], ...]) -> tuple[Handler[Value], ec.Result]:
    owned = tuple(owner.own(e) for e in outputs if e.receipt.capture.operation == ec.parse_summary.OP)
    return Handler[Value](binding=ec.BINDING, parser=owner), owner.finish(owned)
def planted(output: Executed[Value]) -> str:
    return output.value
'''


def test_public_capsule_preserves_strict_union_narrowing_with_one_exact_hosted_negative(tmp_path):
    (tmp_path / "witness.py").write_text(WITNESS, encoding="utf-8")
    config = {"include": ["witness.py"], "extraPaths": [str(Path(__file__).resolve().parents[4])],
        "pythonVersion": "3.14", "typeCheckingMode": "strict", "enableTypeIgnoreComments": False, "reportUnnecessaryTypeIgnoreComment": "error"}
    (tmp_path / "pyrightconfig.json").write_text(json.dumps(config), encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "pyright", "--outputjson", "--project", "pyrightconfig.json"],
                         cwd=tmp_path, capture_output=True, text=True, check=False, timeout=60)
    report = json.loads(run.stdout)
    assert run.returncode == 1 and report["summary"]["errorCount"] == len(report["generalDiagnostics"]) == 1, report
    diagnostic, = report["generalDiagnostics"]
    assert (diagnostic["severity"], diagnostic["rule"]) == ("error", "reportReturnType")
    assert Path(diagnostic["file"]).resolve() == (tmp_path / "witness.py").resolve()
    assert diagnostic["range"]["start"]["line"] == WITNESS.splitlines().index("    return output.value")
