import json
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
from atlas_brain.packs.l2.stp import build as stp

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


def build(root):
    peer = gp.SummaryPack[stp.stp.Result](LIMITS)
    return peer, stp.build_root_guard_global(root, LIMITS, peers=(peer,))


@pytest.mark.parametrize("word,expected", [(b"LACP", "lacp"), (b"PAgP", "pagp"), (b"-", "none_reported")])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["bare", "command", "prompt"])
def test_two_real_owners_keep_global_identity_and_declared_proofs_at_ec_write(tmp_path, monkeypatch, word, expected, ending, frame):
    raw = BODY.replace(b"LACP", word)
    raw = raw if frame == "bare" else (b"fixture#" + ec.parse_summary.COMMAND.encode() + b"\n" + raw + b"fixture#\n" if frame == "prompt" else ec.parse_summary.COMMAND.encode() + b"\n" + raw)
    raw = raw.replace(b"\n", ending)
    side, seen, writes, subjects = scenario(tmp_path, raw), {}, [], {}
    peer = gp.SummaryPack[stp.stp.Result](LIMITS)
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
    facts = peer.finish(out.execution)
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
    before = peer.finish(out.execution)
    side["captures"] = [r for r in side["captures"] if r["target"] != "ec"]
    (tmp_path / "ec.txt").unlink()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("uncaptured EC parsed"))
    peer, out = build(tmp_path)
    missing = peer.finish(out.execution)
    assert [r.subject for r in missing.rows] == [r.subject for r in before.rows]
    assert all(r.value.reason is k.UnknownReason.NOT_COLLECTED and {"synthetic_p2.nodes", "synthetic_p4.context", "synthetic_p4.targets"} == {p.table for p in r.value.evidence if type(p) is k.RegistryRef} for r in missing.rows)
    assert all(p.table_digest == sha256((tmp_path / "p2.json").read_bytes() if p.table == "synthetic_p2.nodes" else canonical(side)).hexdigest() for row in missing.rows for p in row.value.evidence if type(p) is k.RegistryRef)
    side["targets"] = side["targets"][:1]
    (tmp_path / "p4.json").write_bytes(canonical(side))
    peer, out = build(tmp_path)
    assert peer.finish(out.execution).rows == ()


@pytest.mark.parametrize("plant", ["environment", "result-type", "shape", "receipt-type", "peer-receipt-type", "missing", "missing-peer", "duplicate", "extra", "capture", "value", "parse", "coherent",
    *[prefix + field for prefix in ("", "peer-") for field in ("owner", "operation", "source", "raw", "context", "registration")], "foreign-value", "containers", "reorder", "peer-capture-copy", "peer-receipt-copy"])
def test_ec_finish_refuses_forged_global_evidence_before_ec_writes_and_can_retry(tmp_path, monkeypatch, plant):
    scenario(tmp_path)
    peer, out = build(tmp_path)
    run, entries = out.execution, out.execution.executed
    index = next(i for i, e in enumerate(entries) if e.receipt.capture.operation == (stp.stp.OP if plant.startswith("peer-") else ec.parse_summary.OP))
    item, field = entries[index], plant.removeprefix("peer-")
    code, forged = "etherchannel_global_receipt", run
    if plant in ("environment", "result-type"):
        code, forged = "etherchannel_global_run", replace(run, envelope=replace(run.envelope)) if plant == "environment" else object()
    elif plant == "shape":
        forged = replace(run, executed=list(entries))
    elif field == "receipt-type":
        item = replace(item, receipt=object())
    elif plant in ("missing", "missing-peer", "duplicate", "extra"):
        changed = tuple(e for e in entries if e.receipt.capture.operation != (stp.stp.OP if plant == "missing-peer" else ec.parse_summary.OP))
        if plant in ("duplicate", "extra"):
            added = item if plant == "duplicate" else replace(item, receipt=replace(item.receipt, capture=replace(item.receipt.capture, id=k.CaptureId("cap:extra"))))
            changed = entries + (added,)
        code, forged = "etherchannel_global_coverage", replace(run, executed=changed)
    elif field in ("owner", "operation", "source", "raw", "context", "registration", "capture"):
        capture = item.receipt.capture
        changes = {"owner": {"owner": stp.STEP.id if capture.operation == ec.parse_summary.OP else ec.STEP.id},
            "operation": {"capture": replace(capture, operation=stp.stp.OP if capture.operation == ec.parse_summary.OP else ec.parse_summary.OP)},
            "source": {"capture": replace(capture, source=k.EntityKey("node:wrong"))}, "raw": {"capture": replace(capture, raw=BODY + b"changed\n", lines=text_lines(BODY + b"changed\n", "utf-8"))},
            "context": {"context": "wrong"}, "registration": {"registration_sha256": "0" * 64}, "capture": {"capture": replace(capture)}}[field]
        item = replace(item, receipt=replace(item.receipt, **changes))
        code = "etherchannel_global_capture" if field == "capture" else code
    elif plant in ("value", "parse", "coherent"):
        parsed = replace(item.value.parse, quality="partial") if plant == "coherent" else item.value.parse
        value = replace(item.value, parse=parsed) if plant != "parse" else item.value
        item = replace(item, value=value, receipt=replace(item.receipt, parse=parsed if plant == "coherent" else replace(parsed)) if plant != "value" else item.receipt)
        code = "etherchannel_global_value"
    elif plant in ("foreign-value", "containers", "reorder", "peer-capture-copy", "peer-receipt-copy"):
        ordered = tuple(reversed(entries)) if plant == "reorder" else entries
        if plant.startswith("peer-"):
            receipt = replace(item.receipt, **({"capture": replace(item.receipt.capture)} if plant == "peer-capture-copy" else {}))
            changed = replace(item, receipt=receipt)
            forged = replace(run, executed=tuple(changed if e is item else e for e in ordered))
        else:
            forged = replace(run, executed=tuple(replace(e, value=item.value) if plant == "foreign-value" and e.receipt.capture.operation == stp.stp.OP else replace(e) for e in ordered))
        result = peer.finish(forged)
        assert len(result.rows) == 3 and len(result.executed) == 1
        assert [(r.target.node.id, r.group) for r in result.rows] == [("a", "4"), ("b", "1"), ("b", "2")]
        original = next(e for e in entries if e.receipt.capture.operation == ec.parse_summary.OP)
        assert result.executed[0].receipt is original.receipt and result.executed[0].value is original.value
        return
    if forged is run:
        forged = replace(run, executed=tuple(item if i == index else e for i, e in enumerate(entries)))
    writer = ec.bind_writer
    monkeypatch.setattr(ec, "bind_writer", lambda *args, **kwargs: pytest.fail("EC writer before finish validation"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        peer.finish(forged)
    monkeypatch.setattr(ec, "bind_writer", writer)
    assert len(peer.finish(run).rows) == 3
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        peer.finish(run)


def test_peer_only_global_run_preserves_ec_facts_with_empty_stp_population(tmp_path):
    side = scenario(tmp_path)
    side["targets"] = [t for t in side["targets"] if t["operation"] == ec.parse_summary.OP]
    side["captures"] = [c for c in side["captures"] if c["target"] == "ec"]
    (tmp_path / "tree.txt").unlink()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    peer, out = build(tmp_path)
    built = peer.finish(out.execution)
    assert out.result.rows == out.result.executed == () and len(out.execution.executed) == 1
    assert len(built.rows) == 3 and len(built.executed) == 1 and built.executed[0].value is out.execution.executed[0].value


def test_production_owner_getter_is_read_only_and_failed_prepare_cannot_publish_owner(tmp_path):
    scenario(tmp_path)
    good, out = build(tmp_path)
    peer = gp.SummaryPack[stp.stp.Result](LIMITS)
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        _ = peer.owner
    scenario(tmp_path, b"\xff")
    with pytest.raises(ValueError, match="^etherchannel_folder_text$"):
        stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        _ = peer.owner
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        peer.prepare(out.execution.envelope)
    owner = good.owner
    with pytest.raises(AttributeError):
        good.owner = None
    assert good.owner is owner


def test_owner_is_unavailable_when_the_final_prepared_constructor_fails(tmp_path, monkeypatch):
    scenario(tmp_path)
    _, out = build(tmp_path)
    peer = gp.SummaryPack[stp.stp.Result](LIMITS)
    class Refuse:
        @classmethod
        def __class_getitem__(cls, _):
            return cls
        def __init__(self, *args, **kwargs):
            raise RuntimeError("prepared construction failed")
    created, constructor = [], ec.ProtocolOwner
    def owned(*args):
        owner = constructor(*args)
        created.append(owner)
        return owner
    monkeypatch.setattr(ec, "ProtocolOwner", owned)
    monkeypatch.setattr(gp.p4_pipeline, "Prepared", Refuse)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("parser during preparation"))
    with pytest.raises(RuntimeError, match="^prepared construction failed$"):
        peer.prepare(out.execution.envelope)
    assert len(created) == 1 and type(created[0]) is constructor
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        _ = peer.owner


WITNESS = '''from pathlib import Path
from atlas_brain.evidence.admission import Budgets
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import global_parse as gp
def client(root: Path, budgets: Budgets) -> tuple[stp.GlobalFacts[ec.parse_summary.Result], ec.Result]:
    peer = gp.SummaryPack[stp.stp.Result](budgets)
    run = stp.build_root_guard_global(root, budgets, peers=(peer,))
    return run, peer.finish(run.execution)
def planted(run: stp.GlobalFacts[ec.parse_summary.Result]) -> str:
    return run.execution.executed[0].value
'''


def test_production_summary_handoff_keeps_strict_union_with_one_exact_hosted_negative(tmp_path):
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
    assert diagnostic["range"]["start"]["line"] == WITNESS.splitlines().index("    return run.execution.executed[0].value")
