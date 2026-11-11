"""Global STP production adapter with a real opaque EtherChannel peer."""
import json
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.etherchannel import parse_summary as channel
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Parsed, Parser

type Value = b.stp.Result | channel.Result
P = "GigabitEthernet1/0/1"
LIMITS = pipe.Budgets(1000000, 1000000, 1000)
TABLES = {"synthetic_p2.nodes", "synthetic_p4.context", "synthetic_p4.targets"}
HEADER = f"Port 1 ({P}) of VLAN0001 is designated forwarding\n".encode()
BODY = HEADER + b"   Root guard is enabled on the port\n"
EC_BYTES = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
            b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")


def scenario(raw=BODY, tree_capture=True, tree_targets=True):
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [P, "Gi1/0/1", "Gi1/0/2"]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(discovery).hexdigest()}]})
    files = {"p2.json": base, "discovery.txt": discovery, "channel.txt": EC_BYTES}
    targets = [{"id": "t" + str(i), "node": n, "operation": b.stp.OP, "params": {"port": P, "vlans": [2, 1] if i == 0 else [1]}}
               for i, n in enumerate(("a", "b"))] if tree_targets else []
    targets.append({"id": "ec", "node": "b", "operation": channel.OP, "params": {}})
    captures = [{"target": "ec", "path": "channel.txt", "sha256": sha256(EC_BYTES).hexdigest()}]
    if tree_capture:
        files["tree.txt"] = raw
        captures.append({"target": "t0", "path": "tree.txt", "sha256": sha256(raw).hexdigest()})
    return files, {"schema": pipe.p4.SCHEMA, "semantic_group": "declared_synthetic", "context": "round",
                   "base_sha256": sha256(base).hexdigest(), "targets": targets, "captures": captures}


def write(root, files, side):
    for path, raw in (files | {"p4.json": canonical(side)}).items():
        (root / path).write_bytes(raw)


class ECParser(Parser[channel.Result]):
    def __init__(self, events, failure=False):
        self.events, self.failure, self.outputs = events, failure, {}

    def parse(self, request: CaptureRequest) -> Parsed[channel.Result]:
        self.events.append(("parse", "ec", request.capture.id))
        if self.failure:
            raise RuntimeError("peer_parser_failed")
        result = channel.parse_capture(request.capture, ("1", "2"), ("Gi1/0/1", "Gi1/0/2"))
        self.outputs[request.capture.id] = result
        return result, result.parse


class Peer(pipe.Pack[Value]):
    def __init__(self, events, failure=""):
        self.events, self.failure = events, failure
        self.parser = ECParser(events, failure == "parser")

    def declaration(self):
        self.events.append(("declaration", "ec"))
        return ec.DECLARATION

    def prepare(self, envelope):
        self.events.append(("prepare", "ec"))
        targets = tuple(t for t in envelope.targets if t.operation == channel.OP)
        requests = tuple(CaptureRequest(context="wrong" if self.failure == "prepare" else envelope.context,
            capture=Capture(id=m.id, source=m.target.node.key, operation=channel.OP, rendered=channel.COMMAND,
                raw=m.raw, codec="utf-8", integrity=k.IntegrityState.COMPLETE, lines=text_lines(m.raw, "utf-8"),
                read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN))
            for m in envelope.captures if m.target.operation == channel.OP)
        return pipe.Prepared[Value](targets=targets, handlers=(pipe.Handler[Value](binding=ec.BINDING, parser=self.parser),), requests=requests)


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("word", [b"enabled", b"disabled"])
def test_real_global_run_preserves_full_registration_objects_and_provenance_before_writes(tmp_path, monkeypatch, ending, word):
    files, side = scenario(BODY.replace(b"enabled", word).replace(b"\n", ending))
    write(tmp_path, files, side)
    events, calls, writes = [], [], []
    peer = Peer(events)
    real, parse, writer = b.p4_pipeline.execute_p4_folder, b.stp.parse_capture, FactWriter.write
    def traced(*args, **kwargs):
        own = kwargs["packs"][0]
        declaration, prepare = own.declaration, own.prepare
        def declared():
            events.append(("declaration", "stp"))
            return declaration()
        def prepared(envelope):
            events.append(("prepare", "stp"))
            return prepare(envelope)
        monkeypatch.setattr(own, "declaration", declared)
        monkeypatch.setattr(own, "prepare", prepared)
        result = real(*args, **kwargs)
        calls.append(result)
        return result
    def parsed(*args):
        events.append(("parse", "stp", args[0].id))
        return parse(*args)
    def checked(self, **kwargs):
        assert TABLES == {r.table for r in kwargs["value"].evidence if type(r) is k.RegistryRef}
        assert all(r.table_digest == sha256(files["p2.json"] if r.table == "synthetic_p2.nodes" else canonical(side)).hexdigest() for r in kwargs["value"].evidence if type(r) is k.RegistryRef)
        writes.append(kwargs["value"])
        return writer(self, **kwargs)
    monkeypatch.setattr(b.p4_pipeline, "execute_p4_folder", traced)
    monkeypatch.setattr(b.stp, "parse_capture", parsed)
    monkeypatch.setattr(FactWriter, "write", checked)
    monkeypatch.setattr(b, "execute_parsers", lambda *args: pytest.fail("singleton parser rerun"))
    out = b.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    assert len(calls) == 1 and out.execution is calls[0]
    assert all(events.count((kind, pack)) == 1 for kind in ("declaration", "prepare") for pack in ("stp", "ec"))
    assert sum(e[0] == "parse" for e in events) == 2
    assert max(i for i, e in enumerate(events) if e[0] == "prepare") < next(i for i, e in enumerate(events) if e[0] == "parse")
    assert len(out.execution.executed) == 2 and len(out.result.executed) == 1 and len(out.result.rows) == 3
    own, = out.result.executed
    original = next(e for e in out.execution.executed if e.receipt.capture.operation == b.stp.OP)
    foreign = next(e for e in out.execution.executed if e.receipt.capture.operation == channel.OP)
    assert own.receipt is original.receipt and own.value is original.value
    assert foreign.value is peer.parser.outputs[foreign.receipt.capture.id] and foreign.value.missing_ports == ("Gi1/0/2",)
    assert own.receipt.registration_sha256 == foreign.receipt.registration_sha256 == out.execution.envelope.registration_sha256
    known, = [row for row in out.result.rows if type(row.value) is k.Known]
    assert known.value.value is (word == b"enabled") and known.value.raw == word.decode()
    assert writes == [row.value for row in out.result.rows]
    refs = [r for r in known.value.evidence if type(r) is k.EvidenceRef]
    assert len(refs) == 5 and all(r.capture == own.receipt.capture.id and r.excerpt_sha256 == sha256(own.receipt.capture.raw[r.locator.start:r.locator.end]).hexdigest() for r in refs)


def test_missing_or_peer_only_input_keeps_declared_population_without_root_parser_calls(tmp_path, monkeypatch):
    files, side = scenario()
    write(tmp_path, files, side)
    first = b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),))
    side["captures"] = [row for row in side["captures"] if row["target"] == "ec"]
    files.pop("tree.txt")
    (tmp_path / "tree.txt").unlink()
    write(tmp_path, files, side)
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("uncaptured STP parsed"))
    missing = b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),))
    assert [r.subject for r in missing.result.rows] == [r.subject for r in first.result.rows]
    assert all(r.value.reason is k.UnknownReason.NOT_COLLECTED for r in missing.result.rows)
    assert all(TABLES <= {p.table for p in r.value.evidence if type(p) is k.RegistryRef} for r in missing.result.rows)
    write(tmp_path, *scenario(tree_capture=False, tree_targets=False))
    peer_only = b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),))
    assert peer_only.result.rows == peer_only.result.executed == () and len(peer_only.execution.executed) == 1


@pytest.mark.parametrize("failure", ["prepare", "parser"])
def test_peer_failure_never_opens_a_fact_writer_and_a_fresh_retry_succeeds(tmp_path, monkeypatch, failure):
    write(tmp_path, *scenario())
    real_writer = b.bind_writer
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before global completion"))
    with pytest.raises(ValueError if failure == "prepare" else RuntimeError, match="^" + ("p4_pipeline_capture" if failure == "prepare" else "peer_parser_failed") + "$"):
        b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([], failure),))
    monkeypatch.setattr(b, "bind_writer", real_writer)
    assert len(b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),)).result.rows) == 3


@pytest.mark.parametrize("plant,code", [("environment", "stp_global_run"), ("missing", "stp_global_coverage"),
    ("missing-peer", "stp_global_coverage"), ("duplicate", "stp_global_coverage"), ("extra", "stp_global_coverage"), ("owner", "stp_global_receipt"),
    ("operation", "stp_global_receipt"), ("source", "stp_global_receipt"), ("raw", "stp_global_receipt"), ("context", "stp_global_receipt"),
    ("registration", "stp_global_receipt"), *[(f"peer-{field}", "stp_global_receipt") for field in ("owner", "operation", "source", "raw", "context", "registration")], ("capture", "stp_global_capture"), ("value", "stp_global_value"),
    ("unknown", "stp_global_value"), ("coherent", "stp_global_value"), ("parse", "stp_global_value"), ("containers", None), ("foreign-value", None)])
def test_returned_global_result_is_checked_before_fact_writing(tmp_path, monkeypatch, plant, code):
    write(tmp_path, *scenario())
    execute = b.p4_pipeline.execute_p4_folder
    def forged(*args, plant=plant, **kwargs):
        run = execute(*args, **kwargs)
        entries = run.executed
        index = next(i for i, e in enumerate(entries) if e.receipt.capture.operation == (channel.OP if plant.startswith("peer-") else b.stp.OP))
        plant = plant.removeprefix("peer-")
        item = entries[index]
        if plant == "environment":
            return replace(run, envelope=replace(run.envelope))
        if plant in ("missing", "missing-peer"):
            removed = index if plant == "missing" else next(i for i, e in enumerate(entries) if e.receipt.capture.operation == channel.OP)
            return replace(run, executed=tuple(e for i, e in enumerate(entries) if i != removed))
        if plant == "duplicate":
            return replace(run, executed=entries + (item,))
        if plant == "extra":
            receipt = replace(item.receipt, capture=replace(item.receipt.capture, id=k.CaptureId("cap:extra")))
            return replace(run, executed=entries + (replace(item, receipt=receipt),))
        if plant in ("owner", "operation", "source", "raw", "context", "registration", "capture"):
            receipt = item.receipt
            changes = {"source": {"capture": replace(receipt.capture, source=k.EntityKey("node:other"))}, "owner": {"owner": b.STEP.id if receipt.owner == ec.STEP.id else ec.STEP.id}, "context": {"context": "other"},
                "registration": {"registration_sha256": "0" * 64},
                "operation": {"capture": replace(receipt.capture, operation=b.stp.OP if receipt.capture.operation == channel.OP else channel.OP)},
                "raw": {"capture": replace(receipt.capture, raw=BODY + b"changed", lines=text_lines(BODY + b"changed", "utf-8"))},
                "capture": {"capture": replace(receipt.capture)}}[plant]
            item = replace(item, receipt=replace(item.receipt, **changes))
        elif plant == "coherent":
            parsed = replace(item.value.parse, quality="partial")
            value = replace(item.value, parse=parsed, reason=k.UnknownReason.PARSE_PARTIAL, rows=tuple(replace(r, reason=k.UnknownReason.PARSE_PARTIAL) for r in item.value.rows))
            item = replace(item, value=value, receipt=replace(item.receipt, parse=parsed))
        elif plant in ("value", "unknown", "parse"):
            value = item.value if plant == "parse" else replace(item.value, **({"reason": k.UnknownReason.PARSE_PARTIAL} if plant == "unknown" else {}))
            item = replace(item, value=value, receipt=replace(item.receipt, parse=replace(item.receipt.parse)) if plant == "parse" else item.receipt)
        elif plant in ("containers", "foreign-value"):
            return replace(run, executed=tuple(replace(e, value=item.value) if plant == "foreign-value" and e.receipt.capture.operation == channel.OP else replace(e) for e in entries))
        return replace(run, executed=tuple(item if i == index else e for i, e in enumerate(entries)))
    monkeypatch.setattr(b.p4_pipeline, "execute_p4_folder", forged)
    if code is None:
        result = b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),))
        assert len(result.result.rows) == 3 and len(result.result.executed) == 1 and len(result.execution.executed) == 2
        assert plant != "foreign-value" or all(type(e.value) is b.stp.Result for e in result.execution.executed)
    else:
        monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("writer before returned-run validation"))
        with pytest.raises(ValueError, match="^" + code + "$"):
            b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),))


def test_bad_peer_collection_refuses_before_global_callbacks(tmp_path, monkeypatch):
    monkeypatch.setattr(b.p4_pipeline, "execute_p4_folder", lambda *args, **kwargs: pytest.fail("invalid peers reached global core"))
    with pytest.raises(ValueError, match="^stp_global_peers$"):
        b.build_root_guard_global(tmp_path, LIMITS, peers=[])


def test_duplicate_owned_capture_refuses_before_either_parser_or_writer(tmp_path, monkeypatch):
    files, side = scenario()
    files["again.txt"] = BODY
    side["captures"].append({"target": "t0", "path": "again.txt", "sha256": sha256(BODY).hexdigest()})
    write(tmp_path, files, side)
    monkeypatch.setattr(b.stp, "parse_capture", lambda *args: pytest.fail("duplicate STP target parsed"))
    monkeypatch.setattr(channel, "parse_capture", lambda *args: pytest.fail("peer parsed before duplicate target refusal"))
    monkeypatch.setattr(b, "bind_writer", lambda *args, **kwargs: pytest.fail("duplicate target writer"))
    with pytest.raises(ValueError, match="^stp_duplicate_target_capture$"):
        b.build_root_guard_global(tmp_path, LIMITS, peers=(Peer([]),))


WITNESS = '''from pathlib import Path
from atlas_brain.evidence.admission import Budgets
from atlas_brain.packs.l2.stp import build as b
from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.packs.l2.etherchannel import parse_summary as ec
from atlas_brain.runner.p4_pipeline import Pack
type Value = stp.Result | ec.Result
def client(root: Path, budgets: Budgets, peers: tuple[Pack[Value], ...]) -> b.GlobalFacts[ec.Result]:
    return b.build_root_guard_global(root, budgets, peers=peers)
def planted(result: b.GlobalFacts[ec.Result]) -> str:
    return result.execution.executed[0].value
'''


def test_production_peer_union_remains_typed_with_one_exact_hosted_negative(tmp_path):
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
    assert diagnostic["range"]["start"]["line"] == WITNESS.splitlines().index("    return result.execution.executed[0].value")
