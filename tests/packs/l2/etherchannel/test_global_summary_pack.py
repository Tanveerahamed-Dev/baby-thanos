import json
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.kernel import states as k
from atlas_brain.packs.l2.etherchannel import build as facts
from atlas_brain.packs.l2.etherchannel import global_parse as ec
from atlas_brain.packs.l2.stp import build as stp

P = "GigabitEthernet1/0/1"
LIMITS = ec.Budgets(1000000, 1000000, 1000)
BODY = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
        b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")
TREE = f"Port 1 ({P}) of VLAN0001 is designated forwarding\n   Root guard is enabled on the port\n".encode()
OPEN = b"fixture#" + ec.parse_summary.COMMAND.encode() + b"\n"


def scenario(root, raw=BODY):
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [P, "Gi1/0/1", "Gi1/0/2", "Gi1/0/15", "Gi1/0/16", "Gi1/0/17"]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(discovery).hexdigest()}]})
    side = {"schema": ec.p4.SCHEMA, "semantic_group": "declared_synthetic", "context": "round", "base_sha256": sha256(base).hexdigest(),
        "targets": [{"id": "tree", "node": "a", "operation": stp.stp.OP, "params": {"port": P, "vlans": [1]}},
                    {"id": "ec", "node": "b", "operation": ec.parse_summary.OP, "params": {"groups": ["2", "1"], "ports": ["Gi1/0/1", "Gi1/0/2"]}}],
        "captures": [{"target": name, "path": name + ".txt", "sha256": sha256(data).hexdigest()} for name, data in (("tree", TREE), ("ec", raw))]}
    for name, data in {"p2.json": base, "discovery.txt": discovery, "tree.txt": TREE, "ec.txt": raw}.items():
        (root / name).write_bytes(data)
    (root / "p4.json").write_bytes(canonical(side))
    return side


def build(root):
    peer = ec.SummaryPack[stp.stp.Result](LIMITS)
    return peer, stp.build_root_guard_global(root, LIMITS, peers=(peer,))


@pytest.mark.parametrize("word,expected", [(b"LACP", ec.parse_summary.Protocol.LACP), (b"PAgP", ec.parse_summary.Protocol.PAGP), (b"-", ec.parse_summary.Protocol.NONE)])
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
@pytest.mark.parametrize("frame", ["bare", "command", "prompt"])
def test_two_production_parsers_preserve_original_global_objects_and_source_custody(tmp_path, monkeypatch, word, expected, ending, frame):
    raw = BODY.replace(b"LACP", word)
    raw = raw if frame == "bare" else (OPEN + raw + b"fixture#\n" if frame == "prompt" else ec.parse_summary.COMMAND.encode() + b"\n" + raw)
    raw = raw.replace(b"\n", ending)
    side, seen = scenario(tmp_path, raw), {}
    peer = ec.SummaryPack[stp.stp.Result](LIMITS)
    def watch(obj, name, tag):
        original = getattr(obj, name)
        def traced(*args, **kwargs):
            value = original(*args, **kwargs)
            seen.setdefault(tag, []).append(value)
            return value
        monkeypatch.setattr(obj, name, traced)
    for obj, name, tag in ((peer, "declaration", "declaration"), (peer, "prepare", "prepare"),
        (ec.p4_pipeline, "execute_p4_folder", "run"), (ec.p4_pipeline.p4, "admit_folder", "admit"),
        (ec.parse_summary, "parse_capture", "ec"), (stp.stp, "parse_capture", "stp")):
        watch(obj, name, tag)
    monkeypatch.setattr(facts, "execute_parsers", lambda *args: pytest.fail("singleton EC execution"))
    out = stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    assert all(len(items) == 1 for items in seen.values()) and set(seen) == {"declaration", "prepare", "run", "admit", "ec", "stp"}
    run = out.execution
    assert run is seen["run"][0] and run.envelope is seen["admit"][0]
    own = next(e for e in run.executed if e.receipt.capture.operation == ec.parse_summary.OP)
    assert own.value is seen["ec"][0] and own.receipt.parse is own.value.parse and own.receipt.capture is seen["prepare"][0].requests[0].capture
    assert len(run.executed) == 2 and own.value.missing_ports == ("Gi1/0/2",) and tuple(r.group for r in own.value.rows) == ("1", "2")
    assert dict(own.value.rows[0].fields)["protocol"].value is expected and own.value.rows[1].reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    assert own.receipt.owner == facts.STEP.id and own.receipt.registration_sha256 == run.envelope.registration_sha256 == out.result.executed[0].receipt.registration_sha256
    assert out.result.store.owners == {spec[0]: spec[2] for spec in stp.projection_contract()} and out.result.rows[0].value.value is True
    member = next(m for m in run.envelope.captures if m.target.operation == ec.parse_summary.OP)
    capture, target = own.receipt.capture, member.target
    assert seen["prepare"][0].targets == (target,) and seen["prepare"][0].targets[0] is target
    assert capture.id == member.id and capture.source == target.node.key and capture.raw == member.raw == raw and capture.bytes_sha256 == member.sha256 == sha256(raw).hexdigest()
    assert capture.rendered == ec.parse_summary.COMMAND and capture.scope.node == capture.source and capture.scope.plane == "exec"
    assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN and capture.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    refs = (target.node.declaration.evidence[0], run.envelope.declaration.evidence[0], target.declaration.evidence[0])
    assert {r.table for r in refs} == {"synthetic_p2.nodes", "synthetic_p4.context", "synthetic_p4.targets"} and all(type(r) is k.RegistryRef for r in refs)
    assert all(r.table_digest == sha256((tmp_path / "p2.json").read_bytes() if r.table == "synthetic_p2.nodes" else canonical(side)).hexdigest() for r in refs)


@pytest.mark.parametrize("raw,integrity,reason", [(b"", k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
    (ec.parse_summary.COMMAND.encode() + b"\n", k.IntegrityState.EMPTY, k.UnknownReason.EMPTY_UNREGISTERED),
    *[(prefix + damage, integrity, reason) for prefix in (b"", OPEN) for damage, integrity, reason in
      ((b"% Invalid input\n", k.IntegrityState.ERROR, k.UnknownReason.CAPTURE_ERROR),
       (BODY + b"--More--\n", k.IntegrityState.PAGING_ARTIFACTS, k.UnknownReason.CAPTURE_TRUNCATED),
       (BODY + b"[truncated]\n", k.IntegrityState.TRUNCATED, k.UnknownReason.CAPTURE_TRUNCATED))],
    *[(prefix + BODY, k.IntegrityState.UNKNOWN_FORMAT, k.UnknownReason.PARSE_UNSUPPORTED_VARIANT) for prefix in
      (b"unrecognised summary\n", "Flags:\u00a0D - down P - bundled in port-channel\n".encode(), "Flags:\u2003D - down P - bundled in port-channel\n".encode())]])
def test_damaged_empty_or_unknown_ec_bytes_remain_honest_opaque_results(tmp_path, raw, integrity, reason):
    scenario(tmp_path, raw)
    _, out = build(tmp_path)
    own = next(e for e in out.execution.executed if e.receipt.owner == facts.STEP.id)
    assert own.receipt.capture.integrity is integrity and own.value.reason is reason
    assert all(r.reason is reason for r in own.value.rows)


@pytest.mark.parametrize("spacing", [b"  ", b"\t"])
def test_checked_in_flags_legend_keeps_raw_framing_and_parser_quality(tmp_path, spacing):
    raw = (Path(__file__).resolve().parents[4] / "fixtures/tier-p/iosxe/show-etherchannel-summary/raw.txt").read_bytes().replace(b"Flags:  D", b"Flags:" + spacing + b"D")
    side = scenario(tmp_path, raw)
    side["targets"][1]["params"] = {"groups": ["10"], "ports": ["Gi1/0/15", "Gi1/0/16", "Gi1/0/17"]}
    (tmp_path / "p4.json").write_bytes(canonical(side))
    _, out = build(tmp_path)
    own = next(e for e in out.execution.executed if e.receipt.owner == facts.STEP.id)
    assert own.receipt.capture.raw == raw and own.receipt.capture.integrity is k.IntegrityState.COMPLETE and own.value.reason is (None if spacing == b"  " else k.UnknownReason.PARSE_PARTIAL)
    assert dict(own.value.rows[0].fields)["protocol"].value is ec.parse_summary.Protocol.PAGP
    assert tuple(m.port.raw for m in own.value.rows[0].members) == ("Gi1/0/15", "Gi1/0/16", "Gi1/0/17")


@pytest.mark.parametrize("plant,code", [(b"\xff", "etherchannel_folder_text"), (BODY + b"\r", "etherchannel_folder_text"),
    (BODY + b"\x00", "etherchannel_folder_text"), *[(BODY + c.encode(), "etherchannel_folder_text") for c in ("\u0085", "\u2028", "\u2029")],
    (b"other#show version\n% Invalid input\n", "etherchannel_folder_frame"), (OPEN + BODY, "etherchannel_folder_frame"),
    (OPEN + BODY + b"--More--\nother#\n", "etherchannel_folder_frame"), ("groups", "etherchannel_folder_strings"),
    ("ports", "synthetic_undeclared_port"), ("extra", "invalid_record_fields"), ("target", "etherchannel_duplicate_target"), ("duplicate", "etherchannel_duplicate_target_capture")])
def test_late_ec_preparation_faults_precede_both_real_parsers_and_stp_writer(tmp_path, monkeypatch, plant, code):
    side = scenario(tmp_path, plant if type(plant) is bytes else BODY)
    if plant in ("groups", "ports", "extra"):
        side["targets"][1]["params"].update({"groups": [True]} if plant == "groups" else {"ports": ["Gi99"]} if plant == "ports" else {"rendered": "show version"})
    elif plant == "target":
        side["targets"].append({"id": "ec2", "node": "b", "operation": ec.parse_summary.OP, "params": {"groups": ["3"], "ports": []}})
    elif plant == "duplicate":
        (tmp_path / "again.txt").write_bytes(BODY)
        side["captures"].append({"target": "ec", "path": "again.txt", "sha256": sha256(BODY).hexdigest()})
    (tmp_path / "p4.json").write_bytes(canonical(side))
    for obj, name in ((ec.parse_summary, "parse_capture"), (stp.stp, "parse_capture"), (stp, "bind_writer")):
        monkeypatch.setattr(obj, name, lambda *args, **kwargs: pytest.fail("execution before complete EC preparation"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        build(tmp_path)


def test_uncaptured_ec_targets_remain_claimed_and_peer_free_capture_population_is_valid(tmp_path, monkeypatch):
    side = scenario(tmp_path)
    side["captures"] = [r for r in side["captures"] if r["target"] != "ec"]
    (tmp_path / "ec.txt").unlink()
    (tmp_path / "p4.json").write_bytes(canonical(side))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("uncaptured EC parsed"))
    peer, out = build(tmp_path)
    assert len(out.execution.envelope.targets) == 2 and len(out.execution.executed) == 1
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        peer.prepare(out.execution.envelope)
    side["targets"] = side["targets"][:1]
    (tmp_path / "p4.json").write_bytes(canonical(side))
    _, empty = build(tmp_path)
    assert len(empty.execution.envelope.targets) == len(empty.execution.executed) == 1


@pytest.mark.parametrize("plant,code", [("context", "etherchannel_folder_declaration"), ("target", "etherchannel_folder_declaration"),
    ("params", "etherchannel_folder_target"), ("node", "etherchannel_folder_node"), ("node-ref", "etherchannel_folder_declaration"),
    ("registry", "etherchannel_folder_declaration"), ("group", "etherchannel_folder_declaration"), ("raw", "etherchannel_folder_member"), ("id", "etherchannel_folder_member")])
def test_public_prepare_binds_original_registry_rows_before_accepting_an_envelope(tmp_path, monkeypatch, plant, code):
    scenario(tmp_path)
    _, out = build(tmp_path)
    env = out.execution.envelope
    target = next(t for t in env.targets if t.operation == ec.parse_summary.OP)
    if plant == "context":
        forged = replace(env, declaration=replace(env.declaration, basis=k.Basis.OBSERVED))
    elif plant in ("registry", "group"):
        forged = replace(env, raw=env.raw + b"\n") if plant == "registry" else replace(env, base=replace(env.base, declaration=replace(env.base.declaration, basis=k.Basis.OBSERVED)))
    elif plant in ("target", "params", "node", "node-ref"):
        node = replace(target.node, ports=tuple(p for p in target.node.ports if p != "Gi1/0/2")) if plant == "node" else (
            replace(target.node, declaration=replace(target.node.declaration, basis=k.Basis.OBSERVED)) if plant == "node-ref" else target.node)
        changed = replace(target, node=node, **({"declaration": replace(target.declaration, basis=k.Basis.OBSERVED)} if plant == "target" else
            {"params": canonical({"groups": ["1"], "ports": []})} if plant == "params" else {}))
        forged = replace(env, targets=tuple(changed if t is target else t for t in env.targets),
            base=replace(env.base, nodes=tuple(node if n is target.node else n for n in env.base.nodes)),
            captures=tuple(replace(m, target=changed) if m.target is target else m for m in env.captures))
    else:
        forged = replace(env, captures=tuple(replace(m, **({"raw": BODY + b"changed"} if plant == "raw" else {"id": k.CaptureId("cap:forged")})) if m.target is target else m for m in env.captures))
    peer = ec.SummaryPack[stp.stp.Result](LIMITS)
    monkeypatch.setattr(ec.parse_summary, "parse_capture", lambda *args: pytest.fail("parser inside failed preparation"))
    with pytest.raises(ValueError, match="^" + code + "$"):
        peer.prepare(forged)
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        peer.prepare(env)


def test_failed_parser_consumes_prepare_attempt_and_requires_a_fresh_adapter(tmp_path, monkeypatch):
    scenario(tmp_path)
    peer, parser = ec.SummaryPack[stp.stp.Result](LIMITS), ec.parse_summary.parse_capture
    def failed(*args):
        raise RuntimeError("EC parser failed")
    monkeypatch.setattr(ec.parse_summary, "parse_capture", failed)
    with pytest.raises(RuntimeError, match="^EC parser failed$"):
        stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    monkeypatch.setattr(ec.parse_summary, "parse_capture", parser)
    with pytest.raises(ValueError, match="^etherchannel_global_run$"):
        stp.build_root_guard_global(tmp_path, LIMITS, peers=(peer,))
    assert build(tmp_path)[1].result.rows[0].value.value is True


WITNESS = '''from pathlib import Path
from atlas_brain.evidence.admission import Budgets
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l2.etherchannel import global_parse as ec
def client(root: Path, budgets: Budgets) -> stp.GlobalFacts[ec.parse_summary.Result]:
    peer = ec.SummaryPack[stp.stp.Result](budgets)
    return stp.build_root_guard_global(root, budgets, peers=(peer,))
def planted(run: stp.GlobalFacts[ec.parse_summary.Result]) -> str:
    return run.execution.executed[0].value
'''


def test_production_summary_peer_keeps_strict_union_with_one_exact_hosted_negative(tmp_path):
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
