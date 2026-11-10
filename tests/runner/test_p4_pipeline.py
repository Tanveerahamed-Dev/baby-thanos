"""Two real packs through one P4 admission and global execution barrier."""
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
from atlas_brain.model import pack_registration as registration
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.packs.l2.etherchannel import parse_summary as channel
from atlas_brain.packs.l2.stp import build as tree_build
from atlas_brain.packs.l2.stp import parse as tree
from atlas_brain.runner import p4_pipeline as pipe
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Handler, Parsed, Parser

type Value = tree.Result | channel.Result
PORT = "GigabitEthernet1/0/1"
STP = tree_build.DECLARATION
STEP = StepSpec(id=StepId("l2.etherchannel/fixture"), pack=k.PackId("l2.etherchannel"), kind="parse_build", scope="device", reads=(), produces=(), evaluator="l2.etherchannel.uninstalled")
EC = registration.PackDeclaration(pack=STEP.pack, entity_kinds=(), facts=(), relations=(), steps=(STEP,),
                                 operations=(registration.OperationBinding(operation=channel.OP, step=STEP.id),))
LIMITS = pipe.Budgets(1000000, 1000000, 1000)
TREE_BYTES = (f"Port 1 ({PORT}) of VLAN0001 is designated forwarding\n".encode()
              + b"   Root guard is enabled on the port\n   Root guard is disabled on the port\n")
EC_BYTES = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
            b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")


def folder(root, captures=True, multiple=False):
    discovery = b"Device ID: fixture-b\n"
    base = canonical({"schema": "atlas-brain.synthetic-p2/1", "semantic_group": "declared_synthetic", "group": "demo",
        "nodes": [{"id": n, "discovery_id": "fixture-" + n, "ports": [PORT, "Gi1/0/1", "Gi1/0/2"]} for n in ("a", "b")],
        "captures": [{"path": "discovery.txt", "node": "a", "operation": "iosxe.show_cdp_neighbors_detail", "sha256": sha256(discovery).hexdigest()}]})
    files = {"p2.json": base, "discovery.txt": discovery}
    side = {"schema": pipe.p4.SCHEMA, "semantic_group": "declared_synthetic", "context": "round",
        "base_sha256": sha256(base).hexdigest(), "targets": [
            {"id": "tree", "node": "a", "operation": tree.OP, "params": {}},
            {"id": "channel", "node": "b", "operation": channel.OP, "params": {}}], "captures": []}
    for target, raw, path in (("tree", TREE_BYTES, "tree.txt"), ("channel", EC_BYTES, "channel.txt"),
                              ("channel", EC_BYTES, "again.txt"))[:3 if multiple else 2] if captures else ():
        files[path] = raw
        side["captures"].append({"target": target, "path": path, "sha256": sha256(raw).hexdigest()})
    for path, raw in (files | {"p4.json": canonical(side)}).items():
        (root / path).write_bytes(raw)


class Real(Parser[Value]):
    def __init__(self, trace, label):
        self.trace, self.label, self.outputs, self.failure = trace, label, {}, False

    def parse(self, request: CaptureRequest) -> Parsed[Value]:
        self.trace.append(("parse", self.label, request.capture.id))
        if self.failure:
            raise RuntimeError("planted_parser_failure")
        value = (tree.parse_capture(request.capture, PORT, (1,)) if self.label == tree.OP else
                 channel.parse_capture(request.capture, ("1", "2"), ("Gi1/0/1", "Gi1/0/2")))
        self.outputs[request.capture.id] = value
        return value, value.parse


class Provider(pipe.Pack[Value]):
    def __init__(self, declaration, handlers, trace):
        self.spec, self.handlers, self.trace = declaration, handlers, trace
        self.declared, self.environments, self.alternate = 0, [], None
        self.request_ops = {binding.operation for binding in declaration.operations}

    def declaration(self):
        self.declared += 1
        return self.spec if self.declared == 1 else self.alternate if self.alternate is not None else replace(self.spec, operations=())

    def prepare(self, envelope):
        self.environments.append(envelope)
        self.trace.append(("prepare", self.spec.pack))
        own = {binding.operation for binding in self.spec.operations}
        targets = tuple(t for t in envelope.targets if t.operation in own)
        requests = tuple(CaptureRequest(context=envelope.context, capture=Capture(id=m.id, source=m.target.node.key,
            operation=m.target.operation, rendered=tree.command(PORT) if m.target.operation == tree.OP else channel.COMMAND,
            codec="utf-8", raw=m.raw, integrity=k.IntegrityState.COMPLETE, lines=text_lines(m.raw, "utf-8"),
            read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)) for m in envelope.captures if m.target.operation in self.request_ops)
        return pipe.Prepared[Value](targets=targets, handlers=self.handlers, requests=requests)


def mutate(batch, envelope, fault):
    targets, handlers, requests = batch.targets, batch.handlers, batch.requests
    if fault == "prepare":
        raise ValueError("planted_prepare_failure")
    if fault == "prepared":
        return object()
    changes = {
        "targets-list": {"targets": list(targets)}, "targets-missing": {"targets": ()},
        "targets-double": {"targets": targets * 2}, "targets-copy": {"targets": tuple(replace(t) for t in targets)},
        "targets-other": {"targets": tuple(t for t in envelope.targets if t not in targets)},
        "handlers-list": {"handlers": list(handlers)}, "handlers-missing": {"handlers": ()},
        "handlers-double": {"handlers": handlers * 2},
        "handlers-owner": {"handlers": (replace(handlers[0], binding=replace(handlers[0].binding, step=tree_build.STEP.id)),)},
        "requests-list": {"requests": list(requests)}, "requests-missing": {"requests": ()},
        "requests-double": {"requests": requests * 2}}
    if fault in changes:
        if fault == "targets-copy":
            assert all(a == b and a is not b for a, b in zip(targets, changes[fault]["targets"], strict=True))
        return replace(batch, **changes[fault])
    request, = requests
    capture = request.capture
    fields = {"extra": {"id": k.CaptureId("cap:extra")}, "raw": {"raw": b"changed\n", "lines": text_lines(b"changed\n", "utf-8")},
        "source": {"source": k.EntityKey("node:demo:a")}, "operation": {"operation": tree.OP},
        "lines": {"lines": (replace(capture.lines[0], text="forged"),) + capture.lines[1:]}, "context": {}}
    return replace(batch, requests=(replace(request, capture=replace(capture, **fields[fault]),
        context="other" if fault == "context" else request.context),))


def providers(trace):
    parsers = {operation: Real(trace, operation) for operation in (tree.OP, channel.OP)}
    first = Provider(STP, tuple(Handler[Value](binding=b, parser=parsers[b.operation]) for b in STP.operations), trace)
    second = Provider(EC, tuple(Handler[Value](binding=b, parser=parsers[b.operation]) for b in EC.operations), trace)
    return (first, second), parsers


def test_real_folder_has_one_admission_one_global_dispatch_and_rich_union_results(tmp_path, monkeypatch):
    folder(tmp_path)
    trace, envelopes, executions = [], [], []
    packs, parsers = providers(trace)
    load, execute = pipe.p4.admit_folder, pipe.execute_parsers
    def tracked(function, records):
        def called(*args, **kwargs):
            value = function(*args, **kwargs)
            records.append((args, kwargs, value))
            return value
        return called
    monkeypatch.setattr(pipe.p4, "admit_folder", tracked(load, envelopes))
    monkeypatch.setattr(pipe, "execute_parsers", tracked(execute, executions))
    result = pipe.execute_p4_folder(tmp_path, LIMITS, packs=packs)
    assert len(envelopes) == len(executions) == 1 and result.envelope is envelopes[0][2] and result.executed is executions[0][2]
    assert executions[0][0][0] is envelopes[0][1]["declarations"]
    assert all(p.declared == len(p.environments) == 1 and p.environments[0] is result.envelope for p in packs)
    assert max(i for i, e in enumerate(trace) if e[0] == "prepare") < next(i for i, e in enumerate(trace) if e[0] == "parse")
    assert [x.receipt.capture.id for x in result.executed] == sorted(m.id for m in result.envelope.captures)
    for output in result.executed:
        receipt = output.receipt
        assert receipt.registration_sha256 == result.envelope.registration_sha256 == registration.compile_packs((STP, EC)).registration_sha256
        assert output.value is parsers[receipt.capture.operation].outputs[receipt.capture.id]
    tree_out = next(x.value for x in result.executed if x.receipt.capture.operation == tree.OP)
    channel_out = next(x.value for x in result.executed if x.receipt.capture.operation == channel.OP)
    assert tree_out.parse.quality == "complete" and tree_out.rows[0].reason is k.UnknownReason.CONFLICTING_EVIDENCE
    assert channel_out.missing_ports == ("Gi1/0/2",) and channel_out.rows[1].reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE


@pytest.mark.parametrize("fault,code", [
    ("prepare", "planted_prepare_failure"), ("prepared", "prepared"), ("targets-list", "targets"),
    ("targets-missing", "target_claims"), ("targets-double", "target_claims"), ("targets-copy", "target_claims"), ("targets-other", "target_claims"),
    ("handlers-list", "handlers"), ("handlers-missing", "handler_claims"), ("handlers-double", "handler_claims"), ("handlers-owner", "handler_claims"),
    ("requests-list", "requests"), ("requests-missing", "member_claims"), ("requests-double", "member_claims"), ("extra", "member_claims"),
    ("raw", "capture"), ("source", "capture"), ("operation", "capture"), ("context", "capture"), ("lines", "capture_lines")])
def test_second_pack_fault_refuses_before_the_single_dispatch(tmp_path, monkeypatch, fault, code):
    folder(tmp_path)
    trace = []
    packs, _ = providers(trace)
    prepare = packs[1].prepare
    monkeypatch.setattr(packs[1], "prepare", lambda envelope: mutate(prepare(envelope), envelope, fault))
    monkeypatch.setattr(pipe, "execute_parsers", lambda *args: pytest.fail("dispatch before all pack preflight"))
    with pytest.raises(ValueError, match="^" + ("" if fault == "prepare" else "p4_pipeline_") + code + "$"):
        pipe.execute_p4_folder(tmp_path, LIMITS, packs=packs)
    assert not [e for e in trace if e[0] == "parse"]


@pytest.mark.parametrize("plant", ["handlers", "requests", "uncollected", "unrequested"])
def test_global_coverage_cannot_hide_wrong_preparer_or_unrequested_registration(tmp_path, monkeypatch, plant):
    folder(tmp_path, captures=plant not in ("uncollected", "unrequested"))
    trace = []
    packs, _ = providers(trace)
    if plant == "handlers":
        packs[0].handlers, packs[1].handlers = packs[1].handlers, packs[0].handlers
    elif plant == "requests":
        packs[0].request_ops, packs[1].request_ops = packs[1].request_ops, packs[0].request_ops
    elif plant == "uncollected":
        prepare = packs[1].prepare
        monkeypatch.setattr(packs[1], "prepare", lambda envelope: replace(prepare(envelope), targets=()))
    else:
        packs[0].handlers = ()
    code = {"handlers": "handler_claims", "requests": "member_claims", "uncollected": "target_claims", "unrequested": "handler_claims"}[plant]
    monkeypatch.setattr(pipe, "execute_parsers", lambda *args: pytest.fail("globally complete but wrongly attributed"))
    with pytest.raises(ValueError, match="^p4_pipeline_" + code + "$"):
        pipe.execute_p4_folder(tmp_path, LIMITS, packs=packs)


@pytest.mark.parametrize("captures,multiple", [(False, False), (True, True)])
def test_empty_and_repeated_operation_members_remain_exact_under_pack_permutations(tmp_path, captures, multiple):
    folder(tmp_path, captures=captures, multiple=multiple)
    packs, _ = providers([])
    first = pipe.execute_p4_folder(tmp_path, LIMITS, packs=packs)
    reversed_packs, _ = providers([])
    second = pipe.execute_p4_folder(tmp_path, LIMITS, packs=tuple(reversed(reversed_packs)))
    assert first.executed == second.executed and first.envelope == second.envelope
    assert len(first.executed) == (0 if not captures else 3) and len(first.envelope.targets) == 2


@pytest.mark.parametrize("plant,code,error", [("list", "p4_pipeline_packs", ValueError), ("object", "p4_pipeline_pack", TypeError),
    ("duplicate", "duplicate_pack", ValueError), ("instance", "p4_pipeline_duplicate_pack_instance", ValueError)])
def test_invalid_static_composition_refuses_before_admission(tmp_path, monkeypatch, plant, code, error):
    packs, _ = providers([])
    packs[0].alternate = EC
    if plant == "duplicate":
        packs[1].spec = STP
    supplied = list(packs) if plant == "list" else (object(),) if plant == "object" else (packs[0], packs[0]) if plant == "instance" else packs
    monkeypatch.setattr(pipe.p4, "admit_folder", lambda *args, **kwargs: pytest.fail("admission before static composition"))
    with pytest.raises(error, match="^" + code + "$"):
        pipe.execute_p4_folder(tmp_path, LIMITS, packs=supplied)
    assert not any(p.environments for p in packs) and not packs[0].trace
    assert [p.declared for p in packs] == ([1, 1] if plant == "duplicate" else [0, 0])


def test_wrong_registration_and_parser_failure_never_return_a_completed_result(tmp_path, monkeypatch):
    folder(tmp_path)
    packs, parsers = providers([])
    original = pipe.p4.admit_folder
    def forged(*args, **kwargs):
        return replace(original(*args, **kwargs), registration_sha256="0" * 64)
    with monkeypatch.context() as context:
        context.setattr(pipe.p4, "admit_folder", forged)
        context.setattr(pipe, "execute_parsers", lambda *args: pytest.fail("dispatch with wrong registration"))
        with pytest.raises(ValueError, match="^p4_pipeline_registration$"):
            pipe.execute_p4_folder(tmp_path, LIMITS, packs=packs)
    packs, parsers = providers([])
    parsers[channel.OP].failure = True
    with pytest.raises(RuntimeError, match="^planted_parser_failure$"):
        pipe.execute_p4_folder(tmp_path, LIMITS, packs=packs)


WITNESS = '''from pathlib import Path
from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.p4_admission import Envelope, Target
from atlas_brain.model.pack_registration import OperationBinding, PackDeclaration
from atlas_brain.packs.l2.stp import parse as tree
from atlas_brain.packs.l2.etherchannel import parse_summary as channel
from atlas_brain.runner import p4_pipeline as p
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Executed, Handler, Parsed, Parser

type Value = tree.Result | channel.Result
class Tree(Parser[tree.Result]):
    def parse(self, request: CaptureRequest) -> Parsed[tree.Result]:
        value = tree.parse_capture(request.capture, "GigabitEthernet1/0/1", (1,))
        return value, value.parse
class Bundle(Parser[channel.Result]):
    def parse(self, request: CaptureRequest) -> Parsed[channel.Result]:
        value = channel.parse_capture(request.capture, ("1",), ("Gi1/0/1",))
        return value, value.parse
class Plugin(p.Pack[Value]):
    def __init__(self, spec: PackDeclaration, ready: p.Prepared[Value]) -> None: self.spec, self.ready = spec, ready
    def declaration(self) -> PackDeclaration: return self.spec
    def prepare(self, envelope: Envelope) -> p.Prepared[Value]: return p.Prepared[Value](targets=tuple(t for t in envelope.targets if t.id in {x.id for x in self.ready.targets}), handlers=self.ready.handlers, requests=self.ready.requests)
def mixed(root: Path, budgets: Budgets, a: PackDeclaration, b: PackDeclaration,
          x: OperationBinding, y: OperationBinding, first_targets: tuple[Target, ...], second_targets: tuple[Target, ...],
          first_requests: tuple[CaptureRequest, ...], second_requests: tuple[CaptureRequest, ...]) -> tuple[Executed[Value], ...]:
    first = p.Prepared[Value](targets=first_targets, handlers=(Handler[Value](binding=x, parser=Tree()),), requests=first_requests)
    second = p.Prepared[Value](targets=second_targets, handlers=(Handler[Value](binding=y, parser=Bundle()),), requests=second_requests)
    return p.execute_p4_folder(root, budgets, packs=(Plugin(a, first), Plugin(b, second))).executed
def planted(item: Executed[Value]) -> str:
    return item.value
'''


def test_strict_mixed_pack_client_and_exact_single_planted_diagnostic(tmp_path):
    (tmp_path / "witness.py").write_text(WITNESS, encoding="utf-8")
    config = {"include": ["witness.py"], "extraPaths": [str(Path(__file__).resolve().parents[2])],
              "pythonVersion": "3.14", "typeCheckingMode": "strict", "enableTypeIgnoreComments": False,
              "reportUnnecessaryTypeIgnoreComment": "error"}
    (tmp_path / "pyrightconfig.json").write_text(json.dumps(config), encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "pyright", "--outputjson", "--project", "pyrightconfig.json"],
                         cwd=tmp_path, capture_output=True, text=True, check=False, timeout=60)
    assert run.returncode == 1, (run.stdout, run.stderr)
    report = json.loads(run.stdout)
    print(json.dumps(report["generalDiagnostics"], indent=2))
    assert report["summary"]["errorCount"] == len(report["generalDiagnostics"]) == 1, report
    diagnostic, = report["generalDiagnostics"]
    assert (diagnostic["severity"], diagnostic["rule"]) == ("error", "reportReturnType"), diagnostic
    assert Path(diagnostic["file"]).resolve() == (tmp_path / "witness.py").resolve()
    assert diagnostic["range"]["start"]["line"] == WITNESS.splitlines().index("    return item.value")
