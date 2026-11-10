"""Hosted parser execution contracts, real pack results and strict mixed-type usage."""
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import StepId, StepSpec
from atlas_brain.packs.l2.etherchannel import parse_summary as channel
from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.runner import pack_runtime
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Handler, Parsed, Parser, execute_parsers


def pack(name, *operations):
    identity = k.PackId("test." + name)
    owner = StepId(identity + "/parse")
    step = StepSpec(id=owner, pack=identity, kind="parse_build", scope="device", reads=(), produces=(),
                    evaluator=identity + ".uninstalled")
    return PackDeclaration(pack=identity, entity_kinds=(), facts=(), relations=(), steps=(step,),
                           operations=tuple(OperationBinding(operation=op, step=owner) for op in operations))


def request(identity, operation, *, raw=b"synthetic\n", rendered="show synthetic"):
    capture = Capture(id=k.CaptureId("cap:" + identity), source=k.EntityKey("node:fixture"),
                      operation=operation, rendered=rendered, codec="utf-8", raw=raw,
                      integrity=k.IntegrityState.COMPLETE, lines=text_lines(raw, "utf-8"),
                      read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)
    return CaptureRequest(capture=capture, context="context:" + identity)


class Probe(Parser[object]):
    def __init__(self, label, trace):
        self.label, self.trace = label, trace
        self.failure = None
        self.outputs = {}

    def parse(self, request):
        self.trace.append((self.label, request))
        if self.failure == "exception":
            raise RuntimeError("parser refusal")
        parse = ParseResult((), (), (), "partial")
        if self.failure == "wrong-envelope":
            return parse
        if self.failure == "wrong-parse":
            return Parsed(value=object(), parse="partial")
        output = Parsed(value=object(), parse=parse)
        self.outputs[request.capture.id] = output
        return output


def setup_plan():
    alpha = pack("alpha", "collect.alpha", "collect.alias")
    beta = pack("beta", "collect.beta")
    trace = []
    handlers = tuple(Handler(binding=b, parser=Probe(b.operation, trace)) for b in alpha.operations + beta.operations)
    requests = (request("c", "collect.beta"), request("b", "collect.alias"), request("a", "collect.beta"),
                request("d", "collect.alpha"))
    return (alpha, beta), handlers, requests, trace


@pytest.mark.parametrize("reverse", [False, True])
def test_dispatch_is_per_operation_and_capture_once_in_id_order(reverse):
    packs, handlers, requests, trace = setup_plan()
    source = {item.capture.id: item for item in requests}
    if reverse:
        packs, handlers, requests = tuple(reversed(packs)), tuple(reversed(handlers)), tuple(reversed(requests))
    actual = execute_parsers(packs, handlers, requests)
    assert [(name, item.capture.id) for name, item in trace] == [
        ("collect.beta", "cap:a"), ("collect.alias", "cap:b"), ("collect.beta", "cap:c"),
        ("collect.alpha", "cap:d")]
    digest = compile_packs(packs).registration_sha256
    for executed, (_, supplied) in zip(actual, trace, strict=True):
        original = source[supplied.capture.id]
        assert supplied == original and supplied.capture is original.capture
        handler = next(h for h in handlers if h.binding.operation == supplied.capture.operation)
        expected = handler.parser.outputs[supplied.capture.id]
        assert executed.value is expected.value and executed.receipt.parse is expected.parse
        assert executed.receipt.capture is supplied.capture and executed.receipt.context == supplied.context
        assert executed.receipt.owner == handler.binding.step and executed.receipt.registration_sha256 == digest


@pytest.mark.parametrize("plant,code", [
    ("duplicate-pack", "duplicate_pack"), ("missing-handler", "pack_runtime_handler_coverage"),
    ("extra-handler", "pack_runtime_handler_coverage"), ("duplicate-handler", "pack_runtime_duplicate_handler"), ("wrong-owner", "pack_runtime_handler_owner"),
])
@pytest.mark.parametrize("empty", [False, True])
def test_complete_composition_is_verified_before_any_call_even_for_absent_operations(plant, code, empty):
    packs, handlers, requests, trace = setup_plan()
    # Only beta is requested. A defect in the unused alpha mapping must still refuse.
    supplied = () if empty else (requests[2],)
    alpha, alias, beta = handlers
    if plant == "duplicate-pack":
        packs = packs + (packs[0],)
    elif plant == "missing-handler":
        handlers = (alias, beta)
    elif plant == "extra-handler":
        handlers = handlers + (replace(alpha, binding=replace(alpha.binding, operation="collect.extra")),)
    elif plant == "duplicate-handler":
        handlers = handlers + (alias,)
    else:
        handlers = (replace(alpha, binding=replace(alpha.binding, step=beta.binding.step)), alias, beta)
    with pytest.raises(ValueError, match="^" + code + "$"):
        execute_parsers(packs, handlers, supplied)
    assert trace == []


@pytest.mark.parametrize("plant,code", [
    ("unregistered", "pack_runtime_unregistered_operation"), ("missing-operation", "pack_runtime_unregistered_operation"),
    ("duplicate-id", "pack_runtime_duplicate_capture"), ("bad-element", "pack_runtime_requests"),
])
def test_late_bad_request_cannot_follow_an_earlier_parser_call(plant, code):
    packs, handlers, requests, trace = setup_plan()
    first, later = requests[2], requests[3]
    if plant == "duplicate-id":
        later = replace(later, capture=replace(later.capture, id=first.capture.id))
    elif plant == "bad-element":
        later = later.capture
    else:
        op = None if plant == "missing-operation" else "collect.unregistered"
        later = replace(later, capture=replace(later.capture, operation=op))
    with pytest.raises(ValueError, match="^" + code + "$"):
        execute_parsers(packs, handlers, (first, later))
    assert trace == []


@pytest.mark.parametrize("plant,code", [
    (lambda h, r: (list(h), r), "pack_runtime_handlers"),
    (lambda h, r: (h + (object(),), r), "pack_runtime_handlers"),
    (lambda h, r: (h, list(r)), "pack_runtime_requests"),
    (lambda h, r: ((replace(h[0], binding="collect.alpha"),) + h[1:], r), "pack_runtime_binding"),
    (lambda h, r: ((replace(h[0], parser=object()),) + h[1:], r), "pack_runtime_parser"),
])
def test_closed_shapes_refuse_before_execution(plant, code):
    packs, handlers, requests, trace = setup_plan()
    with pytest.raises(ValueError, match="^" + code + "$"):
        handlers, requests = plant(handlers, requests)
        execute_parsers(packs, handlers, requests)
    assert trace == []


def test_empty_and_subset_inputs_run_only_supplied_captures():
    packs, handlers, requests, trace = setup_plan()
    assert execute_parsers((), (), ()) == execute_parsers(packs, handlers, ()) == ()
    assert trace == []
    actual, = execute_parsers(packs, handlers, (requests[1],))
    assert actual.receipt.capture is requests[1].capture
    assert trace == [("collect.alias", requests[1])]


@pytest.mark.parametrize("mode,error,code", [
    ("exception", RuntimeError, "parser refusal"), ("wrong-envelope", ValueError, "pack_runtime_result"),
    ("wrong-parse", ValueError, "pack_runtime_parse"),
])
def test_handler_failure_stops_later_calls_and_raises_to_caller(mode, error, code):
    packs, handlers, requests, trace = setup_plan()
    handlers[1].parser.failure = mode
    with pytest.raises(error, match="^" + code + "$"):
        execute_parsers(packs, handlers, requests)
    assert [(name, item.capture.id) for name, item in trace] == [
        ("collect.beta", "cap:a"), ("collect.alias", "cap:b")]


def test_custody_refusal_after_all_calls_reaches_the_caller(monkeypatch):
    packs, handlers, requests, trace = setup_plan()

    def refuse(declarations, authoritative, receipts):
        assert declarations == packs and authoritative == requests
        assert len(receipts) == len(requests)
        assert {item.capture.id for item in receipts} == {item.capture.id for item in requests}
        raise ValueError("planted_custody_refusal")

    monkeypatch.setattr(pack_runtime, "validate_receipts", refuse)
    with pytest.raises(ValueError, match="^planted_custody_refusal$"):
        execute_parsers(packs, handlers, requests)
    assert len(trace) == len(requests)


def test_real_parsers_retain_semantic_results_and_their_exact_accounting():
    port = "GigabitEthernet1/0/1"
    tree_pack, bundle_pack = pack("tree", stp.OP), pack("bundle", channel.OP)
    calls = []

    class Tree(Parser[stp.Result]):
        def parse(self, request):
            result = stp.parse_capture(request.capture, port, (1,))
            calls.append((request, result))
            return Parsed(value=result, parse=result.parse)

    class Bundle(Parser[channel.Result]):
        def parse(self, request):
            result = channel.parse_capture(request.capture, ("1", "2"), ("Gi1/0/1", "Gi1/0/2"))
            calls.append((request, result))
            return Parsed(value=result, parse=result.parse)

    stp_bytes = (b"Port 1 (GigabitEthernet1/0/1) of VLAN0001 is designated forwarding\n"
                 b"   Root guard is enabled on the port\n   Root guard is disabled on the port\n")
    ec_bytes = (b"Number of channel-groups in use: 1\nNumber of aggregators: 1\nGroup Port-channel Protocol Ports\n"
                b"--+--+--+--\n1 Po1(SU) LACP Gi1/0/1(P)\n")
    tree = request("tree", stp.OP, raw=stp_bytes, rendered=stp.command(port))
    bundle = request("bundle", channel.OP, raw=ec_bytes, rendered=channel.COMMAND)
    handlers = (Handler(binding=tree_pack.operations[0], parser=Tree()),
                Handler(binding=bundle_pack.operations[0], parser=Bundle()))
    ec_out, stp_out = execute_parsers((tree_pack, bundle_pack), handlers, (tree, bundle))
    assert [supplied for supplied, _ in calls] == [bundle, tree]
    assert ec_out.value is calls[0][1] and stp_out.value is calls[1][1]
    assert stp_out.receipt.parse is stp_out.value.parse and stp_out.receipt.parse.quality == "complete"
    assert stp_out.value.rows[0].reason is k.UnknownReason.CONFLICTING_EVIDENCE
    assert ec_out.receipt.parse is ec_out.value.parse and ec_out.value.missing_ports == ("Gi1/0/2",)
    found, absent = ec_out.value.rows
    assert absent.reason is k.UnknownReason.SUBJECT_ABSENT_FROM_CAPTURE
    member, = found.members
    assert ec_bytes[member.span.start:member.span.end] == b"Gi1/0/1(P)"


def test_trusted_adapter_can_pair_real_stp_rows_with_separate_accounting():
    port = "GigabitEthernet1/0/1"
    separate = ParseResult((), (), (), "complete")

    class Adapter(Parser[stp.Result]):
        def parse(self, request):
            self.result = stp.parse_capture(request.capture, port, (1,))
            return Parsed(value=self.result, parse=separate)

    declaration, adapter = pack("tree", stp.OP), Adapter()
    raw = f"Port 1 ({port}) of VLAN0001 is designated forwarding\n".encode("ascii")
    supplied = request("tree", stp.OP, raw=raw, rendered=stp.command(port))
    handler = Handler(binding=declaration.operations[0], parser=adapter)
    executed, = execute_parsers((declaration,), (handler,), (supplied,))
    assert executed.value is adapter.result and executed.value.parse.records
    assert executed.receipt.parse is separate and separate.records == ()
    assert executed.value.parse is not executed.receipt.parse


TYPE_WITNESS = '''from atlas_brain.model.pack_registration import OperationBinding, PackDeclaration
from atlas_brain.packs.l2.etherchannel import parse_summary as channel
from atlas_brain.packs.l2.stp import parse as stp
from atlas_brain.runner import pack_runtime as runtime
from atlas_brain.runner.pack_receipts import CaptureRequest

type Value = stp.Result | channel.Result

class Tree(runtime.Parser[stp.Result]):
    def parse(self, request: CaptureRequest) -> runtime.Parsed[stp.Result]:
        result = stp.parse_capture(request.capture, "GigabitEthernet1/0/1", (1,))
        return runtime.Parsed(value=result, parse=result.parse)

class Bundle(runtime.Parser[channel.Result]):
    def parse(self, request: CaptureRequest) -> runtime.Parsed[channel.Result]:
        result = channel.parse_capture(request.capture, ("1",), ("Gi1/0/1",))
        return runtime.Parsed(value=result, parse=result.parse)

def mixed(packs: tuple[PackDeclaration, ...], tree: OperationBinding, channel_op: OperationBinding,
          requests: tuple[CaptureRequest, ...]) -> tuple[runtime.Executed[Value], ...]:
    handlers: tuple[runtime.Handler[Value], ...] = (
        runtime.Handler(binding=tree, parser=Tree()),
        runtime.Handler(binding=channel_op, parser=Bundle()),
    )
    return runtime.execute_parsers(packs, handlers, requests)

def planted(item: runtime.Executed[Value]) -> str:
    return item.value
'''


def test_strict_pyright_accepts_mixed_real_types_and_rejects_the_planted_return(tmp_path):
    (tmp_path / "witness.py").write_text(TYPE_WITNESS, encoding="utf-8")
    config = {"include": ["witness.py"], "extraPaths": [str(Path(__file__).resolve().parents[2])],
              "pythonVersion": "3.14", "typeCheckingMode": "strict", "enableTypeIgnoreComments": False,
              "reportUnnecessaryTypeIgnoreComment": "error"}
    (tmp_path / "pyrightconfig.json").write_text(json.dumps(config), encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "pyright", "--outputjson", "--project", "pyrightconfig.json"],
                         cwd=tmp_path, capture_output=True, text=True, check=False, timeout=60)
    assert run.returncode == 1, (run.stdout, run.stderr)
    report = json.loads(run.stdout)
    assert report["summary"]["errorCount"] == 1, report
    assert len(report["generalDiagnostics"]) == 1, report["generalDiagnostics"]
    diagnostic = report["generalDiagnostics"][0]
    assert (diagnostic["severity"], diagnostic["rule"]) == ("error", "reportReturnType"), diagnostic
    assert Path(diagnostic["file"]).resolve() == (tmp_path / "witness.py").resolve()
    assert diagnostic["range"]["start"]["line"] == TYPE_WITNESS.splitlines().index("    return item.value")
