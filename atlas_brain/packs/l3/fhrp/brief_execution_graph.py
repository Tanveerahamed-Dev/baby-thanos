"""Close current HSRP BRIEF execution graphs; never admission or execution seals.

Trusted callers retain and reclose original owners, plans, requests, raw bytes,
budgets, registration and population. In particular, StateOwner.own needs its
original expected/produced mappings closed separately before use. This helper
neither establishes those bindings nor authorizes proof or result publication.
"""
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.parsekit.rules import ParseResult
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_hsrp_brief as brief
from atlas_brain.packs.l3.fhrp.version_inputs import validate_fhrp_request_graph
from atlas_brain.runner.pack_receipts import CaptureRequest, ParseReceipt
from atlas_brain.runner.pack_runtime import Executed


def validate_brief_execution_graph[T](outputs: tuple[Executed[T], ...]) -> None:
    """Close carriers before filtering; validate BRIEF claims after capture closure."""
    k.require(
        type(outputs) is tuple
        and all(type(output) is Executed and type(output.receipt) is ParseReceipt
                for output in outputs),
        "hsrp_brief_execution_graph",
    )
    for output in outputs:
        receipt = output.receipt
        k.require(
            type(receipt.capture) is Capture and type(receipt.parse) is ParseResult
            and type(receipt.owner) is str and bool(receipt.owner)
            and type(receipt.registration_sha256) is str
            and (
                receipt.context is None
                or type(receipt.context) is str and bool(receipt.context)
            ),
            "hsrp_brief_execution_graph",
        )
        k.digest(receipt.registration_sha256)
    for output in outputs:
        receipt = output.receipt
        validate_fhrp_request_graph(
            CaptureRequest(capture=receipt.capture, context=receipt.context),
        )
    for output in outputs:
        if output.receipt.capture.operation == brief.OP:
            value = output.value
            if type(value) is not brief.Result:
                raise ValueError("hsrp_brief_execution_graph")
            k.require(output.receipt.parse is value.parse, "hsrp_brief_execution_graph")
            brief.validate_claims(output.receipt.capture, value)
