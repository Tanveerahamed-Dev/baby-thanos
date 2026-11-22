"""Own actual census parser calls over one prepared folder, without receipt or fact authority."""
from dataclasses import dataclass
from pathlib import Path

from atlas_brain.evidence.admission import Budgets
from atlas_brain.evidence.capture import Capture
from atlas_brain.evidence.p4_admission import CaptureMember, Envelope, Target
from atlas_brain.evidence.parsekit import rules
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import build as brief
from atlas_brain.packs.l3.fhrp import census_parse_accounting as accounting
from atlas_brain.packs.l3.fhrp import census_product_snapshot as product_snapshot
from atlas_brain.packs.l3.fhrp import census_request_anchors as request_anchors
from atlas_brain.packs.l3.fhrp import census_requests as requests
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census
from atlas_brain.packs.l3.fhrp import reported_presence_context as context
from atlas_brain.packs.l3.fhrp import reported_presence_custody as custody
from atlas_brain.runner.pack_receipts import CaptureRequest
from atlas_brain.runner.pack_runtime import Parsed, Parser


def _need(value: bool, reason: str) -> None:
    k.require(value, "hsrp_census_owner_" + reason)


@dataclass(frozen=True, slots=True)
class _Emission:
    capture: Capture
    pair: Parsed[census.Result]
    original_parse: rules.ParseResult | None
    original_census: census.Census | None
    snapshot: tuple[object, ...]


type Birth = tuple[str, _Emission, Parsed[census.Result], census.Result,
                   rules.ParseResult, tuple[object, ...]]


def _check_prepared(plan: requests.Plan, budgets: Budgets) -> None:
    _need(type(plan) is requests.Plan and type(plan.envelope) is Envelope
          and type(plan.budgets) is Budgets and plan.budgets is budgets
          and type(plan.brief) is brief.StateOwner and type(plan.brief_bindings) is custody.PlanBindings
          and type(plan.scopes) is tuple and type(plan.request_values) is tuple, "plan")
    for scope in plan.scopes:
        _need(type(scope) is requests.Scope and type(scope.target) is Target and type(scope.source) is Target
              and type(scope.interface) is str and type(scope.key) is str
              and (scope.member is None or type(scope.member) is CaptureMember)
              and (scope.request is None or type(scope.request) is CaptureRequest)
              and (scope.member is None) == (scope.request is None), "plan")
    for value in plan.request_values:
        _need(type(value) is tuple and len(value) == 4 and type(value[0]) is str
              and type(value[1]) is CaptureRequest and type(value[2]) is Capture
              and type(value[2].raw) is bytes and type(value[3]) is bytes, "plan")


class CensusOwner(Parser[census.Result]):
    """Retain original parser products as comparison data for one owning invocation."""

    def __init__(self, root: Path, budgets: Budgets) -> None:
        plan = requests.prepare_census_folder(root, budgets)
        _check_prepared(plan, budgets)
        requests.validate_census_scopes(plan, budgets)
        self.plan = plan
        self.original_plan, self.original_scopes = plan, plan.scopes
        self.envelope, self.budgets = plan.envelope, budgets
        self.envelope_coordinates = requests.retain_envelope_coordinates(self.envelope)
        self.brief, self.bindings = plan.brief, plan.brief_bindings
        self.scopes = tuple((scope, scope.target, scope.source, scope.interface, scope.key, scope.member, scope.request)
                            for scope in plan.scopes)
        self.expected = plan.request_values
        self.anchors = tuple(request_anchors.retain_live_request(item[1]) for item in self.expected)
        self.coordinates = self.scopes, self.anchors
        self.attempted: set[str] = set()
        self.dispatched: tuple[str, ...] = ()
        self.emitted: dict[str, _Emission] = {}
        self.original_attempted, self.original_emitted = self.attempted, self.emitted
        self.births: tuple[Birth, ...] = ()
        self.dispatching = False
        CensusOwner.close_inputs(self)

    def checked_plan(self) -> requests.Plan:
        _need(type(self) is CensusOwner, "owner")
        plan = self.plan
        _need(type(plan) is requests.Plan and plan is self.original_plan and plan.envelope is self.envelope
              and type(self.brief) is brief.StateOwner and type(self.bindings) is custody.PlanBindings
              and plan.budgets is self.budgets and plan.brief is self.brief and plan.brief_bindings is self.bindings
              and plan.scopes is self.original_scopes and plan.request_values is self.expected, "plan")
        return plan

    def close_inputs(self) -> None:
        CensusOwner.checked_plan(self)
        current_values = context.request_values(tuple(item[1] for item in self.expected))
        CensusOwner.checked_plan(self)
        custody.validate_plan(self.bindings, self.brief, self.envelope, self.budgets)
        plan = CensusOwner.checked_plan(self)
        requests.close_envelope_coordinates(self.envelope, self.envelope_coordinates)
        _need(self.brief.finished is False and not self.bindings.produced, "brief")
        _need(type(plan.scopes) is tuple and type(self.coordinates) is tuple and len(self.coordinates) == 2
              and self.scopes is self.coordinates[0]
              and self.anchors is self.coordinates[1] and len(plan.scopes) == len(self.scopes), "scopes")
        for scope, (original, target, source, interface, key, member, request) in zip(plan.scopes, self.scopes, strict=True):
            _need(type(scope) is requests.Scope and scope is original and scope.target is target
                  and scope.source is source and type(scope.interface) is str and scope.interface == interface
                  and type(scope.key) is str and scope.key == key and scope.member is member and scope.request is request,
                  "scopes")
        _need(len(current_values) == len(self.expected), "inputs")
        for live, before, anchor in zip(current_values, self.expected, self.anchors, strict=True):
            _need(live[0] == before[0] and live[1] is before[1] and live[2] is before[2]
                  and type(live[2]) is Capture and live[2].raw is anchor.raw and live[3] == before[3], "inputs")
            request_anchors.validate_live_request(before[1], anchor)

    def close_emitted(self, pending: str | None = None) -> None:
        _need(type(self) is CensusOwner and type(self.attempted) is set and self.attempted is self.original_attempted
              and type(self.emitted) is dict and self.emitted is self.original_emitted
              and all(type(identity) is str for identity in self.attempted)
              and type(self.dispatched) is tuple and all(type(identity) is str for identity in self.dispatched)
              and all(type(identity) is str for identity in self.emitted) and type(self.births) is tuple
              and (pending is None or type(pending) is str)
              and all(type(row) is tuple and len(row) == 6 and type(row[0]) is str
                      and type(row[1]) is _Emission for row in self.births), "emissions")
        _need((pending is None or pending not in self.emitted)
              and set(self.emitted) | (set() if pending is None else {pending}) == self.attempted
              and self.attempted == set(self.dispatched) and len(self.dispatched) == len(self.attempted)
              and self.attempted <= {item[0] for item in self.expected} and len(self.emitted) == len(self.births),
              "emissions")
        expected: dict[str, Capture] = {identity: capture for identity, _, capture, _ in self.expected}
        for identity, item, pair, value, parsed, saved in self.births:
            _need(self.emitted.get(identity) is item and item.capture is expected.get(identity)
                  and item.pair is pair and type(pair) is tuple and len(pair) == 2
                  and pair[0] is value and pair[1] is parsed and item.snapshot is saved, "emissions")
            _need(type(value) is census.Result and value.parse is item.original_parse
                  and value.census is item.original_census
                  and product_snapshot.snapshot_product(value, parsed, item.capture) == saved, "emissions")

    def bound_request(self, request: CaptureRequest) -> tuple[str, request_anchors.RequestAnchor]:
        _need(type(self) is CensusOwner and type(request) is CaptureRequest and type(request.capture) is Capture
              and type(request.context) is str, "request")
        anchor = next((item for item in self.anchors
                       if item.capture is request.capture and request.context == item.context), None)
        if anchor is not None:
            request_anchors.validate_live_request(request, anchor)
            for _, _, _, interface, _, _, original in self.scopes:
                if original is not None and original.capture is anchor.capture:
                    return interface, anchor
        raise ValueError("hsrp_census_owner_request")

    def parse(self, request: CaptureRequest) -> Parsed[census.Result]:
        _need(type(self) is CensusOwner and self.dispatching is False, "reentry")
        self.dispatching = True
        try:
            CensusOwner.close_inputs(self)
            CensusOwner.close_emitted(self)
            interface, anchor = CensusOwner.bound_request(self, request)
            capture, identity, node, raw = anchor.capture, anchor.identity, anchor.node, anchor.raw
            _need(identity not in self.attempted, "request")
            operation, command = census.OP, census.COMMAND
            _need(type(operation) is str and operation == anchor.operation
                  and type(command) is str and command == anchor.command, "request")
            maximum_lines, births = len(anchor.lines), self.births
            request_anchors.validate_live_request(request, anchor)
            self.attempted.add(identity)
            self.dispatched += (identity,)
            dispatched = self.dispatched
            value = census.parse_capture(capture, node=node, interface=interface)
            _need(type(value) is census.Result, "result")
            source_parse, source_census = value.parse, value.census

            def reclose() -> None:
                CensusOwner.close_inputs(self)
                request_anchors.validate_live_request(request, anchor)
                _need(self.dispatching is True and self.births is births and self.dispatched is dispatched, "emissions")
                CensusOwner.close_emitted(self, pending=identity)
                _need(type(value) is census.Result and value.parse is source_parse
                      and value.census is source_census, "result")

            reclose()
            parsed = source_parse
            if parsed is None:
                parsed = accounting.refused_parse_accounting(value, raw, max_bytes=len(raw), max_lines=maximum_lines)
                reclose()
            pair = (value, parsed)
            values = product_snapshot.snapshot_product(value, parsed, capture)
            census.validate_product(capture, node=node, interface=interface, value=value)
            reclose()
            _need(product_snapshot.snapshot_product(value, parsed, capture) == values, "result")
            emission = _Emission(capture, pair, source_parse, source_census, values)
            self.emitted[identity] = emission
            self.births += ((identity, emission, pair, value, parsed, values),)
            return pair
        finally:
            if type(self) is CensusOwner:
                self.dispatching = False

    def close(self) -> tuple[Parsed[census.Result], ...]:
        """Reclose every produced pair, requiring the full supplied request population."""
        CensusOwner.close_inputs(self)
        CensusOwner.close_emitted(self)
        _need(len(self.emitted) == len(self.expected), "emissions")
        return tuple(self.emitted[identity].pair for identity, _, _, _ in self.expected)
