"""Census owner fixture readiness over an admitted capture and the real parser."""
from census_owner_cases import observe_parser, zero_frame
from census_request_cases import input_folder
from test_gateway_source import LIMITS

from atlas_brain.packs.l3.fhrp import census_requests as requests
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census


def test_observer_retains_the_original_real_parser_result(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    wire = zero_frame()
    input_folder(root, wire)
    plan = requests.prepare_census_folder(root, LIMITS)
    scope = next(scope for scope in plan.scopes if scope.target.id == "census-b")
    assert scope.request is not None and scope.member is not None
    capture = scope.request.capture
    assert capture.raw is scope.member.raw and capture.raw == wire
    assert scope.target.node.key == "node:demo:b" and scope.interface == "BD10"

    calls = observe_parser(monkeypatch)
    value = census.parse_capture(capture, node=scope.target.node.key, interface=scope.interface)
    (observed_capture, node, interface, observed_value), = calls
    assert observed_capture is capture and observed_value is value
    assert (node, interface) == ("node:demo:b", "BD10")
    assert value.census.groups == () and value.parse.quality == "complete"
