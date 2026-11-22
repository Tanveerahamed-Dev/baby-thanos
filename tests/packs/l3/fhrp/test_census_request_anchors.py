"""Compare the live cached fields of a real capture without preparing another one."""
from dataclasses import replace

import pytest
from test_parse_hsrp_census import EMPTY, _capture

from atlas_brain.packs.l3.fhrp import census_request_anchors as anchors
from atlas_brain.runner.pack_receipts import CaptureRequest


@pytest.mark.parametrize("change", ["none", "id", "lines", "span"])
def test_original_census_request_anchor_covers_live_coordinates_and_lines(change):
    capture = _capture(EMPTY, codec="utf-8")
    request = CaptureRequest(capture=capture, context="round")
    held = anchors.retain_live_request(request)
    if change == "none":
        anchors.validate_live_request(request, held)
        return
    if change == "id":
        class OpenId(str):
            def __hash__(self):
                raise AssertionError("hashed open ID")

        object.__setattr__(capture, "id", OpenId(capture.id))
    elif change == "lines":
        lines = (replace(capture.lines[0], text="different"), *capture.lines[1:])
        object.__setattr__(capture, "lines", lines)
    else:
        span = capture.lines[0].span
        object.__setattr__(span, "start", span.start + 1)
    with pytest.raises(ValueError, match="^hsrp_census_request$"):
        anchors.validate_live_request(request, held)
