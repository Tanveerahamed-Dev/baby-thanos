"""A vendor-neutral command or lookalike fields cannot establish an IOS-XE capture."""
from pathlib import Path

import pytest

from atlas_brain.kernel.states import Known
from atlas_brain.packs.platform.system.build import build_capture
from atlas_brain.runner.evidence import analyse_evidence
from atlas_brain.runner.records import RunnerRefused

FRAGMENT = (
    b"sw-a uptime is 1 day, 2 hours, 3 minutes\n"
    b'System image file is "bootflash:packages.conf"\n'
    b"Last reload reason: PowerOn\n"
)


def admit(tmp_path: Path, raw: bytes):
    (tmp_path / "show-version.txt").write_bytes(raw)
    capture, = analyse_evidence(tmp_path)
    return capture


@pytest.mark.parametrize("header", (
    b"Cisco Nexus Operating System (NX-OS) Software\n",
    b"NX-OS Software, Version 9.3\n",
    b"Cisco IOS XR Software, Version 7.8\n",
    b"Arista Networks EOS version 4.28.1\n",
    b"JUNOS Software Release [22.1]\n",
    b"unrecognized vendor or command output\n",
))
@pytest.mark.parametrize("prompt", (b"", b"sw-a#show version\n"))
def test_foreign_or_unknown_header_with_matching_fields_refuses(tmp_path, header, prompt):
    with pytest.raises(RunnerRefused, match="^evidence_unsupported_capture$"):
        admit(tmp_path, prompt + header + FRAGMENT)


@pytest.mark.parametrize("raw", (
    b"sw-a#show version\n",
    b"sw-a#show version\nsw-a uptime is 1 day\nsw-a#\n",
    b"sw-a#\n",
))
def test_prompt_alone_does_not_establish_platform(tmp_path, raw):
    with pytest.raises(RunnerRefused, match="^evidence_unsupported_capture$"):
        admit(tmp_path, raw)


@pytest.mark.parametrize("raw", (
    FRAGMENT,
    b"sw-a#show version\n" + FRAGMENT + b"sw-a#\n",
    b"\n" + FRAGMENT + b"\n",
    b"Cisco IOS XE Software, Version 17.09.04a\n" + FRAGMENT,
))
def test_positive_twin_preserves_raw_bytes_and_observed_fields(tmp_path, raw):
    capture = admit(tmp_path, raw)
    assert capture.raw == raw
    fields = build_capture(capture)
    assert all(isinstance(field, Known) for field in (fields.uptime, fields.image, fields.reload_reason))


def test_huge_uptime_integer_is_unknown_without_unbounded_integer_decode(tmp_path):
    raw = b"Cisco IOS XE Software, Version 17.09.04a\nsw-a uptime is " + b"9" * 5000 + b" days\n"
    fields = build_capture(admit(tmp_path, raw))
    assert fields.uptime.reason == "parse_partial"
    assert fields.uptime.detail == "invalid_uptime_integer"
