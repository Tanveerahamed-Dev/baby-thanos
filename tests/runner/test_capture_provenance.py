"""Synthetic response-boundary regressions through the public runner CLI."""
import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BANNER = b"Cisco IOS XE Software, Version 17.09.04a\n"
FRAGMENT = (
    b"sw-a uptime is 1 day, 2 hours, 3 minutes\n"
    b'System image file is "bootflash:packages.conf"\n'
    b"Last reload reason: PowerOn\n"
)
SAMPLE = BANNER + FRAGMENT
MOTD_CAPTURE = (
    b"sw-a#show running-config\n"
    b"Building configuration...\n!\nbanner motd ^C\n"
    + SAMPLE
    + b"^C\nend\nsw-a#\n"
)


def cli(evidence, out):
    return subprocess.run(
        [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
         "--out", str(out), "--workers", "1"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )


def snapshot(root):
    if not root.exists():
        return None
    return {
        path.relative_to(root).as_posix():
            ("directory", None) if path.is_dir() else ("file", path.read_bytes())
        for path in root.rglob("*")
    }


def assert_refused(tmp_path, members, code="evidence_unsupported_capture", *, existing=False):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name, raw in members.items():
        (evidence / name).write_bytes(raw)
    out = tmp_path / "out"
    if existing:
        out.mkdir()
        (out / "SUMMARY.txt").write_bytes(b"prior summary must survive\n")
        (out / "MANIFEST.json").write_bytes(b'{"prior": "manifest must survive"}\n')
        (out / "keep").mkdir()
        (out / "keep" / "sentinel.bin").write_bytes(b"\x00retained\xff")
    evidence_before, out_before = snapshot(evidence), snapshot(out)
    completed = cli(evidence, out)
    assert completed.returncode == 2, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert completed.stderr == f"runner refused: {code}\n"
    assert snapshot(evidence) == evidence_before
    assert snapshot(out) == out_before


CONTEXT_REFUSALS = [
    pytest.param(MOTD_CAPTURE, id="running-config-motd"),
    pytest.param(b"Building configuration...\nbanner motd ^C\n" + SAMPLE + b"^C\nend\n",
                 id="config-without-command-echo"),
    pytest.param(b"sw-a#show running-config\n" + SAMPLE, id="wrong-command-echo"),
    pytest.param(b"unrelated command output\n" + SAMPLE, id="arbitrary-prefix"),
    pytest.param(b"Cisco IOS XE Softwareish, Version 17.09.04a\n" + FRAGMENT,
                 id="banner-prefix-lookalike"),
    pytest.param(BANNER + b"sw-a#show running-config\n" + FRAGMENT,
                 id="interior-command"),
    pytest.param(BANNER + b"sw-a(config)#hostname sw-a\n" + FRAGMENT,
                 id="configuration-mode-prompt"),
    pytest.param(BANNER + b"sw-a#\n" + FRAGMENT, id="interior-bare-prompt"),
    pytest.param(SAMPLE + b"sw-a#show clock\n", id="trailing-command"),
    pytest.param(b"sw-a#show version\n" + SAMPLE + b"sw-a#show version\n" + SAMPLE,
                 id="concatenated-command-responses"),
    pytest.param(SAMPLE + SAMPLE, id="second-platform-banner"),
    pytest.param(b"sw-a#show version\n" + SAMPLE + b"sw-b#\n",
                 id="conflicting-terminal-host"),
    pytest.param(b"sw-a#show version\n" + SAMPLE + b"sw-a>\n",
                 id="conflicting-terminal-mode"),
    pytest.param(BANNER + b"Building configuration...\n" + FRAGMENT,
                 id="building-configuration-in-body"),
    pytest.param(BANNER + b"Current configuration : 123 bytes\n" + FRAGMENT,
                 id="current-configuration-in-body"),
    pytest.param(BANNER + b"banner motd ^C\n" + FRAGMENT + b"^C\n",
                 id="banner-directive-in-body"),
    pytest.param(BANNER + b"show running-config\n" + FRAGMENT,
                 id="bare-command-in-body"),
    pytest.param(SAMPLE + b"Cisco Nexus Operating System (NX-OS) Software\n",
                 id="mixed-nxos-response"),
    pytest.param(SAMPLE + b"Cisco IOS XR Software, Version 7.8\n",
                 id="mixed-iosxr-response"),
    pytest.param(SAMPLE + b"Arista Networks EOS version 4.28.1\n",
                 id="mixed-eos-response"),
    pytest.param(SAMPLE + b"JUNOS Software Release [22.1]\n",
                 id="mixed-junos-response"),
    pytest.param(BANNER + b"BANNER MOTD ^C\n" + FRAGMENT + b"^C\n",
                 id="uppercase-banner-directive-in-body"),
    pytest.param(BANNER + b"ShOw RuNnInG-CoNfIg\n" + FRAGMENT,
                 id="mixedcase-command-in-body"),
    pytest.param(BANNER + b"sh run\n" + FRAGMENT,
                 id="abbreviated-sh-command-in-body"),
    pytest.param(BANNER + b"sho run\n" + FRAGMENT,
                 id="abbreviated-sho-command-in-body"),
    pytest.param(BANNER + b"do sh run\n" + FRAGMENT,
                 id="do-abbreviated-command-in-body"),
    pytest.param(SAMPLE + b"   " + BANNER,
                 id="indented-second-platform-banner"),
    pytest.param(SAMPLE + b"cIsCo iOs xE sOfTwArE, Version 17.09.04a\n",
                 id="mixedcase-second-platform-banner"),
]


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("raw", CONTEXT_REFUSALS)
def test_cli_refuses_marker_free_context_conflicts_without_outputs(tmp_path, raw, newline):
    # These cases must fail on response context, independently of error/pager markers.
    assert b"%" not in raw
    assert all(marker not in raw.lower()
               for marker in (b"--more--", b"<--- more --->", b"[truncated]", b"--(more)--"))
    assert_refused(tmp_path, {"show-version.txt": raw.replace(b"\n", newline)})


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("bad_name", ["aa-invalid.txt", "zz-invalid.txt"])
@pytest.mark.parametrize("existing", [False, True], ids=["absent-output", "existing-output"])
def test_one_config_member_refuses_whole_folder_without_any_mutation(
        tmp_path, newline, bad_name, existing):
    assert_refused(tmp_path, {
        "valid.txt": SAMPLE.replace(b"\n", newline),
        bad_name: MOTD_CAPTURE.replace(b"\n", newline),
    }, existing=existing)


@pytest.mark.parametrize("separator", [
    pytest.param(b"\r", id="bare-cr"),
    pytest.param("\u0085".encode("utf-8"), id="unicode-nel"),
    pytest.param("\u2028".encode("utf-8"), id="unicode-line-separator"),
    pytest.param("\u2029".encode("utf-8"), id="unicode-paragraph-separator"),
])
def test_non_capture_line_separators_have_stable_invalid_text_refusal(tmp_path, separator):
    raw = BANNER + FRAGMENT.replace(b"\n", separator)
    assert_refused(tmp_path, {"show-version.txt": raw}, "evidence_invalid_text")


@pytest.mark.parametrize("marker,code", [
    (b"% Invalid input detected at '^' marker.\n", "evidence_capture_error"),
    (b"Command authorization failed\n", "evidence_capture_error"),
    (b"--More--", "evidence_capture_incomplete"),
])
def test_existing_error_and_pager_refusals_precede_context_refusal(tmp_path, marker, code):
    assert_refused(tmp_path, {"show-version.txt": MOTD_CAPTURE + marker}, code)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("raw", [
    pytest.param(SAMPLE, id="raw-response"),
    pytest.param(b"\n" + SAMPLE + b"\n", id="blank-edges"),
    pytest.param(b"sw-a#show version\n" + SAMPLE + b"sw-a#\n",
                 id="prompt-wrapped-response"),
    pytest.param(b"sw-a> show version\n" + SAMPLE + b"sw-a>\n",
                 id="prompt-with-space"),
    pytest.param(FRAGMENT, id="headerless-fragment"),
    pytest.param(b"sw-a#show version\n" + FRAGMENT + b"sw-a#\n",
                 id="prompt-wrapped-fragment"),
    pytest.param(SAMPLE + b"sw-a#\n", id="raw-response-terminal-prompt"),
    pytest.param(FRAGMENT + b"sw-a#\n", id="fragment-terminal-prompt"),
    # Generated grammar example, not a captured device fixture.
    pytest.param(
        BANNER
        + b"Cisco IOS Software [Synthetic], Synthetic Switch Software, Version 17.09.04a\n"
        + b"Copyright (c) 2000-2026 Synthetic Example Authors\n"
        + b"Technical Support: https://example.invalid/support\n"
        + b"ROM: IOS-XE ROMMON\n"
        + FRAGMENT
        + b"License Level: synthetic-lab\n"
        + b"Next reload license Level: synthetic-lab\n"
        + b"cisco SYNTHETIC-TEST chassis with 1024K bytes of memory.\n"
        + b"Configuration register is 0x102\n",
        id="full-synthetic-response-with-descriptive-lines",
    ),
    *[
        pytest.param(
            header + FRAGMENT.replace(b"sw-a uptime", hostname + b" uptime"),
            id=f"hostname-{hostname.decode('ascii')}-{'headered' if header else 'headerless'}",
        )
        for hostname in (
            b"banner", b"show", b"Arista-switch", b"NX-OS-switch", b"JUNOS", b"Building"
        )
        for header in (BANNER, b"")
    ],
])
def test_valid_single_response_twins_preserve_known_values_and_raw_provenance(
        tmp_path, raw, newline):
    raw = raw.replace(b"\n", newline)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    source = evidence / "show-version.txt"
    source.write_bytes(raw)
    before = snapshot(evidence)
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert snapshot(evidence) == before
    manifest = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["evidence"]["files"] == 1
    assert len(manifest["facts"]) == 1
    capture_id, facts = next(iter(manifest["facts"].items()))
    expected = {
        "uptime": ([[1, "day"], [2, "hour"], [3, "minute"]], b"1 day, 2 hours, 3 minutes"),
        "image": ("bootflash:packages.conf", b"bootflash:packages.conf"),
        "reload_reason": ("PowerOn", b"PowerOn"),
    }
    assert set(facts) == set(expected) | {"boot_epoch"}
    for name, (value, excerpt) in expected.items():
        fact = facts[name]
        assert fact["state"] == "known"
        assert fact["value"] == value
        assert fact["basis"] == "observed"
        assert len(fact["evidence"]) == 1
        ref = fact["evidence"][0]
        assert ref["capture"] == capture_id
        assert ref["locator"] == "bytes"
        assert 0 <= ref["start"] < ref["end"] <= len(raw)
        assert raw[ref["start"]:ref["end"]] == excerpt
        assert ref["sha256"] == sha256(excerpt).hexdigest()
    boot = facts["boot_epoch"]
    assert boot["state"] == "unknown"
    assert boot["reason"] == "as_of_missing"
    assert boot["detail"] == "no_collector_time"
    assert "value" not in boot
    assert boot["evidence"] == [{
        "capture": capture_id, "locator": "whole_capture",
        "sha256": sha256(raw).hexdigest(),
    }]
