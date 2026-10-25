"""Synthetic P1 bare full-command and closed Autostate-token regressions."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.kernel import states as k
from atlas_brain.packs.l1.interface.build import build_capture
from atlas_brain.runner.evidence import analyse_evidence
from atlas_brain.runner.records import RunnerRefused

ROOT = Path(__file__).resolve().parents[4]
OUTPUTS = ("SUMMARY.txt", "MANIFEST.json")
ECHO = b"show interfaces\n"
HEADER = b"Vlan123 is up, line protocol is up , Autostate Enabled\n"


def admitted(tmp_path, raw):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "capture.txt"
    target.write_bytes(raw)
    capture, = analyse_evidence(evidence)
    assert capture.raw == raw == target.read_bytes()
    assert capture.rendered == "show interfaces" and capture.operation == "iosxe.show_interfaces"
    assert capture.read_scope is k.ReadScope.UNKNOWN and capture.view is k.ViewConsistency.UNKNOWN
    return capture


def assert_refs(fact, capture):
    for ref in fact.evidence:
        assert ref.capture == capture.id
        if isinstance(ref.locator, k.ByteSpan):
            assert 0 <= ref.locator.start < ref.locator.end <= len(capture.raw)
            raw = capture.raw[ref.locator.start:ref.locator.end]
        else:
            assert isinstance(ref.locator, k.WholeCapture)
            raw = capture.raw
        assert ref.excerpt_sha256 == sha256(raw).hexdigest()


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("echo", [b"", b"\nshow interfaces\n\n"])
@pytest.mark.parametrize("status,oper,admin,verdict", [
    ("up", "up", "up", "ok"), ("up", "down", "up", "problem"),
    ("administratively down", "up", "down", "problem"),
    ("administratively down", "down", "down", "ok"),
    ("down", "up", None, "unknown"), ("down", "down", None, "unknown"),
])
def test_exact_full_tokens_preserve_observations(tmp_path, newline, echo, status, oper, admin, verdict):
    token = oper + " , Autostate Enabled"
    raw = (echo + f"Vlan123 is {status}, line protocol is {token}\n".encode()).replace(b"\n", newline)
    capture = admitted(tmp_path, raw)
    result = build_capture(capture)
    row, = result.interfaces
    assert result.observed == 1 and result.parse.quality == "complete"
    assert row.verdict == verdict and row.name.value == "Vlan123"
    assert isinstance(row.oper, k.Known) and row.oper.value == oper and row.oper.raw == token
    oper_ref = row.oper.evidence[0].locator
    assert isinstance(oper_ref, k.ByteSpan) and raw[oper_ref.start:oper_ref.end] == token.encode()
    if admin is None:
        assert isinstance(row.admin, k.Unknown) and row.admin.reason is k.UnknownReason.NOT_OBSERVABLE
    else:
        assert isinstance(row.admin, k.Known) and row.admin.value == admin
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN and result.coverage.next_evidence
    for fact in (row.name, row.admin, row.oper, result.coverage):
        assert_refs(fact, capture)
    assert b"".join(raw[item.span.start:item.span.end] for item in result.parse.lines) == raw
    if echo:
        account, = (item for item in result.parse.lines if item.rule_id == "bare_command")
        assert account.status == "consumed" and raw[account.span.start:account.span.end] == ECHO.replace(b"\n", newline)


@pytest.mark.parametrize("token", [
    "up, Autostate Enabled", "up , autostate Enabled", "up , Autostate Disabled",
    "up , Autostate Enabled ", "up  , Autostate Enabled", "up , Autostate Enabled, extra",
    "down , Autostate Enabled (looped)",
])
def test_other_oper_spellings_remain_unknown(tmp_path, token):
    raw = ECHO + f"Vlan123 is up, line protocol is {token}\n".encode()
    result = build_capture(admitted(tmp_path, raw))
    row, = result.interfaces
    assert result.parse.quality == "partial" and row.verdict == "unknown" and row.next_evidence
    assert isinstance(row.oper, k.Unknown) and row.oper.reason is k.UnknownReason.PARSE_PARTIAL


@pytest.mark.parametrize("raw", [
    ECHO, ECHO + b"synthetic-a#\n" + HEADER,
    b" \tshow interfaces\n" + HEADER, b"show interfaces \t\n" + HEADER,
    b"SHOW interfaces\n" + HEADER, b"show interfaces Vlan123\n" + HEADER,
    b"show interfaces | include protocol\n" + HEADER, b"show ip interface brief\n" + HEADER,
    b"show version\n" + HEADER, b"unrelated\n" + ECHO + HEADER,
    ECHO + ECHO + HEADER, ECHO + HEADER + ECHO,
    HEADER + ECHO, ECHO + HEADER + b"show version\n",
    ECHO + b"Sdwan-system-intf is up, line protocol is up\n",
    ECHO + b"Vlan123 is dormant, line protocol is up\n",
    ECHO + b"Interface IP-Address OK? Method Status Protocol\n",
    ECHO + HEADER + b"banner motd ^C\n", ECHO + HEADER + b"end\n",
    ECHO + HEADER + b" ^\n% Invalid input detected at '^' marker.\n",
])
def test_bare_echo_exception_does_not_admit_other_contexts(tmp_path, raw):
    with pytest.raises(RunnerRefused, match="^evidence_unsupported_capture$"):
        admitted(tmp_path, raw)


def test_bare_error_without_numeric_header_stays_refused(tmp_path):
    with pytest.raises(RunnerRefused, match="^evidence_capture_error$"):
        admitted(tmp_path, ECHO + b"% Invalid input detected at '^' marker.\n")


@pytest.mark.parametrize("marker,integrity", [
    (b"% Invalid input detected at '^' marker.\n", k.IntegrityState.ERROR),
    (b"Command authorization failed\n", k.IntegrityState.ERROR),
    (b"[truncated]\n", k.IntegrityState.TRUNCATED),
    (b"--More--\n", k.IntegrityState.TRUNCATED),
])
def test_echo_does_not_override_failure_integrity(tmp_path, marker, integrity):
    capture = admitted(tmp_path, ECHO + HEADER + marker)
    assert capture.integrity is integrity
    result = build_capture(capture)
    assert result.parse.quality == "partial"
    if integrity is k.IntegrityState.ERROR:
        assert result.observed == 0 and result.coverage.reason is k.UnknownReason.CAPTURE_ERROR
    else:
        row, = result.interfaces
        assert isinstance(row.admin, k.Unknown) and row.admin.reason is k.UnknownReason.CAPTURE_TRUNCATED
        assert isinstance(row.oper, k.Unknown) and row.verdict == "unknown"


def cli(evidence, out, workers):
    return subprocess.run(
        [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
         "--out", str(out), "--workers", str(workers)], cwd=ROOT, capture_output=True,
        text=True, check=False, timeout=30,
        env={**os.environ, "PYTHONHASHSEED": str(workers)},
    )


def test_full_echo_cli_preserves_inputs_and_determinism(tmp_path):
    first = b"\n" + ECHO + b"Vlan123 is up, line protocol is down , Autostate Enabled\n  MTU 1500 bytes\n"
    second = (ECHO + b"Vlan123 is down, line protocol is down , Autostate Enabled\n").replace(b"\n", b"\r\n")
    members = {"first.txt": first, "second.txt": second}
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name, raw in members.items():
        (evidence / name).write_bytes(raw)
    runs = []
    for workers in (1, 4):
        out = tmp_path / str(workers)
        completed = cli(evidence, out, workers)
        assert completed.returncode == 0, (completed.stdout, completed.stderr)
        assert sorted(path.name for path in out.iterdir()) == sorted(OUTPUTS)
        runs.append({name: (out / name).read_bytes() for name in OUTPUTS})
    assert runs[0] == runs[1]
    facts = json.loads(runs[0]["MANIFEST.json"])["facts"]
    assert len(facts) == 2
    for name, raw in members.items():
        identity = "cap:" + sha256(name.encode() + b"\0" + raw).hexdigest()
        result = facts[identity]
        row, = result["interfaces"]
        assert result["denominator"] == {"scope": "observed_in_capture", "count": 1}
        assert result["coverage"]["reason"] == "denominator_open"
        assert row["check"]["state"] == ("problem" if name == "first.txt" else "unknown")
        assert result["parse"] == ("partial" if name == "first.txt" else "complete")
        for field in ("name", "admin", "oper"):
            for ref in row[field]["evidence"]:
                assert ref["capture"] == identity and ref["locator"] == "bytes"
                assert 0 <= ref["start"] < ref["end"] <= len(raw)
                assert ref["sha256"] == sha256(raw[ref["start"]:ref["end"]]).hexdigest()
        assert (evidence / name).read_bytes() == raw


@pytest.mark.parametrize("tail", [ECHO, b"show interfaces | include protocol\n"])
def test_bare_echo_cli_refusal_preserves_previous_outputs(tmp_path, tail):
    evidence, out = tmp_path / "evidence", tmp_path / "out"
    evidence.mkdir()
    out.mkdir()
    raw = ECHO + HEADER + tail
    (evidence / "capture.txt").write_bytes(raw)
    prior = {name: b"prior output\n" for name in OUTPUTS}
    for name, data in prior.items():
        (out / name).write_bytes(data)
    completed = cli(evidence, out, 1)
    assert completed.returncode == 2 and completed.stdout == ""
    assert completed.stderr == "runner refused: evidence_unsupported_capture\n"
    assert sorted(path.name for path in out.iterdir()) == sorted(OUTPUTS)
    assert {name: (out / name).read_bytes() for name in OUTPUTS} == prior
    assert (evidence / "capture.txt").read_bytes() == raw
