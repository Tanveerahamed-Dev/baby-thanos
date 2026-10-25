"""P2 capture-diagnostic regressions through the public CLI.

All inputs are synthetic bytes generated under tmp_path. These tests establish
regression behavior and byte provenance, not device/train qualification.
"""
import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK = "l1.interface.admin_up_oper_down"
INVALID_INPUT = b"% Invalid input detected at '^' marker.\n"
PROBLEM_LINE = b"Gi1/0/5 is up, line protocol is down\n"
OUTPUT_NAMES = ("SUMMARY.txt", "MANIFEST.json")


def response(command, payload):
    return b"sw-a#" + command.encode("ascii") + b"\n" + payload + b"sw-a#\n"


def write_evidence(tmp_path, members):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name, raw in members.items():
        (evidence / name).write_bytes(raw)
    return evidence


def cli(evidence, out):
    return subprocess.run(
        [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
         "--out", str(out), "--workers", "1"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )


def capture_id(name, raw):
    return "cap:" + sha256(name.encode("utf-8") + b"\0" + raw).hexdigest()


def output_bytes(out):
    return {name: (out / name).read_bytes() for name in OUTPUT_NAMES}


def seed_outputs(out):
    out.mkdir()
    prior = {
        "SUMMARY.txt": b"prior summary must survive refusal\n",
        "MANIFEST.json": b'{"prior":"manifest must survive refusal"}\n',
    }
    for name, raw in prior.items():
        (out / name).write_bytes(raw)
    return prior


def read_manifest(out):
    return json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))


def assert_inputs_unchanged(evidence, members):
    assert {path.name for path in evidence.iterdir()} == set(members)
    for name, raw in members.items():
        assert (evidence / name).read_bytes() == raw


def assert_unknown(fact, reason=None):
    assert fact["state"] == "unknown"
    assert "value" not in fact
    assert fact["reason"]
    assert fact["next_evidence"]
    if reason is not None:
        assert fact["reason"] == reason


def assert_reference(ref, identity, raw, excerpt=None):
    assert ref["capture"] == identity
    if ref["locator"] == "bytes":
        assert 0 <= ref["start"] < ref["end"] <= len(raw)
        actual = raw[ref["start"]:ref["end"]]
    else:
        assert ref["locator"] == "whole_capture"
        actual = raw
    if excerpt is not None:
        assert actual == excerpt
    assert ref["sha256"] == sha256(actual).hexdigest()


def assert_all_references(value, raw_by_id):
    if isinstance(value, dict):
        if isinstance(value.get("evidence"), list):
            for ref in value["evidence"]:
                assert ref["capture"] in raw_by_id
                assert_reference(ref, ref["capture"], raw_by_id[ref["capture"]])
        for child in value.values():
            assert_all_references(child, raw_by_id)
    elif isinstance(value, list):
        for child in value:
            assert_all_references(child, raw_by_id)


def interface_result(record, name, raw, command, count):
    identity = capture_id(name, raw)
    result = record["facts"][identity]
    assert result["pack"] == "l1.interface"
    assert result["variant_support"] == "allowlisted"
    assert result["operation"] == command
    assert result["denominator"] == {"scope": "observed_in_capture", "count": count}
    assert len(result["interfaces"]) == count
    assert_unknown(result["coverage"])
    assert_all_references(result, {identity: raw})
    return result


def assert_known_interface_fields(result, name, raw, oper):
    row, = result["interfaces"]
    identity = capture_id(name, raw)
    for field, value in (("name", "Gi1/0/5"), ("admin", "up"), ("oper", oper)):
        fact = row[field]
        assert fact["state"] == "known"
        assert fact["value"] == value
        first, *_ = fact["evidence"]
        assert first["locator"] == "bytes"
        assert_reference(first, identity, raw, value.encode("ascii"))
    return row


def assert_problem(result, name, raw):
    row = assert_known_interface_fields(result, name, raw, "down")
    assert row["check"]["id"] == CHECK
    assert row["check"]["state"] == "problem"
    assert row["check"]["next_evidence"]
    assert result["coverage"]["reason"] == "denominator_open"


DESCRIPTION_LITERALS = [
    pytest.param(b"Command authorization failed", id="authorization-text"),
    pytest.param(b"% Invalid input detected at '^' marker.", id="invalid-input-text"),
    pytest.param(b"[truncated]", id="bracket-truncation-text"),
    pytest.param(b"<output truncated>", id="angle-truncation-text"),
    pytest.param(b"--More--", id="pager-text"),
    pytest.param(b"<--- more --->", id="arrow-pager-text"),
    pytest.param(b"--(more)--", id="parenthesized-pager-text"),
]


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("literal", DESCRIPTION_LITERALS)
@pytest.mark.parametrize("oper", ["down", "up"])
def test_description_diagnostic_literals_preserve_observed_facts(tmp_path, newline, literal, oper):
    line = b"Gi1/0/5 is up, line protocol is " + oper.encode("ascii") + b"\n"
    raw = response(
        "show interfaces", line + b"  Description: " + literal + b"\n",
    ).replace(b"\n", newline)
    members = {"description.txt": raw}
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    record = read_manifest(out)
    result = interface_result(record, "description.txt", raw, "show interfaces", 1)
    # An unmodelled Description stays partial; it must not erase known mismatch facts.
    assert result["parse"] == "partial"
    if oper == "down":
        assert_problem(result, "description.txt", raw)
    else:
        row = assert_known_interface_fields(result, "description.txt", raw, "up")
        assert row["check"]["id"] == CHECK
        assert_unknown(row["check"], "parse_partial")
        assert result["coverage"]["reason"] == "denominator_open"
    assert_inputs_unchanged(evidence, members)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("command", ["show interfaces", "show ip interface brief"])
@pytest.mark.parametrize("diagnostic", [
    pytest.param(b"                 ^\n" + INVALID_INPUT, id="exact"),
    pytest.param(b" \t^ \t\n\n \t% INVALID INPUT DETECTED AT '^' MARKER.  \n",
                 id="padded-casefold-next-nonblank"),
])
def test_paired_invalid_input_is_capture_error_and_keeps_companion_problem(
        tmp_path, newline, command, diagnostic):
    failed = response(command, diagnostic).replace(b"\n", newline)
    valid = response("show interfaces", PROBLEM_LINE).replace(b"\n", newline)
    members = {"failed.txt": failed, "valid.txt": valid}
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    prior = seed_outputs(out)
    completed = cli(evidence, out)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    current = output_bytes(out)
    assert all(current[name] != prior[name] for name in OUTPUT_NAMES)
    assert sorted(path.name for path in out.iterdir()) == sorted(OUTPUT_NAMES)
    assert b"execution status: OK\n" in current["SUMMARY.txt"]
    record = read_manifest(out)
    assert record["evidence"]["files"] == 2
    assert set(record["facts"]) == {capture_id(name, raw) for name, raw in members.items()}
    error = interface_result(record, "failed.txt", failed, command, 0)
    assert error["interfaces"] == []
    assert error["parse"] == "partial"
    assert_unknown(error["coverage"], "capture_error")
    good = interface_result(record, "valid.txt", valid, "show interfaces", 1)
    assert_problem(good, "valid.txt", valid)
    assert_all_references(record, {capture_id(name, raw): raw for name, raw in members.items()})
    assert_inputs_unchanged(evidence, members)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("marker", [
    pytest.param(b"Command authorization failed\n", id="authorization"),
    pytest.param(INVALID_INPUT, id="invalid-input"),
    pytest.param(b" \tcOmMaNd AuThOrIzAtIoN fAiLeD. \t\n", id="authorization-padded-case-period"),
    pytest.param(b" \t% INVALID INPUT DETECTED AT '^' MARKER. \t\n", id="invalid-padded-case"),
])
def test_standalone_error_still_suppresses_an_earlier_mismatch(tmp_path, newline, marker):
    raw = response("show interfaces", PROBLEM_LINE + marker).replace(b"\n", newline)
    members = {"error.txt": raw}
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    result = interface_result(read_manifest(out), "error.txt", raw, "show interfaces", 0)
    assert result["interfaces"] == []
    assert result["parse"] == "partial"
    assert_unknown(result["coverage"], "capture_error")
    assert_inputs_unchanged(evidence, members)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("marker", [
    pytest.param(b"[truncated]\n", id="bracket-truncation"),
    pytest.param(b"<output truncated>\n", id="angle-truncation"),
    pytest.param(b"--More--\n", id="pager"),
    pytest.param(b"<--- more --->\n", id="arrow-pager"),
    pytest.param(b"--(more)--\n", id="parenthesized-pager"),
    pytest.param(b" \t[TrUnCaTeD] \t\n", id="bracket-padded-case"),
    pytest.param(b" \t<OUTPUT TRUNCATED> \t\n", id="angle-padded-case"),
    pytest.param(b" \t--mOrE-- \t\n", id="pager-padded-case"),
    pytest.param(b" \t<--- MORE ---> \t\n", id="arrow-padded-case"),
    pytest.param(b" \t--(MoRe)-- \t\n", id="parenthesized-padded-case"),
])
def test_standalone_truncation_or_pager_downgrades_an_earlier_mismatch(tmp_path, newline, marker):
    raw = response("show interfaces", PROBLEM_LINE + marker).replace(b"\n", newline)
    members = {"partial.txt": raw}
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    result = interface_result(read_manifest(out), "partial.txt", raw, "show interfaces", 1)
    assert result["parse"] == "partial"
    row, = result["interfaces"]
    assert row["name"]["state"] == "known"
    assert row["name"]["value"] == "Gi1/0/5"
    assert_unknown(row["admin"], "capture_truncated")
    assert_unknown(row["oper"], "capture_truncated")
    assert row["check"]["id"] == CHECK
    assert row["check"]["state"] == "unknown"
    assert row["check"]["next_evidence"]
    assert_inputs_unchanged(evidence, members)


REFUSED_CONTEXTS = [
    pytest.param(
        PROBLEM_LINE + b"   ^\n" + INVALID_INPUT,
        id="paired-pointer-without-command-envelope",
    ),
    pytest.param(response("show interfaces", PROBLEM_LINE + b"   ^\n"), id="unpaired-caret"),
    pytest.param(
        response("show interfaces", b"   ^\nCommand authorization failed\n"),
        id="caret-before-other-diagnostic",
    ),
    pytest.param(
        response("show interfaces", b"   ^\nDescription: " + INVALID_INPUT),
        id="caret-before-diagnostic-in-description",
    ),
    pytest.param(
        response("show interfaces", b"   ^\nDescription: unrelated text\n" + INVALID_INPUT),
        id="caret-separated-from-error-by-nonblank-body",
    ),
    pytest.param(
        response("show interfaces", INVALID_INPUT + b"   ^\n"),
        id="error-before-caret-is-not-paired",
    ),
    pytest.param(
        response("show interfaces", b"   ^C\n" + INVALID_INPUT),
        id="caret-c-is-not-error-pointer",
    ),
    pytest.param(
        response("show interfaces", b"   ^\n" + INVALID_INPUT + b"end\n"),
        id="paired-pointer-does-not-hide-end",
    ),
    pytest.param(
        response("show interfaces", b"   ^\n" + INVALID_INPUT
                 + b"sw-a#show ip interface brief\n"),
        id="paired-pointer-does-not-hide-conflicting-command",
    ),
    pytest.param(response("show interfaces", PROBLEM_LINE + b"!\n"), id="configuration-separator"),
    pytest.param(response("show interfaces", PROBLEM_LINE + b"end\n"), id="configuration-end"),
    pytest.param(
        response("show interfaces", b"banner motd ^C\n" + PROBLEM_LINE + b"^C\n"),
        id="motd-after-supported-command",
    ),
    pytest.param(
        b"sw-a#show running-config\nBuilding configuration...\nbanner motd ^C\n"
        + PROBLEM_LINE + b"^C\nend\nsw-a#\n",
        id="interface-text-inside-configuration-motd",
    ),
]


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("invalid", REFUSED_CONTEXTS)
def test_caret_exception_keeps_context_refusal_atomic(tmp_path, newline, invalid):
    members = {
        "valid.txt": response("show interfaces", PROBLEM_LINE).replace(b"\n", newline),
        "invalid.txt": invalid.replace(b"\n", newline),
    }
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    prior = seed_outputs(out)
    completed = cli(evidence, out)
    assert completed.returncode == 2, (completed.stdout, completed.stderr)
    assert completed.stdout == ""
    assert completed.stderr == "runner refused: evidence_unsupported_capture\n"
    assert output_bytes(out) == prior
    assert sorted(path.name for path in out.iterdir()) == sorted(OUTPUT_NAMES)
    assert_inputs_unchanged(evidence, members)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("literal", [
    pytest.param(b"Command authorization failed", id="authorization-text"),
    pytest.param(b"[truncated]", id="truncation-text"),
])
def test_description_literals_preserve_reverse_mismatch(tmp_path, newline, literal):
    raw = response(
        "show interfaces",
        b"Gi1/0/5 is administratively down, line protocol is up\n"
        + b"  Description: " + literal + b"\n",
    ).replace(b"\n", newline)
    name = "reverse.txt"
    members = {name: raw}
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    result = interface_result(read_manifest(out), name, raw, "show interfaces", 1)
    assert result["parse"] == "partial"
    assert result["coverage"]["reason"] == "denominator_open"
    row, = result["interfaces"]
    identity = capture_id(name, raw)
    for field, value, token in (
        ("name", "Gi1/0/5", b"Gi1/0/5"),
        ("admin", "down", b"administratively down"),
        ("oper", "up", b"up"),
    ):
        assert row[field]["state"] == "known"
        assert row[field]["value"] == value
        first, *_ = row[field]["evidence"]
        assert first["locator"] == "bytes"
        assert_reference(first, identity, raw, token)
    assert row["check"]["id"] == CHECK
    assert row["check"]["state"] == "problem"
    assert row["check"]["next_evidence"]
    assert_inputs_unchanged(evidence, members)
