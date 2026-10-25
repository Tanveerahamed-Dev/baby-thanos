"""Synthetic regressions for the exact capture-local brief name; no device qualification."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from itertools import pairwise
from pathlib import Path

import pytest

from atlas_brain.kernel import states as k
from atlas_brain.packs.l1.interface.build import extract_interfaces

ROOT = Path(__file__).resolve().parents[4]
COMMAND = "show ip interface brief"
NAME = b"Sdwan-system-intf"
HEADER = b"Interface IP-Address OK? Method Status Protocol\n"
OUTPUTS = ("SUMMARY.txt", "MANIFEST.json")


def line(status="up", oper="up", name=NAME):
    return name + b" unassigned YES unset " + status.encode() + (b" " + oper.encode() if oper else b"")


def table(rows, newline=b"\n", prompt=b""):
    raw = HEADER + b"\n".join(rows) + b"\n"
    if prompt:
        raw = prompt + COMMAND.encode() + b"\n" + raw + prompt + b"\n"
    return raw.replace(b"\n", newline)


def extract(raw, command=COMMAND):
    return extract_interfaces(raw, k.CaptureId("cap:synthetic"), command=command,
                              integrity=k.IntegrityState.COMPLETE, source=k.EntityKey("node:synthetic"))


def assert_ref(ref, raw, expected=None):
    assert ref.capture == "cap:synthetic"
    if isinstance(ref.locator, k.ByteSpan):
        assert 0 <= ref.locator.start < ref.locator.end <= len(raw)
        excerpt = raw[ref.locator.start:ref.locator.end]
    else:
        assert isinstance(ref.locator, k.WholeCapture)
        excerpt = raw
    assert ref.excerpt_sha256 == sha256(excerpt).hexdigest()
    if expected is not None:
        assert excerpt == expected


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("prompt", [b"", b"synthetic-a#", b"synthetic-a>"])
@pytest.mark.parametrize("status,oper,admin,verdict", [
    ("up", "up", "up", "ok"), ("up", "down", "up", "problem"),
    ("administratively down", "down", "down", "ok"),
    ("administratively down", "up", "down", "problem"),
    ("down", "up", None, "unknown"), ("down", "down", None, "unknown"),
])
def test_exact_brief_name_states_and_byte_custody(newline, prompt, status, oper, admin, verdict):
    raw = table([line(status, oper)], newline, prompt)
    result = extract(raw)
    row, = result.interfaces
    assert result.observed == 1 and result.parse.quality == "complete"
    assert row.name.value == NAME.decode() and row.verdict == verdict
    assert_ref(row.name.evidence[0], raw, NAME)
    if admin is None:
        assert isinstance(row.admin, k.Unknown) and row.admin.reason is k.UnknownReason.NOT_OBSERVABLE
    else:
        assert isinstance(row.admin, k.Known) and row.admin.value == admin
        assert_ref(row.admin.evidence[0], raw, status.encode())
    assert isinstance(row.oper, k.Known) and row.oper.value == oper
    assert_ref(row.oper.evidence[0], raw, oper.encode())
    for fact in (row.name, row.admin, row.oper, result.coverage):
        for ref in fact.evidence:
            assert_ref(ref, raw)
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN
    assert result.coverage.next_evidence and (row.next_evidence or verdict == "ok")
    spans = [account.span for account in result.parse.lines]
    assert spans[0].start == 0 and spans[-1].end == len(raw)
    assert all(left.end == right.start for left, right in pairwise(spans))


@pytest.mark.parametrize("suffix", [
    b" unassigned YES unset up", b" unassigned YES unset administratively down",
    b" unassigned YES unset up dormant", b" unassigned YES unset administratively down dormant",
    b" unassigned YES unset dormant up", b" unassigned YES unset", b"",
])
def test_missing_or_unmapped_named_states_stay_unknown(suffix):
    result = extract(table([NAME + suffix]))
    row, = result.interfaces
    assert result.observed == 1 and result.parse.quality == "partial"
    assert row.verdict == "unknown" and row.next_evidence
    assert isinstance(row.admin, k.Unknown) or isinstance(row.oper, k.Unknown)
    assert result.coverage.reason is k.UnknownReason.DENOMINATOR_OPEN


@pytest.mark.parametrize("duplicate", [NAME, NAME + b" malformed", line("up", "down")])
def test_valid_and_malformed_named_duplicates_conflict(duplicate):
    result = extract(table([line(), duplicate]))
    row, = result.interfaces
    assert result.observed == 1 and result.parse.quality == "partial"
    assert row.verdict == "unknown" and row.next_evidence
    for fact in (row.admin, row.oper):
        assert isinstance(fact, k.Unknown) and fact.reason is k.UnknownReason.CONFLICTING_EVIDENCE
        assert len(fact.evidence) == 2


def test_numbered_and_named_rows_remain_distinct_and_numbered_rules_stable():
    result = extract(table([line(name=b"Gi1/0/5"), line("administratively down", "down")]))
    assert result.observed == 2 and result.parse.quality == "complete"
    assert [row.name.value for row in result.interfaces] == ["Gi1/0/5", NAME.decode()]
    assert all(row.verdict == "ok" for row in result.interfaces)
    assert [record.rule_id for record in result.parse.records] == ["table_header", "state", "admin_named"]
    detail = extract(b"Gi1/0/5 is up, line protocol is up\n", "show interfaces")
    assert detail.observed == 1 and detail.interfaces[0].verdict == "ok"
    assert detail.parse.records[0].rule_id == "interface"


@pytest.mark.parametrize("name", [b"sdwan-system-intf", b"Sdwan-system-intf-extra", b"Other-system-intf"])
def test_numberless_lookalikes_remain_unrecognised(name):
    result = extract(table([line(name=b"Gi1/0/5"), line(name=name)]))
    assert result.observed == 1 and result.parse.quality == "partial"
    assert result.interfaces[0].verdict == "unknown"
    assert result.parse.lines[-1].status == "unrecognised"


def test_literal_name_is_not_admitted_to_full_interfaces():
    result = extract(NAME + b" is up, line protocol is up\n", "show interfaces")
    assert result.observed == 0 and result.parse.quality == "partial"
    assert result.parse.lines[0].status == "unrecognised"


def cli(evidence, out, workers):
    return subprocess.run(
        [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
         "--out", str(out), "--workers", str(workers)], cwd=ROOT, capture_output=True,
        text=True, check=False, timeout=30,
        env={**os.environ, "PYTHONHASHSEED": str(workers)},
    )


def test_named_cli_is_capture_scoped_deterministic_and_preserves_inputs(tmp_path):
    members = {"first.txt": table([line("up", "down"), line(name=b"Gi1/0/5")]),
               "second.txt": table([line("administratively down", "down")], b"\r\n", b"synthetic-b#")}
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
        assert result["parse"] == "complete"
        count = 2 if name == "first.txt" else 1
        assert result["denominator"] == {"scope": "observed_in_capture", "count": count}
        assert result["coverage"]["reason"] == "denominator_open"
        named = next(row for row in result["interfaces"] if row["name"]["value"] == NAME.decode())
        assert named["check"]["state"] == ("problem" if count == 2 else "ok")
        for row in result["interfaces"]:
            for field in ("name", "admin", "oper"):
                for ref in row[field]["evidence"]:
                    assert ref["capture"] == identity and ref["locator"] == "bytes"
                    assert 0 <= ref["start"] < ref["end"] <= len(raw)
                    excerpt = raw[ref["start"]:ref["end"]]
                    assert ref["sha256"] == sha256(excerpt).hexdigest()
        assert (evidence / name).read_bytes() == raw


@pytest.mark.parametrize("tail", [b"Gi1/0/6 is up, line protocol is up\n",
                                  b"synthetic-a#show interfaces\n",
                                  NAME + b" is up, line protocol is up\n",
                                  NAME + b" is down, line protocol is down\n",
                                  NAME + b" is administratively down, line protocol is down\n",
                                  NAME + b" is up\n"])
def test_named_brief_mixed_command_refusal_preserves_outputs(tmp_path, tail):
    evidence, out = tmp_path / "evidence", tmp_path / "out"
    evidence.mkdir()
    out.mkdir()
    raw = table([line()]) + tail
    (evidence / "mixed.txt").write_bytes(raw)
    prior = {name: b"prior output\n" for name in OUTPUTS}
    for name, data in prior.items():
        (out / name).write_bytes(data)
    completed = cli(evidence, out, 1)
    assert completed.returncode == 2 and completed.stdout == ""
    assert completed.stderr == "runner refused: evidence_unsupported_capture\n"
    assert sorted(path.name for path in out.iterdir()) == sorted(OUTPUTS)
    assert {name: (out / name).read_bytes() for name in OUTPUTS} == prior
    assert (evidence / "mixed.txt").read_bytes() == raw
