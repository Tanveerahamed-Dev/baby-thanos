"""P1 interface answers through the public CLI over generated, temporary captures."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK = "l1.interface.admin_up_oper_down"
BRIEF_HEADER = b"Interface              IP-Address      OK? Method Status                Protocol\n"
SYSTEM = (
    b"Cisco IOS XE Software, Version 17.09.04a\n"
    b"sw-a uptime is 1 day, 2 hours, 3 minutes\n"
    b'System image file is "bootflash:packages.conf"\n'
    b"Last reload reason: PowerOn\n"
)


def cli(evidence, out, *, workers=1, hash_seed=None):
    env = dict(os.environ)
    if hash_seed is not None:
        env["PYTHONHASHSEED"] = str(hash_seed)
    return subprocess.run(
        [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
         "--out", str(out), "--workers", str(workers)],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False, env=env,
    )


def write_evidence(tmp_path, members):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name, raw in members.items():
        target = evidence / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return evidence


def outputs(out):
    return {name: (out / name).read_bytes() for name in ("SUMMARY.txt", "MANIFEST.json")}


def manifest(out):
    return json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))


def capture_id(name, raw):
    return "cap:" + sha256(name.encode("utf-8") + b"\0" + raw).hexdigest()


def response(command, payload, *, host="sw-a"):
    prompt = host.encode("ascii") + b"#"
    return prompt + command.encode("ascii") + b"\n" + payload + prompt + b"\n"


def assert_reference(ref, expected_id, raw, excerpt=None):
    assert ref["capture"] == expected_id
    if ref["locator"] == "bytes":
        assert 0 <= ref["start"] < ref["end"] <= len(raw)
        actual = raw[ref["start"]:ref["end"]]
    else:
        assert ref["locator"] == "whole_capture"
        actual = raw
    if excerpt is not None:
        assert actual == excerpt
    assert ref["sha256"] == sha256(actual).hexdigest()


def assert_unknown(fact):
    assert fact["state"] == "unknown"
    assert "value" not in fact
    assert fact["reason"]
    assert fact["next_evidence"]


def assert_scalar_contract(value):
    if isinstance(value, dict):
        assert list(value) == sorted(value)
        assert all(type(key) is str for key in value)
        for child in value.values():
            assert_scalar_contract(child)
    elif isinstance(value, list):
        for child in value:
            assert_scalar_contract(child)
    else:
        assert type(value) in (int, str), repr(value)


def assert_capture_refs(value, raw_by_id):
    if isinstance(value, dict):
        if "evidence" in value and isinstance(value["evidence"], list):
            for ref in value["evidence"]:
                assert ref["capture"] in raw_by_id
                assert_reference(ref, ref["capture"], raw_by_id[ref["capture"]])
        for child in value.values():
            assert_capture_refs(child, raw_by_id)
    elif isinstance(value, list):
        for child in value:
            assert_capture_refs(child, raw_by_id)


def state_row(command, name, status, protocol):
    ending = " " + protocol if protocol else ""
    if command == "show interfaces":
        return f"{name} is {status}, line protocol is{ending}\n".encode("ascii")
    return BRIEF_HEADER + f"{name} unassigned YES unset {status}{ending}\n".encode("ascii")


def interface_capture(record, identity):
    result = record["facts"][identity]
    assert result["pack"] == "l1.interface"
    assert result["variant_support"] == "allowlisted"
    rows = result["interfaces"]
    assert isinstance(rows, list)
    assert all(row["name"]["state"] == "known" for row in rows)
    names = [row["name"]["value"] for row in rows]
    assert names == sorted(set(names))
    return {**result, "interfaces": dict(zip(names, rows, strict=True))}


def row_check(row):
    result = row["check"]
    assert result["id"] == CHECK
    return result


def assert_denominator(result, count):
    assert result["denominator"] == {"scope": "observed_in_capture", "count": count}
    assert_unknown(result["coverage"])


@pytest.mark.parametrize("command", ["show interfaces", "show ip interface brief"])
@pytest.mark.parametrize("status,protocol,admin,oper,verdict", [
    ("up", "down", "up", "down", "problem"),
    ("administratively down", "up", "down", "up", "problem"),
    ("up", "up", "up", "up", "ok"),
    ("administratively down", "down", "down", "down", "ok"),
    ("down", "down", None, "down", "unknown"),
    ("down", "up", None, "up", "unknown"),
])
def test_ei_r01_state_matrix(tmp_path, command, status, protocol, admin, oper, verdict):
    raw = response(command, state_row(command, "Gi1/0/5", status, protocol))
    name = "capture.txt"
    evidence = write_evidence(tmp_path, {name: raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    record = manifest(out)
    identity = capture_id(name, raw)
    result = interface_capture(record, identity)
    row = result["interfaces"]["Gi1/0/5"]
    assert row["name"]["value"] == "Gi1/0/5"
    name_ref, = row["name"]["evidence"]
    assert_reference(name_ref, identity, raw, b"Gi1/0/5")
    assert result["operation"] == command
    if admin is None:
        assert_unknown(row["admin"])
    else:
        assert row["admin"]["state"] == "known"
        assert row["admin"]["value"] == admin
        assert_reference(row["admin"]["evidence"][0], identity, raw, status.encode())
        for ref in row["admin"]["evidence"]:
            assert_reference(ref, identity, raw)
    assert row["oper"]["state"] == "known"
    assert row["oper"]["value"] == oper
    assert_reference(row["oper"]["evidence"][0], identity, raw, protocol.encode())
    for ref in row["oper"]["evidence"]:
        assert_reference(ref, identity, raw)
    assert row_check(row)["state"] == verdict
    if verdict == "unknown":
        assert row_check(row)["next_evidence"]
    assert_denominator(result, 1)
    assert (evidence / name).read_bytes() == raw
    assert CHECK in (out / "SUMMARY.txt").read_text(encoding="ascii")


@pytest.mark.parametrize("command", ["show interfaces", "show ip interface brief"])
@pytest.mark.parametrize("protocol", ["", "dormant"])
@pytest.mark.parametrize("status", ["up", "administratively down"])
def test_missing_or_unmapped_oper_is_unknown_never_ok(tmp_path, command, protocol, status):
    raw = response(command, state_row(command, "Gi1/0/5", status, protocol))
    evidence = write_evidence(tmp_path, {"capture.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("capture.txt", raw))
    row = result["interfaces"]["Gi1/0/5"]
    assert row["admin"]["state"] == "known"
    assert row["admin"]["value"] == ("up" if status == "up" else "down")
    assert_unknown(row["oper"])
    assert row_check(row)["state"] == "unknown"
    assert row_check(row)["next_evidence"]
    assert result["parse"] == "partial"
    assert_denominator(result, 1)


@pytest.mark.parametrize("marker", [b"[truncated]\n", b"<output truncated>\n", b"--More--\n"])
def test_ei_r16_truncation_is_visible_partial_not_healthy(tmp_path, marker):
    raw = response("show ip interface brief",
                   state_row("show ip interface brief", "Gi1/0/5", "up", "up") + marker)
    evidence = write_evidence(tmp_path, {"partial.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("partial.txt", raw))
    assert result["parse"] == "partial"
    assert row_check(result["interfaces"]["Gi1/0/5"])["state"] != "ok"
    assert_unknown(result["coverage"])
    assert_denominator(result, 1)
    assert (evidence / "partial.txt").read_bytes() == raw


@pytest.mark.parametrize("command", ["show interfaces", "show ip interface brief"])
@pytest.mark.parametrize("marker", [
    b"% Invalid input detected at '^' marker.\n",
    b"Command authorization failed\n",
])
def test_failed_command_is_not_an_empty_healthy_table(tmp_path, command, marker):
    raw = response(command, marker)
    evidence = write_evidence(tmp_path, {"failed.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("failed.txt", raw))
    assert result["interfaces"] == {}
    assert result["parse"] == "partial"
    assert_unknown(result["coverage"])
    assert result["coverage"]["reason"] == "capture_error"
    assert_denominator(result, 0)
    assert (evidence / "failed.txt").read_bytes() == raw


def test_empty_brief_population_is_unknown_with_zero_denominator(tmp_path):
    raw = response("show ip interface brief", BRIEF_HEADER)
    evidence = write_evidence(tmp_path, {"empty.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("empty.txt", raw))
    assert result["interfaces"] == {}
    assert_unknown(result["coverage"])
    assert_denominator(result, 0)


@pytest.mark.parametrize("duplicate", [b"up", b"down"])
def test_duplicate_interface_is_conflicting_evidence_not_last_row_wins(tmp_path, duplicate):
    payload = (
        b"Gi1/0/5 is up, line protocol is up\n"
        b"Gi1/0/5 is up, line protocol is " + duplicate + b"\n"
    )
    raw = response("show interfaces", payload)
    evidence = write_evidence(tmp_path, {"duplicate.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("duplicate.txt", raw))
    row = result["interfaces"]["Gi1/0/5"]
    assert_unknown(row["admin"])
    assert_unknown(row["oper"])
    assert row["admin"]["reason"] == row["oper"]["reason"] == "conflicting_evidence"
    assert row_check(row)["state"] == "unknown"
    assert_denominator(result, 1)


def test_exact_interface_names_and_capture_ids_do_not_join_unproven_devices(tmp_path):
    first = response("show interfaces",
                     b"Gi1/0/5 is up, line protocol is\n"
                     b"GigabitEthernet1/0/5 is administratively down, line protocol is down\n",
                     host="sw-a")
    second = response("show ip interface brief",
                      state_row("show ip interface brief", "Gi1/0/5", "up", "up"),
                      host="sw-b")
    evidence = write_evidence(tmp_path, {"same-device/first.txt": first, "same-device/second.txt": second})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    record = manifest(out)
    first_id = capture_id("same-device/first.txt", first)
    second_id = capture_id("same-device/second.txt", second)
    left = interface_capture(record, first_id)
    right = interface_capture(record, second_id)
    assert set(left["interfaces"]) == {"Gi1/0/5", "GigabitEthernet1/0/5"}
    assert set(right["interfaces"]) == {"Gi1/0/5"}
    assert_unknown(left["interfaces"]["Gi1/0/5"]["oper"])
    assert row_check(left["interfaces"]["Gi1/0/5"])["state"] == "unknown"
    assert right["interfaces"]["Gi1/0/5"]["oper"]["value"] == "up"
    for identity, result in ((first_id, left), (second_id, right)):
        for row in result["interfaces"].values():
            for field in ("admin", "oper"):
                assert all(ref["capture"] == identity for ref in row[field]["evidence"])


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_multi_command_runs_preserve_all_raw_bytes_and_repeat_across_workers(tmp_path, newline):
    interface = response("show interfaces",
                         b"GigabitEthernet1/0/5 is up, line protocol is down\n")
    brief = response("show ip interface brief",
                     state_row("show ip interface brief", "Gi1/0/7", "administratively down", "down"))
    members = {
        "one.txt": interface.replace(b"\n", newline),
        "nested/two.txt": brief.replace(b"\n", newline),
        "system.txt": SYSTEM.replace(b"\n", newline),
    }
    evidence = write_evidence(tmp_path, members)
    runs = []
    for index, (workers, hash_seed) in enumerate(((1, 1), (4, 2), (4, 2))):
        out = tmp_path / f"out-{index}"
        completed = cli(evidence, out, workers=workers, hash_seed=hash_seed)
        assert completed.returncode == 0, completed.stderr
        runs.append(outputs(out))
    assert runs[0] == runs[1] == runs[2]
    assert b"execution status: OK\n" in runs[0]["SUMMARY.txt"]
    for name, raw in members.items():
        assert (evidence / name).read_bytes() == raw
    record = manifest(tmp_path / "out-0")
    assert record["evidence"]["files"] == 3
    system = record["facts"][capture_id("system.txt", members["system.txt"])]
    assert system["uptime"]["value"] == [[1, "day"], [2, "hour"], [3, "minute"]]
    assert system["image"]["value"] == "bootflash:packages.conf"
    assert system["reload_reason"]["value"] == "PowerOn"
    assert system["boot_epoch"]["state"] == "unknown"
    assert system["boot_epoch"]["reason"] == "as_of_missing"
    assert_scalar_contract(record)
    assert_capture_refs(record, {capture_id(name, raw): raw for name, raw in members.items()})
    assert b"\r" not in runs[0]["SUMMARY.txt"] and b"\r" not in runs[0]["MANIFEST.json"]
    assert sorted(path.name for path in (tmp_path / "out-0").iterdir()) == ["MANIFEST.json", "SUMMARY.txt"]

INTERFACE_LINE = b"Gi1/0/5 is up, line protocol is up\n"
INTERFACE_CONTEXT_REFUSALS = [
    pytest.param(
        b"sw-a#show running-config\nBuilding configuration...\nbanner motd ^C\n"
        + INTERFACE_LINE + b"^C\nend\nsw-a#\n",
        id="interface-text-inside-configuration-banner",
    ),
    pytest.param(
        b"sw-a#show interfaces\nbanner motd ^C\n" + INTERFACE_LINE + b"^C\nsw-a#\n",
        id="configuration-marker-after-supported-command",
    ),
    pytest.param(
        b"unrelated output\n" + response("show interfaces", INTERFACE_LINE),
        id="arbitrary-prefix",
    ),
    pytest.param(
        b"sw-a#show version\n" + INTERFACE_LINE + b"sw-a#\n",
        id="different-command-echo",
    ),
    pytest.param(
        b"sw-a#show interfaces\n" + INTERFACE_LINE + b"sw-b#\n",
        id="different-terminal-host",
    ),
    pytest.param(
        b"sw-a#show interfaces\n" + INTERFACE_LINE + b"sw-a>\n",
        id="different-terminal-mode",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"sw-a#\n" + INTERFACE_LINE),
        id="interior-bare-prompt",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"sw-a#show ip interface brief\n" + BRIEF_HEADER),
        id="interior-command",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE) + response("show version", SYSTEM),
        id="concatenated-responses",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"Cisco Nexus Operating System (NX-OS) Software\n"),
        id="foreign-platform-context",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"  ShOw RuNnInG-CoNfIg\n"),
        id="indented-command-context",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"end\n"),
        id="closing-configuration-context",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE
                 + b"Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2\n"),
        id="classic-ios-context",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"sw-a uptime is 1 day\n"),
        id="system-uptime-record-in-interface-response",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE
                 + b'System image file is "bootflash:packages.conf"\n'),
        id="system-image-record-in-interface-response",
    ),
    pytest.param(
        response("show interfaces", INTERFACE_LINE + b"Last reload reason: PowerOn\n"),
        id="system-reload-record-in-interface-response",
    ),
]


@pytest.mark.parametrize("raw", INTERFACE_CONTEXT_REFUSALS)
def test_interface_recognition_does_not_resurrect_configuration_banner_facts(tmp_path, raw):
    members = {"valid.txt": SYSTEM, "invalid.txt": raw}
    evidence = write_evidence(tmp_path, members)
    out = tmp_path / "out"
    out.mkdir()
    prior = {"SUMMARY.txt": b"keep summary\n", "MANIFEST.json": b'{"keep":"manifest"}\n'}
    for name, data in prior.items():
        (out / name).write_bytes(data)
    completed = cli(evidence, out)
    assert completed.returncode == 2, (completed.stdout, completed.stderr)
    assert completed.stderr == "runner refused: evidence_unsupported_capture\n"
    assert completed.stdout == ""
    assert outputs(out) == prior
    assert all((evidence / name).read_bytes() == data for name, data in members.items())


@pytest.mark.parametrize("suffix", [b" (looped)", b" (disabled)"])
def test_unmodelled_oper_modifier_is_not_silently_healthy(tmp_path, suffix):
    raw = response("show interfaces", b"Gi1/0/5 is up, line protocol is up" + suffix + b"\n")
    evidence = write_evidence(tmp_path, {"modifier.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("modifier.txt", raw))
    assert result["parse"] == "partial"
    assert row_check(result["interfaces"]["Gi1/0/5"])["state"] == "unknown"
    assert row_check(result["interfaces"]["Gi1/0/5"])["next_evidence"]
    assert_unknown(result["coverage"])


def test_malformed_second_interface_is_not_dropped_from_coverage(tmp_path):
    raw = response("show interfaces", INTERFACE_LINE + b"Gi1/0/6 is up, line protocol is\n")
    evidence = write_evidence(tmp_path, {"partial.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("partial.txt", raw))
    assert result["parse"] == "partial"
    assert set(result["interfaces"]) == {"Gi1/0/5", "Gi1/0/6"}
    assert row_check(result["interfaces"]["Gi1/0/5"])["state"] != "ok"
    assert_unknown(result["interfaces"]["Gi1/0/6"]["oper"])
    assert row_check(result["interfaces"]["Gi1/0/6"])["state"] == "unknown"
    assert_denominator(result, 2)
    assert_unknown(result["coverage"])


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_multibyte_prefix_and_crlf_do_not_shift_evidence_spans(tmp_path, newline):
    raw = response(
        "show interfaces",
        INTERFACE_LINE + "  Description: synthetic \u03bb\n".encode("utf-8")
        + b"Gi1/0/6 is up, line protocol is down\n",
    ).replace(b"\n", newline)
    evidence = write_evidence(tmp_path, {"unicode.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    identity = capture_id("unicode.txt", raw)
    result = interface_capture(manifest(out), identity)
    row = result["interfaces"]["Gi1/0/6"]
    start = raw.index(b"Gi1/0/6")
    for name, excerpt in (("admin", b"up"), ("oper", b"down")):
        assert row[name]["state"] == "known"
        assert row[name]["value"] == excerpt.decode("ascii")
        ref = row[name]["evidence"][0]
        assert ref["start"] >= start
        assert_reference(ref, identity, raw, excerpt)
        for ref in row[name]["evidence"]:
            assert_reference(ref, identity, raw)
    assert (evidence / "unicode.txt").read_bytes() == raw


def test_malformed_duplicate_cannot_leave_an_earlier_healthy_row(tmp_path):
    raw = response("show interfaces", INTERFACE_LINE + b"Gi1/0/5 is up, line protocol is\n")
    evidence = write_evidence(tmp_path, {"duplicate.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    result = interface_capture(manifest(out), capture_id("duplicate.txt", raw))
    row = result["interfaces"]["Gi1/0/5"]
    assert result["parse"] == "partial"
    assert_unknown(row["admin"])
    assert_unknown(row["oper"])
    assert row["admin"]["reason"] == row["oper"]["reason"] == "conflicting_evidence"
    assert row_check(row)["state"] == "unknown"
    assert row_check(row)["next_evidence"]
    assert_denominator(result, 1)


def assert_interface_commands_not_collected(record, identity):
    assert set(record["facts"]) == {identity}
    assert set(record["facts"][identity]) == {"uptime", "image", "reload_reason", "boot_epoch"}
    coverage = record["interface_coverage"]
    assert_unknown(coverage)
    assert coverage["reason"] == "not_collected"
    assert coverage["detail"] == "interface_commands_missing"
    assert coverage["evidence"] == []
    assert any(need["operation"] == "show interfaces" for need in coverage["next_evidence"])
    assert all(need["node"] == "node:unresolved" for need in coverage["next_evidence"])


def test_system_only_input_explicitly_leaves_interface_analysis_not_collected(tmp_path):
    evidence = write_evidence(tmp_path, {"system.txt": SYSTEM})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    record = manifest(out)
    identity = capture_id("system.txt", SYSTEM)
    assert_interface_commands_not_collected(record, identity)
    assert record["facts"][identity]["image"]["value"] == "bootflash:packages.conf"
    summary = (out / "SUMMARY.txt").read_text(encoding="ascii")
    assert "interface_commands_missing" in summary
    assert "show interfaces" in summary
    assert (evidence / "system.txt").read_bytes() == SYSTEM


def test_python_api_accepts_additive_missing_interface_coverage(tmp_path):
    from atlas_brain.runner import RunResult, run

    evidence = write_evidence(tmp_path, {"system.txt": SYSTEM})
    out = tmp_path / "out"
    result = run(evidence, out, workers=1)
    assert isinstance(result, RunResult)
    assert result.out == out
    assert result.evidence_files == 1
    assert result.egress_denied == 40
    assert_interface_commands_not_collected(manifest(out), capture_id("system.txt", SYSTEM))
    assert (evidence / "system.txt").read_bytes() == SYSTEM


@pytest.mark.parametrize("raw", [
    b"% Invalid input detected at '^' marker.\n",
    b"Command authorization failed\n",
])
def test_error_without_supported_command_envelope_still_refuses(tmp_path, raw):
    evidence = write_evidence(tmp_path, {"unattributed.txt": raw})
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 2
    assert completed.stderr == "runner refused: evidence_capture_error\n"
    assert not out.exists()
    assert (evidence / "unattributed.txt").read_bytes() == raw
