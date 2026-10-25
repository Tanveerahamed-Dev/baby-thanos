"""P0 proofs over synthetic captures; no copied or unproven fixture files."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from atlas_brain.evidence.admission import Budgets
from atlas_brain.kernel import states as k
from atlas_brain.runner import RunnerRefused, run
from atlas_brain.runner.evidence import analyse_evidence

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE = (
    b"Cisco IOS XE Software, Version 17.09.04a\n"
    b"sw-a uptime is 1 day, 2 hours, 3 minutes\n"
    b'System image file is "bootflash:packages.conf"\n'
    b"Last reload reason: PowerOn\n"
)
FACT_NAMES = {"uptime", "image", "reload_reason", "boot_epoch"}


def capture_dir(tmp_path, raw=SAMPLE, name="show-version.txt"):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / name).write_bytes(raw)
    return root


def cli(evidence, out, *arguments, env=None):
    return subprocess.run(
        [sys.executable, "-m", "atlas_brain.runner", "--evidence", str(evidence),
         "--out", str(out), *arguments], cwd=REPO_ROOT, capture_output=True,
        text=True, check=False, env=env,
    )


def manifest(out):
    return json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))


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


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("banner_suffix", [b"", " synthetic \u03bb".encode()])
def test_cli_facts_have_exact_raw_spans_and_missing_clock_stays_unknown(tmp_path, newline, banner_suffix):
    raw = SAMPLE.replace(b"17.09.04a", b"17.09.04a" + banner_suffix).replace(b"\n", newline)
    evidence = capture_dir(tmp_path, raw)
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 0, completed.stderr
    record = manifest(out)
    assert len(record["facts"]) == 1
    capture_id, facts = next(iter(record["facts"].items()))
    assert set(facts) == FACT_NAMES
    expected = {
        "uptime": ([[1, "day"], [2, "hour"], [3, "minute"]], b"1 day, 2 hours, 3 minutes"),
        "image": ("bootflash:packages.conf", b"bootflash:packages.conf"),
        "reload_reason": ("PowerOn", b"PowerOn"),
    }
    for name, (value, excerpt) in expected.items():
        fact = facts[name]
        assert fact["state"] == "known"
        assert fact["value"] == value
        assert fact["basis"] == "observed"
        assert len(fact["evidence"]) == 1
        ref = fact["evidence"][0]
        assert ref["capture"] == capture_id and ref["locator"] == "bytes"
        assert 0 <= ref["start"] < ref["end"] <= len(raw)
        assert raw[ref["start"]:ref["end"]] == excerpt
        assert ref["sha256"] == sha256(excerpt).hexdigest()
    boot = facts["boot_epoch"]
    assert boot["state"] == "unknown"
    assert boot["reason"] == "as_of_missing"
    assert boot["detail"] == "no_collector_time"
    assert "value" not in boot
    assert boot["evidence"] == [{"capture": capture_id, "locator": "whole_capture",
                                "sha256": sha256(raw).hexdigest()}]
    summary = (out / "SUMMARY.txt").read_text(encoding="ascii")
    assert "FACTS" in summary and capture_id in summary
    assert "unknown(as_of_missing)" in summary and "no_collector_time" in summary
    capture_lines = summary.split("\nFACTS\n", 1)[1].splitlines()
    parse_lines = [line for line in capture_lines if " parse:" in line]
    assert parse_lines == [f"{capture_id} parse: partial"]
    fact_lines = [line for line in capture_lines if " parse:" not in line]
    assert len(fact_lines) == 4
    for name in FACT_NAMES:
        matching = [line for line in fact_lines if f" {name}:" in line]
        assert len(matching) == 1 and capture_id in matching[0]
    for name in expected:
        ref = facts[name]["evidence"][0]
        line = next(line for line in fact_lines if f" {name}:" in line)
        assert "known" in line and f"span={ref['start']}..{ref['end']}" in line
    assert_scalar_contract(record)
    assert str(tmp_path) not in json.dumps(record)


def test_capture_witness_uses_untouched_bytes_and_no_invented_collector_metadata(tmp_path):
    raw = SAMPLE.replace(b"\n", b"\r\n")
    root = capture_dir(tmp_path, raw)
    captures = analyse_evidence(root)
    assert len(captures) == 1
    capture = captures[0]
    assert capture.raw == raw
    assert capture.bytes_sha256 == sha256(raw).hexdigest()
    assert capture.operation == "iosxe.show_version" and capture.rendered == "show version"
    assert capture.read_scope is k.ReadScope.UNKNOWN
    assert capture.read_scope_evidence == ()
    assert isinstance(capture.collected_utc, k.Unknown)
    assert capture.collected_utc.reason is k.UnknownReason.AS_OF_MISSING
    assert capture.collected_utc.detail == "no_collector_time"
    assert capture.integrity_evidence == (k.EvidenceRef(
        capture=capture.id, locator=k.WholeCapture(), role=k.EvidenceRole.SUBJECT,
        excerpt_sha256=sha256(raw).hexdigest(),
    ),)


def test_capture_identity_tracks_relative_name_and_raw_bytes_not_host_root(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for root in (first, second):
        (root / "show-version.txt").write_bytes(SAMPLE)
    initial = analyse_evidence(first)[0].id
    assert analyse_evidence(second)[0].id == initial
    (second / "show-version.txt").rename(second / "renamed.txt")
    assert analyse_evidence(second)[0].id != initial
    (second / "renamed.txt").rename(second / "show-version.txt")
    (second / "show-version.txt").write_bytes(SAMPLE.replace(b"PowerOn", b"ReloadCommand"))
    assert analyse_evidence(second)[0].id != initial


def test_unicode_filename_preserves_ascii_summary_and_stable_capture_identity(tmp_path):
    evidence = capture_dir(tmp_path, name="\u03bb-show-version.txt")
    out = tmp_path / "out"
    result = run(evidence, out)
    assert result.evidence_files == 1
    assert len(manifest(out)["facts"]) == 1
    assert (out / "SUMMARY.txt").read_bytes().isascii()
    assert_scalar_contract(manifest(out))


def test_partial_capture_and_duplicate_fields_are_never_defaulted(tmp_path):
    evidence = capture_dir(tmp_path, b"Cisco IOS XE Software, Version 17.09.04a\nsw-a uptime is 2 hours\n")
    out = tmp_path / "partial"
    run(evidence, out)
    facts = next(iter(manifest(out)["facts"].values()))
    assert facts["uptime"]["value"] == [[2, "hour"]]
    for name in ("image", "reload_reason"):
        assert facts[name]["state"] == "unknown"
        assert "value" not in facts[name]
    (evidence / "show-version.txt").write_bytes(SAMPLE + b"Last reload reason: ReloadCommand\n")
    duplicate = tmp_path / "duplicate"
    run(evidence, duplicate)
    facts = next(iter(manifest(duplicate)["facts"].values()))
    assert facts["reload_reason"]["state"] == "unknown"
    assert facts["reload_reason"]["reason"] == "conflicting_evidence"
    assert facts["reload_reason"]["detail"] == "duplicate_system_field"
    assert len(facts["reload_reason"]["evidence"]) == 2


def test_determinism_across_roots_creation_order_hash_seed_and_workers(tmp_path):
    outputs = []
    for index, (order, workers, seed) in enumerate((("ba", "1", "1"), ("ab", "4", "97"))):
        evidence = tmp_path / f"evidence-{index}"
        evidence.mkdir()
        for label in order:
            (evidence / f"sw-{label}.txt").write_bytes(SAMPLE.replace(b"sw-a", f"sw-{label}".encode()))
        out = tmp_path / f"out-{index}"
        completed = cli(evidence, out, "--workers", workers,
                        env={**os.environ, "PYTHONHASHSEED": seed})
        assert completed.returncode == 0, completed.stderr
        outputs.append(tuple((out / name).read_bytes() for name in ("SUMMARY.txt", "MANIFEST.json")))
        assert len(manifest(out)["facts"]) == 2
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("child", ["", "results"])
def test_output_cannot_overlap_evidence(tmp_path, child):
    evidence = capture_dir(tmp_path)
    before = (evidence / "show-version.txt").read_bytes()
    completed = cli(evidence, evidence / child)
    assert completed.returncode == 2
    assert completed.stderr == "runner refused: evidence_output_overlap\n"
    assert (evidence / "show-version.txt").read_bytes() == before
    assert list(evidence.iterdir()) == [evidence / "show-version.txt"]


def test_output_cannot_be_evidence_ancestor(tmp_path):
    evidence = capture_dir(tmp_path)
    completed = cli(evidence, tmp_path)
    assert completed.returncode == 2
    assert completed.stderr == "runner refused: evidence_output_overlap\n"
    assert not (tmp_path / "SUMMARY.txt").exists()
    assert not (tmp_path / "MANIFEST.json").exists()


def test_python_api_propagates_refusal_without_success_artifacts(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RunnerRefused) as caught:
        run(empty, tmp_path / "out")
    assert caught.value.code == "evidence_empty"
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("raw,code", [
    (b"", "evidence_capture_empty"),
    (b" \r\n\t", "evidence_capture_empty"),
    (b"GigabitEthernet0/0 is up, line protocol is down\n", "evidence_unsupported_capture"),
    (SAMPLE + b"\xff\n", "evidence_invalid_encoding"),
    (SAMPLE + b"% Invalid input detected at '^' marker.\n", "evidence_capture_error"),
    (SAMPLE + b"--More--", "evidence_capture_incomplete"),
])
def test_invalid_member_refuses_entire_folder_and_preserves_input(tmp_path, raw, code):
    evidence = capture_dir(tmp_path)
    (evidence / "zz-invalid.txt").write_bytes(raw)
    before = {path.name: path.read_bytes() for path in evidence.iterdir()}
    out = tmp_path / "out"
    completed = cli(evidence, out)
    assert completed.returncode == 2
    assert completed.stderr == f"runner refused: {code}\n"
    assert not out.exists()
    assert {path.name: path.read_bytes() for path in evidence.iterdir()} == before


@pytest.mark.parametrize("budgets", [
    Budgets(bundle_bytes=10000, artifact_bytes=10, artifacts=10),
    Budgets(bundle_bytes=len(SAMPLE), artifact_bytes=10000, artifacts=10),
    Budgets(bundle_bytes=10000, artifact_bytes=10000, artifacts=1),
])
def test_admission_enforces_artifact_total_and_file_count_limits(tmp_path, budgets):
    evidence = capture_dir(tmp_path)
    (evidence / "second.txt").write_bytes(SAMPLE)
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(evidence, budgets=budgets)
    assert caught.value.code == "evidence_budget_exceeded"


def test_nested_paths_have_distinct_capture_ids_and_enforce_depth_budget(tmp_path):
    evidence = capture_dir(tmp_path)
    nested = evidence / "device-b"
    nested.mkdir()
    (nested / "show-version.txt").write_bytes(SAMPLE)
    captures = analyse_evidence(evidence)
    assert len(captures) == 2 and len({capture.id for capture in captures}) == 2
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(evidence, budgets=Budgets(bundle_bytes=10000, artifact_bytes=10000,
                                                 artifacts=10, nesting_depth=1))
    assert caught.value.code == "evidence_budget_exceeded"


@pytest.mark.parametrize("method", ["iterdir", "open"])
def test_unreadable_evidence_has_stable_refusal(tmp_path, monkeypatch, method):
    evidence = capture_dir(tmp_path)
    original = getattr(Path, method)

    def inaccessible(path, *args, **kwargs):
        if path == (evidence if method == "iterdir" else evidence / "show-version.txt"):
            raise PermissionError("synthetic denied path must not leak")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, method, inaccessible)
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(evidence)
    assert caught.value.code == "evidence_unreadable"


def test_hardlinked_capture_is_refused(tmp_path):
    evidence = capture_dir(tmp_path)
    os.link(evidence / "show-version.txt", tmp_path / "outside.txt")
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(evidence)
    assert caught.value.code == "evidence_linked_member"


@pytest.mark.parametrize("root_link", [False, True])
def test_symlink_root_and_members_are_refused(tmp_path, root_link):
    evidence = capture_dir(tmp_path)
    link = tmp_path / "linked-root" if root_link else evidence / "linked.txt"
    target = evidence if root_link else evidence / "show-version.txt"
    try:
        link.symlink_to(target, target_is_directory=root_link)
    except OSError as error:
        pytest.skip(f"symlink creation unavailable: {error.errno}")
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(link if root_link else evidence)
    assert caught.value.code == ("evidence_linked_root" if root_link else "evidence_linked_member")


def test_changed_capture_bytes_change_run_digest_and_observed_fact(tmp_path):
    evidence = capture_dir(tmp_path)
    first = run(evidence, tmp_path / "first")
    (evidence / "show-version.txt").write_bytes(SAMPLE.replace(b"PowerOn", b"ReloadCommand"))
    second = run(evidence, tmp_path / "second")
    assert first.evidence_digest != second.evidence_digest
    assert set(manifest(first.out)["facts"]) != set(manifest(second.out)["facts"])
    facts = next(iter(manifest(second.out)["facts"].values()))
    assert facts["reload_reason"]["value"] == "ReloadCommand"


@pytest.mark.parametrize("raw,reason", [
    (b"Cisco IOS XE Software, Version 17.09.04a\n", "parse_unsupported_variant"),
    (SAMPLE.replace(b"1 day, 2 hours, 3 minutes", b"not-a-duration"), "parse_partial"),
    (SAMPLE + b"sw-a uptime is 2 hours\n", "conflicting_evidence"),
])
def test_boot_epoch_missing_clock_is_independent_of_uptime_parse(tmp_path, raw, reason):
    evidence = capture_dir(tmp_path, raw)
    out = tmp_path / "out"
    run(evidence, out)
    facts = next(iter(manifest(out)["facts"].values()))
    assert facts["uptime"]["state"] == "unknown"
    assert facts["uptime"]["reason"] == reason
    assert facts["boot_epoch"]["state"] == "unknown"
    assert facts["boot_epoch"]["reason"] == "as_of_missing"
    assert facts["boot_epoch"]["detail"] == "no_collector_time"
    assert "value" not in facts["boot_epoch"]


def test_unencodable_member_name_has_stable_refusal(tmp_path, monkeypatch):
    from atlas_brain.runner import evidence as admission

    root = capture_dir(tmp_path)
    monkeypatch.setattr(admission, "folder_members", lambda *_: {"bad\udcff.txt": SAMPLE})
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(root)
    assert caught.value.code == "evidence_unsafe_member_name"


def test_special_file_is_refused(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")
    evidence = capture_dir(tmp_path)
    os.mkfifo(evidence / "pipe")
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(evidence)
    assert caught.value.code == "evidence_special_member"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junction control")
@pytest.mark.parametrize("root_link", [False, True])
def test_windows_junction_root_and_members_are_refused(tmp_path, root_link):
    evidence = capture_dir(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "show-version.txt").write_bytes(SAMPLE)
    link = tmp_path / "linked-root" if root_link else evidence / "linked-directory"
    target = evidence if root_link else outside
    completed = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert link.is_junction()
    with pytest.raises(RunnerRefused) as caught:
        analyse_evidence(link if root_link else evidence)
    assert caught.value.code == ("evidence_linked_root" if root_link else "evidence_linked_member")


@pytest.mark.parametrize("member", ["SUMMARY.txt", "MANIFEST.json"])
@pytest.mark.parametrize("link_kind", ["hardlink", "symlink"])
def test_output_member_links_cannot_overwrite_evidence_or_partial_results(tmp_path, member, link_kind):
    evidence = capture_dir(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    other = "MANIFEST.json" if member == "SUMMARY.txt" else "SUMMARY.txt"
    prior = b"preexisting output must survive refusal\n"
    (out / other).write_bytes(prior)
    target = evidence / "show-version.txt"
    link = out / member
    if link_kind == "hardlink":
        os.link(target, link)
    else:
        try:
            link.symlink_to(target)
        except OSError as error:
            pytest.skip(f"symlink creation unavailable: {error.errno}")
    completed = cli(evidence, out)
    assert completed.returncode == 2
    assert completed.stderr == "runner refused: output_unsafe_member\n"
    assert target.read_bytes() == SAMPLE
    assert (out / other).read_bytes() == prior
