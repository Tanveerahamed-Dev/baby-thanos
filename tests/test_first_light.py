"""P0a first-light demo tests: evidence -> fact -> deterministic summary for show version."""
import json
from pathlib import Path

from tools.first_light import EXIT_INPUT, SAMPLE, main, render, run


def test_demo_is_deterministic_and_reports_known_facts_with_evidence():
    first, summary_first = render(SAMPLE)
    second, summary_second = render(SAMPLE)
    assert first == second
    assert summary_first == summary_second
    assert "bootflash:packages.conf" in first
    assert "1 day, 2 hours, 3 minutes" in first
    assert "PowerOn" in first
    assert "capture=first-light-capture" in first
    assert "unknown(as_of_missing)" in first
    facts = summary_first["facts"]
    assert isinstance(facts, dict)
    assert facts["image"]["state"] == "known"
    assert facts["boot_epoch"]["state"] == "unknown"


def test_summary_is_float_free_and_json_safe():
    _, summary = render(SAMPLE)
    dumped = json.dumps(summary, sort_keys=True)
    assert "Infinity" not in dumped and "NaN" not in dumped
    parsed = json.loads(dumped)
    assert parsed["parse_quality"] == "complete"


def test_file_mode_reads_real_bytes(tmp_path: Path):
    capture_file = tmp_path / "show-version.txt"
    capture_file.write_bytes(SAMPLE)
    text = run(raw=capture_file.read_bytes(), out=None)
    assert "bootflash:packages.conf" in text
    code = main(["--file", str(capture_file)])
    assert code == 0


def test_missing_file_is_refused_with_input_exit_code(tmp_path: Path):
    code = main(["--file", str(tmp_path / "does-not-exist.txt")])
    assert code == EXIT_INPUT


def test_out_directory_writes_deterministic_artifacts(tmp_path: Path):
    text = run(raw=SAMPLE, out=tmp_path)
    assert (tmp_path / "first-light-summary.txt").read_text(encoding="utf-8") == text
    first_json = (tmp_path / "first-light-summary.json").read_text(encoding="utf-8")
    run(raw=SAMPLE, out=tmp_path)
    assert (tmp_path / "first-light-summary.json").read_text(encoding="utf-8") == first_json
