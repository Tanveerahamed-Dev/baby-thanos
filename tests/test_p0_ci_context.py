"""P0 cohort context checks; context records alone do not attest test execution."""
import json
import os
import shutil
import subprocess
import sys
from enum import StrEnum
from pathlib import Path

import pytest
from test_ci_pytest_cli import _commit, _git

from tools import p0_ci_context as context

HEAD, RUN, ATTEMPT = "a" * 40, "123", "2"
TOOL = Path(__file__).resolve().parents[1] / "tools" / "p0_ci_context.py"


class Alias(StrEnum):
    HEAD = HEAD
    RUN = RUN
    ATTEMPT = ATTEMPT
    LINUX = "linux"
    SUCCESS = "success"


def pair(head=HEAD):
    return tuple(json.dumps(context.make_context(head=head, run_id=RUN, run_attempt=ATTEMPT, platform=platform))
        for platform in ("linux", "win32"))


def verify(texts=None, **changes):
    values = {"head": HEAD, "run_id": RUN, "run_attempt": ATTEMPT,
        "linux_result": "success", "windows_result": "success"}
    values.update(changes)
    return context.verify_contexts(*(pair() if texts is None else texts), **values)


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_exact_context_schema_and_two_os_summary_are_context_only(platform):
    value = context.make_context(head=HEAD, run_id=RUN, run_attempt=ATTEMPT, platform=platform)
    assert value == {"schema": "atlas-brain.p0-ci-context/1", "head": HEAD, "run_id": RUN,
        "run_attempt": ATTEMPT, "platform": platform}
    assert verify() == {"head": HEAD, "run_id": RUN, "run_attempt": ATTEMPT, "platforms": ["linux", "win32"]}
    assert not {"tests", "passed", "qualified"}.intersection(value)


@pytest.mark.parametrize("field,value", [
    *[("head", value) for value in ("a" * 39, "A" * 40, "g" * 40, "", None, False, [], Alias.HEAD)],
    *[("run_id", value) for value in ("0", "01", "-1", "1.0", "\u0661", 123, None, Alias.RUN)],
    *[("run_attempt", value) for value in ("0", "01", "-1", 2, False, Alias.ATTEMPT)],
    *[("platform", value) for value in ("darwin", "", None, False, [], Alias.LINUX)]])
def test_context_fields_require_exact_closed_plain_values_before_side_effects(field, value):
    assert verify()["head"] == HEAD
    arguments = {"head": HEAD, "run_id": RUN, "run_attempt": ATTEMPT, "platform": "linux"}
    arguments[field] = value
    with pytest.raises(ValueError, match="^invalid_" + field + "$"):
        context.make_context(**arguments)


@pytest.mark.parametrize("side", ["linux_result", "windows_result"])
@pytest.mark.parametrize("value", ["failure", "cancelled", "skipped", "", None, False, Alias.SUCCESS])
def test_both_job_results_must_be_exact_success_even_when_receipts_look_valid(side, value):
    assert verify()["platforms"] == ["linux", "win32"]
    with pytest.raises(ValueError, match="^regression_jobs_not_successful$"):
        verify(**{side: value})


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("field,value", [("schema", "other"), ("head", "b" * 40), ("run_id", "124"),
    ("run_attempt", "3"), ("platform", "other"), ("run_id", 123), ("run_attempt", True),
    ("extra", "unknown"), ("missing", None)])
def test_every_context_field_type_closed_schema_and_same_attempt_cohort_are_required(side, field, value):
    texts = list(pair())
    assert verify(texts)["head"] == HEAD
    item = json.loads(texts[side])
    if field == "missing":
        item.pop("schema")
    else:
        item.update({field: value})
    texts[side] = json.dumps(item)
    with pytest.raises(ValueError, match="^regression_context_mismatch$"):
        verify(texts)


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("plant", ["swapped", "missing", "object", "duplicate", "nan", "infinity", "negative_infinity", "scalar", "malformed"])
def test_json_input_is_exact_no_duplicate_nonfinite_swapped_or_missing_receipt(side, plant):
    texts = list(pair())
    assert verify(texts)["run_attempt"] == ATTEMPT
    if plant == "swapped":
        texts[side] = texts[1 - side]
    elif plant == "object":
        texts[side] = {}
    elif plant == "missing":
        texts[side] = ""
    elif plant == "duplicate":
        texts[side] = texts[side].replace('"schema":', '"schema":"other","schema":', 1)
    elif plant in ("nan", "infinity", "negative_infinity"):
        texts[side] = '{"schema":' + {"nan": "NaN", "infinity": "Infinity", "negative_infinity": "-Infinity"}[plant] + "}"
    else:
        texts[side] = "[]" if plant == "scalar" else "{"
    code = "regression_context_mismatch" if plant in ("swapped", "scalar") else "invalid_context_json" if plant == "object" else (
        "duplicate_json_key" if plant == "duplicate" else "nonfinite_json_value")
    with pytest.raises(json.JSONDecodeError if plant in ("missing", "malformed") else ValueError,
        match=None if plant in ("missing", "malformed") else "^" + code + "$"):
        verify(texts)


@pytest.mark.parametrize("field,value", [("head", "b" * 40), ("run_id", "124"), ("run_attempt", "3")])
def test_expected_context_cannot_be_substituted(field, value):
    assert verify()["head"] == HEAD
    with pytest.raises(ValueError, match="^regression_context_mismatch$"):
        verify(**{field: value})


@pytest.fixture
def repository(tmp_path):
    (tmp_path / "tools").mkdir()
    shutil.copyfile(TOOL, tmp_path / "tools" / "p0_ci_context.py")
    (tmp_path / "tracked.txt").write_bytes(b"canonical\n")
    _git(tmp_path, "init", "-q")
    head = _commit(tmp_path)
    env = {key: value for key, value in os.environ.items() if not key.startswith("P0_")
        and key not in ("GITHUB_OUTPUT", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    env.update(P0_REVIEWED_SHA=head, GITHUB_RUN_ID=RUN, GITHUB_RUN_ATTEMPT=ATTEMPT)
    return tmp_path, head, env


def cli(repository, command, *, platform=None, changes=None, cwd=None):
    root, _, supplied = repository
    env = dict(supplied)
    env.update(changes or {})
    args = [sys.executable, str(root / "tools" / "p0_ci_context.py"), command]
    if platform is not None:
        args += ["--platform", platform]
    return subprocess.run(args, cwd=root if cwd is None else cwd, env=env,
        capture_output=True, text=True, check=False, timeout=30)


def test_real_clean_git_check_record_and_verify_preserve_source_and_output_prefix(repository):
    root, head, _ = repository
    assert sys.platform in ("linux", "win32")
    assert cli(repository, "check", platform=sys.platform).returncode == 0
    output = root / "output.txt"
    output.write_bytes(b"sentinel\n")
    recorded = cli(repository, "record", platform=sys.platform, changes={"GITHUB_OUTPUT": str(output)})
    assert recorded.returncode == 0 and not recorded.stdout
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and lines[0] == "sentinel" and lines[1].startswith("receipt=")
    value = json.loads(lines[1].removeprefix("receipt="))
    assert value == context.make_context(head=head, run_id=RUN, run_attempt=ATTEMPT, platform=sys.platform)
    linux, windows = pair(head)
    result = cli(repository, "verify", changes={"P0_LINUX_CONTEXT": linux, "P0_WINDOWS_CONTEXT": windows,
        "P0_LINUX_RESULT": "success", "P0_WINDOWS_RESULT": "success"})
    assert result.returncode == 0 and result.stdout.startswith("P0_REGRESSION_COHORT ")
    assert json.loads(result.stdout.removeprefix("P0_REGRESSION_COHORT "))["head"] == head
    assert (root / "tracked.txt").read_bytes() == b"canonical\n" and not _git(root, "diff", "HEAD", "--")
    assert set(value) == {"schema", "head", "run_id", "run_attempt", "platform"}


@pytest.mark.parametrize("fault", ["cwd", "head", "dirty", "platform", "missing_head", "missing_run", "attempt"])
def test_real_source_context_refusal_never_appends_to_output_channel(repository, fault):
    root, _, _ = repository
    assert cli(repository, "check", platform=sys.platform).returncode == 0
    output = root / "output.txt"
    output.write_bytes(b"sentinel\n")
    changes, cwd, platform = {"GITHUB_OUTPUT": str(output)}, root, sys.platform
    code = {"cwd": "repository_cwd_required", "head": "checked_out_head_mismatch", "dirty": "tracked_source_not_clean",
        "platform": "native_platform_mismatch", "missing_head": "invalid_head", "missing_run": "invalid_run_id", "attempt": "invalid_run_attempt"}[fault]
    if fault == "cwd":
        cwd = root / "elsewhere"
        cwd.mkdir()
    elif fault == "dirty":
        (root / "tracked.txt").write_text("changed\n", encoding="utf-8")
    elif fault == "platform":
        platform = "linux" if sys.platform == "win32" else "win32"
    else:
        name, value = {"head": ("P0_REVIEWED_SHA", "b" * 40), "missing_head": ("P0_REVIEWED_SHA", ""),
            "missing_run": ("GITHUB_RUN_ID", ""), "attempt": ("GITHUB_RUN_ATTEMPT", "01")}[fault]
        changes[name] = value
    result = cli(repository, "record", platform=platform, changes=changes, cwd=cwd)
    assert result.returncode == 2 and "P0 context refused: " + code in result.stderr
    assert output.read_bytes() == b"sentinel\n"


@pytest.mark.parametrize("fault", ["missing", "bad_parent", "directory"])
def test_record_output_channel_failure_does_not_publish_a_receipt(repository, fault):
    root, _, _ = repository
    assert cli(repository, "check", platform=sys.platform).returncode == 0
    output = root / "no-parent" / "output" if fault == "bad_parent" else root / "output"
    if fault == "directory":
        output.mkdir()
    result = cli(repository, "record", platform=sys.platform, changes={} if fault == "missing" else {"GITHUB_OUTPUT": str(output)})
    assert result.returncode == 2 and result.stderr.startswith("P0 context refused: ") and not result.stdout
    assert output.is_dir() if fault == "directory" else not output.exists()


@pytest.mark.parametrize("fault", ["linux_failure", "windows_missing", "cross_attempt", "cross_head", "duplicate"])
def test_real_verify_cli_requires_both_successful_exact_contexts_and_current_source(repository, fault):
    _, head, _ = repository
    linux, windows = pair(head)
    env = {"P0_LINUX_CONTEXT": linux, "P0_WINDOWS_CONTEXT": windows, "P0_LINUX_RESULT": "success", "P0_WINDOWS_RESULT": "success"}
    assert cli(repository, "verify", changes=env).returncode == 0
    if fault == "linux_failure":
        env["P0_LINUX_RESULT"] = "failure"
    elif fault == "windows_missing":
        env.pop("P0_WINDOWS_CONTEXT")
    else:
        value = json.loads(env["P0_WINDOWS_CONTEXT"])
        value["run_attempt" if fault == "cross_attempt" else "head"] = "3" if fault == "cross_attempt" else "b" * 40
        env["P0_WINDOWS_CONTEXT"] = json.dumps(value) if fault != "duplicate" else windows.replace('"schema":', '"schema":"other","schema":', 1)
    result = cli(repository, "verify", changes=env)
    assert result.returncode == 2 and result.stderr.startswith("P0 context refused: ") and not result.stdout
