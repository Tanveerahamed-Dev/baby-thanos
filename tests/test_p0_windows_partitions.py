"""Windows P0 activation contracts; context output still is not test-execution attestation."""
import json
import os
import re
import shutil
import sys
from hashlib import sha1
from pathlib import Path

import pytest
import test_ci_pytest_cli
from test_ci_pytest import ATTEMPT, RUN_ID
from test_ci_pytest_cli import _commit
from test_ci_pytest_p0 import artifact, values, verify_cli
from test_p0_ci_context import cli as context_cli

isolated_repo = test_ci_pytest_cli.isolated_repo
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "p0-runner.yml"
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
UV = "astral-sh/setup-uv@1c37ad07a6a961277cf70c0d37d6f313000f5884"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
JOB_IDS = ("p0_regression_linux", "p0_regression_windows_parts", "p0_regression_windows", "p0-runner")
FORMER_WINDOWS = """  p0_regression_windows:
    name: P0 runner regression (windows-latest)
    runs-on: windows-latest
    timeout-minutes: 10
    outputs:
      receipt: ${{ steps.context.outputs.receipt }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - uses: astral-sh/setup-uv@1c37ad07a6a961277cf70c0d37d6f313000f5884 # v10.3.0
        with:
          version: '0.13.1'
          enable-cache: false
      - run: uv sync --locked
      - run: uv run --no-sync python tools/p0_ci_context.py check --platform win32
      - run: uv run --no-sync pytest -q -rs --durations=20 tests/runner
      - id: context
        run: uv run --no-sync python tools/p0_ci_context.py record --platform win32
"""


def expr(value):
    return "$" + "{{ " + value + " }}"


HEAD = expr("github.event.pull_request.head.sha || github.sha")
RUN, ATTEMPT_EXPR, INDEX = expr("github.run_id"), expr("github.run_attempt"), expr("matrix.shard")
RESULT = expr("needs.p0_regression_windows_parts.result")
PART_NAME = f"p0-windows-pytest-{INDEX}-{HEAD}-{RUN}-{ATTEMPT_EXPR}"
PATTERN = f"p0-windows-pytest-*-{HEAD}-{RUN}-{ATTEMPT_EXPR}"


def blob(raw):
    return sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw, usedforsecurity=False).hexdigest()


def jobs(text):
    assert text.count("jobs:\n") == 1
    section = text.split("jobs:\n", 1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z0-9_-]+):\n", section))
    assert tuple(match[1] for match in matches) == JOB_IDS
    return {match[1]: section[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(section)]
            for index, match in enumerate(matches)}


def command(block, name):
    marker = f"      - name: {name}\n        run: >-\n"
    assert block.count(marker) == 1
    lines = block.split(marker, 1)[1].splitlines()
    selected = []
    for line in lines:
        if not line.startswith("          "):
            break
        selected.append(line.strip())
    assert selected
    return " ".join(selected)


def contract(text):
    blocks = jobs(text)
    parts, aggregate = (blocks[name] for name in JOB_IDS[1:3])
    restored = text.replace(parts, "", 1).replace(aggregate, FORMER_WINDOWS, 1)
    assert blob(restored.encode("utf-8")) == "63c1071044584bd1bdafe256272fb353c558c2af"
    assert "    strategy:\n      fail-fast: false\n      matrix:\n        shard: [1, 2, 3, 4]\n    steps:\n" in parts
    assert parts.count("    strategy:") == parts.count("        shard:") == 1
    for block in (parts, aggregate):
        assert block.count("    runs-on: windows-latest\n") == 1
        assert block.count("    timeout-minutes: 10\n") == 1
        assert "continue-on-error" not in block
        assert f"          ref: {HEAD}\n" in block
        assert "          version: '0.13.1'\n          enable-cache: false\n" in block
        assert "tools/p0_ci_context.py check --platform win32" in block
    assert set(re.findall(r"uses: (\S+)", text)) == {CHECKOUT, UV, UPLOAD, DOWNLOAD}
    expected = ("uv run --no-sync python tools/ci_pytest.py run --scope p0 --count 4 "
                f"--index {INDEX} --head {HEAD} --run-id {RUN} --attempt {ATTEMPT_EXPR} "
                f"--receipt .ci-evidence/p0-windows-shards/shard-{INDEX}.json")
    assert command(parts, "Run complete P0 collection partition") == expected
    assert "outputs:" not in parts and "p0_ci_context.py record" not in parts
    assert f"      - uses: {UPLOAD} # v4\n        if: always()\n" in parts
    assert f"          name: {PART_NAME}\n          path: .ci-evidence/p0-windows-shards/shard-{INDEX}.json\n" in parts
    assert "          include-hidden-files: true\n          if-no-files-found: error\n          retention-days: 14\n" in parts
    assert "    needs: [p0_regression_windows_parts]\n    if: always()\n" in aggregate
    assert f"      receipt: {expr('steps.context.outputs.receipt')}\n" in aggregate
    assert f"      - uses: {DOWNLOAD} # v4\n        with:\n          pattern: {PATTERN}\n" in aggregate
    assert "          path: .ci-evidence/p0-windows-receipts\n          merge-multiple: false\n" in aggregate
    assert not any(key in aggregate for key in ("github-token:", "repository:", "run-id:"))
    expected = ("uv run --no-sync python tools/ci_pytest.py verify --scope p0 --platform win32 "
                "--directory .ci-evidence/p0-windows-receipts --count 4 "
                f'--head {HEAD} --run-id {RUN} --attempt {ATTEMPT_EXPR} --jobs-result "{RESULT}"')
    assert command(aggregate, "Require complete native Windows P0 regression") == expected
    tail = "      - id: context\n        if: success()\n        run: uv run --no-sync python tools/p0_ci_context.py record --platform win32\n"
    assert aggregate.endswith(tail) and aggregate.count("- id: context") == 1
    order = [aggregate.index(value) for value in ("p0_ci_context.py check", DOWNLOAD, "ci_pytest.py verify", "p0_ci_context.py record")]
    assert order == sorted(order) and len(set(order)) == 4
    assert len(re.findall(r"(?m)^(?:      -|       ) run:", parts)) == 3
    assert len(re.findall(r"(?m)^(?:      -|       ) run:", aggregate)) == 4
    indices = re.search(r"shard: \[([0-9, ]+)\]", parts)[1].split(",")
    hosts = re.search(r"os: \[([a-z, -]+)\]", blocks["p0-runner"])[1].split(",")
    assert len(indices) + len(hosts) + len(blocks) - 2 == 8


def test_windows_activation_preserves_all_other_payloads_and_context_helper_bytes():
    contract(WORKFLOW.read_bytes().decode("utf-8"))
    assert blob((ROOT / "tools" / "p0_ci_context.py").read_bytes()) == "583f5162c7e528fb8aec54fbf47fc52469667a11"


PLANTS = [
    ("p0_regression_windows_parts", "shard: [1, 2, 3, 4]", "shard: [1, 2, 3]"),
    ("p0_regression_windows_parts", "fail-fast: false", "fail-fast: true"),
    ("p0_regression_windows_parts", "timeout-minutes: 10", "timeout-minutes: 20"),
    ("p0_regression_windows_parts", "--scope p0 --count 4", "--scope full --count 4"),
    ("p0_regression_windows_parts", "p0-windows-pytest-", "windows-pytest-"),
    ("p0_regression_windows_parts", "        if: always()", "        if: success()"),
    ("p0_regression_windows_parts", "--attempt " + ATTEMPT_EXPR, "--attempt 1"),
    ("p0_regression_windows", "runs-on: windows-latest", "runs-on: ubuntu-latest"),
    ("p0_regression_windows", "needs: [p0_regression_windows_parts]", "needs: [p0_regression_linux]"),
    ("p0_regression_windows", "    if: always()", "    if: success()"),
    ("p0_regression_windows", "merge-multiple: false", "merge-multiple: true"),
    ("p0_regression_windows", '--jobs-result "' + RESULT + '"', '--jobs-result "success"'),
    ("p0_regression_windows", "        if: success()", "        if: always()"),
    ("p0-runner", "needs: [p0_regression_linux, p0_regression_windows]", "needs: [p0_regression_windows]"),
    ("p0_regression_linux", "--durations=20 tests/runner", "--durations=20 tests"),
]


@pytest.mark.parametrize("job,before,after", PLANTS)
def test_activation_guards_reject_omitted_partition_changed_namespace_and_context_bypasses(job, before, after):
    text = WORKFLOW.read_bytes().decode("utf-8")
    block = jobs(text)[job]
    assert before in block
    changed = text.replace(block, block.replace(before, after, 1), 1)
    assert changed != text
    with pytest.raises(AssertionError):
        contract(changed)


@pytest.mark.parametrize("result", ["success", "failure", "skipped", "cancelled"])
def test_native_cli_gate_never_records_context_after_nonsuccessful_partition_cohort(isolated_repo, result):
    root = isolated_repo
    shutil.copyfile(ROOT / "tools" / "p0_ci_context.py", root / "tools" / "p0_ci_context.py")
    head = _commit(root)
    data = values(platform=sys.platform)
    for value in data:
        value["head"] = head
    directory = artifact(root, data)
    channel = root / "context-output.txt"
    channel.write_bytes(b"sentinel\n")
    verified = verify_cli(root, head, directory, jobs=result)
    if verified.returncode == 0:
        env = {"P0_REVIEWED_SHA": head, "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": ATTEMPT, "GITHUB_OUTPUT": str(channel)}
        native = (root, head, {**os.environ, **env})
        recorded = context_cli(native, "record", platform=sys.platform)
        assert recorded.returncode == 0, recorded.stdout + recorded.stderr
    lines = channel.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "sentinel"
    if result == "success":
        assert verified.returncode == 0 and len(lines) == 2
        assert json.loads(lines[1].removeprefix("receipt=")) == {"schema": "atlas-brain.p0-ci-context/1", "head": head,
                "run_id": RUN_ID, "run_attempt": ATTEMPT, "platform": sys.platform}
    else:
        assert verified.returncode == 2 and "shard_jobs_not_successful" in verified.stderr
        assert lines == ["sentinel"]
