"""Missing, stale, failed or skipped main receipts cannot imply complete CI."""
import base64
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from tools.main_receipts import expected_jobs, verify, workflow_paths

SHA = "a" * 40
SOURCE = """name: Synthetic
on: [push]
jobs:
  check:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    timeout-minutes: 10
    steps:
      - run: echo synthetic
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: echo synthetic
"""


def source_blob(text):
    raw = text.encode()
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    return {"sha": digest, "encoding": "base64", "content": base64.b64encode(raw).decode()}


def receipts():
    paths = [f".github/workflows/gate{i}.yml" for i in range(3)]
    blob = source_blob(SOURCE)
    return {"tree": {"truncated": False, "tree": [{"path": p, "type": "blob", "sha": blob["sha"]} for p in paths]},
            "sources": {p: deepcopy(blob) for p in paths},
            "catalog": [{"id": i + 1, "path": p, "state": "active"} for i, p in enumerate(paths)],
            "runs": [{"id": i + 10, "workflow_id": i + 1, "head_sha": SHA, "event": "push",
                      "run_number": 1, "run_attempt": 1, "status": "completed", "conclusion": "success"}
                     for i in range(3)],
            "jobs": {str(i + 10): [{"name": n, "status": "completed", "conclusion": "success",
                                   "steps": [{"number": 1, "name": "Set up job", "status": "completed", "conclusion": "success"},
                                             {"number": 2, "name": "Run echo synthetic", "status": "completed", "conclusion": "success"},
                                             {"number": 3, "name": "Complete job", "status": "completed", "conclusion": "success"}]}
                                  for n in ("check (ubuntu-latest)", "check (windows-latest)", "audit")]
                     for i in range(3)}}


def test_full_source_derived_class_passes():
    result = verify(receipts(), SHA, "push")
    assert result["workflow_count"] == 3 and result["job_count"] == 9


@pytest.mark.parametrize("step", [
    "      - run: exit 1\n        continue-on-error: true\n",
    "      - run: uv run pytest\n        if: false\n",
    "      - if: false\n        run: uv run pytest\n",
    '      - run: exit 1\n        "continue-on-error": true\n',
    "      - {run: exit 1, continue-on-error: true}\n",
    "      - run: uv run pytest\n        <<: *skip_gate\n",
])
def test_source_step_bypasses_cannot_hide_behind_green_jobs(step):
    data = receipts()
    path = data["catalog"][0]["path"]
    blob = source_blob(SOURCE.replace("      - run: echo synthetic\n", step, 1))
    data["sources"][path] = blob
    data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


@pytest.mark.parametrize("plant", ["missing", "empty", "skipped", "failure", "cancelled", "pending"])
def test_green_job_requires_successful_step_receipts(plant):
    data = receipts()
    job = data["jobs"]["10"][0]
    if plant == "missing":
        del job["steps"]
    elif plant == "empty":
        job["steps"] = []
    elif plant == "pending":
        job["steps"][1]["status"] = "in_progress"
    else:
        job["steps"][1]["conclusion"] = plant
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def test_missing_one_of_two_source_steps_refuses_then_complete_pair_passes():
    data = receipts()
    path = data["catalog"][0]["path"]
    blob = source_blob(SOURCE.replace("      - run: echo synthetic\n",
                                     "      - run: echo synthetic\n      - run: uv run pytest\n", 1))
    data["sources"][path] = blob
    data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")
    for index, job in enumerate(data["jobs"]["10"][:2]):
        steps = job["steps"]
        steps[-1]["number"] = 4
        steps.insert(2, {"number": 3, "name": "Run uv run pytest", "status": "completed", "conclusion": "success"})
        if index == 0:
            with pytest.raises(ValueError):
                verify(data, SHA, "push")
    assert verify(data, SHA, "push")["job_count"] == 9


@pytest.mark.parametrize("plant", ["missing", "duplicate", "name", "number", "extra", "setup", "boolean"])
def test_source_step_identity_is_unambiguous(plant):
    data = receipts()
    steps = data["jobs"]["10"][0]["steps"]
    if plant == "missing":
        steps.pop(1)
    elif plant == "duplicate":
        steps.append(deepcopy(steps[1]))
    elif plant == "name":
        steps[1]["name"] = "Run a different gate"
    elif plant == "number":
        steps[1]["number"] = 4
    elif plant == "extra":
        steps.append({**steps[1], "number": 4, "name": "Run unexpected gate"})
    elif plant == "setup":
        steps.pop(0)
    else:
        steps[0]["number"] = True
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def test_action_post_receipts_are_separate_from_required_source_steps():
    data = receipts()
    path = data["catalog"][0]["path"]
    blob = source_blob(SOURCE.replace("      - run: echo synthetic\n", "      - uses: actions/example@abc # pinned\n", 1))
    data["sources"][path] = blob
    data["tree"]["tree"][0]["sha"] = blob["sha"]
    for job in data["jobs"]["10"][:2]:
        steps = job["steps"]
        steps[1]["name"] = "Run actions/example@abc"
        steps[-1]["number"] = 5
        steps.insert(2, {"number": 4, "name": "Post Run actions/example@abc", "status": "completed", "conclusion": "success"})
    assert verify(data, SHA, "push")["job_count"] == 9
    steps = data["jobs"]["10"][0]["steps"]
    steps[1]["name"] = "Post Run actions/example@abc"
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


@pytest.mark.parametrize("step", [
    "      - run: echo synthetic\n      - run: echo synthetic\n",
    "      - run: echo synthetic\n        name:\n",
    "      - name: Set up job\n        run: echo synthetic\n",
    "      - name: ${{ github.sha }}\n        run: echo synthetic\n",
])
def test_ambiguous_source_step_names_refuse(step):
    data = receipts()
    path = data["catalog"][0]["path"]
    blob = source_blob(SOURCE.replace("      - run: echo synthetic\n", step, 1))
    data["sources"][path] = blob
    data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def test_matrix_values_come_from_source_not_an_os_list():
    data = receipts()
    for entry in data["tree"]["tree"]:
        blob = source_blob(SOURCE.replace("windows-latest", "other-runner"))
        data["sources"][entry["path"]] = blob
        entry["sha"] = blob["sha"]
    for jobs in data["jobs"].values():
        jobs[1]["name"] = "check (other-runner)"
    assert verify(data, SHA, "push")["job_count"] == 9


@pytest.mark.parametrize("plant", ["windows", "job", "duplicate", "extra", "unbound", "tampered",
                                  "dynamic", "include", "condition", "renamed", "controller"])
def test_exact_source_job_inventory_refusals(plant):
    data = receipts()
    path = data["catalog"][0]["path"]
    if plant in {"windows", "job"}:
        data["jobs"]["10"].pop(1 if plant == "windows" else 2)
    elif plant in {"duplicate", "extra"}:
        data["jobs"]["10"].append({**data["jobs"]["10"][0], "name": "extra" if plant == "extra" else "audit"})
    elif plant == "unbound":
        data["sources"][path]["sha"] = "b" * 40
    elif plant == "tampered":
        data["sources"][path]["content"] = base64.b64encode(b"jobs:\n").decode()
    elif plant == "controller":
        data["runs"][0]["head_sha"] = "b" * 40
    else:
        replacement = {"dynamic": "${{ needs.build.outputs.os }}", "include": "[]\n        include: []",
                       "condition": "[ubuntu-latest, windows-latest]\n    if: false",
                       "renamed": "[other-os]"}[plant]
        blob = source_blob(SOURCE.replace("[ubuntu-latest, windows-latest]", replacement))
        data["sources"][path] = blob
        data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


@pytest.mark.parametrize("plant", ["absent", "one_missing", "stale", "schedule", "failure", "pending",
                                  "skipped", "cancelled", "no_jobs", "newer_red", "new_gate", "disabled",
                                  "duplicate_catalog", "bad_identity", "truncated"])
def test_main_receipt_refusals(plant):
    data = receipts()
    if plant == "absent":
        data["runs"] = []
    elif plant == "one_missing":
        data["runs"].pop()
    elif plant == "stale":
        data["runs"][0]["head_sha"] = "b" * 40
    elif plant == "schedule":
        data["runs"][0]["event"] = "schedule"
    elif plant == "failure":
        data["runs"][0]["conclusion"] = "failure"
    elif plant == "pending":
        data["runs"][0]["status"] = "in_progress"
    elif plant in {"skipped", "cancelled"}:
        data["jobs"]["10"][0]["conclusion"] = plant
    elif plant == "no_jobs":
        data["jobs"]["10"] = []
    elif plant == "newer_red":
        data["runs"].append({**deepcopy(data["runs"][0]), "id": 99, "run_number": 2, "conclusion": "failure"})
    elif plant == "new_gate":
        data["tree"]["tree"].append({"path": ".github/workflows/new.yml", "type": "blob"})
    elif plant == "disabled":
        data["catalog"][0]["state"] = "disabled_manually"
    elif plant == "duplicate_catalog":
        data["catalog"].append(deepcopy(data["catalog"][0]))
    elif plant == "bad_identity":
        data["catalog"][0]["id"] = True
    else:
        data["tree"]["truncated"] = True
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def test_real_cli_positive_and_missing_snapshot(tmp_path: Path):
    path = tmp_path / "receipts.json"
    omitted = receipts()
    omitted["jobs"]["10"].pop(1)
    for data, expected in ((receipts(), 0), ({**receipts(), "runs": []}, 1), (omitted, 1)):
        path.write_text(json.dumps(data), encoding="utf-8")
        result = subprocess.run([sys.executable, "-m", "tools.main_receipts", "--sha", SHA,
                                 "--snapshot", str(path)], capture_output=True, text=True, check=False)
        assert result.returncode == expected
        assert json.loads(result.stdout)["verified"] is (expected == 0)


@pytest.mark.parametrize("sha,expected", [("a293f540eb75d11c8849736302bfeea183cdfb61", 0),
                                         ("228a16b7197e75253cf2426d700cf23eb8c3b13f", 1)])
def test_live_published_positive_and_missing_push_history(sha, expected):
    result = subprocess.run([sys.executable, "-m", "tools.main_receipts", "--sha", sha],
                            capture_output=True, text=True, check=False)
    assert result.returncode == expected, result.stdout + result.stderr
    record = json.loads(result.stdout)
    assert record["sha"] == sha and record["event"] == "push"
    assert record["verified"] is (expected == 0)
    if expected:
        assert "missing exact-SHA push receipt" in record["reason"], result.stdout


def test_every_registered_workflow_has_one_explicit_manual_recovery_trigger():
    paths = workflow_paths({"truncated": False, "tree": [
        {"path": p.as_posix(), "type": "blob"} for p in Path(".github/workflows").iterdir() if p.is_file()]})
    assert paths
    for name in sorted(paths):
        path = Path(name)
        text = path.read_text(encoding="utf-8")
        assert text.count("  workflow_dispatch:\n") == 1
        assert "github.event.pull_request.head.sha || github.sha" in text
        blob = source_blob(text)
        data = {"sources": {path.as_posix(): blob},
                "tree": {"tree": [{"path": path.as_posix(), "sha": blob["sha"]}]}}
        ordinary = expected_jobs(data, path.as_posix(), "push")
        manual = expected_jobs(data, path.as_posix(), "workflow_dispatch")
        assert len(manual) == len(ordinary) and set(manual).isdisjoint(ordinary)
        assert all(name.startswith("manual-") for name in manual)


@pytest.mark.parametrize("plant", ["collision", "unlabelled"])
def test_yaml_workflow_cannot_escape_manual_context_class(tmp_path: Path, monkeypatch, plant):
    source = Path(".github/workflows/governance.yml").read_text(encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "valid.yml").write_text(source, encoding="utf-8")
    yaml_path = workflows / "planted.yaml"
    yaml_path.write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    test_every_registered_workflow_has_one_explicit_manual_recovery_trigger()
    bad = (source.replace("'manual-governance-foundation'", "'governance-foundation'") if plant == "collision"
           else "\n".join(line for line in source.splitlines() if not line.startswith("    name:")) + "\n")
    yaml_path.write_text(bad, encoding="utf-8")
    with pytest.raises((ValueError, AssertionError)):
        test_every_registered_workflow_has_one_explicit_manual_recovery_trigger()


@pytest.mark.parametrize("kind", ["matrix", "single"])
def test_real_verifier_refuses_unlabelled_manual_yaml_receipts(kind):
    data = receipts()
    path = ".github/workflows/extra.yaml"
    raw = SOURCE.replace("on: [push]", "on: [push, workflow_dispatch]").replace("  check:", "  governance-foundation:")
    jobs = data["jobs"]["10"]
    for job in jobs[:2]:
        job["name"] = job["name"].replace("check", "governance-foundation")
    if kind == "single":
        raw = "name: Synthetic\non: [push, workflow_dispatch]\njobs:\n  audit:\n" + SOURCE.split("  audit:\n")[1]
        jobs = jobs[2:]
    blob = source_blob(raw)
    data["tree"]["tree"] = [{"path": path, "type": "blob", "sha": blob["sha"]}]
    data["sources"] = {path: blob}
    data["catalog"] = [{**data["catalog"][0], "path": path}]
    data["runs"] = data["runs"][:1]
    data["jobs"] = {"10": jobs}
    assert verify(data, SHA, "push")["job_count"] == len(jobs)
    data["runs"][0]["event"] = "workflow_dispatch"
    with pytest.raises(ValueError, match="manual"):
        verify(data, SHA, "workflow_dispatch")


@pytest.mark.parametrize("event,prefix", [("push", ""), ("schedule", ""), ("workflow_dispatch", "manual-")])
def test_event_bound_job_names_have_positive_receipts(event, prefix):
    data = receipts()
    text = SOURCE
    for job, suffix in (("check", " (${{ matrix.os }})"), ("audit", "")):
        expression = "${{ github.event_name == 'workflow_dispatch' && 'manual-" + job + "' || '" + job + "' }}" + suffix
        text = text.replace(f"  {job}:\n", f"  {job}:\n    name: {expression}\n")
    blob = source_blob(text)
    for entry in data["tree"]["tree"]:
        entry["sha"] = blob["sha"]
        data["sources"][entry["path"]] = blob
    for run in data["runs"]:
        run["event"] = event
    for jobs in data["jobs"].values():
        for job in jobs:
            job["name"] = prefix + job["name"]
    assert verify(data, SHA, event)["job_count"] == 9
    if prefix:
        data["jobs"]["10"][0]["name"] = "check (ubuntu-latest)"
        with pytest.raises(ValueError):
            verify(data, SHA, event)


def test_manual_context_collision_is_refused():
    data = receipts()
    text = SOURCE.replace("  audit:\n", "  audit:\n    name: ${{ github.event_name == 'workflow_dispatch' && 'audit' || 'audit' }}\n")
    blob = source_blob(text)
    path = data["catalog"][0]["path"]
    data["sources"][path] = blob
    data["tree"]["tree"][0]["sha"] = blob["sha"]
    with pytest.raises(ValueError):
        verify(data, SHA, "push")


def native_receipts():
    data = receipts()
    data["checks"] = []
    for run in data["runs"]:
        run["head_branch"] = "main"
        run["path"] = data["catalog"][run["workflow_id"] - 1]["path"]
        for index, job in enumerate(data["jobs"][str(run["id"])]):
            identity = run["id"] * 10 + index
            job.update(id=identity, run_id=run["id"], head_sha=SHA,
                       check_run_url=f"https://api.github.com/repos/Tanveerahamed-Dev/atlas-brain-staging/check-runs/{identity}")
            data["checks"].append({"id": identity, "head_sha": SHA, "name": job["name"],
                                   "app": {"id": 15368}, "status": "completed", "conclusion": "success"})
    return data


def test_native_jobs_are_bound_to_actual_checks_with_manual_siblings():
    from tools.main_receipts import verify_native

    data = native_receipts()
    manual = deepcopy(data["runs"][0])
    manual.update(id=900, event="workflow_dispatch")
    data["runs"].append(manual)
    data["checks"].extend([{**deepcopy(row), "id": row["id"] + 1000,
                            "name": "manual-" + row["name"]} for row in data["checks"][:]])
    result = verify_native(data, SHA)
    assert result["verified"] and result["job_count"] == 9
    assert len(result["check_ids"]) == 9
    assert all(identity < 900 for identity in result["check_ids"])
    data["runs"] = [manual]
    with pytest.raises(ValueError, match="missing exact-SHA push receipt"):
        verify_native(data, SHA)


@pytest.mark.parametrize("plant", ["branch", "path", "job_run", "job_sha", "url", "foreign_repo", "job_id",
                                  "missing_check", "duplicate_check", "app", "check_sha", "check_name",
                                  "check_pending", "check_failure", "duplicate_job_id", "ambiguous_run"])
def test_native_receipts_reject_unassociated_or_wrong_identity(plant):
    from tools.main_receipts import verify_native

    data = native_receipts()
    job, check = data["jobs"]["10"][0], data["checks"][0]
    if plant == "branch":
        data["runs"][0]["head_branch"] = "topic"
    elif plant == "path":
        data["runs"][0]["path"] = ".github/workflows/controller.yml"
    elif plant == "job_run":
        job["run_id"] = 900
    elif plant == "job_sha":
        job["head_sha"] = "b" * 40
    elif plant == "url":
        job["check_run_url"] += "?quoted=100"
    elif plant == "foreign_repo":
        job["check_run_url"] = job["check_run_url"].replace("atlas-brain-staging", "other")
    elif plant == "job_id":
        job["id"] = True
    elif plant == "missing_check":
        data["checks"].pop(0)
    elif plant == "duplicate_check":
        data["checks"].append(deepcopy(check))
    elif plant == "app":
        check["app"]["id"] = 999
    elif plant == "check_sha":
        check["head_sha"] = "b" * 40
    elif plant == "check_name":
        check["name"] = "quoted " + check["name"]
    elif plant == "check_pending":
        check["status"] = "in_progress"
    elif plant == "check_failure":
        check["conclusion"] = "failure"
    elif plant == "duplicate_job_id":
        data["jobs"]["10"][1]["id"] = job["id"]
    else:
        data["runs"].append({**deepcopy(data["runs"][0]), "id": 900})
    with pytest.raises(ValueError):
        verify_native(data, SHA)


def test_base_target_binding_cannot_require_its_own_pr_push_receipt():
    from tools.base_native_receipts import target

    other = "b" * 40
    assert target(SHA, other, "pull_request") == SHA
    assert target(SHA, other, "merge_group") == SHA
    assert target(SHA, other, "push") == SHA
    assert target(other, other, "schedule") == other
    assert target(other, other, "workflow_dispatch") == other
    for base, head, event in ((SHA, SHA, "pull_request"), (SHA, SHA, "push"),
                              (SHA, other, "schedule"), ("HEAD^", other, "push"), (SHA, other, "unknown")):
        with pytest.raises(ValueError):
            target(base, head, event)


@pytest.mark.parametrize("sha,expected", [("b09f2935e2e3cf52e83de2c8cc4b5409b8a68a78", 0),
                                         ("0bf9f263c4fde7007c49c3fa7b984c9e51c1d88b", 0),
                                         ("6d0093eed4a2edcbeaeb9875e1f6a21f355e26d5", 1),
                                         ("228a16b7197e75253cf2426d700cf23eb8c3b13f", 1)])
def test_enforced_base_real_cli_published_positive_and_missing_native(sha, expected):
    result = subprocess.run([sys.executable, "-m", "tools.base_native_receipts", "--base", sha,
                             "--event", "pull_request"], capture_output=True, text=True, check=False)
    assert result.returncode == expected, result.stdout + result.stderr
    record = json.loads(result.stdout)
    assert record["base_sha"] == sha and record["verified"] is (expected == 0)
    if expected:
        assert "missing exact-SHA push receipt" in record["reason"], result.stdout
    else:
        assert record["job_count"] == len(record["check_ids"]) == 16
        assert record["workflow_count"] == 7 and record["event"] == "push"


def test_governance_runs_native_base_gate_without_replacing_existing_commands():
    text = Path(".github/workflows/governance.yml").read_text(encoding="utf-8")
    assert 'uv run --no-sync python -m tools.base_native_receipts --base "$BASE" --event "$EVENT"' in text
    assert "BASE: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}" in text
    assert "EVENT: ${{ github.event_name }}" in text
    assert "uv run --no-sync pytest -q tests/test_governance.py tests/test_main_receipts.py" in text
    assert 'uv run --no-sync python -m tools.governance --base "$BASE" --head HEAD' in text


def source_native_class():
    """Synthetic identities/steps from current workflow source DATA, not real receipts."""
    paths = sorted(workflow_paths({"truncated": False, "tree": [
        {"path": p.as_posix(), "type": "blob"} for p in Path(".github/workflows").iterdir() if p.is_file()]}))
    sources = {path: source_blob(Path(path).read_text(encoding="utf-8")) for path in paths}
    data = {"tree": {"truncated": False, "tree": [
        {"path": path, "type": "blob", "sha": sources[path]["sha"]} for path in paths]},
        "sources": sources, "catalog": [], "runs": [], "jobs": {}, "checks": []}
    for index, path in enumerate(paths):
        run_id, workflow_id = 100 + index, 10 + index
        data["catalog"].append({"id": workflow_id, "path": path, "state": "active"})
        data["runs"].append({"id": run_id, "workflow_id": workflow_id, "path": path, "head_sha": SHA,
                             "head_branch": "main", "event": "push", "run_number": 1, "run_attempt": 1,
                             "status": "completed", "conclusion": "success"})
        jobs = []
        for ordinal, (name, required) in enumerate(expected_jobs(data, path, "push", with_steps=True).items()):
            identity = run_id * 100 + ordinal
            steps = [{"number": 1, "name": "Set up job", "status": "completed", "conclusion": "success"}]
            steps.extend({"number": number, "name": step["name"], "status": "completed", "conclusion": "success"}
                         for number, step in enumerate(required, 2))
            steps.append({"number": len(required) + 2, "name": "Complete job", "status": "completed", "conclusion": "success"})
            jobs.append({"id": identity, "run_id": run_id, "head_sha": SHA, "name": name,
                         "status": "completed", "conclusion": "success", "steps": steps,
                         "check_run_url": f"https://api.github.com/repos/Tanveerahamed-Dev/atlas-brain-staging/check-runs/{identity}"})
            data["checks"].append({"id": identity, "head_sha": SHA, "name": name,
                                   "app": {"id": 15368}, "status": "completed", "conclusion": "success"})
        data["jobs"][str(run_id)] = jobs
    assert len(paths) == 7 and sum(map(len, data["jobs"].values())) == 16
    return data


def boundary_api(monkeypatch, data, rows, total=None, failure=None):
    from tools import main_receipts

    commands = []
    def read(command, encoding):
        commands.append(command)
        endpoint = command[2].removeprefix(f"repos/{main_receipts.REPO}/")
        if endpoint.startswith("git/trees/"):
            return json.dumps(data["tree"])
        if endpoint.startswith("actions/workflows?"):
            return json.dumps([{"workflows": data["catalog"], "total_count": len(data["catalog"])}])
        if endpoint.startswith("actions/runs?"):
            if failure == "http":
                raise subprocess.CalledProcessError(1, command, output="unlogged-response", stderr="unlogged-response")
            if failure == "json":
                return "invalid-json"
            return json.dumps([{"workflow_runs": rows, "total_count": len(rows) if total is None else total}])
        if endpoint.startswith("git/blobs/"):
            return json.dumps(next(blob for blob in data["sources"].values() if blob["sha"] == endpoint.split("/")[-1]))
        if endpoint.startswith("actions/runs/"):
            jobs = data["jobs"][endpoint.split("/")[2]]
            return json.dumps([{"jobs": jobs, "total_count": len(jobs)}])
        if endpoint.startswith("commits/"):
            return json.dumps([{"check_runs": data["checks"], "total_count": len(data["checks"])}])
        raise AssertionError(endpoint)
    monkeypatch.setattr(main_receipts.subprocess, "check_output", read)
    return commands


@pytest.mark.parametrize("case", ["healthy", "healthy_manual", "latest_failure", "wrong_sha_filler", "partial"])
def test_complete_source_class_cannot_hide_replaced_latest_failure(monkeypatch, case):
    from tools import main_receipts

    data = source_native_class()
    rows = deepcopy(data["runs"])
    ci = next(run for run in rows if run["path"] == ".github/workflows/ci.yml")
    newer = {**ci, "id": 900, "run_number": 2, "run_attempt": 2, "conclusion": "failure"}
    if case in {"latest_failure", "wrong_sha_filler"}:
        rows.append({**newer, "head_sha": "b" * 40} if case == "wrong_sha_filler" else newer)
    if case == "healthy_manual":
        rows.append({**ci, "id": 900, "event": "workflow_dispatch"})
    total = 8 if case == "partial" else len(rows)
    assert len({run["workflow_id"] for run in rows}) == 7
    assert len({run["id"] for run in rows}) == len(rows)
    commands = boundary_api(monkeypatch, data, rows, total)
    if case in {"wrong_sha_filler", "partial"}:
        def forbidden(*args, **kwargs):
            raise AssertionError("selection must not run for a malformed listing")
        monkeypatch.setattr(main_receipts, "select_runs", forbidden)
    if case in {"healthy", "healthy_manual"}:
        result = main_receipts.verify_native(main_receipts.collect(SHA, "push", with_checks=True), SHA)
        assert result["verified"] and result["workflow_count"] == 7 and result["job_count"] == 16
    else:
        reason = {"latest_failure": "latest workflow is not successful", "wrong_sha_filler": "wrong-subject",
                  "partial": "incomplete or inconsistent listing"}[case]
        with pytest.raises(ValueError, match=reason):
            main_receipts.collect(SHA, "push", with_checks=True)
        assert not any("/jobs?" in command[2] for command in commands)
    assert sum("actions/runs?" in command[2] for command in commands) == 1


@pytest.mark.parametrize("subject", [None, True, 12, [], "short", "b" * 40])
def test_extra_irrelevant_wrong_subject_refuses_before_selection(monkeypatch, subject):
    from tools import main_receipts

    data = source_native_class()
    filler = {**data["runs"][0], "id": 900, "workflow_id": 9999, "head_sha": subject}
    if subject is None:
        del filler["head_sha"]
    commands = boundary_api(monkeypatch, data, [*data["runs"], filler])
    def forbidden(*args, **kwargs):
        raise AssertionError("wrong-subject row reached selection")
    monkeypatch.setattr(main_receipts, "select_runs", forbidden)
    with pytest.raises(ValueError, match="wrong-subject"):
        main_receipts.collect(SHA, "push", with_checks=True)
    assert not any("/jobs?" in command[2] for command in commands)


@pytest.mark.parametrize("kind", ["empty", "manual", "manual_only", "partial_required", "latest_attempt",
                                 "wrong_sha", "wrong_workflow", "http", "json"])
def test_source_query_retains_original_closed_response_cases(monkeypatch, kind):
    from tools.main_receipts import collect

    data = source_native_class()
    rows = deepcopy(data["runs"])
    total = None
    if kind == "empty":
        rows = []
    elif kind == "manual":
        rows[0]["event"] = "workflow_dispatch"
    elif kind == "manual_only":
        for row in rows:
            row["event"] = "workflow_dispatch"
    elif kind == "partial_required":
        rows.pop()
        total = 7
    elif kind == "latest_attempt":
        rows.append({**rows[0], "id": 900, "run_attempt": 2, "conclusion": "failure"})
    elif kind == "wrong_sha":
        rows[0]["head_sha"] = "b" * 40
    elif kind == "wrong_workflow":
        rows[0]["workflow_id"] = 9999
    commands = boundary_api(monkeypatch, data, rows, total=total, failure=kind)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        collect(SHA, "push", with_checks=True)
    assert sum("actions/runs?" in command[2] for command in commands) == 1
    assert not any("/jobs?" in command[2] for command in commands)


@pytest.mark.parametrize("plant", ["healthy", "missing_count", "boolean_count", "negative_count",
                                  "inconsistent_totals", "duplicate", "bad_id", "missing_page"])
def test_paginated_query_class_is_complete_before_admission(monkeypatch, plant):
    from tools.main_receipts import github

    rows = source_native_class()["runs"]
    pages = [{"total_count": 7, "workflow_runs": rows[:4]}, {"total_count": 7, "workflow_runs": rows[4:]}]
    if plant == "missing_count":
        del pages[0]["total_count"]
    elif plant == "boolean_count":
        pages[0]["total_count"] = True
    elif plant == "negative_count":
        pages[0]["total_count"] = -1
    elif plant == "inconsistent_totals":
        pages[1]["total_count"] = 8
    elif plant == "duplicate":
        pages[1]["workflow_runs"] = [rows[0], *rows[5:]]
    elif plant == "bad_id":
        pages[1]["workflow_runs"][0] = {**rows[4], "id": True}
    elif plant == "missing_page":
        pages = []
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: json.dumps(pages))
    if plant == "healthy":
        assert github("actions/runs?head_sha=" + SHA, "workflow_runs") == rows
    else:
        with pytest.raises(ValueError, match="incomplete or inconsistent listing"):
            github("actions/runs?head_sha=" + SHA, "workflow_runs")


def test_same_collection_evidence_reports_native_positive_without_payload(monkeypatch):
    from tools.main_receipts import collect, verify_native

    data = source_native_class()
    data["runs"][0]["private_payload"] = "unlogged-response"
    commands = boundary_api(monkeypatch, data, data["runs"])
    observed = collect(SHA, "push", with_checks=True)
    assert verify_native(observed, SHA)["job_count"] == 16
    trace = observed["retrieval_evidence"]
    query = next(row for row in trace["queries"] if row["key"] == "workflow_runs")
    assert query["pages"] == [{"total_count": 7, "returned_count": 7}]
    assert query["outcome"] == "decoded" and query["exit_code"] == 0
    assert query["http_status"] == "not captured by this transport"
    assert len(trace["selection"]) == 7 and all(row["exact_count"] == 1 for row in trace["selection"])
    assert sum("actions/runs?" in command[2] for command in commands) == 1
    assert "unlogged-response" not in json.dumps(trace)


@pytest.mark.parametrize("kind", ["empty", "partial", "manual", "wrong_sha", "wrong_sha_filler",
                                 "wrong_workflow", "latest", "http", "json"])
def test_same_collection_refusal_evidence_preserves_admission_boundary(monkeypatch, kind):
    from tools.main_receipts import collect

    data = source_native_class()
    rows, total = deepcopy(data["runs"]), None
    if kind == "empty":
        rows = []
    elif kind == "partial":
        rows.pop()
        total = 7
    elif kind == "manual":
        rows[0]["event"] = "workflow_dispatch"
    elif kind == "wrong_sha":
        rows[0]["head_sha"] = "b" * 40
    elif kind in {"wrong_sha_filler", "latest"}:
        rows.append({**rows[0], "id": 900, "run_attempt": 2, "conclusion": "failure",
                     "head_sha": "b" * 40 if kind == "wrong_sha_filler" else SHA})
    elif kind == "wrong_workflow":
        rows[0]["workflow_id"] = 9999
    commands = boundary_api(monkeypatch, data, rows, total=total, failure=kind)
    with pytest.raises(ValueError) as refused:
        collect(SHA, "push", with_checks=True)
    trace = refused.value.evidence
    query = next(row for row in trace["queries"] if row["key"] == "workflow_runs")
    assert query["outcome"] == {"partial": "incomplete_listing", "http": "process_error",
                                "json": "invalid_json"}.get(kind, "decoded")
    assert sum("actions/runs?" in command[2] for command in commands) == 1
    assert not any("/jobs?" in command[2] for command in commands)
    assert "unlogged-response" not in json.dumps(trace) and "unlogged-response" not in str(refused.value)
    if kind in {"partial", "http", "json", "wrong_sha", "wrong_sha_filler"}:
        assert trace["selection"] == []
    else:
        assert len(trace["selection"]) == 7


@pytest.mark.parametrize("kind", ["empty", "http"])
def test_main_cli_failure_uses_original_collection_evidence(monkeypatch, capsys, kind):
    from tools import main_receipts

    data = source_native_class()
    boundary_api(monkeypatch, data, [], failure=kind)
    monkeypatch.setattr(sys, "argv", ["main_receipts", "--sha", SHA])
    assert main_receipts.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert not result["verified"] and "unlogged-response" not in json.dumps(result)
    trace = result["retrieval_evidence"]
    assert trace["sha"] == SHA and trace["event"] == "push"
    if kind == "empty":
        assert "missing exact-SHA push receipt" in result["reason"]
        assert trace["queries"][-1]["pages"] == [{"total_count": 0, "returned_count": 0}]
        assert all(row["exact_count"] == 0 for row in trace["selection"])
    else:
        assert trace["queries"][-1]["outcome"] == "process_error" and trace["selection"] == []


def test_base_cli_failure_keeps_original_safe_evidence(monkeypatch, capsys):
    from tools import base_native_receipts, main_receipts

    trace = {"sha": SHA, "event": "push", "queries": [], "selection": []}
    def refused(*args, **kwargs):
        raise main_receipts.ReceiptReadError("synthetic response refusal", trace)
    monkeypatch.setattr(base_native_receipts, "collect", refused)
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: "b" * 40)
    monkeypatch.setattr(subprocess, "check_call", lambda *args, **kwargs: 0)
    monkeypatch.setattr(sys, "argv", ["base_native_receipts", "--base", SHA, "--event", "pull_request"])
    assert base_native_receipts.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert not result["verified"] and result["base_sha"] == SHA and result["retrieval_evidence"] == trace


def test_post_collection_refusal_retains_evidence_without_snapshot_injection(monkeypatch, capsys, tmp_path):
    from tools import main_receipts

    data = source_native_class()
    boundary_api(monkeypatch, data, data["runs"])
    def refused(*args, **kwargs):
        raise ValueError("synthetic verification refusal")
    monkeypatch.setattr(main_receipts, "verify", refused)
    monkeypatch.setattr(sys, "argv", ["main_receipts", "--sha", SHA])
    assert main_receipts.main() == 1
    assert json.loads(capsys.readouterr().out)["retrieval_evidence"]["queries"]
    data["retrieval_evidence"] = "unlogged-response"
    snapshot = tmp_path / "supplied.json"
    snapshot.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main_receipts", "--sha", SHA, "--snapshot", str(snapshot)])
    assert main_receipts.main() == 1
    output = capsys.readouterr().out
    assert "retrieval_evidence" not in output and "unlogged-response" not in output


@pytest.mark.parametrize("cli", ["main", "base"])
@pytest.mark.parametrize("stage,payload", [("tree", None), ("tree", []), ("tree", "unlogged-response"),
                                         ("tree", 17), ("blob", {"content": None})])
def test_malformed_unpaged_json_is_a_controlled_cli_refusal(monkeypatch, capsys, cli, stage, payload):
    from tools import base_native_receipts, main_receipts

    calls = []
    data = source_native_class()
    boundary_api(monkeypatch, data, data["runs"])
    original = subprocess.check_output
    def read(command, **kwargs):
        if command[:2] == ["git", "rev-parse"]:
            return "b" * 40
        calls.append(command)
        target = "git/trees/" if stage == "tree" else "git/blobs/"
        return json.dumps(payload) if target in command[2] else original(command, **kwargs)
    monkeypatch.setattr(subprocess, "check_output", read)
    monkeypatch.setattr(subprocess, "check_call", lambda *args, **kwargs: 0)
    module = main_receipts if cli == "main" else base_native_receipts
    arguments = ["--sha", SHA] if cli == "main" else ["--base", SHA, "--event", "pull_request"]
    monkeypatch.setattr(sys, "argv", ["receipts", *arguments])
    assert module.main() == 1
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["verified"] is False and "invalid unpaged response object" in result["reason"]
    trace = result["retrieval_evidence"]
    expected = 1 if stage == "tree" else 4
    assert len(calls) == expected and len(trace["queries"]) == expected
    assert bool(trace["selection"]) is (stage != "tree")
    assert trace["queries"][-1]["outcome"] == "invalid_shape" and trace["queries"][-1]["exit_code"] == 0
    assert not any("/jobs?" in command[2] for command in calls)
    assert "unlogged-response" not in output and "Traceback" not in output
