"""Host driver witnesses use fresh hooked children; pytest's parent stays unhooked."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.runner.p4 import analyse_folder
from tools import p4_estate_demo as d

HEAD = "a" * 40
CASES = ("baseline", "pagp", "missing")


def write_batch(root, batch):
    for case in CASES:
        reports = analyse_folder(root / case / "inputs", Budgets(1000000, 1000000, 1000))
        for name, content in reports.items():
            path = root / case / f"out{batch}" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


@pytest.mark.parametrize("plant,code,exception", [("host", "hosted_only", SystemExit),
    ("shape", "reviewed_head", ValueError), ("checkout", "checkout_head", ValueError)])
def test_host_and_exact_head_refuse_before_output_directory(tmp_path, monkeypatch, capsys, plant, code, exception):
    root = tmp_path / "not-created"
    monkeypatch.setattr(d, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["p4_estate_demo"])
    monkeypatch.setenv("GITHUB_ACTIONS", "false" if plant == "host" else "true")
    monkeypatch.setenv("P4_ESTATE_REVIEWED_SHA", "short" if plant == "shape" else HEAD)
    monkeypatch.setattr(d.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, stdout="b" * 40))
    with pytest.raises(exception, match="^p4_estate_demo_" + code + "$"):
        d.main()
    assert not root.exists() and "P4_ESTATE_RECEIPT" not in capsys.readouterr().out


@pytest.mark.parametrize("timeout", [False, True])
def test_child_failure_and_timeout_save_original_partial_streams(tmp_path, monkeypatch, capsys, timeout):
    def failed(*args, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(["child"], 60, output=b"partial-out", stderr=b"partial-error")
        return subprocess.CompletedProcess(["child"], 1, stdout=b"partial-out", stderr=b"partial-error")
    monkeypatch.setattr(d.subprocess, "run", failed)
    with pytest.raises(subprocess.TimeoutExpired if timeout else ValueError, match=None if timeout else "^p4_estate_demo_child_failed$"):
        d.run_saved(["child"], {}, tmp_path, 0)
    assert (tmp_path / "batch0.stdout.txt").read_bytes() == b"partial-out"
    assert (tmp_path / "batch0.stderr.txt").read_bytes() == b"partial-error"
    assert "partial-error" in capsys.readouterr().err


def test_two_fresh_seeded_api_children_probe_before_import_without_polluting_pytest(tmp_path):
    for case in CASES:
        folder = tmp_path / case / "inputs"
        folder.mkdir(parents=True)
        for name, content in d.members(canonical, case).items():
            (folder / name).write_bytes(content)
    code = ("import builtins,sys\n"
            "from pathlib import Path\n"
            "from tools import p4_estate_demo as d\n"
            "from atlas_brain.runner import tripwire\n"
            "assert 'atlas_brain.runner.p4' not in sys.modules\n"
            "original=builtins.__import__\n"
            "def checked(name,globals=None,locals=None,fromlist=(),level=0):\n"
            "    if name=='atlas_brain.runner.p4' or name=='atlas_brain.runner' and 'p4' in fromlist: assert len(tripwire.violations())==4\n"
            "    return original(name,globals,locals,fromlist,level)\n"
            "builtins.__import__=checked\n"
            "d.ROOT=Path(sys.argv[1])\n"
            "d.run_batch(int(sys.argv[2]),'a'*40)")
    for batch, seed in enumerate(("1", "83")):
        child = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path), str(batch)],
            env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True, text=True, check=True, timeout=60)
        line, = child.stdout.splitlines()
        receipt = json.loads(line.removeprefix("P4_ESTATE_BATCH "))
        assert receipt == {"schema": "atlas-brain.p4-estate-api-batch/1", "reviewed_head": HEAD, "batch": batch,
            "seed": seed, "api_runs": 3, "api_process_denied": 4, "additional_denials": 0}
        for case in CASES:
            inputs = d.snapshot(tmp_path / case / "inputs")
            reports = d.snapshot(tmp_path / case / f"out{batch}")
            d.validate(reports, inputs, case, canonical)
            if batch:
                assert reports == d.snapshot(tmp_path / case / "out0")
    assert not (tmp_path / "DIGESTS.json").exists()


@pytest.mark.parametrize("plant,code", [("partial", "planted-partial"), ("input", "p4_estate_demo_input_changed"),
    ("head", "p4_estate_demo_batch_receipt"), ("count", "p4_estate_demo_batch_receipt"), ("batch_bool", "p4_estate_demo_batch_receipt"),
    ("additional_bool", "p4_estate_demo_batch_receipt"), ("duplicate", "p4_estate_demo_batch_receipt"), ("noncanonical", "p4_estate_demo_batch_receipt"),
    ("corrupt", "p4_estate_demo_report"), ("missing_family", "p4_estate_demo_report"), ("determinism", "p4_estate_demo_determinism")])
def test_parent_preserves_partial_batch_and_never_emits_pass_receipt(tmp_path, monkeypatch, capsys, plant, code):
    root = tmp_path / "demo"
    monkeypatch.setattr(d, "ROOT", root)
    monkeypatch.setattr(d, "guard", lambda: HEAD)
    monkeypatch.setattr(sys, "argv", ["p4_estate_demo"])
    def saved(command, env, destination, batch):
        (destination / "batch0.stdout.txt").write_bytes(b"retained")
        if plant == "partial":
            (destination / "baseline" / "partial.txt").write_bytes(b"retained")
            raise ValueError("planted-partial")
        receipt = {"schema": "atlas-brain.p4-estate-api-batch/1", "reviewed_head": "b" * 40 if plant == "head" else HEAD,
            "batch": batch, "seed": env["PYTHONHASHSEED"], "api_runs": 2 if plant == "count" else 3,
            "api_process_denied": 4, "additional_denials": 0}
        if batch == 0 and plant == "batch_bool":
            receipt["batch"] = False
        if batch == 0 and plant == "additional_bool":
            receipt["additional_denials"] = False
        payload = canonical(receipt)
        if batch == 0 and plant == "duplicate":
            payload = payload[:-1] + b',"batch":0}'
        if batch == 0 and plant == "noncanonical":
            payload = json.dumps(receipt, sort_keys=True).encode()
        write_batch(destination, batch)
        if plant == "input":
            (destination / "baseline" / "inputs" / "tree.txt").write_bytes(b"changed")
        if plant == "missing_family":
            (destination / "baseline" / f"out{batch}" / "facts/fhrp_local.jsonl").unlink()
        if plant == "corrupt":
            (destination / "baseline" / f"out{batch}" / "MANIFEST.sha256").write_bytes(b"corrupt")
        return subprocess.CompletedProcess(command, 0, stdout=b"P4_ESTATE_BATCH " + payload, stderr=b"")
    monkeypatch.setattr(d, "run_saved", saved)
    if plant == "determinism":
        validate = d.validate
        def drift(reports, inputs, case, canonical):
            result = validate(reports, inputs, case, canonical)
            if (root / case / "out1").exists():
                reports["result.json"] += b"drift"
            return result
        monkeypatch.setattr(d, "validate", drift)
    with pytest.raises(ValueError, match="^" + code + "$"):
        d.main()
    assert (root / "batch0.stdout.txt").read_bytes() == b"retained"
    assert not (root / "DIGESTS.json").exists() and "P4_ESTATE_RECEIPT" not in capsys.readouterr().out


def test_actual_parent_runs_two_real_seeded_batches_and_retains_all_evidence(tmp_path):
    repository = Path(__file__).resolve().parents[4]
    reviewed = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True).stdout.strip()
    git_dir = subprocess.run(["git", "-C", str(repository), "rev-parse", "--absolute-git-dir"],
        check=True, capture_output=True, text=True).stdout.strip()
    env = {**os.environ, "GITHUB_ACTIONS": "true", "P4_ESTATE_REVIEWED_SHA": reviewed,
        "GIT_DIR": git_dir, "GIT_WORK_TREE": str(repository), "PYTHONPATH": str(repository)}
    child = subprocess.run([sys.executable, "-B", "-m", "tools.p4_estate_demo"], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=True, timeout=180)
    line, = child.stdout.splitlines()
    assert line.startswith("P4_ESTATE_RECEIPT ")
    receipt = json.loads(line.removeprefix("P4_ESTATE_RECEIPT "))
    root = tmp_path / ".ci-evidence/p0-demo/p4-estate"
    assert (root / "DIGESTS.json").read_bytes() == canonical(receipt) + b"\n"
    assert (receipt["schema"], receipt["reviewed_head"], receipt["qualification"], receipt["scope"], receipt["source_required"]) == (
        "atlas-brain.p4-estate-hosted-receipt/1", reviewed, "synthetic_observations_only",
        "observations_only", "original_pinned_evidence_folder")
    assert receipt["cells_per_case"] == 19 and receipt["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}
    assert len(d.snapshot(root)) == 51
    assert (receipt["measured_cases"], receipt["api_runs"], receipt["api_processes"], receipt["hash_seeds"],
        receipt["api_process_denied"], receipt["additional_denials"]) == (3, 6, 2, ["1", "83"], [4, 4], [0, 0])
    for case in CASES:
        inputs = d.snapshot(root / case / "inputs")
        assert inputs == d.members(canonical, case) and len(inputs) == (4 if case == "missing" else 6)
        left, right = d.snapshot(root / case / "out0"), d.snapshot(root / case / "out1")
        assert left == right and len(left) == 5
        assert d.validate(left, inputs, case, canonical) == receipt["cases"][case]
        summary = receipt["cases"][case]
        assert summary["facts"] == 19 and summary["denominator"] == {"l2.stp": 3, "l2.etherchannel": 4, "l3.fhrp": 5}
        assert (summary["known"], summary["unknown"]) == ((4, 15) if case == "missing" else (11, 8))
    for batch, seed in enumerate(("1", "83")):
        batch_line, = (root / f"batch{batch}.stdout.txt").read_text().splitlines()
        batch_receipt = json.loads(batch_line.removeprefix("P4_ESTATE_BATCH "))
        assert (batch_receipt["batch"], batch_receipt["seed"], batch_receipt["api_runs"],
            batch_receipt["api_process_denied"], batch_receipt["additional_denials"]) == (batch, seed, 3, 4, 0)
        assert (root / f"batch{batch}.stderr.txt").read_bytes() == b""


def test_wrong_hash_seed_refuses_before_any_hook_or_output(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "ROOT", tmp_path / "not-created")
    monkeypatch.setenv("PYTHONHASHSEED", "83")
    with pytest.raises(ValueError, match="^p4_estate_demo_hash_seed$"):
        d.run_batch(0, HEAD)
    assert not d.ROOT.exists()


def test_fresh_api_child_additional_actual_denials_refuse_batch_and_preserve_reports(tmp_path):
    for case in CASES:
        folder = tmp_path / case / "inputs"
        folder.mkdir(parents=True)
        for name, content in d.members(canonical, case).items():
            (folder / name).write_bytes(content)
    code = ("import sys\n"
            "from pathlib import Path\n"
            "from tools import p4_estate_demo as d\n"
            "from atlas_brain.runner import tripwire\n"
            "original=tripwire.violations\n"
            "calls=0\n"
            "def observed():\n"
            "    global calls\n"
            "    calls+=1\n"
            "    if calls==2: tripwire.probe()\n"
            "    return original()\n"
            "tripwire.violations=observed\n"
            "d.ROOT=Path(sys.argv[1])\n"
            "d.run_batch(0,'a'*40)")
    child = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)],
        env={**os.environ, "PYTHONHASHSEED": "1"}, capture_output=True, text=True, check=False, timeout=60)
    assert child.returncode != 0 and "p4_estate_demo_extra_egress" in child.stderr
    assert "P4_ESTATE_BATCH" not in child.stdout and "P4_ESTATE_RECEIPT" not in child.stdout
    assert all(len(d.snapshot(tmp_path / case / "out0")) == 5 for case in CASES)
    assert not (tmp_path / "DIGESTS.json").exists()


def test_parent_timeout_preserves_run_saved_context_without_a_pass_receipt(tmp_path, monkeypatch, capsys):
    root = tmp_path / "timeout-demo"
    monkeypatch.setattr(d, "ROOT", root)
    monkeypatch.setattr(d, "guard", lambda: HEAD)
    monkeypatch.setattr(sys, "argv", ["p4_estate_demo"])
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 60, output=b"timed-out", stderr=b"original-timeout-context")
    monkeypatch.setattr(d.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        d.main()
    assert (root / "batch0.stdout.txt").read_bytes() == b"timed-out"
    assert (root / "batch0.stderr.txt").read_bytes() == b"original-timeout-context"
    captured = capsys.readouterr()
    assert "P4_ESTATE_TIMEOUT batch=0" in captured.err and "original-timeout-context" in captured.err
    assert not (root / "DIGESTS.json").exists() and "P4_ESTATE_RECEIPT" not in captured.out


def test_fresh_api_child_failure_retains_first_real_case_without_batch_receipt(tmp_path):
    for case in CASES:
        folder = tmp_path / case / "inputs"
        folder.mkdir(parents=True)
        for name, content in d.members(canonical, case).items():
            (folder / name).write_bytes(content)
    code = ("import builtins,sys\n"
            "from pathlib import Path\n"
            "from tools import p4_estate_demo as d\n"
            "from atlas_brain.runner import tripwire\n"
            "original=builtins.__import__\n"
            "def checked(name,globals=None,locals=None,fromlist=(),level=0):\n"
            "    module=original(name,globals,locals,fromlist,level)\n"
            "    if name=='atlas_brain.runner.p4':\n"
            "        assert len(tripwire.violations())==4\n"
            "        real=module.analyse_folder\n"
            "        calls=0\n"
            "        def failed(*args,**kwargs):\n"
            "            nonlocal calls\n"
            "            calls+=1\n"
            "            if calls==2: raise RuntimeError('planted_api_failure')\n"
            "            return real(*args,**kwargs)\n"
            "        module.analyse_folder=failed\n"
            "    return module\n"
            "builtins.__import__=checked\n"
            "d.ROOT=Path(sys.argv[1])\n"
            "d.run_batch(0,'a'*40)")
    child = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path)],
        env={**os.environ, "PYTHONHASHSEED": "1"}, capture_output=True, text=True, check=False, timeout=60)
    assert child.returncode != 0 and "planted_api_failure" in child.stderr
    assert len(d.snapshot(tmp_path / "baseline" / "out0")) == 5
    assert not (tmp_path / "pagp" / "out0").exists()
    assert "P4_ESTATE_BATCH" not in child.stdout and not (tmp_path / "DIGESTS.json").exists()
