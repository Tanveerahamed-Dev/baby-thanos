"""Hosted guard evidence is qualified from sources; audit hooks stay in fresh children."""
import json
import os
import subprocess
import sys
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.admission import Budgets
from atlas_brain.runner.p4_guard_policy import policy, report_guard_comparisons
from tools import p4_guard_demo as d

HEAD = "a" * 40


def prepared(root, case="mismatch"):
    inputs = d.members(canonical, case)
    evidence = root / "inputs"
    evidence.mkdir()
    for name, content in inputs.items():
        (evidence / name).write_bytes(content)
    caller = policy.GuardPolicy(id="same_guard", domain="demo", expectation="same_reported_root_guard",
        participants=tuple(policy.GuardParticipant(target_id=name, vlan=1, declared_mode="pvst",
            position="designated_downstream") for name in ("left", "right")))
    return inputs, report_guard_comparisons(evidence, Budgets(1000000, 1000000, 1000), (caller,))


def reseal(reports):
    reports["MANIFEST.sha256"] = b"".join(f"{sha256(reports[name]).hexdigest()}  {name}\n".encode()
        for name in sorted(reports) if name != "MANIFEST.sha256")


def capture_refs(value):
    if isinstance(value, dict):
        if value.get("kind") == "capture":
            yield value
        for item in value.values():
            yield from capture_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from capture_refs(item)


@pytest.mark.parametrize("case,wanted", [
    ("mismatch", ("problem", None, "reported_root_guard")),
    ("omitted_guard", ("unknown", "field_not_printed", "reported_root_guard")),
    ("equal_untimed", ("unknown", "as_of_missing", "reported_root_guard")),
    ("role_excludes", ("not_applicable", "role_excludes", "reported_role"))])
def test_real_original_inputs_and_five_reports_qualify_all_declared_cases(tmp_path, case, wanted):
    inputs, reports = prepared(tmp_path, case)
    receipt = d.validate(reports, inputs, case, canonical)
    assert (receipt["state"], receipt["reason"], receipt["last_hop"]) == wanted
    assert receipt["source"] == {name: sha256(content).hexdigest() for name, content in inputs.items()}
    assert receipt["reports"] == {name: sha256(content).hexdigest() for name, content in reports.items()}


@pytest.mark.parametrize("plant", ["source", "span", "hash", "policy", "manifest", "outcome", "missing", "pair", "no_right", "participant"])
def test_recomputed_manifest_cannot_hide_planted_proof_or_intent_damage(tmp_path, plant):
    inputs, reports = prepared(tmp_path)
    finding, = [json.loads(line) for line in reports[d.CHECKS].splitlines()]
    if plant == "source":
        inputs["left.txt"] += b"x"
    elif plant == "missing":
        reports.pop(d.FACTS)
    elif plant == "manifest":
        reports["MANIFEST.sha256"] += b"x"
    elif plant in ("policy", "participant"):
        document = json.loads(reports[d.POLICY])
        if plant == "policy":
            document["policies"][0]["domain"] = "other"
        else:
            document["policies"][0]["participants"] = document["policies"][0]["participants"][:1]
        reports[d.POLICY] = canonical(document)
    else:
        if plant in ("span", "hash"):
            ref = next(capture_refs(finding))
            ref["end" if plant == "span" else "sha256"] = 1000000 if plant == "span" else "0" * 64
        elif plant == "outcome":
            finding["state"] = "unknown"
        elif plant == "pair":
            finding["evidence"][-1]["subject"] = "subject:foreign"
        else:
            finding["evidence"] = [ref for ref in finding["evidence"] if ref.get("subject") == finding["left"] or ref["kind"] == "registry"]
        reports[d.CHECKS] = canonical(finding) + b"\n"
    if plant not in ("missing", "manifest"):
        reseal(reports)
    with pytest.raises(ValueError, match="^p4_guard_demo_"):
        d.validate(reports, inputs, "mismatch", canonical)


def test_expected_label_is_not_a_semantic_source_oracle(tmp_path):
    inputs, reports = prepared(tmp_path, "equal_untimed")
    finding, = [json.loads(line) for line in reports[d.CHECKS].splitlines()]
    finding["state"], finding["reason"] = "problem", None
    last = finding["hops"][-1]["state"]
    finding["hops"][-1]["state"] = {"state": "known", "basis": "derived", "value": True, "raw": None, "evidence": last["evidence"]}
    reports[d.CHECKS] = canonical(finding) + b"\n"
    reseal(reports)
    with pytest.raises(ValueError, match="^p4_guard_demo_"):
        d.validate(reports, inputs, "mismatch", canonical)


@pytest.mark.parametrize("plant", ["host", "shape", "checkout"])
def test_host_and_exact_head_refuse_before_output_directory(tmp_path, monkeypatch, capsys, plant):
    root = tmp_path / "not-created"
    monkeypatch.setattr(d, "ROOT", root)
    monkeypatch.setattr(sys, "argv", ["p4_guard_demo"])
    monkeypatch.setenv("GITHUB_ACTIONS", "false" if plant == "host" else "true")
    monkeypatch.setenv("P4_REVIEWED_SHA", "short" if plant == "shape" else HEAD)
    monkeypatch.setattr(d.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, stdout="b" * 40))
    with pytest.raises((ValueError, SystemExit), match="p4_guard_demo_"):
        d.main()
    assert not root.exists() and "P4_GUARD_RECEIPT" not in capsys.readouterr().out


@pytest.mark.parametrize("timeout", [False, True])
def test_child_failure_and_timeout_save_original_partial_streams(tmp_path, monkeypatch, capsys, timeout):
    def failed(*args, **kwargs):
        if timeout:
            raise subprocess.TimeoutExpired(["child"], 60, output=b"partial-out", stderr=b"partial-error")
        return subprocess.CompletedProcess(["child"], 1, stdout=b"partial-out", stderr=b"partial-error")
    monkeypatch.setattr(d.subprocess, "run", failed)
    with pytest.raises((ValueError, subprocess.TimeoutExpired)):
        d.run_saved(["child"], {}, tmp_path, 0)
    assert (tmp_path / "batch0.stdout.txt").read_bytes() == b"partial-out"
    assert (tmp_path / "batch0.stderr.txt").read_bytes() == b"partial-error"
    assert "partial-error" in capsys.readouterr().err


def test_two_fresh_seeded_workers_probe_before_api_import_without_polluting_pytest(tmp_path):
    for case in ("mismatch", "omitted_guard", "equal_untimed", "role_excludes"):
        folder = tmp_path / case / "inputs"
        folder.mkdir(parents=True)
        for name, content in d.members(canonical, case).items():
            (folder / name).write_bytes(content)
    code = ("import builtins,sys\n"
            "from pathlib import Path\n"
            "from tools import p4_guard_demo as d\n"
            "from atlas_brain.runner import tripwire\n"
            "assert 'atlas_brain.runner.p4_guard_policy' not in sys.modules\n"
            "original=builtins.__import__\n"
            "def checked(name,globals=None,locals=None,fromlist=(),level=0):\n"
            "    if name.endswith('p4_guard_policy') or name=='atlas_brain.runner' and 'p4_guard_policy' in fromlist: assert len(tripwire.violations())==4\n"
            "    return original(name,globals,locals,fromlist,level)\n"
            "builtins.__import__=checked\n"
            "d.ROOT=Path(sys.argv[1])\n"
            "d.run_batch(int(sys.argv[2]),'a'*40)")
    for batch, seed in enumerate(("1", "83")):
        child = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path), str(batch)],
            env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True, text=True, check=True, timeout=60)
        line, = child.stdout.splitlines()
        receipt = json.loads(line.removeprefix("P4_GUARD_BATCH "))
        assert receipt == {"schema": "atlas-brain.p4-guard-api-batch/1", "reviewed_head": HEAD, "batch": batch,
            "seed": seed, "api_runs": 4, "api_process_denied": 4, "additional_denials": 0}
        for case in ("mismatch", "omitted_guard", "equal_untimed", "role_excludes"):
            inputs = d.snapshot(tmp_path / case / "inputs")
            reports = d.snapshot(tmp_path / case / f"out{batch}")
            d.validate(reports, inputs, case, canonical)
            if batch:
                assert reports == d.snapshot(tmp_path / case / "out0")
    assert not (tmp_path / "DIGESTS.json").exists()


@pytest.mark.parametrize("plant", ["partial", "input", "head", "count"])
def test_parent_preserves_partial_batch_and_never_emits_pass_receipt(tmp_path, monkeypatch, capsys, plant):
    root = tmp_path / "demo"
    monkeypatch.setattr(d, "ROOT", root)
    monkeypatch.setattr(d, "guard", lambda: HEAD)
    monkeypatch.setattr(sys, "argv", ["p4_guard_demo"])
    def saved(command, env, destination, batch):
        (destination / "batch0.stdout.txt").write_bytes(b"retained")
        if plant == "partial":
            (destination / "mismatch" / "partial.txt").write_bytes(b"retained")
            raise ValueError("planted-partial")
        receipt = {"schema": "atlas-brain.p4-guard-api-batch/1", "reviewed_head": "b" * 40 if plant == "head" else HEAD,
            "batch": batch, "seed": env["PYTHONHASHSEED"], "api_runs": 3 if plant == "count" else 4,
            "api_process_denied": 4, "additional_denials": 0}
        if plant == "input":
            (destination / "mismatch" / "inputs" / "left.txt").write_bytes(b"changed")
        return subprocess.CompletedProcess(command, 0, stdout=b"P4_GUARD_BATCH " + canonical(receipt), stderr=b"")
    monkeypatch.setattr(d, "run_saved", saved)
    with pytest.raises(ValueError):
        d.main()
    assert (root / "batch0.stdout.txt").read_bytes() == b"retained"
    assert not (root / "DIGESTS.json").exists() and "P4_GUARD_RECEIPT" not in capsys.readouterr().out
