"""Synthetic intake witnesses; no device output or external services."""
import hashlib
import json

import pytest

from atlas_brain.evidence import admission as a


def bundle(tmp_path, raw=b"", succeeded="unknown", prompt_verified=False):
    path = "devices/sw-a/captures/1-table.txt"
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    manifest = {"version": 1, "bundle_id": "synthetic", "importer": "folder/1", "attempts": [
        {"source": "sw-a", "operation": "table", "attempted": "yes" if succeeded != "unknown" else "unknown",
         "succeeded": succeeded, "transport_defect": ""}], "captures": [
        {"path": path, "source": "sw-a", "operation": "table", "rendered": "show table",
         "codec": "utf-8", "sha256": hashlib.sha256(raw).hexdigest(), "prompt_verified": prompt_verified}]}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a/../b", "a\\b", "D:escape", "a//b", "a/./b", "a\x00b"])
def test_planted_traversal_refuses(name):
    with pytest.raises(a.AdmissionRefused):
        a.member_names([name])


@pytest.mark.parametrize("names", [["a", "a"], ["a", "A"], ["a", "A/file"]])
def test_planted_collisions_refuse(names):
    with pytest.raises(a.AdmissionRefused):
        a.member_names(names)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'"\xff"'])
def test_planted_json_refuses(raw, tmp_path):
    (tmp_path / "payload.JSON").write_bytes(raw)
    with pytest.raises(a.AdmissionRefused):
        a.folder_members(tmp_path, a.Budgets(10000, 10000, 10))


def test_manifest_attempt_degradation_and_bound_identity(tmp_path):
    manifest = bundle(tmp_path, b"record\n")
    admitted = a.import_folder(tmp_path, a.Budgets(10000, 10000, 10))
    assert admitted.attempts[0].succeeded == "unknown"
    assert admitted.attempts[0].detail == "attempt_unknown"
    assert admitted.captures[0].raw == b"record\n"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    assert admitted.captures[0].id == a.import_folder(tmp_path, a.Budgets(10000, 10000, 10)).captures[0].id
    other = tmp_path / "second"
    other.mkdir()
    bundle(other, b"changed\n")
    assert admitted.captures[0].id != a.import_folder(other, a.Budgets(10000, 10000, 10)).captures[0].id


def test_budget_identity_and_outcome(tmp_path):
    bundle(tmp_path, b"record\n")
    assert a.Budgets(10000, 10000, 10).sha256 != a.Budgets(10000, 10000, 11).sha256
    with pytest.raises(a.BudgetExceeded) as error:
        a.import_folder(tmp_path, a.Budgets(10000, 3, 10))
    assert error.value.reason == "budget_exceeded"
    assert error.value.member


def test_manifest_mismatch_refuses(tmp_path):
    manifest = bundle(tmp_path)
    (tmp_path / manifest["captures"][0]["path"]).write_bytes(b"changed")
    with pytest.raises(a.AdmissionRefused):
        a.import_folder(tmp_path, a.Budgets(10000, 10000, 10))


def test_link_refuses(tmp_path):
    bundle(tmp_path)
    source = tmp_path / "manifest.json"
    try:
        (tmp_path / "linked.json").symlink_to(source)
    except OSError:
        import os
        os.link(source, tmp_path / "linked.json")
    with pytest.raises(a.AdmissionRefused):
        a.import_folder(tmp_path, a.Budgets(10000, 10000, 10))


def test_r13_registered_empty_and_failed_looks_empty(tmp_path):
    from atlas_brain.evidence.capture import classify_cli
    assert classify_cli(b"", "yes", True).value == "empty"
    assert classify_cli(b"", "no", False).value == "unverified_prompt"
    assert classify_cli(b"", "unknown", False).value == "unverified_prompt"
    manifest = bundle(tmp_path, succeeded="no", prompt_verified=True)
    assert a.import_folder(tmp_path, a.Budgets(10000, 10000, 10)).captures[0].integrity.value == "unverified_prompt"
    manifest["attempts"][0].update(succeeded="yes", transport_defect="timeout")
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(a.AdmissionRefused):
        a.import_folder(tmp_path, a.Budgets(10000, 10000, 10))


def test_lf_only_and_raw_locator():
    from atlas_brain.evidence.text import text_lines
    raw = "é\r\nx\v\fy\r\r\nz".encode()
    lines = text_lines(raw, "utf-8")
    assert [line.text for line in lines] == ["é", "x\v\fy\r", "z"]
    assert [(line.span.start, line.span.end) for line in lines] == [(0, 4), (4, 11), (11, 12)]
    assert lines[0].raw_span(0, 1).start == 0
    assert lines[0].raw_span(0, 1).end == 2
    assert raw[lines[1].raw_span(2, 3).start:lines[1].raw_span(2, 3).end] == b"\f"
    assert text_lines(b"", "utf-8") == ()
    assert len(text_lines(b"x\n", "utf-8")) == 1


def test_capture_uses_kernel_classifications(tmp_path):
    from atlas_brain.kernel import states as k
    bundle(tmp_path, succeeded="yes", prompt_verified=True)
    capture = a.import_folder(tmp_path, a.Budgets(10000, 10000, 10)).captures[0]
    assert capture.integrity is k.IntegrityState.EMPTY
    assert capture.read_scope is k.ReadScope.UNKNOWN
    assert capture.view is k.ViewConsistency.UNKNOWN
