"""Merged-intake audit witnesses for issues 56 and 57."""
import json

import pytest
from test_evidence import bundle

from atlas_brain.evidence.admission import AdmissionRefused, Budgets, import_folder
from atlas_brain.kernel.states import IntegrityState


def prepared(tmp_path, name):
    root = tmp_path / name
    root.mkdir()
    return root, bundle(root, succeeded="yes", prompt_verified=True)


def admitted(root, manifest):
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return import_folder(root, Budgets(10000, 10000, 10)).captures[0]


def test_same_capture_row_and_raw_bind_the_relevant_attempt_outcome(tmp_path):
    good_root, good = prepared(tmp_path, "good")
    bad_root, bad = prepared(tmp_path, "bad")
    bad["attempts"][0]["succeeded"] = "no"
    assert good["captures"] == bad["captures"]
    success, failure = admitted(good_root, good), admitted(bad_root, bad)
    assert success.raw == failure.raw == b""
    assert success.id != failure.id
    assert success.integrity is IntegrityState.EMPTY
    assert failure.integrity is IntegrityState.UNVERIFIED_PROMPT


def test_unrelated_attempt_does_not_change_capture_identity(tmp_path):
    first_root, first = prepared(tmp_path, "first")
    other_root, other = prepared(tmp_path, "other")
    other["attempts"].append({"source": "sw-b", "operation": "other", "attempted": "unknown",
                              "succeeded": "unknown", "transport_defect": ""})
    assert admitted(first_root, first).id == admitted(other_root, other).id


def test_declared_source_must_match_device_directory(tmp_path):
    root, manifest = prepared(tmp_path, "mismatch")
    manifest["captures"][0]["source"] = "sw-b"
    manifest["attempts"][0]["source"] = "sw-b"
    with pytest.raises(AdmissionRefused, match="capture_source_path_mismatch"):
        admitted(root, manifest)


@pytest.mark.parametrize("section,field", [("attempts", "source"), ("attempts", "operation"),
                                          ("captures", "source"), ("captures", "operation")])
@pytest.mark.parametrize("value", ["", "   "])
def test_empty_or_blank_operation_identity_refuses_bundle(tmp_path, section, field, value):
    root, manifest = prepared(tmp_path, "blank")
    manifest[section][0][field] = value
    with pytest.raises(AdmissionRefused):
        admitted(root, manifest)


@pytest.mark.parametrize("path", ["files/1-table.txt", "controllers/sw-a/responses/1-table.txt",
                                  "devices/sw-a/captures/nested/1-table.txt"])
def test_other_cli_storage_layouts_refuse_even_when_hash_correct(tmp_path, path):
    root, manifest = prepared(tmp_path, "layout")
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"")
    manifest["captures"][0]["path"] = path
    with pytest.raises(AdmissionRefused, match="capture_source_path_mismatch"):
        admitted(root, manifest)
