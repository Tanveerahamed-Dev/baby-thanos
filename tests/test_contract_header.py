"""Header publication and real Git-baseline version plants (hosted acceptance)."""
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import get_type_hints

import pytest

from atlas_brain.contract.header import (
    AnalysisAsOf,
    EffectiveSemantics,
    ResultHeader,
    encode_header,
)
from atlas_brain.kernel.states import CaptureId
from tools.contract_schema import schema_for
from tools.publish_contract_schema import generated_header, verify_base


def sample_header():
    return ResultHeader(schema="atlas-brain.result", schema_version="0.1.0",
        semantics={"core": 1}, effective_semantics=EffectiveSemantics(packs={}, checks={}),
        catalogue_digest="a" * 64, pack_build_fingerprints={},
        input_manifest_sha256="b" * 64, options_sha256="c" * 64,
        analysis_as_of=AnalysisAsOf(utc=None, source="unknown", evidence=()), status="incomplete")


def test_header_projection_preserves_unknown_and_completion():
    header = sample_header()
    wire = json.loads(encode_header(header))
    assert wire["status"] == "incomplete"
    assert wire["analysis_as_of"] == {"utc": None, "source": "unknown", "evidence": []}
    capture = CaptureId("cap:sample")
    timed = replace(header, analysis_as_of=AnalysisAsOf(
        utc="2026-01-01T00:00:00Z", source="evidence_latest", evidence=(capture,)))
    assert json.loads(encode_header(timed))["analysis_as_of"]["evidence"] == [capture]
    assert get_type_hints(AnalysisAsOf)["evidence"] == tuple[CaptureId, ...]


def test_generated_header_schema_binds_declared_version_and_kernel_capture_id():
    schema = generated_header()
    assert schema["x-schema-version"] == "0.1.0"
    header = schema["$defs"]["ResultHeader"]
    assert header["properties"]["schema_version"] == {"enum": ["0.1.0"]}
    assert schema["$defs"]["AnalysisAsOf"]["properties"]["evidence"]["items"] == {"type": "string"}
    assert header["additionalProperties"] is False


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()


def baseline_repo(tmp_path, monkeypatch, schema):
    monkeypatch.chdir(tmp_path)
    git("init", "-q")
    path = Path("docs/contract/header.schema.json")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(schema), encoding="utf-8")
    source = Path("atlas_brain/contract/header.py")
    source.parent.mkdir(parents=True)
    source.write_text('"""Synthetic header input."""', encoding="utf-8")
    git("add", ".")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "baseline")
    return git("rev-parse", "HEAD")


def test_real_baseline_refuses_unversioned_schema_change(tmp_path, monkeypatch):
    schema = generated_header()
    base = baseline_repo(tmp_path, monkeypatch, schema)
    verify_base(schema, base)
    changed = generated_header()
    changed["$defs"]["ResultHeader"]["properties"]["new_field"] = {"type": "string"}
    with pytest.raises(ValueError, match="schema_version"):
        verify_base(changed, base)
    changed["x-schema-version"] = "0.2.0"
    verify_base(changed, base)
    with pytest.raises(subprocess.CalledProcessError):
        verify_base(schema, "not-a-commit")


def test_real_baseline_refuses_missing_published_schema(tmp_path, monkeypatch):
    schema = generated_header()
    baseline_repo(tmp_path, monkeypatch, schema)
    git("rm", "docs/contract/header.schema.json")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "plant missing schema")
    with pytest.raises(ValueError, match="baseline_schema_missing"):
        verify_base(schema, "HEAD")


def test_first_schema_is_admitted_only_before_header_source_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git("init", "-q")
    Path("README.md").write_text("synthetic", encoding="utf-8")
    git("add", ".")
    git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "empty baseline")
    verify_base(generated_header(), "HEAD")


@pytest.mark.parametrize("version", ["bad", "01.0.0", "1.0", "1.0.0-01", "1.0.0+"])
def test_schema_generator_refuses_invalid_semver(version):
    with pytest.raises(ValueError, match="schema_version"):
        schema_for(ResultHeader, version)


@pytest.mark.parametrize("version", ["0.1.0", "1.0.0-alpha.1", "1.0.0+build.01"])
def test_schema_generator_accepts_semver(version):
    assert schema_for(ResultHeader, version)["x-schema-version"] == version


def test_real_schema_entrypoint_refuses_stale_committed_bytes(tmp_path):
    environment = {**os.environ, "PYTHONPATH": str(Path.cwd())}
    command = [sys.executable, "-m", "tools.publish_contract_schema"]
    written = subprocess.run([*command, "--write"], cwd=tmp_path,
        env=environment, capture_output=True, check=False)
    assert written.returncode == 0
    assert subprocess.run(command, cwd=tmp_path, env=environment,
        capture_output=True, check=False).returncode == 0
    (tmp_path / "docs/contract/header.schema.json").write_bytes(b"{}")
    refused = subprocess.run(command, cwd=tmp_path, env=environment,
        capture_output=True, check=False)
    assert refused.returncode == 1
    assert b"publication refused" in refused.stdout
