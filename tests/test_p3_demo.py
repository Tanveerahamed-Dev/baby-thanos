"""Hosted-demo verifier catches planted evidence defects without running a local demo."""
import json

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from atlas_brain.runner import p3
from tools import p3_demo
from tools.p3_cases import members


def record(case):
    files = members(canonical, case)
    payload, _ = p3.analyse_group(admit_members(files))
    from hashlib import sha256
    digest_input = {"captures": sorted(({"capture": item["id"], "sha256": item["sha256"]}
        for item in payload["captures"]), key=lambda item: item["capture"]),
        "registry_sha256": payload["registry_sha256"], "base_registry_sha256": payload["base_registry_sha256"]}
    evidence = {key: value for key, value in digest_input.items() if key != "captures"}
    evidence.update(digest=sha256(canonical(digest_input)).hexdigest(), files=len(files), captures=len(files) - 2)
    return files, {"schema": "atlas-brain.runner-manifest/3", "facts": {}, "p3": payload, "evidence": evidence,
        "egress": {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40},
        "plan": {"steps": 8, "witness_attempts": 4}, "steps": [{"denied": 4, "id": f"witness/{index:02d}"} for index in range(8)]}


@pytest.mark.parametrize("case", p3_demo.EXPECTED)
def test_demo_independently_resolves_generated_registry_and_byte_proofs(case):
    files, manifest = record(case)
    assert p3_demo.validate(manifest, files, case, canonical) == manifest["p3"]


@pytest.mark.parametrize("plant", ["span_hash", "path", "whole_hash", "registry_value", "egress"])
def test_demo_does_not_accept_planted_proof_or_witness_failure(plant):
    files, manifest = record("supported")
    manifest = json.loads(canonical(manifest))
    refs = list(p3_demo.leaves(manifest["p3"]["findings"][0]["evidence"]))
    if plant == "egress":
        manifest["egress"]["denied"] = 0
    elif plant == "registry_value":
        next(ref for ref in refs if ref["kind"] == "registry")["value"] = "wrong"
    else:
        ref = next(ref for ref in refs if ref["kind"] == "capture")
        ref[{"span_hash": "sha256", "path": "path", "whole_hash": "capture_sha256"}[plant]] = (
            "wrong.txt" if plant == "path" else "0" * 64)
    with pytest.raises(ValueError):
        p3_demo.validate(manifest, files, "supported", canonical)


def test_demo_main_refuses_non_hosted_execution(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(SystemExit, match="^p3_demo_hosted_only$"):
        p3_demo.main()
