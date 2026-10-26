"""The generated case matrix is admitted and never supplies hidden semantic values."""
import json
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.p3_admission import admit_members
from tools.p3_cases import CASES, members


@pytest.mark.parametrize("case", CASES)
def test_generated_cases_have_exact_partition_hashes_and_bounded_declarations(case):
    files = members(canonical, case)
    group = admit_members(files)
    declaration = json.loads(files["p3.json"])
    assert declaration["base_sha256"] == sha256(files["p2.json"]).hexdigest()
    assert set(declaration) == {"schema", "semantic_group", "base_sha256", "adjacencies", "samples"}
    for adjacency in declaration["adjacencies"]:
        assert set(adjacency) == {"id", "domain", "area", "left", "right"}
        for point in (adjacency["left"], adjacency["right"]):
            assert set(point) == {"node", "port", "process", "router_id", "address", "vrf"}
    refs = json.loads(files["p2.json"])["captures"] + [
        capture for sample in declaration["samples"] for capture in sample["captures"]]
    assert set(files) == {"p2.json", "p3.json"} | {ref["path"] for ref in refs}
    assert all(set(ref) == {"path", "node", "operation", "sha256"}
               and sha256(files[ref["path"]]).hexdigest() == ref["sha256"] for ref in refs)
    assert len(group.base.nodes) == 2 and len(group.adjacencies) == 1
    assert members(canonical, case) == files


@pytest.mark.parametrize("case,count", [("supported", 22), ("single_sample", 12),
                                        ("missing_mtu", 21), ("missing_ignore", 20),
                                        ("missing_peer", 21), ("no_rounds", 2)])
def test_case_removal_changes_only_the_visible_capture_population(case, count):
    group = admit_members(members(canonical, case))
    assert len(group.base.captures) + sum(len(sample.captures) for sample in group.samples) == count


def test_unknown_case_cannot_silently_run_supported_demo():
    with pytest.raises(ValueError, match="^p3_demo_case$"):
        members(canonical, "unknown")
