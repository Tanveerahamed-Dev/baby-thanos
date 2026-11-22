"""Named census operation admission and the default-profile boundary."""
import pytest
from census_request_cases import REGISTRATION, forbid_observations, input_folder
from test_gateway_source import LIMITS

from atlas_brain.evidence import p4_admission as p4
from atlas_brain.packs.l2.etherchannel import build as ec
from atlas_brain.packs.l2.stp import build as stp
from atlas_brain.packs.l3.fhrp import required_report_census_profile as extended
from atlas_brain.packs.l3.fhrp import required_report_profile as original


def test_extended_profile_admits_the_original_census_declarations_and_member(tmp_path, monkeypatch):
    root = tmp_path / "inputs"
    files, _ = input_folder(root)
    forbid_observations(monkeypatch)
    envelope = p4.admit_folder(root, LIMITS, declarations=(stp.DECLARATION, ec.DECLARATION, extended.declaration()))
    assert envelope.registration_sha256 == REGISTRATION and envelope.raw == files["p4.json"]
    targets = tuple(target for target in envelope.targets if target.operation == "synthetic.hsrp_ipv4_interface_census")
    assert [target.id for target in targets] == ["census-a", "census-b"]
    assert all(target.owner == "l3.fhrp/parse_hsrp_census" for target in targets)
    member, = (member for member in envelope.captures if member.target is targets[0])
    assert member.raw == files["census-a.txt"] and member.path == "census-a.txt"
    assert all(member.target is not targets[1] for member in envelope.captures)


def test_original_profile_still_refuses_the_new_operation(tmp_path):
    root = tmp_path / "inputs"
    input_folder(root)
    with pytest.raises(ValueError, match="^p4_target_operation$"):
        p4.admit_folder(root, LIMITS, declarations=(stp.DECLARATION, ec.DECLARATION, original.declaration()))
