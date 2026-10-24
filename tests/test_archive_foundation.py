"""Canonical member admission foundation for streamed archive transports."""
import pytest
from test_evidence import bundle

from atlas_brain.evidence import admission as a


def test_admitted_member_reader_preserves_folder_bundle_identity(tmp_path):
    bundle(tmp_path, raw=b"record\n")
    budgets = a.Budgets(1000000, 500000, 100)
    members = a.folder_members(tmp_path, budgets)
    assert a.import_members(members, budgets) == a.import_folder(tmp_path, budgets)


def test_admitted_member_reader_requires_manifest():
    with pytest.raises(a.AdmissionRefused, match="missing_manifest"):
        a.import_members({}, a.Budgets(1000000, 500000, 100))


@pytest.mark.parametrize("field", ["compression_ratio", "archive_index_bytes"])
def test_archive_budgets_are_hashed_positive_integers(field):
    baseline = a.Budgets(1000000, 500000, 100)
    assert baseline.sha256 != a.Budgets(1000000, 500000, 100, **{field: 5}).sha256
    for bad in (0, -1, True):
        with pytest.raises(ValueError, match="invalid_budget"):
            a.Budgets(1000000, 500000, 100, **{field: bad})
