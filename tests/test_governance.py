import json
import subprocess
from pathlib import Path

import pytest

from tools.governance import audit, diff_digest


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    commit(tmp_path, allow_empty=True)
    return tmp_path


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()


def commit(repo, allow_empty=False):
    git(repo, "-c", "core.autocrlf=false", "add", ".")
    return git(repo, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
               "commit", "-qm", "synthetic", *(["--allow-empty"] if allow_empty else []))


def write(repo, name, text):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_size_boundary_and_generated_diff(repo):
    write(repo, "governance/generators.json", json.dumps({"uv.lock": {"command": "uv lock"}}))
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "tools/example.py", "# synthetic\n" * 400)
    write(repo, "uv.lock", "generated\n" * 500)
    write(repo, "fixtures/sample.txt", "synthetic\n" * 500)
    commit(repo)
    assert audit(repo, base, "HEAD")["counted_lines"] == 400
    digest = diff_digest(repo, base, "HEAD")
    write(repo, "uv.lock", "regenerated\n")
    commit(repo)
    assert diff_digest(repo, base, "HEAD") == digest
    write(repo, "tools/example.py", "# synthetic\n" * 401)
    commit(repo)
    with pytest.raises(ValueError, match="AD-03"):
        audit(repo, base, "HEAD")


@pytest.mark.parametrize("plant", ["self_exemption", "binary", "two_modules", "root_modules"])
def test_size_refuses_planted_bypasses(repo, plant):
    base = git(repo, "rev-parse", "HEAD")
    if plant == "self_exemption":
        write(repo, "governance/generators.json", json.dumps({"tools/example.py": {}}))
    elif plant == "binary":
        (repo / "blob.bin").write_bytes(bytes([0, 1, 2]))
    else:
        prefixes = ("kernel/", "model/") if plant == "two_modules" else ("", "")
        write(repo, f"atlas_brain/{prefixes[0]}a.py", "# synthetic\n")
        write(repo, f"atlas_brain/{prefixes[1]}b.py", "# synthetic\n")
    commit(repo)
    with pytest.raises(ValueError, match="AD-03"):
        audit(repo, base, "HEAD")


@pytest.mark.parametrize("paths,passes", [
    (["kernel/states.py", "kernel/lints.py"], False),
    (["model/steps.py", "model/catalogue.py"], False),
    (["evidence/capture.py", "evidence/admission.py"], False),
    (["kernel/nested/a.py", "kernel/nested/b.py"], False),
    (["kernel/states.py"], True),
    (["packs/platform/system/a.py", "packs/platform/system/b.py"], True),
    (["packs/platform/system/a.py", "packs/platform/interface/a.py"], False),
    (["platform/iosxe/a.py", "platform/iosxe/b.py"], True),
    (["platform/iosxe/a.py", "platform/nxos/a.py"], False),
])
def test_core_file_identity_and_pack_family_boundaries(repo, paths, passes):
    base = git(repo, "rev-parse", "HEAD")
    for path in paths:
        write(repo, "atlas_brain/" + path, "# synthetic\n")
    commit(repo)
    if passes:
        assert audit(repo, base, "HEAD")["counted_lines"] == len(paths)
    else:
        with pytest.raises(ValueError, match="AD-03"):
            audit(repo, base, "HEAD")


@pytest.mark.parametrize("plant", ["overlong", "overwide", "edit_accepted", "delete_accepted"])
def test_adr_refuses_planted_violations(repo, plant):
    name = "docs/adr/0000-example.md"
    write(repo, name, "# Synthetic ADR\nStatus: accepted\nFrozen decision.\n")
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    if plant == "delete_accepted":
        (repo / name).unlink()
    elif plant == "overwide":
        write(repo, name, "x" * 4001)
    else:
        write(repo, name, "line\n" * 61 if plant == "overlong" else "# Synthetic ADR\nStatus: accepted\nAltered.\n")
    commit(repo)
    with pytest.raises(ValueError, match="AD-07"):
        audit(repo, base, "HEAD")


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_accepted_adr_status_only_change_passes(repo, ending):
    name = "docs/adr/0000-example.md"
    write(repo, name, "# Synthetic ADR\nStatus: accepted\nFrozen decision.\n")
    (repo / name).write_bytes((repo / name).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", ending.encode()))
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    write(repo, name, "# Synthetic ADR\nStatus: superseded\nFrozen decision.\n")
    (repo / name).write_bytes((repo / name).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", ending.encode()))
    commit(repo)
    assert audit(repo, base, "HEAD")["counted_lines"] == 2


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
@pytest.mark.parametrize("status", [
    "Status: superseded\nStatus: new unreviewed decision", "", "Status:",
    "Status: superseded\n Status: accepted", "Status: superseded\nStatus: superseded",
    "Status: new unreviewed decision",
])
def test_adr_status_shape_refused_by_real_audit(repo, ending, status):
    name = "docs/adr/0000-example.md"
    path = repo / name
    path.parent.mkdir(parents=True)
    path.write_bytes(ending.join(["# ADR", "Status: accepted", "Frozen decision.", ""]).encode())
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    path.write_bytes(ending.join(["# ADR", status.replace("\n", ending), "Frozen decision.", ""]).encode())
    commit(repo)
    with pytest.raises(ValueError, match="AD-07"):
        audit(repo, base, "HEAD")


def test_adr_status_line_cannot_move(repo):
    name = "docs/adr/0000-example.md"
    write(repo, name, "# ADR\nStatus: accepted\nFrozen decision.\n")
    commit(repo)
    base = git(repo, "rev-parse", "HEAD")
    write(repo, name, "# ADR\nFrozen decision.\nStatus: superseded\n")
    commit(repo)
    with pytest.raises(ValueError, match="AD-07"):
        audit(repo, base, "HEAD")


def test_digest_changes_with_handwritten_diff(repo):
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "tools/example.py", "# first\n")
    commit(repo)
    digest = diff_digest(repo, base, "HEAD")
    write(repo, "tools/example.py", "# second\n")
    commit(repo)
    assert diff_digest(repo, base, "HEAD") != digest


def test_git_diff_helpers_are_never_executed(repo, monkeypatch):
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "tools/example.py", "# synthetic\n")
    commit(repo)
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "helper-that-must-never-execute")
    assert audit(repo, base, "HEAD")["counted_lines"] == 1


@pytest.mark.parametrize("case", json.loads(Path("fixtures/governance/historical-reviews.json").read_text(encoding="utf-8")))
def test_real_review_hashes_including_bootstrap(case):
    assert diff_digest(Path.cwd(), case["base_sha"], case["head_sha"]) == case["diff_sha256"]
