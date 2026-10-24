"""Preserve the two existing read-only path operations before constructor checks."""
import subprocess
import sys
from pathlib import Path

import pytest

from tools.fence import RUNTIME_API, SCOPED_API, STDLIB_API, source_allowed

USING = "atlas_brain/evidence/admission.py"
APIS = {"pathlib.PurePosixPath.is_absolute", "pathlib.PurePosixPath.parts"}


def test_read_admission_is_exact_and_all_previous_grants_remain():
    assert RUNTIME_API == {USING: APIS, "atlas_brain/evidence/archives.py": {
        "zipfile.ZipFile", "zipfile.BadZipFile", "zipfile.ZIP_STORED", "zipfile.ZIP_DEFLATED",
        "zlib.error", "zlib.decompressobj", "stat.S_IFMT", "zipfile.ZipFile.infolist",
        "zipfile.ZipFile.open", "pathlib.Path.suffix",
    }, "atlas_brain/kernel/population.py": {"dataclasses.InitVar"}}
    assert len(STDLIB_API) == 22
    assert len(SCOPED_API["atlas_brain/kernel/token_lints.py"]) == 29
    assert len(SCOPED_API["atlas_brain/kernel/lints.py"] - {"ast.Starred"}) == 32
    text = Path("docs/adr/0009-adr0002-path-read.md").read_text(encoding="utf-8")
    assert all(api in text for api in APIS)


@pytest.mark.parametrize("api", sorted(APIS))
def test_read_member_using_path_and_wrong_file_refusal(api):
    member = api.rsplit(".", 1)[1]
    source = "from pathlib import PurePosixPath\nPurePosixPath." + member
    assert source_allowed(source, path=USING)
    assert not source_allowed(source, path="atlas_brain/probe.py")
    for unlisted in ("parent", "joinpath", "as_uri"):
        assert not source_allowed("from pathlib import PurePosixPath\nPurePosixPath." + unlisted, path=USING)
    assert source_allowed("from pathlib import PurePosixPath\nPurePosixPath('synthetic')", path=USING)


@pytest.mark.parametrize("api", sorted(APIS))
def test_read_capability_exports_stay_per_file(api):
    member = api.rsplit(".", 1)[1]
    sources = {USING: "from pathlib import PurePosixPath\nexported = PurePosixPath." + member,
               "atlas_brain/bridge.py": "from .evidence.admission import exported"}
    assert not source_allowed("from .evidence.admission import exported\nexported", sources)
    assert not source_allowed("from .bridge import exported\nexported", sources)


@pytest.mark.parametrize("api", sorted(APIS))
def test_actual_cli_read_member_is_not_admitted_outside_its_using_file(tmp_path: Path, api):
    file = tmp_path / USING
    file.parent.mkdir(parents=True)
    source = "from pathlib import PurePosixPath\nPurePosixPath." + api.rsplit(".", 1)[1] + "\n"
    file.write_text(source, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    tool = str(Path("tools/fence.py").resolve())
    subprocess.run([sys.executable, tool], cwd=tmp_path, check=True)
    (tmp_path / "atlas_brain/probe.py").write_text(source, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    result = subprocess.run([sys.executable, tool], cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 1 and "scope fence: 1 refused" in result.stdout and "atlas_brain/probe.py" in result.stdout
