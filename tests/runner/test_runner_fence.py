"""ADR-0013: runner admissions are exact, path-scoped and documented."""
from pathlib import Path

import pytest

from tools.fence import RUNNER_API, source_allowed

ADR = "docs/adr/0013-runner-egress-and-child-spawn.md"
EXPECTED = {
    "atlas_brain/runner/__init__.py": {"subprocess.run", "sys.executable"},
    "atlas_brain/runner/cli.py": {"subprocess.run", "sys.argv", "sys.executable", "sys.stderr"},
    "atlas_brain/runner/coordinator.py": {"subprocess.run", "sys.executable"},
    "atlas_brain/runner/tripwire.py": {
        "http.client.HTTPConnection", "http.client.HTTPConnection.close",
        "http.client.HTTPConnection.connect", "socket.AF_INET", "socket.SOCK_STREAM",
        "socket.getaddrinfo", "socket.socket", "socket.socket.close", "socket.socket.connect",
        "sys.addaudithook", "urllib.request.urlopen",
    },
}


def test_runner_admissions_are_exact_and_confined_to_runner_paths():
    assert RUNNER_API == EXPECTED
    assert all(path.startswith("atlas_brain/runner/") for path in RUNNER_API)


def test_admissions_do_not_leak_outside_their_using_path():
    assert source_allowed("import subprocess", path="atlas_brain/runner/cli.py")
    assert not source_allowed("import subprocess", path="atlas_brain/runner/worker.py")
    assert not source_allowed("import subprocess", path="atlas_brain/evidence/admission.py")
    assert not source_allowed("import subprocess")
    assert source_allowed("import socket", path="atlas_brain/runner/tripwire.py")
    assert not source_allowed("import socket", path="atlas_brain/runner/cli.py")
    assert not source_allowed("import socket")
    assert not source_allowed("import socket; socket.socket", path="atlas_brain/runner/worker.py")
    assert not source_allowed("import sys; sys.modules", path="atlas_brain/runner/cli.py")


@pytest.mark.parametrize("path", sorted(EXPECTED))
def test_each_runner_path_still_refuses_an_unadmitted_module(path):
    for source in ("import argparse", "import os", "from pathlib import Path\nPath('x').write_text('y')"):
        assert not source_allowed(source, path=path), source


def test_adr_is_accepted_bounded_and_names_every_admission():
    text = Path(ADR).read_text(encoding="utf-8")
    assert [line for line in text.splitlines() if line.startswith("Status:")] == ["Status: accepted"]
    assert "2026-10-24" in text
    assert len(text.splitlines()) <= 60 and len(text) <= 5000
    for path, apis in EXPECTED.items():
        assert path in text
        for api in apis:
            assert api in text, api
