"""ADR-0015 grants only resolved-path separation in the coordinator."""
from pathlib import Path

import pytest

from tools.fence import RUNNER_API, RUNNER_EVIDENCE_API, admitted_apis, source_allowed

COORDINATOR = "atlas_brain/runner/coordinator.py"
EXPECTED = {COORDINATOR: {"pathlib.Path.resolve", "pathlib.Path.is_relative_to", "pathlib.Path.lstat"}}
ADR = "docs/adr/0015-runner-evidence-path.md"
PATH_OPERATIONS = (
    "from pathlib import Path\nPath.resolve(Path('evidence'))",
    "from pathlib import Path\nPath.is_relative_to(Path('out'), Path('evidence'))",
    "from pathlib import Path\nPath.lstat(Path('out/SUMMARY.txt'))",
    "from pathlib import Path as P\nP.resolve(P('evidence'))",
    "import pathlib\npathlib.Path.is_relative_to(pathlib.Path('out'), pathlib.Path('evidence'))",
)


def test_evidence_admission_map_is_exact_and_in_inventory():
    assert RUNNER_EVIDENCE_API == EXPECTED
    assert EXPECTED[COORDINATOR] <= admitted_apis()


def test_original_runner_inventory_is_unchanged():
    assert RUNNER_API == {
        "atlas_brain/runner/__init__.py": {"subprocess.run", "sys.executable"},
        "atlas_brain/runner/cli.py": {"subprocess.run", "sys.argv", "sys.executable", "sys.stderr"},
        COORDINATOR: {"subprocess.run", "sys.executable"},
        "atlas_brain/runner/tripwire.py": {
            "http.client.HTTPConnection", "http.client.HTTPConnection.close",
            "http.client.HTTPConnection.connect", "socket.AF_INET", "socket.SOCK_STREAM",
            "socket.getaddrinfo", "socket.socket", "socket.socket.close", "socket.socket.connect",
            "sys.addaudithook", "urllib.request.urlopen",
        },
    }


@pytest.mark.parametrize("source", PATH_OPERATIONS)
def test_resolved_path_operations_are_admitted_only_in_coordinator(source):
    assert source_allowed(source, path=COORDINATOR)
    for path in (
        "atlas_brain/runner/evidence.py", "atlas_brain/runner/cli.py",
        "atlas_brain/runner/records.py", "atlas_brain/runner/tripwire.py",
        "atlas_brain/evidence/admission.py", "atlas_brain/kernel/states.py",
        "atlas_brain/packs/platform/system/build.py", "atlas_brain/probe.py",
    ):
        assert not source_allowed(source, path=path), path


@pytest.mark.parametrize("source", (
    "from pathlib import Path\nPath.unlink(Path('x'))",
    "from pathlib import Path\nPath.write_text(Path('x'), 'changed')",
    "from pathlib import Path\nPath.read_bytes(Path('x'))",
    "import os",
    "import socket",
    "import sys\nsys.modules",
))
def test_path_separation_grants_no_adjacent_capability(source):
    assert not source_allowed(source, path=COORDINATOR)


def test_adr_records_exact_accepted_admissions():
    text = Path(ADR).read_text(encoding="utf-8")
    assert [line for line in text.splitlines() if line.startswith("Status:")] == ["Status: accepted"]
    assert "2026-10-25" in text
    assert len(text.splitlines()) <= 60 and len(text) <= 5000
    assert COORDINATOR in text
    for api in EXPECTED[COORDINATOR]:
        assert api in text, api
