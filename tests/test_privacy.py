import json
import os
import subprocess
import sys

import pytest

from tools.privacy import scan


@pytest.mark.parametrize("data", [
    b"C:" + bytes([92]) + b"Users" + bytes([92]) + b"example/file",
    bytes([47]) + b"home/example/file", bytes([47]) + b"Users/example/file",
    b".".join([b"10", b"1", b"2", b"3"]), bytes([102, 99, 48, 48, 58, 58, 49]),
    bytes([70, 79, 67]) + b"1234ABCD", bytes([102, 111, 99]) + b"1234abcd",
])
def test_planted_structural_shapes(data):
    assert scan(data, "a" * 40, [])


@pytest.mark.parametrize("data", [b"192.0.2.1", b"198.51.100.5", b"203.0.113.8", b"2001:db8::1"])
def test_documentation_addresses_pass(data):
    assert not scan(data, "b" * 40, [])


@pytest.mark.parametrize("gate", [False, True])
@pytest.mark.parametrize("separator", [b" + ", b" + " + bytes([92, 10]), b" " + bytes([92, 13, 10])])
@pytest.mark.parametrize("value", [
    bytes([67, 58, 92]) + b"Users" + bytes([92]) + b"example",
    bytes([47]) + b"home/example", bytes([47]) + b"Users/example",
    ".".join(map(str, (10, 1, 2, 3))).encode(),
    bytes([70, 79, 67]) + b"1234ABCD",
])
def test_split_structural_shapes_preserve_offsets(value, gate, separator):
    cut = 3
    source = b"v = " + json.dumps(value[:cut].decode()).encode() + separator + json.dumps(value[cut:].decode()).encode()
    hits = scan(source, "d" * 40, [os.environ["ATLAS_TEST_MARKER"].encode()] if gate else [])
    assert hits == [{"blob": "d" * 40, "offset": 5}]


def test_gate_marker_and_split_receipts():
    marker = os.environ["ATLAS_TEST_MARKER"].encode()
    for prefix in (b"", b"b", b"B", b"r", b"u", b"br", b"rb", b"f", b"F", b"fr", b"rf", b"t", b"tr", b"rt"):
        for data in (b"prefix " + marker,
                     b'v = ' + prefix + b'"' + marker[:5] + b'" + ' + prefix + b'"' + marker[5:] + b'"',
                     b'v = ' + prefix + b'"' + marker[:5] + b'" ' + prefix + b'"' + marker[5:] + b'"',
                     b'v = ' + prefix + b'"' + marker[:5] + b'" + ' + bytes([92, 10]) + prefix + b'"' + marker[5:] + b'"',
                     b'v = (' + prefix + b'"' + marker[:5] + b'" # "ignored"\n ' + prefix + b'"' + marker[5:] + b'")'):
            hits = scan(data, "c" * 40, [marker])
            assert hits == [{"blob": "c" * 40, "offset": data.index(marker[:5])}]
            assert marker.decode() not in json.dumps(hits)
            assert not scan(data, "c" * 40, [])


def test_escaped_newline_inside_literal_preserves_marker_offset():
    marker = os.environ["ATLAS_TEST_MARKER"].encode()
    for newline in (bytes([92, 10]), bytes([92, 13, 10])):
        data = b'v = "' + marker[:5] + newline + marker[5:] + b'"'
        assert scan(data, "e" * 40, [marker]) == [{"blob": "e" * 40, "offset": 5}]


@pytest.mark.parametrize("gate", [True, False])
@pytest.mark.parametrize("changed,removed", [(True, False), (True, True), (False, False)])
def test_cli_refuses_planted_blob(tmp_path, gate, changed, removed):
    marker = os.environ["ATLAS_TEST_MARKER"]
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    commit = ["git", "-C", str(repo), "-c", "user.name=Synthetic",
              "-c", "user.email=synthetic@example.invalid", "commit", "-qm", "synthetic"]
    subprocess.run([*commit, "--allow-empty"], check=True)
    base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
    data = marker if gate else chr(47) + "home/example/file"
    (repo / "sample.txt").write_text(data, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    blob = subprocess.check_output(["git", "-C", str(repo), "rev-parse", ":sample.txt"]).decode().strip()
    if changed:
        subprocess.run(commit, check=True)
    if removed:
        (repo / "sample.txt").write_text("synthetic", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(commit, check=True)
    tool = os.path.abspath("tools/privacy.py")
    flags = (["--gate"] if gate else []) + (["--base", base] if changed else [])
    result = subprocess.run([sys.executable, tool, *flags], cwd=repo,
                            env={**os.environ, "ATLAS_PRIVACY_MARKERS": json.dumps([marker])},
                            capture_output=True, check=False)
    assert result.returncode == 1
    assert marker.encode() not in result.stdout + result.stderr
    assert json.loads(result.stdout) == [{"blob": blob, "offset": 0}]


def test_gate_without_markers_fails_closed():
    result = subprocess.run([sys.executable, "tools/privacy.py", "--gate"],
                            env={k: v for k, v in os.environ.items() if k != "ATLAS_PRIVACY_MARKERS"},
                            capture_output=True, check=False)
    assert result.returncode == 2
