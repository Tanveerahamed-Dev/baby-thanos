"""Literal key-order/error controls and actual-tree hosted diagnostics; no speed gate."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from atlas_brain.contract.canonical import canonical

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("keys,expected", [
    (["z", "a", ""], b'{"":0,"a":1,"z":2}'),
    (["~", "A", "a", "0", "\x7f"], b'{"0":1,"A":2,"a":3,"~":4,"\x7f":0}'),
    (["\\", '"', "\n", "\x00"], b'{"\\u0000":0,"\\n":1,"\\"":2,"\\\\":3}'),
    (["z", "\ue000", "\U0001f600", "a"], '{"a":0,"z":1,"\U0001f600":2,"\ue000":3}'.encode()),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_literal_orders_cover_whole_ascii_branch_and_entire_unicode_fallback(keys, expected, reverse):
    ordered = json.loads(expected)
    pairs = [(key, ordered[key]) for key in keys]
    value = dict(reversed(pairs) if reverse else pairs)
    assert canonical(value) == expected
    assert list(value) == [key for key, _ in (reversed(pairs) if reverse else pairs)]


@pytest.mark.parametrize("keys,kind,reason", [
    (["", "a", "z"], ValueError, "integer_out_of_range"),
    (["z", "a", ""], TypeError, "non_json_type"),
    (["\x00", "\n", '"', "\\"], ValueError, "integer_out_of_range"),
    (["\\", '"', "\n", "\x00"], TypeError, "non_json_type"),
    (["\ue000", "a", "\U0001f600"], TypeError, "non_json_type"),
    (["z", "\ud800"], UnicodeEncodeError, None),
])
def test_nested_keys_and_first_invalid_value_keep_original_exception_precedence(keys, kind, reason):
    value = {key: 9007199254740992 if index == 0 else 1.0 for index, key in enumerate(keys)}
    with pytest.raises(kind, match=None if reason is None else "^" + reason + "$"):
        canonical({"outer": [value]})
    assert canonical({"z": (), "a": {"b": 1}}) == b'{"a":{"b":1},"z":[]}'


@pytest.mark.parametrize("position", ["first", "last"])
def test_one_string_subclass_forces_entire_original_sort_and_preserves_its_hook(position):
    calls = []
    class Key(str):
        def isascii(self):
            raise AssertionError("subclass ASCII hook")
        def encode(self, *args, **kwargs):
            calls.append((args, kwargs))
            raise LookupError("original_key_encoding")
    pairs = [(Key("alias"), 9007199254740992), ("z", 1.0)]
    value = dict(pairs if position == "first" else reversed(pairs))
    with pytest.raises(LookupError, match="^original_key_encoding$"):canonical(value)
    assert calls == [(("utf-16be",), {})]


def test_nonstring_key_guard_precedes_all_key_encoding_and_nested_invalid_values():
    class Key(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("key encoded before nonstring refusal")
    with pytest.raises(TypeError, match="^non_string_key$"):
        canonical({Key("valid"): {"bad": 9007199254740992}, 1: None})


def test_real_repository_tree_compilers_are_paired_without_a_speed_assertion(tmp_path, capsys):
    run = subprocess.run([sys.executable, str(ROOT / "tools/canonical_pair_measure.py"),
        str(ROOT), str(tmp_path)], cwd=ROOT, capture_output=True, text=True, check=False, timeout=90)
    assert run.returncode == 0, (run.stdout, run.stderr)
    record = json.loads(run.stdout)
    assert record["schema"] == "atlas-brain.canonical-ascii-pairs/1"
    assert record["scope"] == "pinned_actual_tree_fresh_compilers_diagnostic_not_420"
    assert record["platform"] == sys.platform and record["python"] == [3, 14, 8]
    assert record["groups_per_sample"] == 32 and len(record["pairs"]) == 8
    assert record["baseline"]["canonical_blob"] == "640c5ccbce24e4e962960313f1acefe36b51e836"
    assert record["baseline"]["outputs"] == record["candidate"]["outputs"]
    assert record["baseline"]["phase_counts"] == record["candidate"]["phase_counts"]
    assert record["checkout_unchanged"] is True
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    assert len(raw) < 16384
    with capsys.disabled():
        print("P4_CANONICAL_ASCII_PAIRS " + raw)


def test_measurement_refuses_an_unrelated_engine_change_before_export_or_execution(tmp_path, monkeypatch):
    from tools import canonical_pair_measure as paired

    repo = tmp_path / "repository"
    repo.mkdir()
    def git(*args):
        run = subprocess.run(["git", "-C", str(repo), *args], check=False,
            capture_output=True, text=True)
        assert run.returncode == 0, (run.stdout, run.stderr)
        return run.stdout.strip()
    git("init", "-q")
    folder = repo / "atlas_brain/contract"
    folder.mkdir(parents=True)
    canonical_file, sibling = folder / "canonical.py", repo / "atlas_brain/sibling.py"
    (repo / ".python-version").write_text("3.14.8\n")
    revisions = []
    for label in ("baseline", "candidate"):
        canonical_file.write_text(label + "\n")
        sibling.write_text(label + "\n")
        git("add", ".")
        git("-c", "user.name=synthetic", "-c", "user.email=synthetic@example.invalid",
            "commit", "-q", "-m", label)
        revisions.append(git("rev-parse", "HEAD"))
    monkeypatch.setattr(paired, "BASELINE", revisions[0])
    monkeypatch.setattr(paired, "CANDIDATE", revisions[1])
    monkeypatch.setattr(paired, "BASE_CODEC", git("rev-parse", revisions[0] + ":" + paired.CODEC))
    monkeypatch.setattr(paired, "CANDIDATE_CODEC", git("rev-parse", revisions[1] + ":" + paired.CODEC))
    monkeypatch.setattr(paired, "export", lambda *_: pytest.fail("foreign engine reached export"))
    with pytest.raises(AssertionError, match="^unexpected_pair_diff$"):
        paired.measure(repo.resolve(), tmp_path / "export")
    assert git("status", "--porcelain", "--untracked-files=no") == ""
