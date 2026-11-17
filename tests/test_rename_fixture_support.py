"""Deterministic fixture coordination, including actual directory identity moves."""
import time
from pathlib import Path

import pytest
import rename_fixture_support as support

from tools import p4_mixed_control as mixed
from tools.p4_process_state import ProcessError


def paths(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    return source, target


def denial(code=5):
    error = PermissionError(13, "fixture access denied")
    error.winerror = code
    return error


def clock(monkeypatch):
    now, sleeps = [0.0], []
    monkeypatch.setattr(support, "monotonic", lambda: now[0])
    def sleeping(delay):
        assert 0 < delay <= 0.02 - now[0]
        sleeps.append(delay)
        now[0] += delay
    monkeypatch.setattr(support, "sleep", sleeping)
    return now, sleeps


def test_two_denials_then_real_inode_swap_and_original_restoration(tmp_path, monkeypatch):
    owner = mixed.MixedCapture(tmp_path / "root", deadline=time.monotonic() + 30)
    original, deadline = owner._identity, owner.deadline
    (owner.root / "original").write_bytes(b"retained")
    saved, failures, calls = tmp_path / "saved", [denial(), denial()], []
    rename = Path.rename
    def controlled(source, target):
        calls.append((source, target))
        if source == owner.root and failures:
            raise failures.pop(0)
        return rename(source, target)
    monkeypatch.setattr(support, "WINDOWS", True)
    monkeypatch.setattr(Path, "rename", controlled)
    support.rename_before_deadline(owner.root, saved, deadline)
    assert len(calls) == 3 and failures == []
    owner.root.mkdir()
    assert not owner._owned()
    assert (saved.stat().st_dev, saved.stat().st_ino) == original[:2]
    support.restore_before_deadline(owner.root, saved, deadline)
    assert owner.deadline == deadline and owner._owned()
    assert (owner.root.stat().st_dev, owner.root.stat().st_ino) == original[:2]
    assert (owner.root / "original").read_bytes() == b"retained"


def test_continuous_denial_raises_same_error_without_late_attempt(tmp_path, monkeypatch):
    source, target = paths(tmp_path)
    now, sleeps = clock(monkeypatch)
    error, attempts = denial(), []
    def refused(*args):
        attempts.append(now[0])
        raise error
    monkeypatch.setattr(support, "WINDOWS", True)
    monkeypatch.setattr(Path, "rename", refused)
    with pytest.raises(PermissionError) as caught:
        support.rename_before_deadline(source, target, 0.02)
    assert caught.value is error and attempts == [0.0, 0.01]
    assert sleeps == [0.01, 0.01] and now[0] == 0.02
    assert source.is_dir() and not target.exists()


def test_preexpired_deadline_never_attempts_or_mutates(tmp_path, monkeypatch):
    source, target = paths(tmp_path)
    clock(monkeypatch)
    calls = []
    monkeypatch.setattr(Path, "rename", lambda *args: calls.append(args))
    with pytest.raises(TimeoutError, match="^rename_fixture_deadline$"):
        support.rename_before_deadline(source, target, 0.0)
    assert calls == [] and source.is_dir() and not target.exists()


@pytest.mark.parametrize("windows,code", [(False, 5), (True, 32), (True, None)])
def test_nonmatching_errors_are_immediate_and_unchanged(tmp_path, monkeypatch, windows, code):
    source, target = paths(tmp_path)
    _now, sleeps = clock(monkeypatch)
    error, calls = denial(code), []
    def refused(*args):
        calls.append(args)
        raise error
    monkeypatch.setattr(support, "WINDOWS", windows)
    monkeypatch.setattr(Path, "rename", refused)
    with pytest.raises(PermissionError) as caught:
        support.rename_before_deadline(source, target, 0.02)
    assert caught.value is error and len(calls) == 1 and sleeps == []


@pytest.mark.parametrize("directory", [False, True])
def test_preexisting_target_is_never_overwritten(tmp_path, monkeypatch, directory):
    source, target = paths(tmp_path)
    target.mkdir() if directory else target.write_bytes(b"preserved")
    before = target.stat().st_ino
    clock(monkeypatch)
    calls = []
    monkeypatch.setattr(Path, "rename", lambda *args: calls.append(args))
    with pytest.raises(FileExistsError):
        support.rename_before_deadline(source, target, 0.02)
    assert calls == [] and target.stat().st_ino == before and source.is_dir()


@pytest.mark.parametrize("changed", ["moved", "replaced"])
def test_move_or_changed_source_then_denial_is_not_retried_or_blessed(tmp_path, monkeypatch, changed):
    source, target = paths(tmp_path)
    original = source.stat().st_ino
    _now, sleeps = clock(monkeypatch)
    rename, error, calls = Path.rename, denial(), []
    displaced = tmp_path / "displaced"
    def uncertain(source, target):
        calls.append((source, target))
        rename(source, target if changed == "moved" else displaced)
        if changed == "replaced":
            source.mkdir()
        raise error
    monkeypatch.setattr(support, "WINDOWS", True)
    monkeypatch.setattr(Path, "rename", uncertain)
    with pytest.raises(PermissionError) as caught:
        support.rename_before_deadline(source, target, 0.02)
    assert caught.value is error and len(calls) == 1 and sleeps == []
    assert (target if changed == "moved" else displaced).stat().st_ino == original
    assert not source.exists() if changed == "moved" else source.stat().st_ino != original


def test_success_returning_after_deadline_is_failure_despite_actual_move(tmp_path, monkeypatch):
    source, target = paths(tmp_path)
    now, _sleeps = clock(monkeypatch)
    rename, calls = Path.rename, []
    def late(source, target):
        calls.append((source, target))
        result = rename(source, target)
        now[0] = 0.02
        return result
    monkeypatch.setattr(Path, "rename", late)
    with pytest.raises(TimeoutError):
        support.rename_before_deadline(source, target, 0.02)
    assert len(calls) == 1 and not source.exists() and target.is_dir()


@pytest.mark.parametrize("pending", [False, True])
def test_restore_failure_preserves_actual_primary_and_native_chain(tmp_path, monkeypatch, pending):
    root, saved = paths(tmp_path)
    saved.mkdir()
    clock(monkeypatch)
    native, primary = ProcessError("descendants", True), RuntimeError("pending primary")
    primary.__cause__ = native
    cleanup = OSError("actual restoration failure")
    def refused(*args):
        raise cleanup
    monkeypatch.setattr(Path, "rename", refused)
    with pytest.raises(OSError) as caught:
        if pending:
            try:
                raise primary
            finally:
                support.restore_before_deadline(root, saved, 0.02, native)
        else:
            support.restore_before_deadline(root, saved, 0.02, primary)
    assert caught.value is cleanup and cleanup.__cause__ is primary
    assert primary.__cause__ is native and saved.is_dir()


def test_preexpired_restore_keeps_both_directories_and_primary(tmp_path, monkeypatch):
    root, saved = paths(tmp_path)
    saved.mkdir()
    clock(monkeypatch)
    native, calls = ProcessError("descendants", True), []
    monkeypatch.setattr(Path, "rmdir", lambda *args: calls.append("rmdir"))
    monkeypatch.setattr(Path, "rename", lambda *args: calls.append("rename"))
    with pytest.raises(TimeoutError) as caught:
        support.restore_before_deadline(root, saved, 0.0, native)
    assert caught.value.__cause__ is native and calls == []
    assert root.is_dir() and saved.is_dir()
