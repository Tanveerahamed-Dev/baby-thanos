"""Metadata contracts only; constructed timeout objects do not prove process execution or quiescence."""
import dataclasses
import subprocess
import sys
from contextlib import ExitStack

import pytest

from tools import p4_process_state as state


def native_primary():
    if sys.platform != "win32":
        return OSError("platform-independent OSError fixture; no Windows native claim")
    from tools import p4_windows_job_api as abi
    api = abi.kernel()
    with ExitStack() as cleanup:
        handle = api.CreateJobObjectW(None, None)
        abi.check(handle)
        cleanup.callback(lambda: abi.check(api.CloseHandle(handle)))
        limits = abi.ExtendedLimit()
        try:
            abi.check(api.SetInformationJobObject(handle, -1, abi.c.byref(limits), abi.c.sizeof(limits)))
        except OSError as primary:
            assert primary.winerror != 0
            return primary
        raise AssertionError("native invalid-class SetInfo must fail")


def primary(kind):
    return subprocess.TimeoutExpired(["python", "-c", "fixture"], 0.1, output=b"partial", stderr=b"error") if kind == "timeout" else native_primary()


def unwind(requests, mode, events, statuses, contexts):
    class CleanupFault(TypeError):
        def __setattr__(self, name, value):
            if name == "owned_process_primary":
                events.append("set_primary")
                if mode in ("attribute_memory", "both_memory"):
                    raise MemoryError("planted attribute allocation")
            super().__setattr__(name, value)
        def add_note(self, note):
            events.append("add_note")
            if mode in ("note_memory", "both_memory"):
                raise MemoryError("planted note allocation")
            super().add_note(note)
    class Issues(list):
        def __repr__(self):
            events.append("format")
            raise MemoryError("planted note formatting")
    try:
        try:
            raise KeyError("existing cleanup context")
        except KeyError:
            raise CleanupFault("unexpected cleanup")
    finally:
        pending = sys.exception()
        contexts.append((pending.__cause__, pending.__context__))
        BaseException.add_note(pending, "existing-note")
        for saved, issues in requests:
            if mode == "format_memory":
                issues = Issues(issues)
            statuses.append(state.retain_pending(saved, issues))


@pytest.mark.parametrize("kind", ("timeout", "os"))
@pytest.mark.parametrize("mode", ("normal", "note_memory", "attribute_memory", "both_memory", "format_memory"))
def test_actual_primary_identity_and_existing_context_survive_each_annotation_path(kind, mode):
    saved = primary(kind)
    issues = [("query", "lost acknowledgement")]
    original = issues.copy()
    events, statuses, contexts = [], [], []
    with pytest.raises(TypeError, match="^unexpected cleanup") as error:
        unwind([(saved, issues)], mode, events, statuses, contexts)
    assert error.value.args == ("unexpected cleanup",)
    pending = error.value
    assert pending.__cause__ is contexts[0][0] is None and pending.__context__ is contexts[0][1]
    assert isinstance(pending.__context__, KeyError) and issues == original
    retained = mode not in ("attribute_memory", "both_memory")
    assert statuses == [retained] and getattr(pending, "quiescent", False) is False
    if retained:
        assert pending.owned_process_primary is saved
        assert isinstance(saved, subprocess.TimeoutExpired if kind == "timeout" else OSError)
    else:
        assert not hasattr(pending, "owned_process_primary")
    assert events == (["set_primary", "format"] if mode == "format_memory" else ["set_primary", "add_note"])
    assert pending.__notes__[0] == "existing-note"
    assert len(pending.__notes__) == (2 if mode in ("normal", "attribute_memory") else 1)


def test_constructor_to_runner_reentry_keeps_prior_identity_and_distinct_primary_reports_conflict():
    first, second = primary("os"), primary("timeout")
    events, statuses, contexts = [], [], []
    with pytest.raises(TypeError, match="^unexpected cleanup") as error:
        unwind([(first, []), (None, []), (first, []), (second, [])], "normal", events, statuses, contexts)
    assert error.value.args == ("unexpected cleanup",)
    assert statuses == [True, True, True, False]
    assert error.value.owned_process_primary is first and error.value.owned_process_primary is not second
    assert events.count("set_primary") == 1 and events.count("add_note") == 3
    assert error.value.__context__ is contexts[0][1] and error.value.__cause__ is None
    assert error.value.__notes__[0] == "existing-note" and len(error.value.__notes__) == 4


def test_no_pending_exception_is_a_noop_and_never_modifies_input_errors():
    saved = primary("timeout")
    before = saved.__dict__.copy()
    assert state.retain_pending(saved, []) is True
    assert saved.__dict__ == before and not hasattr(saved, "owned_process_primary")


def raise_error(error):
    raise error


@pytest.mark.parametrize("error", (OSError("os"), ValueError("stream"), state.ctypes.ArgumentError("ctypes"),
    subprocess.TimeoutExpired(["python"], 1), state.ProcessError("deadline", False), KeyboardInterrupt(), SystemExit(2)))
def test_finite_operation_and_cancellation_categories_are_collected_without_relabeling(error):
    issues = []
    assert state.attempt(issues, "operation", lambda: raise_error(error)) is None
    assert issues == [("operation", repr(error))]
    assert state.FAILURES == (OSError, ValueError, state.ctypes.ArgumentError, subprocess.SubprocessError,
        state.ProcessError, KeyboardInterrupt, SystemExit)


@pytest.mark.parametrize("error", (TypeError("type"), AttributeError("attribute"), AssertionError("assert"),
    MemoryError("allocation"), RuntimeError("unclassified")))
def test_unexpected_programming_errors_propagate_to_caller_owned_finally(error):
    issues, cleanup = [], []
    with pytest.raises(type(error)) as captured:
        try:
            state.attempt(issues, "operation", lambda: raise_error(error))
        finally:
            cleanup.append("ran")
    assert captured.value is error and issues == [] and cleanup == ["ran"]


@pytest.mark.parametrize("deadline", (99, 100, 105))
def test_remaining_uses_one_monotonic_deadline_and_refuses_expired_time(monkeypatch, deadline):
    monkeypatch.setattr(state.time, "monotonic", lambda: 100)
    if deadline > 100:
        assert state.remaining(deadline) == 5
    else:
        with pytest.raises(state.ProcessError, match="^p4_windows_job_deadline$") as error:
            state.remaining(deadline)
        assert error.value.quiescent is False


def test_results_are_immutable_metadata_and_errors_preserve_cleanup_without_ownership_authority():
    value = state.Result(0, b"out", b"err", True)
    assert dataclasses.astuple(value) == (0, b"out", b"err", True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.quiescent = False
    error = state.ProcessError("query", False, (("close", "OSError"),))
    assert error.reason == "query" and error.quiescent is False and error.cleanup == (("close", "OSError"),)
    assert "cleanup=" in str(error)
    issues = []
    assert state.attempt(issues, "value", lambda: value) is value and issues == []


def test_state_primitives_do_not_launch_processes_load_windows_dlls_or_touch_files(tmp_path, monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("metadata must not launch or load native APIs")
    monkeypatch.setattr(state.subprocess, "Popen", forbidden)
    monkeypatch.setattr(state.ctypes, "WinDLL", forbidden, raising=False)
    assert state.Result(0, b"", b"", False).quiescent is False
    assert state.attempt([], "pure", lambda: 7) == 7
    saved = subprocess.TimeoutExpired(["python"], 1)
    assert state.retain_pending(saved, []) is True
    assert calls == [] and list(tmp_path.iterdir()) == []
