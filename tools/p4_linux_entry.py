"""Static Linux worker entry and bounded control codec; neither origin authentication nor a parent supervisor.

Requests arrive only on anonymous stdin; environment values are never encoded here.
A separate caller must bound stalled reads/crashes and retain the worker's process-group anchor.
Emitted frame bytes remain candidates until checked worker completion and caller resource closure.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
from contextlib import ExitStack
from pathlib import Path

from tools import p4_linux_worker as worker
from tools import p4_process_state as metadata

if sys.platform == "linux":
    import fcntl

REQUEST_SCHEMA = "atlas-brain.p4-linux-request/1"
RECEIPT_SCHEMA = "atlas-brain.p4-linux-terminal/1"
REQUEST_LIMIT, RECEIPT_LIMIT = 32768, 2048
REASONS = frozenset(("linux_only", "worker_context", "preexisting_children", "arguments", "deadline", "streams", "capability",
    "spawn", "ownership", "release", "wait", "descendants", "timeout", "cleanup", "quiescence", "original_unreaped", "population_query"))
REQUEST_FIELDS = {"schema", "nonce", "command", "cwd", "stdout", "stderr", "stop_by"}
RECEIPT_FIELDS = {"schema", "nonce", "request_sha256", "worker_pid", "status", "returncode", "reason", "quiescent"}


class ProtocolError(ValueError):
    pass


def encode(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError("duplicate_control_key")
        value[key] = item
    return value


def _constant(value):
    raise ProtocolError("nonfinite_control_value")


def _decode(raw, limit):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise ProtocolError("control_size_or_type")
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    if encode(value) != raw:
        raise ProtocolError("noncanonical_control")
    return value


def request(raw):
    value = _decode(raw, REQUEST_LIMIT)
    if type(value) is not dict or set(value) != REQUEST_FIELDS or value["schema"] != REQUEST_SCHEMA:
        raise ProtocolError("request_fields")
    if type(value["nonce"]) is not str or re.fullmatch("[0-9a-f]{32}", value["nonce"]) is None:
        raise ProtocolError("request_nonce")
    command = value["command"]
    if type(command) is not list or not command or any(type(part) is not str or not part or "\0" in part for part in command):
        raise ProtocolError("request_command")
    for name in ("cwd", "stdout", "stderr"):
        if type(value[name]) is not str or not value[name] or "\0" in value[name] or not Path(value[name]).is_absolute():
            raise ProtocolError("request_path")
    if type(value["stop_by"]) not in (int, float) or not math.isfinite(value["stop_by"]) or value["stop_by"] <= 0:
        raise ProtocolError("request_deadline")
    return value


def terminal(raw_request, pid, result):
    supplied = request(raw_request)
    if type(result) is worker.Outcome and result.quiescent is True and type(result.returncode) is int:
        status, code, reason = "ok", result.returncode, ""
    elif type(result) is worker.LinuxError and result.quiescent is True and result.cleanup == () and type(result.reason) is str and result.reason in REASONS:
        status, code, reason = "error", None, result.reason
    else:
        raise ProtocolError("unverified_worker_terminal")
    return encode({"schema": RECEIPT_SCHEMA, "nonce": supplied["nonce"], "request_sha256": hashlib.sha256(raw_request).hexdigest(),
        "worker_pid": pid, "status": status, "returncode": code, "reason": reason, "quiescent": True}) + b"\n"


def read_terminal(raw, raw_request, pid):
    supplied = request(raw_request)
    if type(raw) is not bytes or len(raw) > RECEIPT_LIMIT or not raw.endswith(b"\n"):
        raise ProtocolError("terminal_frame")
    value = _decode(raw[:-1], RECEIPT_LIMIT)
    if type(value) is not dict or set(value) != RECEIPT_FIELDS:
        raise ProtocolError("terminal_fields")
    expected = {"schema": RECEIPT_SCHEMA, "nonce": supplied["nonce"], "request_sha256": hashlib.sha256(raw_request).hexdigest(),
        "worker_pid": pid, "quiescent": True}
    if type(pid) is not int or pid <= 0 or any(type(value[key]) is not type(item) or value[key] != item for key, item in expected.items()):
        raise ProtocolError("terminal_context")
    if value["status"] == "ok":
        valid = type(value["returncode"]) is int and value["reason"] == ""
    else:
        valid = value["status"] == "error" and value["returncode"] is None and type(value["reason"]) is str and value["reason"] in REASONS
    if not valid:
        raise ProtocolError("terminal_status")
    return value


def diagnose(error):
    """Emit closed labels only; actual exceptions/causes/tracebacks stay inside the worker."""
    known = type(error) is worker.LinuxError
    reason = error.reason if known and type(error.reason) is str and error.reason in REASONS else "unclassified"
    sys.stderr.write("P4_LINUX_FAILURE " + encode({"kind": "LinuxError" if known else "unexpected", "reason": reason}).decode("ascii") + "\n")


def main(descriptor):
    worker.context()  # Fresh isolated/SID/single-reaper role is a premise, never authentication.
    if type(descriptor) is not int or descriptor < 3:
        raise ProtocolError("private_writer_required")
    primary = None
    try:
        with ExitStack() as cleanup:
            cleanup.callback(os.close, descriptor)
            if not stat.S_ISFIFO(os.fstat(descriptor).st_mode) or os.get_blocking(descriptor) or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY:
                raise ProtocolError("nonblocking_pipe_required")
            os.set_inheritable(descriptor, False)
            raw = sys.stdin.buffer.read(REQUEST_LIMIT + 1)
            supplied = request(raw)
            try:
                result = worker.run_backend(supplied["command"], env=dict(os.environ), cwd=supplied["cwd"],
                    stdout_path=supplied["stdout"], stderr_path=supplied["stderr"], deadline=supplied["stop_by"])
            except worker.LinuxError as error:
                if error.quiescent is not True:
                    raise
                primary = error
                result = error
            payload = terminal(raw, os.getpid(), result)
            if primary is not None:
                diagnose(primary)
            if len(payload) > min(RECEIPT_LIMIT, os.fpathconf(descriptor, "PC_PIPE_BUF")):
                raise ProtocolError("terminal_write_bound")
            if os.write(descriptor, payload) != len(payload):
                raise ProtocolError("incomplete_terminal_write")
    finally:
        metadata.retain_pending(primary, [])
