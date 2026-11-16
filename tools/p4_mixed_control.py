"""Parent-only Root9 capture ownership/retention state; never demo completion or upload authentication.

The reviewed orchestrator, trusted fresh artifact tree and no external writers are premises.
API-batch processes may not start nested full controllers. Raw child stderr stays in owned files.
"""
import math
import os
import stat
import sys
import time
from pathlib import Path

from tools import p4_linux_process as linux
from tools import p4_process_state as metadata
from tools import p4_windows_job as windows

REPO = Path(__file__).resolve().parents[1]
CASES = frozenset(("normal", "none", "cold_vrrp", "only_vrrp", "empty", "partial", "no_all_capture", "no_all_target", "zero_vrrp"))
CHANNELS = frozenset(("github_output", "github_env", "github_path", "github_state", "github_step_summary"))


class CaptureError(metadata.ProcessError):
    def __init__(self, reason, quiescent, cleanup=()):
        RuntimeError.__init__(self, "p4_mixed_capture_" + reason)
        self.reason, self.quiescent, self.cleanup = reason, quiescent, cleanup


class MixedCapture:
    def __init__(self, root, *, deadline):
        if "--api-batch" in sys.argv[1:]:
            raise CaptureError("parent_role", False)
        now = time.monotonic()
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or not now < deadline <= now + 420:
            raise CaptureError("deadline", True)
        self._pid, self._deadline = os.getpid(), deadline
        root = Path(root)
        root.mkdir(parents=True, exist_ok=False)
        self.root = root.resolve(strict=True)
        info = self.root.lstat()
        self._identity = info.st_dev, info.st_ino
        self._unknown, self._active, self._captures = False, False, []

    @property
    def deadline(self):
        return self._deadline

    def _parent(self):
        return os.getpid() == self._pid and "--api-batch" not in sys.argv[1:]

    def _owned(self):
        try:
            info = self.root.lstat()
        except OSError:
            return False
        return stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self._identity

    @property
    def retention_ready(self):
        if not self._parent() or self._unknown or self._active:
            return False
        if not self._owned():
            self._unknown = True
            return False
        return all(state == "quiet" for pair, state in self._captures)

    def run_saved(self, command, env, folder, label):
        if not self._parent() or self._active or self._unknown:
            raise CaptureError("parent_or_unknown", False)
        if not self.retention_ready:
            raise CaptureError("root_ownership", False)
        if sys.platform not in ("linux", "win32"):
            raise CaptureError("platform", True)
        if type(command) not in (list, tuple) or not command or any(type(part) is not str or not part or "\0" in part for part in command) or Path(command[0]).resolve() != Path(sys.executable).resolve():
            raise CaptureError("command", True)
        if type(env) is not dict or any(type(key) is not str or not key or "=" in key or "\0" in key or type(value) is not str or "\0" in value for key, value in env.items()):
            raise CaptureError("environment", True)
        if Path.cwd().resolve() != REPO.resolve():
            raise CaptureError("repository_cwd", True)
        folder = Path(folder).resolve(strict=True)
        relative = folder.relative_to(self.root).parts
        if type(label) is not str or not ((label in ("api0", "api1") and not relative) or (label in ("cli0", "cli1") and len(relative) == 1 and relative[0] in CASES)):
            raise CaptureError("capture_path", True)
        pair = folder / (label + ".stdout.txt"), folder / (label + ".stderr.txt")
        if any(path.exists() or path.is_symlink() for path in pair) or any(old == pair for old, state in self._captures):
            raise CaptureError("capture_exists", True)
        module = linux if sys.platform == "linux" else windows
        if self.deadline - time.monotonic() <= (11 if sys.platform == "linux" else 5):
            raise CaptureError("deadline", True)
        verified, known_completion, self._active = False, False, True
        try:
            self._captures.append((pair, "pending"))
            child_env = {key: value for key, value in env.items() if key.casefold() not in CHANNELS}
            try:
                run = module.run_linux if sys.platform == "linux" else module.run_windows
                value = run(command, env=child_env, cwd=REPO, stdout_path=pair[0], stderr_path=pair[1], deadline=self.deadline, timeout=90)
            except metadata.ProcessError as error:
                native_error = type(error) is module.ProcessError
                verified = native_error and error.quiescent is True and error.cleanup == ()
                if verified and (not self._parent() or not self._owned()):
                    verified = False
                known_completion = verified
                raise CaptureError("native_refusal", verified, error.cleanup if native_error else ()) from error
            if type(value) is not module.Result or type(value.returncode) is not int or type(value.stdout) is not bytes or type(value.stderr) is not bytes or value.quiescent is not True:
                raise CaptureError("unverified_result", False)
            verified = True
            if not self._parent() or not self._owned():
                raise CaptureError("root_or_role_changed", False)
            if time.monotonic() >= self.deadline:
                known_completion = True
                raise CaptureError("deadline", True)
            if value.returncode != 0 or value.stderr:
                known_completion = True
                raise CaptureError("child_result", True)
            known_completion = True
            return value
        finally:
            verified &= known_completion
            self._active = False
            self._unknown |= not verified
            if self._captures and self._captures[-1][0] == pair:
                self._captures[-1] = pair, "quiet" if verified else "unknown"
