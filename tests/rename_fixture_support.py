"""Bounded test-fixture renames; no native retry or process-quiescence claim."""
import sys
from time import monotonic, sleep

WINDOWS = sys.platform == "win32"


def _before(deadline, last=None):
    if monotonic() >= deadline:
        if last is not None:
            raise last
        raise TimeoutError("rename_fixture_deadline")


def _identity(path):
    info = path.lstat()
    return info.st_dev, info.st_ino


def rename_before_deadline(source, target, deadline):
    """Retry only Windows access-denied on unchanged fixture paths."""
    _before(deadline)
    identity = _identity(source)
    last = None
    while True:
        _before(deadline, last)
        if target.exists() or target.is_symlink():
            raise FileExistsError(str(target))
        _before(deadline, last)
        try:
            source.rename(target)
        except PermissionError as error:
            if not WINDOWS or getattr(error, "winerror", None) != 5:
                raise
            try:
                unchanged = _identity(source) == identity
            except OSError:
                unchanged = False
            # A changed source or existing target is an uncertain acknowledgement.
            if not unchanged or target.exists() or target.is_symlink():
                raise
            last = error
            left = deadline - monotonic()
            if left <= 0:
                raise
            sleep(min(0.01, left))
        else:
            _before(deadline, last)
            if source.exists() or source.is_symlink() or _identity(target) != identity:
                raise RuntimeError("rename_fixture_identity")
            _before(deadline, last)
            return


def restore_before_deadline(root, preserved, deadline, primary=None):
    """Restore only within the same deadline; never erase an actual primary."""
    pending = sys.exception()
    try:
        _before(deadline)
        if root.exists() or root.is_symlink():
            _before(deadline)
            root.rmdir()
        rename_before_deadline(preserved, root, deadline)
    except BaseException as cleanup:
        original = pending if pending is not None else primary
        if original is not None and original is not cleanup:
            raise cleanup from original
        raise
