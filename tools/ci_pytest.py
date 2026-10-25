"""Run complete Windows test partitions and verify same-run coverage receipts."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

if __package__:
    from .ci_pytest_receipts import (
        SCHEMA, ReceiptError, _ids, _metadata, _positive, _reports,
        shard_for, verify_receipts,
    )
else:
    from ci_pytest_receipts import (
        SCHEMA, ReceiptError, _ids, _metadata, _positive, _reports,
        shard_for, verify_receipts,
    )

ROOT = Path(__file__).resolve().parents[1]


class _Collector:
    def __init__(self, index, count):
        self.index, self.count = index, count
        self.raw, self.universe, self.selected, self.finished = [], [], [], []
        self.reports, self.failed_reports, self.collection_errors = {}, [], []
        self.session_exit = None

    def _fail(self, message):
        self.collection_errors.append(message)
        raise pytest.UsageError(message)

    def pytest_configure(self, config):
        selectors = (
            "keyword", "markexpr", "lf", "failedfirst", "stepwise",
            "stepwise_skip", "collectonly", "deselect", "ignore",
            "ignore_glob", "pyargs", "noconftest", "override_ini",
        )
        if (config.getini("addopts") or list(config.args) != ["tests"]
                or any(getattr(config.option, key, None) for key in selectors)):
            self._fail("selection_configuration_refused")

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_ignore_collect(self, collection_path, config):
        result = yield
        if result.get_result() and collection_path.is_relative_to(ROOT / "tests"):
            paths = collection_path.rglob("*.py") if collection_path.is_dir() else (collection_path,)
            if any(any(path.match(pattern) for pattern in config.getini("python_files")) for path in paths):
                self.collection_errors.append("test_path_ignored:" + collection_path.name)

    def pytest_itemcollected(self, item):
        self.raw.append(item.nodeid)

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_errors.append("collection_failed:" + (report.nodeid or "<root>"))
        elif report.skipped:
            self.collection_errors.append("collection_skipped:" + (report.nodeid or "<root>"))

    def pytest_deselected(self, items):
        if items:
            self.collection_errors.append("external_deselection_refused")

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, items):
        self.universe = list(self.raw)
        try:
            _ids(self.universe, "universe")
        except ReceiptError as error:
            self._fail(str(error))
        self.selected = [
            nodeid for nodeid in self.universe
            if shard_for(nodeid, self.count) == self.index
        ]
        if [item.nodeid for item in items] != self.universe:
            self._fail("raw_collection_was_filtered_or_reordered")
        if not self.selected:
            self._fail("empty_shard")
        items[:] = [item for item in items if shard_for(item.nodeid, self.count) == self.index]

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_collection_finish(self, session):
        yield
        if self.raw != self.universe or [item.nodeid for item in session.items] != self.selected:
            self._fail("final_collection_selection_mismatch")

    def pytest_runtest_logreport(self, report):
        if report.failed:
            self.failed_reports.append(report.nodeid + ":" + report.when)
        if hasattr(report, "wasxfail"):
            self.failed_reports.append("xfail_or_xpass:" + report.nodeid)
        if report.skipped and type(report) is not pytest.TestReport:
            self.failed_reports.append("skipped_subtest:" + report.nodeid)
        if type(report) is pytest.TestReport:
            reason = ""
            if report.skipped:
                detail = report.longrepr
                reason = (str(detail[2]) if isinstance(detail, tuple) and len(detail) == 3
                          else str(detail)).removeprefix("Skipped: ")
            self.reports.setdefault(report.nodeid, []).append({
                "when": report.when, "outcome": report.outcome, "reason": reason,
            })

    def pytest_runtest_logfinish(self, nodeid):
        self.finished.append(nodeid)

    @pytest.hookimpl(hookwrapper=True, tryfirst=True)
    def pytest_sessionfinish(self, session, exitstatus):
        self.session_exit = int(exitstatus)
        yield
        if int(session.exitstatus) != self.session_exit:
            self.collection_errors.append("session_exit_was_changed")


def _clean_source():
    result = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT,
        capture_output=True, check=False, timeout=10,
    )
    if result.returncode:
        raise ReceiptError("tracked_source_not_clean")


def _context(args):
    _metadata(args.head, args.run_id, args.attempt, args.count)
    if Path.cwd().resolve() != ROOT:
        raise ReceiptError("repository_cwd_required")
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, check=False, timeout=10,
    )
    if result.returncode or result.stdout.strip() != args.head:
        raise ReceiptError("checked_out_head_mismatch")
    _clean_source()


def _atomic_json(path, value):
    path = Path(path).absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=True, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _run(args):
    _positive(args.index, "shard_index")
    if args.index > args.count:
        raise ReceiptError("invalid_shard_index")
    receipt_path = Path(args.receipt).absolute()
    collector = _Collector(args.index, args.count)
    code = 2
    try:
        if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
            collector._fail("pytest_environment_options_refused")
        code = int(pytest.main(["-q", "--durations=20", "tests"], plugins=[collector]))
    except (pytest.UsageError, KeyboardInterrupt, SystemExit) as error:
        collector.collection_errors.append("pytest_raised:" + type(error).__name__)
    try:
        _context(args)
    except (ReceiptError, OSError, subprocess.SubprocessError) as error:
        collector.collection_errors.append("source_context_changed:" + type(error).__name__)
    try:
        _ids(collector.universe, "universe")
        _ids(collector.selected, "selected")
        if collector.raw != collector.universe or collector.finished != collector.selected:
            raise ReceiptError("incomplete_ordered_execution")
        _reports(collector.reports, collector.selected, production=False)
    except ReceiptError as error:
        collector.collection_errors.append(str(error))
    receipt = {
        "schema": SCHEMA, "head": args.head, "run_id": args.run_id,
        "run_attempt": args.attempt, "platform": sys.platform,
        "shard_index": args.index, "shard_count": args.count,
        "universe": collector.universe, "selected": collector.selected,
        "finished": collector.finished, "reports": collector.reports,
        "failed_reports": collector.failed_reports,
        "collection_errors": collector.collection_errors,
        "pytest_exit": code, "session_exit": collector.session_exit,
    }
    _atomic_json(receipt_path, receipt)
    if code:
        return code
    return int(bool(collector.failed_reports or collector.collection_errors
                    or collector.session_exit != 0))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("duplicate_json_key")
        result[key] = value
    return result


def _constant(value):
    raise ReceiptError("nonfinite_json_value")


def _linked(path):
    return path.is_symlink() or path.is_junction()


def _read_directory(args):
    root = Path(args.directory)
    expected = {
        f"windows-pytest-{index}-{args.head}-{args.run_id}-{args.attempt}": index
        for index in range(1, args.count + 1)
    }
    if _linked(root) or not root.is_dir() or {p.name for p in root.iterdir()} != set(expected):
        raise ReceiptError("artifact_directory_population_mismatch")
    receipts = []
    for name, index in expected.items():
        folder = root / name
        filename = f"shard-{index}.json"
        if (_linked(folder) or not folder.is_dir()
                or {p.name for p in folder.iterdir()} != {filename}):
            raise ReceiptError("artifact_file_population_mismatch")
        path = folder / filename
        if _linked(path) or not path.is_file():
            raise ReceiptError("receipt_regular_file_required")
        with path.open(encoding="utf-8") as stream:
            receipt = json.load(stream, object_pairs_hook=_object, parse_constant=_constant)
        if (type(receipt) is not dict or type(receipt.get("shard_index")) is not int
                or receipt["shard_index"] != index):
            raise ReceiptError("artifact_shard_index_mismatch")
        receipts.append(receipt)
    return receipts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("run", "verify"):
        sub = commands.add_parser(command)
        for name in ("head", "run-id", "attempt"):
            sub.add_argument("--" + name, required=True)
        sub.add_argument("--count", required=True, type=int)
        if command == "run":
            sub.add_argument("--index", required=True, type=int)
            sub.add_argument("--receipt", required=True)
        else:
            sub.add_argument("--directory", required=True)
            sub.add_argument("--jobs-result", required=True)
    args = parser.parse_args(argv)
    try:
        _context(args)
        if args.command == "run":
            return _run(args)
        if args.jobs_result != "success":
            raise ReceiptError("shard_jobs_not_successful")
        summary = verify_receipts(
            _read_directory(args), head=args.head, run_id=args.run_id,
            run_attempt=args.attempt, count=args.count,
        )
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as error:
        print("CI pytest refused: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
