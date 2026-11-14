"""Bind successful P0 regression jobs to the exact evidence cohort; not test proof."""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "atlas-brain.p0-ci-context/1"


def make_context(*, head, run_id, run_attempt, platform):
    if type(head) is not str or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ValueError("invalid_head")
    for label, value in (("run_id", run_id), ("run_attempt", run_attempt)):
        if type(value) is not str or re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise ValueError("invalid_" + label)
    if type(platform) is not str or platform not in ("linux", "win32"):
        raise ValueError("invalid_platform")
    return {"schema": SCHEMA, "head": head, "run_id": run_id,
            "run_attempt": run_attempt, "platform": platform}


def source_context(platform):
    context = make_context(head=os.environ.get("P0_REVIEWED_SHA", ""),
        run_id=os.environ.get("GITHUB_RUN_ID", ""),
        run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT", ""), platform=platform)
    if sys.platform != platform:
        raise ValueError("native_platform_mismatch")
    if Path.cwd().resolve() != ROOT:
        raise ValueError("repository_cwd_required")
    result = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT,
        capture_output=True, text=True, check=False, timeout=10)
    if result.returncode or result.stdout.strip() != context["head"]:
        raise ValueError("checked_out_head_mismatch")
    result = subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT,
        capture_output=True, check=False, timeout=10)
    if result.returncode:
        raise ValueError("tracked_source_not_clean")
    return context


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _constant(value):
    raise ValueError("nonfinite_json_value")


def verify_contexts(linux_text, windows_text, *, head, run_id, run_attempt,
                    linux_result, windows_result):
    for result in (linux_result, windows_result):
        if type(result) is not str or result != "success":
            raise ValueError("regression_jobs_not_successful")
    for platform, text in (("linux", linux_text), ("win32", windows_text)):
        expected = make_context(head=head, run_id=run_id, run_attempt=run_attempt,
                                platform=platform)
        if type(text) is not str:
            raise ValueError("invalid_context_json")
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_constant)
        if (type(value) is not dict or set(value) != set(expected)
                or any(type(value[key]) is not type(item) or value[key] != item
                       for key, item in expected.items())):
            raise ValueError("regression_context_mismatch")
    return {"head": head, "run_id": run_id, "run_attempt": run_attempt,
            "platforms": ["linux", "win32"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("check", "record", "verify"):
        sub = commands.add_parser(command)
        if command != "verify":
            sub.add_argument("--platform", choices=("linux", "win32"), required=True)
    args = parser.parse_args(argv)
    try:
        context = source_context(sys.platform if args.command == "verify" else args.platform)
        if args.command == "record":
            encoded = json.dumps(context, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8", newline="\n") as stream:
                stream.write("receipt=" + encoded + "\n")
        elif args.command == "verify":
            summary = verify_contexts(os.environ.get("P0_LINUX_CONTEXT", ""),
                os.environ.get("P0_WINDOWS_CONTEXT", ""), head=context["head"],
                run_id=context["run_id"], run_attempt=context["run_attempt"],
                linux_result=os.environ.get("P0_LINUX_RESULT", ""),
                windows_result=os.environ.get("P0_WINDOWS_RESULT", ""))
            print("P0_REGRESSION_COHORT " + json.dumps(summary, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        print("P0 context refused: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
