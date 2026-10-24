"""Read-only audit of complete exact-SHA workflow receipts; defaults to push events."""
import argparse
import base64
import hashlib
import json
import re
import subprocess
from pathlib import Path

REPO = "Tanveerahamed-Dev/atlas-brain-staging"


class ReceiptReadError(ValueError):
    """Refusal evidence from the same collection, never a replacement receipt."""

    def __init__(self, reason, evidence):
        super().__init__(reason)
        self.evidence = evidence


def workflow_paths(tree):
    if tree.get("truncated") is not False:
        raise ValueError("truncated source registry")
    return {r["path"] for r in tree["tree"] if r["type"] == "blob"
            and re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", r["path"])}


def step_scalar(value):
    if not isinstance(value, str):
        raise TypeError("unsupported step scalar")
    if value.startswith('"'):
        value = json.loads(value)
    elif value.startswith("'"):
        if not value.endswith("'"):
            raise ValueError("unsupported step scalar")
        value = value[1:-1].replace("''", "'")
    else:
        value = value.split(" #", 1)[0].rstrip()
    if not isinstance(value, str) or not value.strip() or "${{" in value or value in {"|", ">", "|-", ">-"}:
        raise ValueError("unresolved step display identity")
    return value.lstrip().splitlines()[0]


def check_steps(text):
    """Closed step mappings with ordered, literal runner display identities."""
    fields = None
    required = []
    def finish():
        kinds = set(fields or {}) & {"run", "uses"}
        if len(kinds) != 1:
            raise ValueError("step must have exactly one run or uses command")
        kind = next(iter(kinds))
        if fields[kind] is None or ("name" in fields and fields["name"] is None):
            raise ValueError("missing source step command or name")
        name = step_scalar(fields["name"]) if "name" in fields else "Run " + step_scalar(fields[kind])
        if (name in {"Set up job", "Complete job"} or name.startswith(("Post ", "Pre "))
                or any(s["name"] == name for s in required)):
            raise ValueError("source step collides with runner lifecycle identity")
        required.append({"name": name, "kind": kind})
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("      - "):
            if fields is not None:
                finish()
            match = re.fullmatch(r"      - (name|id|uses|run): (.+)", line)
            if match is None:
                raise ValueError("unsupported source step declaration")
            fields = {match[1]: match[2]}
        elif line.startswith("        ") and not line.startswith("          "):
            match = re.fullmatch(r"        (name|id|uses|run|with|env|shell|working-directory|timeout-minutes):(?: (.+))?", line)
            if match is None or fields is None or match[1] in fields:
                raise ValueError("unapproved or unsupported source step directive")
            fields[match[1]] = match[2]
        elif not line.startswith("          "):
            raise ValueError("unsupported source step indentation")
    finish()
    return required


def expected_jobs(data, path, event, with_steps=False):
    """Closed workflow header grammar; unknown matrices/names/conditions refuse."""
    blob = data["sources"][path]
    raw = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    entry = next(r for r in data["tree"]["tree"] if r["path"] == path)
    if blob["encoding"] != "base64" or digest != blob["sha"] or digest != entry["sha"]:
        raise ValueError("workflow blob does not match exact source tree")
    text = raw.decode("utf-8")
    if "\t" in text or re.findall(r"(?m)^jobs:.*$", text) != ["jobs:"]:
        raise ValueError("unsupported jobs declaration")
    blocks = re.split(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):\n", text.split("\njobs:\n", 1)[1])
    if blocks[0] or len(blocks) == 1:
        raise ValueError("empty or unsupported job registry")
    names = {}
    for job, body in zip(blocks[1::2], blocks[2::2], strict=True):
        header, steps = body.split("    steps:\n", 1)
        header = re.sub(r"(?m)^ *#.*\n", "", header)
        pattern = (r"(?:    name: (.+)\n)?(?:    strategy:\n      fail-fast: false\n      matrix:\n        os: (.+)\n)?"
                   r"    runs-on: (.+)\n    timeout-minutes: [1-9][0-9]*(?: #[^\n]*)?\n")
        match = re.fullmatch(pattern, header)
        if not match:
            raise ValueError("unsupported job header or steps layout")
        required_steps = check_steps(steps)
        label, matrix, runner = match.groups()
        if event == "workflow_dispatch" and label is None:
            raise ValueError("manual job lacks an event-bound context name")
        if label is not None:
            label_match = re.fullmatch(r"\$\{\{ github.event_name == 'workflow_dispatch' && 'manual-([A-Za-z0-9_-]+)'"
                                      r" \|\| '([A-Za-z0-9_-]+)' \}\}( \(\$\{\{ matrix.os \}\}\))?", label)
            if not label_match or label_match[1] != job or label_match[2] != job or bool(label_match[3]) != bool(matrix):
                raise ValueError("unbound or colliding manual job context")
            job = ("manual-" if event == "workflow_dispatch" else "") + job
        if matrix is None:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", runner):
                raise ValueError("unresolved runner")
            if job in names:
                raise ValueError("duplicate configured job")
            names[job] = required_steps
            continue
        if runner != "${{ matrix.os }}":
            raise ValueError("unbound matrix runner")
        if matrix.startswith("${{"):
            expression = re.fullmatch(r"\$\{\{ fromJSON\(\(github.event_name == 'push' \|\| github.event_name == 'schedule'"
                                      r"( \|\| github.event_name == 'workflow_dispatch')?"
                                      r" \|\| vars.BOOTSTRAP_PR_LINUX_ONLY == 'false'\) && '(\[[^']+\])'"
                                      r" \|\| '(\[[^']+\])'\) \}\}", matrix)
            if not expression or not (event in {"push", "schedule"} or (event == "workflow_dispatch" and expression[1])):
                raise ValueError("unresolved matrix expression for event")
            values = json.loads(expression[2])
        else:
            if not re.fullmatch(r"\[[A-Za-z0-9_.-]+(?:, [A-Za-z0-9_.-]+)*\]", matrix):
                raise ValueError("unsupported matrix")
            values = matrix[1:-1].split(", ")
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
            raise ValueError("invalid matrix values")
        expanded = [f"{job} ({value})" for value in values]
        if len(set(expanded)) != len(expanded) or any(name in names for name in expanded):
            raise ValueError("duplicate configured jobs")
        names.update({name: required_steps for name in expanded})
    return names if with_steps else sorted(names)


def verify_steps(required, steps):
    if not isinstance(steps, list) or not steps or any(
        not isinstance(s, dict) or s.get("status") != "completed" or s.get("conclusion") != "success"
        or type(s.get("number")) is not int or s["number"] < 1 or not isinstance(s.get("name"), str) for s in steps
    ):
        raise ValueError("missing or non-success step receipt")
    by_number = {s["number"]: s for s in steps}
    if len(by_number) != len(steps) or by_number.get(1, {}).get("name") != "Set up job":
        raise ValueError("duplicate step ordinal or missing runner setup")
    for number, source in enumerate(required, 2):
        if by_number.get(number, {}).get("name") != source["name"]:
            raise ValueError("missing or mismatched source-required step")
    posts = ["Post " + s["name"] for s in required if s["kind"] == "uses"]
    complete = 0
    for number, observed in by_number.items():
        if number <= len(required) + 1:
            continue
        if observed["name"] == "Complete job":
            complete += 1
        elif observed["name"] in posts:
            posts.remove(observed["name"])
        else:
            raise ValueError("unexpected runner or source step")
    if complete != 1:
        raise ValueError("missing or ambiguous runner completion")


def select_runs(data, sha, event):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("unbound SHA")
    paths = workflow_paths(data["tree"])
    catalog = {r["path"]: r for r in data["catalog"]}
    if not paths or any(p not in catalog or catalog[p]["state"] != "active" for p in paths):
        raise ValueError("empty, missing or disabled workflow registry")
    rows = [r for r in data["catalog"] if r["path"] in paths]
    if len(rows) != len(paths) or any(type(r["id"]) is not int or r["id"] < 1 for r in rows):
        raise ValueError("duplicate or invalid workflow registry identity")
    if len({catalog[p]["id"] for p in paths}) != len(paths):
        raise ValueError("ambiguous workflow identities")
    selected = {}
    for path in sorted(paths):
        rows = [r for r in data["runs"] if r["workflow_id"] == catalog[path]["id"]
                and r["head_sha"] == sha and r["event"] == event]
        if not rows:
            raise ValueError(f"missing exact-SHA {event} receipt: {path}")
        if any(any(type(r[k]) is not int or r[k] < 1 for k in ("id", "workflow_id", "run_number", "run_attempt")) for r in rows):
            raise ValueError("invalid workflow run identity")
        run = max(rows, key=lambda r: (r["run_number"], r["run_attempt"]))
        if run["status"] != "completed" or run["conclusion"] != "success":
            raise ValueError(f"latest workflow is not successful: {path}")
        selected[path] = run
    return selected


def verify(data, sha, event):
    selected = select_runs(data, sha, event)
    count = 0
    expected = {}
    for path, run in selected.items():
        jobs = data["jobs"][str(run["id"])]
        required = expected_jobs(data, path, event, with_steps=True)
        expected[path] = sorted(required)
        if sorted(j["name"] for j in jobs) != expected[path]:
            raise ValueError(f"missing, duplicate or unexpected configured jobs: {path}")
        if not jobs or any(j["status"] != "completed" or j["conclusion"] != "success" for j in jobs):
            raise ValueError(f"missing, failed, pending, skipped or cancelled jobs: {path}")
        for job in jobs:
            verify_steps(required[job["name"]], job.get("steps"))
        count += len(jobs)
    return {"verified": True, "sha": sha, "event": event, "workflow_count": len(selected),
            "job_count": count, "run_ids": [r["id"] for r in selected.values()], "expected_jobs": expected}


def verify_native(data, sha):
    """Require native main jobs and their actual Actions check records, ignoring manual siblings."""
    result = verify(data, sha, "push")
    identities, check_ids = set(), []
    for path, run in select_runs(data, sha, "push").items():
        ties = [r for r in data["runs"] if r["workflow_id"] == run["workflow_id"]
                and r["head_sha"] == sha and r["event"] == "push"
                and (r["run_number"], r["run_attempt"]) == (run["run_number"], run["run_attempt"])]
        if len(ties) != 1 or run["head_branch"] != "main" or run["path"] != path:
            raise ValueError("ambiguous or non-main native run identity")
        for job in data["jobs"][str(run["id"])]:
            if (type(job["id"]) is not int or job["id"] < 1 or job["id"] in identities
                    or job["run_id"] != run["id"] or job["head_sha"] != sha):
                raise ValueError("unbound native job identity")
            identities.add(job["id"])
            match = re.fullmatch(r"https://api\.github\.com/repos/" + re.escape(REPO)
                                 + r"/check-runs/([1-9][0-9]*)", job["check_run_url"])
            if match is None or int(match[1]) in check_ids:
                raise ValueError("unbound native check URL")
            identity = int(match[1])
            rows = [c for c in data["checks"] if c["id"] == identity]
            if len(rows) != 1 or any((rows[0]["app"]["id"] != 15368, rows[0]["head_sha"] != sha,
                                      rows[0]["name"] != job["name"], rows[0]["status"] != "completed",
                                      rows[0]["conclusion"] != "success")):
                raise ValueError("missing, ambiguous or non-success actual Actions check")
            check_ids.append(identity)
    return {**result, "check_ids": check_ids}


def github(endpoint, key=None, evidence=None):
    observation = {"endpoint": endpoint, "key": key, "outcome": "started", "exit_code": None,
                   "http_status": "not captured by this transport"}
    if evidence is not None:
        evidence.append(observation)
    command = ["gh", "api", f"repos/{REPO}/{endpoint}"]
    if key:
        command.extend(["--paginate", "--slurp"])
    try:
        raw = subprocess.check_output(command, encoding="utf-8")
    except subprocess.CalledProcessError as error:
        observation.update(outcome="process_error", exit_code=error.returncode)
        raise
    observation["exit_code"] = 0
    try:
        pages = json.loads(raw)
    except ValueError:
        observation["outcome"] = "invalid_json"
        raise
    observation["outcome"] = "decoded"
    if not key and (not isinstance(pages, dict) or endpoint.startswith("git/blobs/")
                    and not isinstance(pages.get("content"), str)):
        observation["outcome"] = "invalid_shape"
        raise ValueError("invalid unpaged response object: " + endpoint)
    if key:
        refusal = "incomplete or inconsistent listing: " + endpoint
        if (not isinstance(pages, list) or not pages
                or any(not isinstance(page, dict) or not isinstance(page.get(key), list) for page in pages)):
            observation["outcome"] = "incomplete_listing"
            raise ValueError(refusal)
        observation["pages"] = [{"total_count": page.get("total_count") if type(page.get("total_count")) is int else None,
                                 "returned_count": len(page[key])} for page in pages]
        totals = [page.get("total_count") for page in pages]
        rows = [row for page in pages for row in page[key]]
        identities = [row.get("id") if isinstance(row, dict) else None for row in rows]
        if (any(type(total) is not int or total < 0 for total in totals) or len(set(totals)) != 1
                or len(rows) != totals[0] or any(type(identity) is not int or identity < 1 for identity in identities)
                or len(set(identities)) != len(identities)):
            observation["outcome"] = "incomplete_listing"
            raise ValueError(refusal)
        return rows
    return pages


def collect(sha, event, with_checks=False):
    evidence = {"sha": sha, "event": event, "queries": [], "selection": []}
    def read(endpoint, key=None):
        return github(endpoint, key, evidence["queries"])
    try:
        data = {"tree": read(f"git/trees/{sha}?recursive=1"),
                "catalog": read("actions/workflows?per_page=100", "workflows"),
                "runs": read(f"actions/runs?head_sha={sha}&per_page=100", "workflow_runs")}
        if any(row.get("head_sha") != sha for row in data["runs"]):
            raise ValueError("wrong-subject row in exact-SHA workflow run listing")
        for path in sorted(workflow_paths(data["tree"])):
            identities = [r["id"] for r in data["catalog"] if r["path"] == path]
            workflow = [r for r in data["runs"] if r["workflow_id"] in identities]
            subject = [r for r in workflow if r["head_sha"] == sha]
            evidence["selection"].append({"path": path, "catalog_ids": identities,
                                          "workflow_count": len(workflow), "sha_count": len(subject),
                                          "exact_count": sum(r["event"] == event for r in subject)})
        selected = select_runs(data, sha, event)
        entries = {r["path"]: r for r in data["tree"]["tree"]}
        data["sources"] = {p: read(f"git/blobs/{entries[p]['sha']}") for p in selected}
        data["jobs"] = {str(r["id"]): read(f"actions/runs/{r['id']}/jobs?filter=latest&per_page=100", "jobs")
                        for r in selected.values()}
        if with_checks:
            data["checks"] = read(f"commits/{sha}/check-runs?per_page=100", "check_runs")
        data["retrieval_evidence"] = evidence
        return data
    except (KeyError, TypeError, ValueError, IndexError, OSError, subprocess.CalledProcessError) as error:
        raise ReceiptReadError(str(error), evidence) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--event", choices=("push", "schedule", "workflow_dispatch"), default="push")
    parser.add_argument("--snapshot", type=Path, help="Supplied unauthenticated self-test snapshot; no live evidence claim")
    args = parser.parse_args()
    data = None
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
            raise ValueError("exact SHA required")
        if args.snapshot:
            data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        else:
            data = collect(args.sha, args.event)
        result = verify(data, args.sha, args.event)
        result["source"] = "supplied snapshot (not authenticated)" if args.snapshot else "GitHub REST"
        if not args.snapshot:
            result["retrieval_evidence"] = data["retrieval_evidence"]
        print(json.dumps(result, sort_keys=True))
        return 0
    except (KeyError, TypeError, ValueError, IndexError, OSError, subprocess.CalledProcessError) as error:
        trace = error.evidence if isinstance(error, ReceiptReadError) else (
            data.get("retrieval_evidence") if isinstance(data, dict) and not args.snapshot else None)
        evidence = {"retrieval_evidence": trace} if trace is not None else {}
        print(json.dumps({"verified": False, "sha": args.sha, "event": args.event, "reason": str(error), **evidence}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
