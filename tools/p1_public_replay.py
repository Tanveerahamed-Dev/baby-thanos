"""CI-only pinned public-source replay; raw origin unknown and republication held."""
import json
import os
import re
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

try:
    from .privacy import scan
except ImportError:
    from privacy import scan

ROOT = Path(__file__).resolve().parents[1]
PIN = "e62f9467a383997e190e04679d769c5c009e7460"
REPO = "CiscoTestAutomation/genieparser"
PREFIX = "src/genie/libs/parser/iosxe/tests/"
PROFILES = (
    ("brief", "ShowIpInterfaceBrief/cli/equal/golden_output.txt",
     "a00e136b06b045cbe954b0a444364832322aa273", 1661,
     "a07d510ac4b37070c6acfa7e4127292b247749b8544ca003d47fd2ee4fdea29f",
     "show ip interface brief", 21, "complete", 20, 0, 1),
    ("full", "ShowInterfaces/cli/equal/golden_output2_output.txt",
     "16fcc7d22e474b2bf686805db0208d2459339577", 159755,
     "a7c7cd8b9ca402b83bf013e8695374af960be0a287799debef2c67b3b0a87a84",
     "show interfaces", 148, "partial", 0, 21, 127),
)

class StudyRefused(ValueError):
    """Stable refusal; never include input or exception details."""

def need(value):
    if not value:
        raise StudyRefused("refused")

def equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right

def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result

def load(data):
    return json.loads(data, object_pairs_hook=object_pairs, parse_constant=lambda _: need(False))

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise StudyRefused("refused")

def fetch_source(profile):
    url = f"https://raw.githubusercontent.com/{REPO}/{PIN}/{PREFIX}{profile[1]}"
    with build_opener(ProxyHandler({}), NoRedirect()).open(url, timeout=30) as response:
        need(response.status == 200)
        raw = response.read(profile[3] + 1)
    need(type(raw) is bytes and len(raw) == profile[3])
    need(sha256(raw).hexdigest() == profile[4])
    return raw

def summary(manifest, raw, operation):
    need(type(raw) is bytes and type(operation) is str and operation in ("show interfaces", "show ip interface brief"))
    need(type(manifest) is dict and set(manifest) == {"schema", "evidence", "plan", "egress", "steps", "facts"})
    need(equal(manifest["schema"], "atlas-brain.runner-manifest/1"))
    evidence = manifest["evidence"]
    need(type(evidence) is dict and set(evidence) == {"digest", "files"})
    need(type(evidence["digest"]) is str and re.fullmatch(r"[0-9a-f]{64}", evidence["digest"]))
    need(equal(evidence["files"], 1))
    need(equal(manifest["plan"], {"steps": 8, "witness_attempts": 4}))
    need(equal(manifest["egress"], {"parent_denied": 4, "coordinator_denied": 4, "worker_denied": 32, "denied": 40}))
    need(equal(manifest["steps"], [{"denied": 4, "id": f"witness/{i:02d}"} for i in range(8)]))
    facts = manifest["facts"]
    capture = "cap:" + sha256(b"public.txt\0" + raw).hexdigest()
    need(type(facts) is dict and list(facts) == [capture])
    entry = [{"capture": capture, "sha256": sha256(raw).hexdigest()}]
    need(evidence["digest"] == sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest())
    pack = facts[capture]
    need(type(pack) is dict and set(pack) == {"pack", "variant_support", "operation", "parse", "denominator", "coverage", "interfaces"})
    need(equal(pack["pack"], "l1.interface") and equal(pack["variant_support"], "allowlisted"))
    need(equal(pack["operation"], operation) and type(pack["parse"]) is str and pack["parse"] in ("partial", "complete"))
    rows, denominator = pack["interfaces"], pack["denominator"]
    need(type(rows) is list and type(denominator) is dict and set(denominator) == {"scope", "count"})
    need(equal(denominator["scope"], "observed_in_capture"))
    need(type(denominator["count"]) is int and denominator["count"] >= 0 and denominator["count"] == len(rows))
    coverage = pack["coverage"]
    need(type(coverage) is dict and equal(coverage.get("state"), "unknown"))
    verdicts = {"ok": 0, "problem": 0, "unknown": 0}
    projected = [coverage]
    for row in rows:
        need(type(row) is dict and set(row) == {"name", "admin", "oper", "check"})
        projected.extend(row[key] for key in ("name", "admin", "oper"))
        check = row["check"]
        need(type(check) is dict and {"id", "state", "next_evidence"} <= set(check) <= {"id", "state", "next_evidence", "reason"})
        need(equal(check["id"], "l1.interface.admin_up_oper_down"))
        need(type(check["state"]) is str and check["state"] in verdicts and type(check["next_evidence"]) is list)
        verdicts[check["state"]] += 1
    for fact in projected:
        need(type(fact) is dict and type(fact.get("state")) is str and fact["state"] in ("known", "unknown"))
        refs = fact.get("evidence")
        need(type(refs) is list and bool(refs))
        for ref in refs:
            need(type(ref) is dict and ref.get("capture") == capture)
            if ref.get("locator") == "whole_capture":
                need(set(ref) == {"capture", "sha256", "locator"})
                excerpt = raw
            else:
                need(set(ref) == {"capture", "sha256", "locator", "start", "end"} and ref["locator"] == "bytes")
                start, end = ref["start"], ref["end"]
                need(type(start) is int and type(end) is int and 0 <= start < end <= len(raw))
                excerpt = raw[start:end]
            need(type(ref["sha256"]) is str and ref["sha256"] == sha256(excerpt).hexdigest())
    return {"captures": 1, "parse": pack["parse"], "observed": len(rows), "coverage": "unknown", "verdicts": verdicts}

def report(commit):
    profiles = []
    for name, path, blob, size, digest, operation, count, parse, ok, problem, unknown in PROFILES:
        profiles.append({"profile": name, "source_path": PREFIX + path, "git_blob": blob,
                         "bytes": size, "sha256": digest, "operation": operation, "captures": 1,
                         "parse": parse, "observed": count, "coverage": "unknown",
                         "verdicts": {"ok": ok, "problem": problem, "unknown": unknown}})
    return {"schema": "atlas-brain.p1-public-replay/1", "engine_commit": commit, "source_repository": REPO, "source_commit": PIN, "source_license": "Apache-2.0",
            "origin": "unknown", "model": "unknown", "train": "unknown", "capture_authenticity": "unknown", "raw_republication": "held",
            "format_floor": False, "phase_exit": False, "truth": "not_measured",
            "workers": [1, 4, 4], "byte_identical": True, "input_unchanged": True, "profiles": profiles}

def screen(value, commit):
    need(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit))
    need(equal(value, report(commit)))
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    need(not scan(data, "public-replay-aggregate", []))
    return data

def bounded(path, limit=8 * 1024 * 1024):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    need(len(data) <= limit)
    return data

def engine_commit(commit):
    for args in (["rev-parse", "HEAD"], ["diff", "--quiet", "HEAD", "--"]):
        result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=False, timeout=15)
        need(result.returncode == 0)
        if args[0] == "rev-parse":
            need(result.stdout.strip() == commit.encode("ascii"))

def replay(profile, directory, raw):
    need(type(raw) is bytes and len(raw) == profile[3] and sha256(raw).hexdigest() == profile[4])
    source = directory / "input"
    source.mkdir(parents=True)
    capture = source / "public.txt"
    capture.write_bytes(raw)
    outputs = []
    for index, workers in enumerate((1, 4, 4)):
        out = directory / f"out-{index}"
        result = subprocess.run([sys.executable, "-B", "-m", "atlas_brain.runner", "--evidence", str(source),
                                 "--out", str(out), "--workers", str(workers)], cwd=ROOT,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, capture_output=True, check=False, timeout=90)
        need(result.returncode == 0 and result.stdout.strip() == b"runner: ok egress_denied=40" and not result.stderr)
        need(bounded(capture, profile[3]) == raw)
        outputs.append((bounded(out / "MANIFEST.json"), bounded(out / "SUMMARY.txt")))
    need(outputs[0] == outputs[1] == outputs[2])
    expected = {key: report("0" * 40)["profiles"][PROFILES.index(profile)][key] for key in ("captures", "parse", "observed", "coverage", "verdicts")}
    need(equal(summary(load(outputs[0][0]), raw, profile[5]), expected))

def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ("run", "publish"))
    need(os.environ.get("GITHUB_ACTIONS") == "true")
    commit = os.environ.get("EXPECTED_HEAD", "")
    need(re.fullmatch(r"[0-9a-f]{40}", commit))
    location = os.environ.get("RUNNER_TEMP", "")
    need(bool(location) and Path(location).is_absolute())
    temp = Path(location).resolve(strict=True)
    need(temp.is_dir() and not temp.is_relative_to(ROOT) and not ROOT.is_relative_to(temp))
    target = temp / "p1-public-report.json"
    need(not target.is_symlink())
    if sys.argv[1] == "publish":
        sys.stdout.buffer.write(screen(load(bounded(target, 16384)), commit))
        return
    need(not target.exists())
    engine_commit(commit)
    staged = [fetch_source(profile) for profile in PROFILES]
    with tempfile.TemporaryDirectory(prefix="p1-public-", dir=temp) as quarantine:
        for profile, raw in zip(PROFILES, staged):
            replay(profile, Path(quarantine) / profile[0], raw)
    engine_commit(commit)
    data = screen(report(commit), commit)
    with target.open("xb") as stream:
        stream.write(data)

if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("P1 public replay refused", file=sys.stderr)
        raise SystemExit(1)
