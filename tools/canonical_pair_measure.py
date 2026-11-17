"""Hosted actual-tree compiler pairs; no copied encoder, profiling time or speed gate."""
import cProfile
import io
import json
import os
import pstats
import subprocess
import sys
import tarfile
import time
from dataclasses import asdict, fields
from hashlib import sha1, sha256
from pathlib import Path, PurePosixPath

BASELINE = "890a974ee3a2d156f7cc3d6c1c73226fc4470daa"
CANDIDATE = "f3f271d14bfcb947621d0fb3b5e3a8ccff3c29b6"
BASE_CODEC = "640c5ccbce24e4e962960313f1acefe36b51e836"
CANDIDATE_CODEC = "0ad0b0e961fad342714f49238f05122790c1c9ed"
CODEC = "atlas_brain/contract/canonical.py"
GROUPS, PAIRS = 32, 8
PHASES = (
    ("compile_packs", "atlas_brain/model/pack_registration.py"),
    ("compile_mixed_profile", "atlas_brain/packs/l3/fhrp/mixed_profile.py"),
    ("compile_root_mixed_profile", "atlas_brain/packs/l3/fhrp/root_mixed_profile.py"),
    ("root_declaration", "atlas_brain/packs/l2/stp/build.py"),
    ("canonical", CODEC), ("_encode", CODEC),
)


def blob(raw):
    return sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def worker(root, expected_codec, mode):
    assert tuple(sys.version_info[:3]) == (3, 14, 8) and sys.implementation.name == "cpython"
    assert (root / ".python-version").read_text().strip() == "3.14.8"
    assert blob((root / CODEC).read_bytes()) == expected_codec
    sys.path.insert(0, str(root))
    from atlas_brain.contract import canonical as codec
    from atlas_brain.model import pack_registration as registration
    from atlas_brain.packs.l3.fhrp import mixed_profile as mixed
    from atlas_brain.packs.l3.fhrp import root_mixed_profile as root_profile
    assert Path(codec.__file__).resolve() == root / CODEC
    assert Path(registration.__file__).resolve() == root / "atlas_brain/model/pack_registration.py"
    def group():
        return (registration.compile_packs(root_profile.DECLARATIONS),
            mixed.compile_mixed_profile(), root_profile.compile_root_mixed_profile())
    def view(values):
        result = []
        for value in values:
            assert type(value) is registration.CompiledPackSet
            assert tuple(field.name for field in fields(value)) == (
                "catalogue_bytes", "registration_bytes", "registration_sha256", "steps", "operations")
            assert sha256(value.registration_bytes).hexdigest() == value.registration_sha256
            assert json.loads(value.registration_bytes)["catalogue_sha256"] == sha256(value.catalogue_bytes).hexdigest()
            result.append({"catalogue_hex": value.catalogue_bytes.hex(),
                "registration_hex": value.registration_bytes.hex(), "registration_sha256": value.registration_sha256,
                "steps": [asdict(step) for step in value.steps], "operations": [asdict(item) for item in value.operations]})
        return result
    expected = group()
    expected_view = view(expected)
    phase_counts, elapsed = None, None
    if mode == "validate":
        profiler = cProfile.Profile()
        current = profiler.runcall(group)
        stats = pstats.Stats(profiler).stats
        phase_counts = {}
        for name, path in PHASES:
            matches = [item[1] for (filename, _line, function), item in stats.items()
                if function == name and Path(filename).resolve() == root / path]
            assert len(matches) == 1 and type(matches[0]) is int and matches[0] > 0
            phase_counts[name] = matches[0]
        groups = (current,)
    else:
        assert mode == "sample" and sys.getprofile() is None and sys.gettrace() is None
        started = time.perf_counter_ns()
        groups = tuple(group() for _ in range(GROUPS))
        elapsed = time.perf_counter_ns() - started
        assert type(elapsed) is int and elapsed > 0
    previous = expected
    for current in groups:
        assert view(current) == expected_view
        assert all(value is not original and value is not prior
            for value, original, prior in zip(current, expected, previous, strict=True))
        previous = current
    return {"outputs": expected_view, "phase_counts": phase_counts, "sample_ns": elapsed,
        "python": list(sys.version_info[:3]), "platform": sys.platform}


def execute(argv, cwd, deadline):
    remaining = deadline - time.monotonic()
    assert remaining > 0
    environment = {key: value for key, value in os.environ.items()
        if key not in ("GH_TOKEN", "GITHUB_TOKEN", "PYTHONPATH", "PYTHONSTARTUP")}
    try:
        return subprocess.run(argv, cwd=cwd, env=environment,
            capture_output=True, check=True, timeout=remaining).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        sys.stderr.buffer.write(error.stdout or b"")
        sys.stderr.buffer.write(error.stderr or b"")
        raise


def git(repo, deadline, *args):
    return execute(["git", "--no-optional-locks", "-C", str(repo), *args], repo, deadline)


def export(repo, revision, target, deadline):
    lines = git(repo, deadline, "ls-tree", "-r", "--full-tree", revision, "--",
        "atlas_brain", ".python-version").decode("utf-8").splitlines()
    expected = {}
    for line in lines:
        metadata, name = line.split("\t")
        mode, kind, identity = metadata.split()
        assert mode in ("100644", "100755") and kind == "blob"
        expected[name] = identity
    raw = git(repo, deadline, "archive", "--format=tar", revision, "atlas_brain", ".python-version")
    assert 0 < len(raw) <= 16 * 1024 * 1024 and 0 < len(expected) <= 512
    target.mkdir()
    actual = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for entry in archive.getmembers():
            name = PurePosixPath(entry.name)
            assert not name.is_absolute() and ".." not in name.parts
            assert entry.name == ".python-version" or name.parts[0] == "atlas_brain"
            if entry.isdir():
                continue
            assert entry.isfile() and 0 <= entry.size <= 2 * 1024 * 1024
            assert entry.name in expected and entry.name not in actual
            stream = archive.extractfile(entry)
            assert stream is not None
            data = stream.read()
            assert blob(data) == expected[entry.name]
            path = target.joinpath(*name.parts)
            assert path.resolve().is_relative_to(target.resolve())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            actual[entry.name] = expected[entry.name]
    assert actual == expected
    return sha256(wire(actual).encode("ascii")).hexdigest()


def measure(repo, temp):
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert tuple(sys.version_info[:3]) == (3, 14, 8) and sys.implementation.name == "cpython"
    deadline = time.monotonic() + 75
    assert Path(git(repo, deadline, "rev-parse", "--show-toplevel").decode().strip()).resolve() == repo
    assert git(repo, deadline, "rev-parse", "--is-shallow-repository").strip() == b"false"
    assert git(repo, deadline, "status", "--porcelain", "--untracked-files=no") == b""
    head = git(repo, deadline, "rev-parse", "HEAD").decode().strip()
    for revision in (BASELINE, CANDIDATE):
        git(repo, deadline, "cat-file", "-e", revision + "^{commit}")
    assert git(repo, deadline, "show", "-s", "--format=%P", CANDIDATE).decode().strip() == BASELINE
    changed = git(repo, deadline, "diff", "--name-only", BASELINE, CANDIDATE).decode().splitlines()
    assert changed == [CODEC], "unexpected_pair_diff"
    sides = {}
    script = Path(__file__).resolve()
    for label, revision, expected in (("baseline", BASELINE, BASE_CODEC), ("candidate", CANDIDATE, CANDIDATE_CODEC)):
        tree = git(repo, deadline, "rev-parse", revision + "^{tree}").decode().strip()
        engine = git(repo, deadline, "rev-parse", revision + ":atlas_brain").decode().strip()
        assert git(repo, deadline, "rev-parse", revision + ":" + CODEC).decode().strip() == expected
        source = temp / label
        digest = export(repo, revision, source, deadline)
        sides[label] = {"commit": revision, "tree": tree, "engine_tree": engine,
            "canonical_blob": expected, "export_sha256": digest, "root": source}
    def call(label, mode):
        side = sides[label]
        raw = execute([sys.executable, "-I", "-B", str(script), "--worker",
            str(side["root"]), side["canonical_blob"], mode], repo, deadline)
        value = json.loads(raw)
        assert value["python"] == [3, 14, 8] and value["platform"] == sys.platform
        return value
    validation = {label: call(label, "validate") for label in sides}
    assert validation["baseline"]["outputs"] == validation["candidate"]["outputs"]
    assert validation["baseline"]["phase_counts"] == validation["candidate"]["phase_counts"]
    expected_outputs = validation["baseline"]["outputs"]
    record = {"schema": "atlas-brain.canonical-ascii-pairs/1",
        "scope": "pinned_actual_tree_fresh_compilers_diagnostic_not_420",
        "validation_head": head, "platform": sys.platform, "python": list(sys.version_info[:3]),
        "implementation": sys.implementation.name, "version": sys.version,
        "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "groups_per_sample": GROUPS, "pairs": [], "timing_profiled": False,
        "phase_verification": "separate_untimed_cprofile_one_group_per_side",
        "current_engine_matches_candidate": git(repo, deadline, "rev-parse", "HEAD:atlas_brain").decode().strip()
            == sides["candidate"]["engine_tree"]}
    record["measurement_relation"] = ("same_engine_as_validation_head"
        if record["current_engine_matches_candidate"] else "historical_pair_only")
    for label, side in sides.items():
        record[label] = {key: value for key, value in side.items() if key != "root"}
        record[label]["outputs"] = sha256(wire(validation[label]["outputs"]).encode("ascii")).hexdigest()
        record[label]["phase_counts"] = validation[label]["phase_counts"]
    try:
        for pair in range(PAIRS):
            order = ("baseline", "candidate") if pair % 2 == 0 else ("candidate", "baseline")
            sample = {"order": list(order), "samples_ns": {}}
            record["pairs"].append(sample)
            for label in order:
                value = call(label, "sample")
                assert value["outputs"] == expected_outputs and value["phase_counts"] is None
                assert type(value["sample_ns"]) is int and value["sample_ns"] > 0
                sample["samples_ns"][label] = value["sample_ns"]
    finally:
        record["checkout_unchanged"] = False
        try:
            if time.monotonic() < deadline:
                record["checkout_unchanged"] = git(repo, deadline,
                    "status", "--porcelain", "--untracked-files=no") == b""
        except (subprocess.SubprocessError, AssertionError) as error:
            record["checkout_check_error"] = type(error).__name__
        print(wire(record))
    assert record["checkout_unchanged"]


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        assert len(sys.argv) == 5
        print(wire(worker(Path(sys.argv[2]).resolve(), sys.argv[3], sys.argv[4])))
    else:
        assert len(sys.argv) == 3
        measure(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
