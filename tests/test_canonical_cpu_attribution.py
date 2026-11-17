"""Baseline-only compiler attribution, not an encoder variant or performance qualification.
Self/cumulative times stay separate; opaque C work may be charged to a Python caller.
"""
import cProfile
import json
import math
import os
import pstats
import sys
import time
from hashlib import sha256
from pathlib import Path

from atlas_brain.contract.canonical import SAFE
from atlas_brain.model import pack_registration
from atlas_brain.packs.l3.fhrp import mixed_profile as mixed
from atlas_brain.packs.l3.fhrp import root_mixed_profile as root

REPO = Path(__file__).resolve().parents[1]
PHASES = ("compile_packs", "compile_mixed_profile", "compile_root_mixed_profile", "root_declaration")
METRICS = (
    ("compiler.compile_packs", "atlas_brain/model/pack_registration.py", "compile_packs"),
    ("codec.canonical", "atlas_brain/contract/canonical.py", "canonical"),
    ("codec.encode", "atlas_brain/contract/canonical.py", "_encode"),
    ("codec.utf16_key_lambda", "atlas_brain/contract/canonical.py", "<lambda>"),
    ("stdlib.typing.cast", "/typing.py", "cast"),
    ("stdlib.json.dumps", "/json/__init__.py", "dumps"),
    ("stdlib.json.encoder_init", "/json/encoder.py", "__init__"),
    ("stdlib.json.encoder_encode", "/json/encoder.py", "encode"),
    ("stdlib.json.encoder_iterencode", "/json/encoder.py", "iterencode"),
    ("builtin.regex_fullmatch", "~", "method 'fullmatch' of 're.Pattern'"),
    ("builtin.str_encode_all_encodings", "~", "method 'encode' of 'str'"),
    ("builtin.str_join_all_compiler_uses", "~", "method 'join' of 'str'"),
    ("builtin.sorted_all_compiler_uses", "~", "builtins.sorted"),
    ("json.c_make_encoder", "~", "_json.make_encoder"),
    ("json.c_encode_basestring", "~", "_json.encode_basestring>"),
    ("json.c_encode_basestring_ascii", "~", "_json.encode_basestring_ascii>"),
)


def project_path(filename):
    path = Path(filename)
    if not path.is_relative_to(REPO):
        return None
    relative = path.relative_to(REPO)
    return relative.as_posix() if relative.parts and relative.parts[0] in ("atlas_brain", "tools") and ".." not in relative.parts and path.suffix == ".py" else None


def matches(key, filename, function):
    actual_file, _line, actual_function = key
    if filename == "~":
        return actual_file == "~" and function in actual_function
    if filename.startswith("atlas_brain/"):
        return project_path(actual_file) == filename and actual_function == function
    return actual_file.replace("\\", "/").endswith(filename) and actual_function == function


def measured(stats):
    primitive, calls, own, cumulative = stats[:4]
    assert type(primitive) is int and type(calls) is int and 0 <= primitive <= calls
    assert all(type(number) in (int, float) and math.isfinite(number) and number >= 0 for number in (own, cumulative))
    return {"primitive_calls": primitive, "calls": calls,
        "self_ms": round(own * 1000, 6), "cumulative_ms": round(cumulative * 1000, 6)}


def group():
    return (pack_registration.compile_packs(root.DECLARATIONS),
        mixed.compile_mixed_profile(), root.compile_root_mixed_profile())


def verify(values, expected, previous):
    assert len(values) == len(expected) == len(previous) == 3
    for value, wanted, prior in zip(values, expected, previous, strict=True):
        assert type(value) is pack_registration.CompiledPackSet
        assert value == wanted and value is not wanted and value is not prior
        assert value.steps == wanted.steps and value.operations == wanted.operations
        assert value.registration_sha256 == sha256(value.registration_bytes).hexdigest()
        assert json.loads(value.registration_bytes)["catalogue_sha256"] == sha256(value.catalogue_bytes).hexdigest()


def phase_counts(stats):
    return {name: sum(value[1] for key, value in stats.items()
        if key[2] == name and project_path(key[0]) is not None) for name in PHASES}


def inventory(values):
    counts = dict.fromkeys(("wire_objects", "dicts", "lists", "keys", "safe_ascii_keys",
        "value_strings", "safe_ascii_values", "integers", "booleans", "nulls"), 0)
    def walk(value):
        if type(value) is dict:
            counts["dicts"] += 1
            for key, child in value.items():
                assert type(key) is str
                counts["keys"] += 1
                counts["safe_ascii_keys"] += int(SAFE.fullmatch(key) is not None)
                walk(child)
        elif type(value) is list:
            counts["lists"] += 1
            for child in value:
                walk(child)
        elif type(value) is str:
            counts["value_strings"] += 1
            counts["safe_ascii_values"] += int(SAFE.fullmatch(value) is not None)
        elif type(value) is bool:
            counts["booleans"] += 1
        elif type(value) is int:
            counts["integers"] += 1
        else:
            assert value is None
            counts["nulls"] += 1
    for value in values:
        for raw in (value.catalogue_bytes, value.registration_bytes):
            counts["wire_objects"] += 1
            walk(json.loads(raw))
    assert counts["wire_objects"] == 6 and all(type(value) is int and value >= 0 for value in counts.values())
    return counts


def test_baseline_compiler_costs_are_attributed_without_changing_behavior(capsys):
    expected = previous = group()
    profiler = cProfile.Profile()
    last_counts = dict.fromkeys(PHASES, 0)
    wanted_delta, walls = None, []
    for _ in range(32):
        started = time.perf_counter()
        values = profiler.runcall(group)
        elapsed = (time.perf_counter() - started) * 1000
        assert math.isfinite(elapsed) and elapsed >= 0
        walls.append(elapsed)
        verify(values, expected, previous)
        current = phase_counts(pstats.Stats(profiler).stats)
        delta = {name: current[name] - last_counts[name] for name in PHASES}
        assert all(type(value) is int and value > 0 for value in delta.values())
        if wanted_delta is None:
            wanted_delta = delta
        assert delta == wanted_delta
        previous, last_counts = values, current
    verify(group(), expected, previous)
    stats = pstats.Stats(profiler).stats
    functions = {}
    for label, filename, function in METRICS:
        found = [value for key, value in stats.items() if matches(key, filename, function)]
        assert len(found) <= 1
        functions[label] = {"state": "unobserved"} if not found else {"state": "observed", **measured(found[0])}
    assert all(functions[name]["state"] == "observed" for name in (
        "compiler.compile_packs", "codec.canonical", "codec.encode", "codec.utf16_key_lambda",
        "stdlib.typing.cast", "stdlib.json.dumps", "stdlib.json.encoder_encode", "stdlib.json.encoder_iterencode"))
    compiled = [value for key, value in stats.items() if matches(key, METRICS[0][1], METRICS[0][2])]
    assert len(compiled) == 1
    edges, excluded = [], 0
    for (filename, line, function), values in compiled[0][4].items():
        relative = project_path(filename)
        if relative is None:
            excluded += 1
            continue
        assert type(line) is int and line >= 0 and function.isascii() and len(function) <= 100
        assert type(values) is tuple and len(values) == 4
        # CPython caller tuples use total/primitive, unlike function-stat tuples.
        ordered = values[1], values[0], values[2], values[3]
        edges.append({"caller": relative + ":" + function, "definition_line": line, **measured(ordered)})
    edges.sort(key=lambda row: (-row["calls"], row["caller"], row["definition_line"]))
    assert edges
    record = {"schema": "atlas-brain.compiler-cpu-attribution/1", "scope": "baseline_only_compiler_diagnostic",
        "baseline_blob": "640c5ccbce24e4e962960313f1acefe36b51e836",
        "compiler_blob": "534f2aa57a6ec05bddb66e53cbd7865cf73ad411",
        "platform": sys.platform, "run_id": os.environ.get("GITHUB_RUN_ID", "not_hosted"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "not_hosted"), "groups": 32,
        "composition_order": ["root9_direct", "mixed7", "root9_profile"],
        "phase_counts_per_group": wanted_delta, "phase_counts_total": last_counts,
        "profiled_group_wall_ms": walls, "functions": functions,
        "caller_edge_scope": "project_caller_function_aggregates_not_callsites",
        "caller_edges_total": len(edges), "caller_edges": edges[:12],
        "caller_edges_truncated": len(edges) > 12, "nonproject_caller_edges_omitted": excluded,
        "inventory_scope": "six_decoded_wire_objects_from_returned_values_only_not_all_nested_compiles",
        "inventory": inventory(previous), "opaque_c_accounting": "unreported_C_cost_may_be_charged_to_Python_caller",
        "registration_sha256": [value.registration_sha256 for value in previous]}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    assert raw.isascii() and len(raw) < 16384
    with capsys.disabled():
        print("P4_COMPILER_CPU_ATTRIBUTION " + raw)
