"""Test-only SAFE row/batch CPU hypotheses; no memoization, activation, speed threshold, native timing or 420-second qualification."""
import cProfile
import json
import math
import os
import re
import sys
import time
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
from statistics import median
from typing import cast

import pytest
import test_canonical_dispatch_parity as parity

from atlas_brain.contract.canonical import canonical as product
from atlas_brain.model import catalogue, pack_registration
from atlas_brain.model.specs import EntityKindSpec, RelationSpec
from atlas_brain.packs.l3.fhrp import mixed_profile as mixed
from atlas_brain.packs.l3.fhrp import root_mixed_profile as root
from atlas_brain.runner import p4_root_mixed_report
from tools import p4_root_mixed_demo as demo
from tools.p4_root_mixed_cases import members
from tools.p4_root_mixed_expected import expected_bundle

SAFE = re.compile(r"[\x20-\x21\x23-\x5b\x5d-\x7e]*")
BASELINE_BLOB = "640c5ccbce24e4e962960313f1acefe36b51e836"
COMPILER_BLOB = "534f2aa57a6ec05bddb66e53cbd7865cf73ad411"


def reference(value: object) -> bytes:
    return reference_encode(value).encode("utf-8")


def reference_encode(value: object) -> str:
    kind = type(value)
    if kind is str:
        if SAFE.fullmatch(cast(str, value)):
            return f'"{value}"'
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if value is None or kind is bool:
        return json.dumps(value)
    if kind is int:
        if not -9007199254740991 <= cast(int, value) <= 9007199254740991:
            raise ValueError("integer_out_of_range")
        return str(value)
    if kind is list or kind is tuple:
        items = cast("list[object] | tuple[object, ...]", value)
        return f"[{','.join(map(reference_encode, items))}]"
    if kind is not dict:
        raise TypeError("non_json_type")
    entries = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in entries):
        raise TypeError("non_string_key")
    obj = cast(dict[str, object], value)
    keys = sorted(obj, key=lambda key: key.encode("utf-16be"))
    members = (f"{reference_encode(key)}:{reference_encode(obj[key])}" for key in keys)
    return f"{{{','.join(members)}}}"


def probe(value: object) -> bytes:
    return probe_encode(value).encode("utf-8")


def probe_encode(value: object) -> str:
    kind = type(value)
    if kind is str:
        if SAFE.fullmatch(cast(str, value)):
            return f'"{value}"'
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if value is None or kind is bool:
        return json.dumps(value)
    if kind is int:
        if not -9007199254740991 <= cast(int, value) <= 9007199254740991:
            raise ValueError("integer_out_of_range")
        return str(value)
    if kind is list or kind is tuple:
        if eligible_batch(value):
            return json.JSONEncoder(sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(value)
        items = cast("list[object] | tuple[object, ...]", value)
        return f"[{','.join(map(probe_encode, items))}]"
    if kind is not dict:
        raise TypeError("non_json_type")
    entries = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in entries):
        raise TypeError("non_string_key")
    if eligible(entries):
        return json.JSONEncoder(sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(value)
    obj = cast(dict[str, object], value)
    keys = sorted(obj, key=lambda key: key.encode("utf-16be"))
    members = (f"{probe_encode(key)}:{probe_encode(obj[key])}" for key in keys)
    return f"{{{','.join(members)}}}"


def eligible(entries):
    for key, value in entries.items():
        if type(key) is not str or not SAFE.fullmatch(key):
            return False
        if type(value) is str:
            if not SAFE.fullmatch(value):
                return False
        elif type(value) is list or type(value) is tuple:
            if any(type(item) is not str or not SAFE.fullmatch(item) for item in value):
                return False
        else:
            return False
    return True


def eligible_batch(values):
    if type(values) is not list and type(values) is not tuple:
        return False
    return (not values
        or (type(values[0]) is str and all(type(item) is str and SAFE.fullmatch(item) for item in values))
        or (type(values[0]) is dict and all(type(item) is dict and eligible(item) for item in values)))


@contextmanager
def writers(monkeypatch, codec):
    before = catalogue.canonical, pack_registration.canonical
    try:
        with monkeypatch.context() as patch:
            patch.setattr(catalogue, "canonical", codec)
            patch.setattr(pack_registration, "canonical", codec)
            yield
    finally:
        assert catalogue.canonical is before[0] and pack_registration.canonical is before[1]


def relation_declaration():
    pack = "probe.rows"
    return pack_registration.PackDeclaration(pack=pack,
        entity_kinds=(EntityKindSpec(id="left", pack=pack, root=False),
            EntityKindSpec(id="right", pack=pack, root=False)), facts=(),
        relations=(RelationSpec(id=pack + ".edge", pack=pack, source="left",
            target="right", cardinality="one_to_many"),), steps=(), operations=())


def compositions():
    return (pack_registration.compile_packs(root.DECLARATIONS), mixed.compile_mixed_profile(),
        root.compile_root_mixed_profile(), pack_registration.compile_packs((relation_declaration(),)))


def fresh_equal(actual, expected):
    assert len(actual) == len(expected)
    for value, prior in zip(actual, expected, strict=True):
        assert type(value) is pack_registration.CompiledPackSet and value == prior and value is not prior
        assert value.steps == prior.steps and value.operations == prior.operations
        assert value.registration_sha256 == sha256(value.registration_bytes).hexdigest()
        assert json.loads(value.registration_bytes)["catalogue_sha256"] == sha256(value.catalogue_bytes).hexdigest()


def profiled_compilers(monkeypatch, codec):
    profiler = cProfile.Profile()
    with writers(monkeypatch, codec):
        values = profiler.runcall(compositions)
    names = ("compile_packs", "compile_mixed_profile", "compile_root_mixed_profile", "root_declaration")
    counts = {name: sum(row.callcount for row in profiler.getstats()
        if getattr(row.code, "co_name", None) == name) for name in names}
    assert all(type(count) is int and count > 0 for count in counts.values())
    return values, counts


def read_inputs(folder):
    return {path.relative_to(folder).as_posix(): path.read_bytes()
        for path in folder.rglob("*") if path.is_file()}


def emit(capsys, kind, payload):
    fields = {"coverage": {"composition_order", "phase_counts", "row_counts", "batch_counts", "registration_sha256"},
        "compiler_samples": {"orders", "iterations_per_sample", "samples_ms", "medians_ms", "registration_sha256"},
        "real_case_samples": {"case", "orders", "samples_ms", "medians_ms", "oracle_sha256", "input_sha256"}}
    assert kind in fields and set(payload) == fields[kind]
    record = {"schema": "atlas-brain.ascii-row-probe/2", "scope": "test_only_compiler_local_diagnostic",
        "kind": kind, "candidate_shape": "homogeneous_safe_rows_or_strings", "counter_scope": "eligibility_checks", "baseline_blob": BASELINE_BLOB, "compiler_blob": COMPILER_BLOB,
        "platform": sys.platform, "run_id": os.environ.get("GITHUB_RUN_ID", "not_hosted"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "not_hosted"), **payload}
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    assert raw.isascii() and len(raw) < 8192
    with capsys.disabled():
        print("P4_ASCII_ROW_PROBE " + raw)


@pytest.mark.parametrize("value,accepted", [
    ({"fact": "probe.rows", "reads": ("left", "right")}, True), ({}, True),
    ({"empty": [], "tuple": ()}, True), ({"x": "", "z": "safe[]"}, True),
    ({"x": None}, False), ({"x": False}, False), ({"x": 1}, False),
    ({"x": 0.5}, False), ({"x": "\x7f"}, False), ({"é": "safe"}, False),
    ({"x": 'quote"'}, False), ({"x": {"y": "z"}}, False), ({"x": [["nested"]]}, False),
    ({type("KeyAlias", (str,), {})("x"): "safe"}, False),
    ({"x": type("ValueAlias", (str,), {})("safe")}, False),
    ({"x": type("ListAlias", (list,), {})(["safe"])}, False),
    ({"x": type("TupleAlias", (tuple,), {})(("safe",))}, False),
])
def test_eligibility_is_narrow_and_every_fallback_keeps_the_qualified_outcome(value, accepted):
    assert eligible(value) is accepted
    assert parity.outcome(probe, value) == parity.outcome(reference, value) == parity.outcome(product, value)


def test_scalar_nested_unicode_surrogate_and_first_refusal_differential():
    values = [None, True, False, -9007199254740991, -1, 0, 1, 9007199254740991,
        [], (), {}, "", "\x7f", "é", "e\u0301", "\ue000", "\U0001f600", "\U0010ffff",
        chr(0xD800), chr(0xDFFF), ["x", chr(0xD800)], {chr(0xDFFF): "x"}]
    values += [chr(code) for code in range(128)]
    values += [{"first": 9007199254740992, 1: "later"},
        {"a": 1.0, "z": 9007199254740992}, {"a": 9007199254740992, "z": 1.0}]
    for value in values:
        for wrapped in (value, [value], (value,), {"item": value}):
            assert parity.outcome(probe, wrapped) == parity.outcome(reference, wrapped) == parity.outcome(product, wrapped)
    for value, kind, reason in parity.INVALID:
        for wrapped in (value, [value], (value,), {"item": value}):
            assert parity.outcome(probe, wrapped) == ("error", kind, reason)
            assert parity.outcome(probe, wrapped) == parity.outcome(reference, wrapped)
    value = {"\ue000": 3, "\U0001f600": 2, "\r": 1}
    assert probe(value) == reference(value) == '{"\\r":1,"\U0001f600":2,"\ue000":3}'.encode("utf-8")
    assert probe("after refusal") == b'"after refusal"'


def test_custom_key_encode_precedes_values_and_hostile_metaclass_runs_no_hooks():
    class Key(str):
        def encode(self, *args, **kwargs):
            raise LookupError("key_encoding_precedes_value")
    value = {Key("key"): 9007199254740992}
    assert {parity.outcome(codec, item) for codec in (reference, probe) for item in (value, [value])} == {(
        "error", LookupError, "key_encoding_precedes_value")}
    hooks = []
    class Alias(type):
        def __eq__(cls, other):
            hooks.append("equality")
            return True
    class NonJson(metaclass=Alias):
        def __iter__(self):
            hooks.append("iteration")
            return iter(())
    for codec in (reference, probe):
        assert parity.outcome(codec, NonJson()) == ("error", TypeError, "non_json_type")
        assert hooks == [] and eligible_batch(NonJson()) is False and hooks == []


def test_full_dumps_routing_options_and_distinct_return_tokens_are_preserved(monkeypatch):
    real = json.dumps
    value = [{"fact": "probe.rows", "reads": ("safe",)}, 0, None, True, False, "\x7f", 'quote"\n', "é"]
    options = {"ensure_ascii": False, "separators": (",", ":")}
    expected_calls = [(type(None), None, {}), (bool, True, {}), (bool, False, {}),
        (str, "\x7f", options), (str, 'quote"\n', options), (str, "é", options)]
    calls, saved = [], []
    def observed(item, **kwargs):
        calls.append((type(item), item, kwargs))
        return real("route-" + str(len(calls)), ensure_ascii=False, separators=(",", ":"))
    for codec in (reference, probe):
        calls.clear()
        with monkeypatch.context() as patch:
            patch.setattr(json, "dumps", observed)
            raw = codec(value)
        assert calls == expected_calls
        assert json.loads(raw) == [{"fact": "probe.rows", "reads": ["safe"]}, 0,
            "route-1", "route-2", "route-3", "route-4", "route-5", "route-6"]
        saved.append(raw)
    assert saved[0] == saved[1]


def test_live_aliased_row_moves_between_eligible_and_fallback_without_reuse():
    shared = ["safe"]
    value = {"fact": "probe.rows", "reads": shared, "produces": shared}
    batch = [value]
    first = probe(value)
    assert first == reference(value) and eligible(value)
    for item in (None, True, 1, 1.0, "\x7f", "é", ["nested"], type("Alias", (str,), {})("safe")):
        shared[:] = [item]
        assert not eligible(value)
        assert parity.outcome(probe, value) == parity.outcome(reference, value)
        assert not eligible_batch(batch) and parity.outcome(probe, batch) == parity.outcome(reference, batch)
    shared[:] = ["safe"]
    assert eligible(value) and probe(value) == reference(value) == first
    assert eligible_batch(batch) and probe(batch) == reference(batch)
    value["fact"] = "probe.changed"
    assert probe(value) == reference(value) != first


def test_actual_compiler_coverage_fields_freshness_and_phase_counts(monkeypatch, capsys):
    expected, baseline_counts = profiled_compilers(monkeypatch, reference)
    assert all(not json.loads(value.catalogue_bytes)["relations"] for value in expected[:3])
    assert len(json.loads(expected[3].catalogue_bytes)["relations"]) == 1
    top = json.loads(expected[0].catalogue_bytes), json.loads(expected[0].registration_bytes)
    assert all(not eligible(value) for value in top)
    original, original_batch = eligible, eligible_batch
    hits = dict.fromkeys(("eligible", "fallback", "fact", "relation", "step", "operation", "other"), 0)
    batch_hits = {"eligible": 0, "nonempty_actual_fact_batches": 0}
    def counted(entries):
        accepted = original(entries)
        hits["eligible" if accepted else "fallback"] += 1
        if accepted:
            label = next((label for field, label in (("fact", "fact"), ("relation", "relation"),
                ("evaluator", "step"), ("operation", "operation")) if field in entries), "other")
            hits[label] += 1
        return accepted
    def counted_batch(values):
        accepted = original_batch(values)
        batch_hits["eligible"] += int(accepted)
        batch_hits["nonempty_actual_fact_batches"] += int(bool(accepted and values and type(values[0]) is dict and "fact" in values[0]))
        return accepted
    with monkeypatch.context() as patch:
        patch.setattr(sys.modules[__name__], "eligible", counted)
        patch.setattr(sys.modules[__name__], "eligible_batch", counted_batch)
        actual, candidate_counts = profiled_compilers(monkeypatch, probe)
    fresh_equal(actual, expected)
    assert baseline_counts == candidate_counts and all(hits[name] > 0 for name in ("eligible", "fallback", "fact", "relation", "step", "operation"))
    assert batch_hits["nonempty_actual_fact_batches"] > 0
    emit(capsys, "coverage", {"composition_order": ["root9_direct", "mixed7", "root9_profile", "synthetic_relation"],
        "phase_counts": baseline_counts, "row_counts": hits, "batch_counts": batch_hits,
        "registration_sha256": [value.registration_sha256 for value in actual]})


def test_changed_current_metadata_is_seen_and_restoration_does_not_reuse_a_result(monkeypatch):
    declarations = deepcopy(root.DECLARATIONS)
    step = declarations[0].steps[0]
    original = step.evaluator
    for codec in (reference, probe):
        with writers(monkeypatch, codec):
            before = pack_registration.compile_packs(declarations)
            try:
                object.__setattr__(step, "evaluator", step.pack + ".probe")
                changed = pack_registration.compile_packs(declarations)
                assert changed.catalogue_bytes != before.catalogue_bytes
                assert changed.registration_bytes != before.registration_bytes
            finally:
                object.__setattr__(step, "evaluator", original)
            restored = pack_registration.compile_packs(declarations)
        fresh_equal((restored,), (before,))
        assert restored is not changed


def test_alternating_actual_compiler_samples_are_byte_checked_without_a_speed_gate(monkeypatch, capsys):
    with writers(monkeypatch, reference):
        expected = compositions()
    samples = {"baseline": [], "candidate": []}
    encoders = {"baseline": reference, "candidate": probe}
    orders = []
    for repetition in range(8):
        order = ["baseline", "candidate"] if repetition % 2 == 0 else ["candidate", "baseline"]
        orders.append(order)
        for name in order:
            with writers(monkeypatch, encoders[name]):
                started = time.perf_counter()
                for _ in range(8):
                    actual = compositions()
                    fresh_equal(actual, expected)
                elapsed = (time.perf_counter() - started) * 1000
            assert math.isfinite(elapsed) and elapsed >= 0
            samples[name].append(elapsed)
    for codec in (reference, probe):
        with writers(monkeypatch, codec):
            fresh_equal(compositions(), expected)
    emit(capsys, "compiler_samples", {"orders": orders, "iterations_per_sample": 8, "samples_ms": samples,
        "medians_ms": {name: median(values) for name, values in samples.items()},
        "registration_sha256": [value.registration_sha256 for value in expected]})


def test_two_alternating_real_case_pairs_preserve_all_oracle_bytes_and_inputs(monkeypatch, tmp_path, capsys):
    case = "cold_vrrp"
    raw = members(case)
    registration = pack_registration.compile_packs(root.DECLARATIONS).registration_sha256
    expected = expected_bundle(case, raw, registration)
    names = {"MANIFEST.sha256", "facts/etherchannel_group.jsonl", "facts/fhrp_local.jsonl",
        "facts/stp_port_vlan.jsonl", "result.json"}
    assert set(expected) == names and all(type(value) is bytes for value in expected.values())
    folder = tmp_path / "original"
    demo.write_files(folder, raw)
    samples = {"baseline": [], "candidate": []}
    orders = [["baseline", "candidate"], ["candidate", "baseline"]]
    encoders = {"baseline": reference, "candidate": probe}
    for order in orders:
        for name in order:
            with writers(monkeypatch, encoders[name]):
                started = time.perf_counter()
                actual = p4_root_mixed_report.analyse_root_mixed_folder(
                    folder, p4_root_mixed_report.Budgets(16 * 1024 * 1024, 4 * 1024 * 1024, 128))
                elapsed = (time.perf_counter() - started) * 1000
            assert math.isfinite(elapsed) and elapsed >= 0
            assert set(actual) == names and all(type(value) is bytes for value in actual.values())
            assert actual == expected and read_inputs(folder) == raw
            samples[name].append(elapsed)
    emit(capsys, "real_case_samples", {"case": case, "orders": orders, "samples_ms": samples,
        "medians_ms": {name: median(values) for name, values in samples.items()},
        "oracle_sha256": {name: sha256(value).hexdigest() for name, value in sorted(expected.items())},
        "input_sha256": {name: sha256(value).hexdigest() for name, value in sorted(raw.items())}})


def test_homogeneous_batches_are_narrow_and_keep_qualified_fallbacks():
    vectors = (([], True), ((), True), (["safe"], True), ([{"x": "safe"}] * 2, True),
        (({"x": "safe"},), True), (["safe", {"x": "safe"}], False), ([{"x": "safe"}, "safe"], False),
        ([None], False), ([False], False), ([1], False), ([1.0], False), (type("TupleAlias", (tuple,), {})(("safe",)), False),
        (["é"], False), (["\x7f"], False), (['"'], False), ([["safe"]], False), ([{1: "x"}], False),
        (type("ListAlias", (list,), {})(["safe"]), False), ([type("DictAlias", (dict,), {})({"x": "safe"})], False),
        ([type("StrAlias", (str,), {})("safe")], False))
    for value, accepted in vectors:
        assert eligible_batch(value) is accepted
        assert parity.outcome(probe, value) == parity.outcome(reference, value)
