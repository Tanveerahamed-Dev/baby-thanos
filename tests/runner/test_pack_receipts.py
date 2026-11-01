"""Synthetic custody twins; supplied-capture coverage is not semantic completeness."""
import json
from dataclasses import FrozenInstanceError, fields, replace
from hashlib import sha256

import pytest

from atlas_brain.contract.canonical import canonical
from atlas_brain.evidence.capture import Capture, ErrorKind
from atlas_brain.evidence.parsekit.rules import ParseResult, Rule, run_rules
from atlas_brain.evidence.text import text_lines
from atlas_brain.kernel import states as k
from atlas_brain.kernel.time import BoundSource, TimeInterval
from atlas_brain.model.pack_registration import (
    OperationBinding,
    PackDeclaration,
    compile_packs,
)
from atlas_brain.model.specs import EntityKindSpec, FactSpec, StepId, StepSpec
from atlas_brain.runner.pack_receipts import (
    CaptureRequest,
    ParseReceipt,
    validate_receipts,
)


def declaration(name):
    pack, step_id = k.PackId("test." + name), StepId("test." + name + "/parse")
    fact_id = k.FactId(pack + ".value")
    step = StepSpec(id=step_id, pack=pack, kind="parse_build", scope="device",
                    reads=(), produces=(fact_id,), evaluator=pack + ".not_loaded")
    return PackDeclaration(pack=pack, entity_kinds=(EntityKindSpec(id=name, pack=pack, root=True),),
                           facts=(FactSpec(id=fact_id, pack=pack, subject=name,
                                           value_type="text", step=step_id),),
                           relations=(), steps=(step,),
                           operations=(OperationBinding(operation="collect." + name, step=step_id),))


def capture(name, raw=b"value\n"):
    return Capture(id=k.CaptureId("cap:synthetic:" + name), source=k.EntityKey("node:synthetic:" + name),
                   operation="collect." + name, rendered="show synthetic " + name, codec="utf-8", raw=raw,
                   integrity=k.IntegrityState.COMPLETE if raw else k.IntegrityState.EMPTY,
                   lines=text_lines(raw, "utf-8"), read_scope=k.ReadScope.UNKNOWN, view=k.ViewConsistency.UNKNOWN)


def receipt(request, owner, digest):
    item = request.capture
    parsed = run_rules(item.raw, item.id,
                       (Rule("value", "start", "(?P<value>[a-z]++)", "record", "start", "", ("value",)),), ())
    return ParseReceipt(capture=item, owner=owner, context=request.context,
                        registration_sha256=digest, parse=parsed)


def scenario(names=("alpha", "beta")):
    packs = tuple(declaration(name) for name in names)
    requests = tuple(CaptureRequest(capture=capture(name), context="sample:" + name) for name in names)
    digest = compile_packs(packs).registration_sha256
    receipts = tuple(receipt(request, pack.steps[0].id, digest) for request, pack in zip(requests, packs, strict=True))
    return packs, requests, receipts


@pytest.mark.parametrize("reverse_packs", [False, True])
@pytest.mark.parametrize("reverse_requests", [False, True])
@pytest.mark.parametrize("reverse_receipts", [False, True])
def test_exact_bijection_is_sorted_without_replacing_payloads(reverse_packs, reverse_requests, reverse_receipts):
    packs, requests, receipts = scenario()
    actual = validate_receipts(tuple(reversed(packs)) if reverse_packs else packs,
                               tuple(reversed(requests)) if reverse_requests else requests,
                               tuple(reversed(receipts)) if reverse_receipts else receipts)
    assert actual == receipts
    assert all(result is original and result.parse is original.parse for result, original in zip(actual, receipts))
    copied = tuple(replace(item, capture=replace(item.capture)) for item in receipts)
    assert validate_receipts(packs, requests, copied) == receipts


@pytest.mark.parametrize("plant,code", [
    (lambda r: r[:-1], "pack_receipts_coverage"),
    (lambda r: (), "pack_receipts_coverage"),
    (lambda r: (r[0], r[0]), "pack_receipts_duplicate_receipt"),
    (lambda r: r + (replace(r[0], capture=replace(r[0].capture, id=k.CaptureId("cap:extra"))),),
     "pack_receipts_coverage"),
    (lambda r: (r[0], replace(r[1], capture=replace(r[1].capture, id=k.CaptureId("cap:extra")))),
     "pack_receipts_coverage"),
])
def test_missing_duplicate_and_unexpected_receipts_are_independent_refusals(plant, code):
    packs, requests, receipts = scenario()
    assert validate_receipts(packs, requests, receipts) == receipts
    with pytest.raises(ValueError, match="^" + code + "$"):
        validate_receipts(packs, requests, plant(receipts))


def test_capture_ids_are_unique_even_across_different_contexts():
    packs, requests, receipts = scenario()
    duplicate = replace(requests[0], context="another-sample")
    with pytest.raises(ValueError, match="^pack_receipts_duplicate_capture$"):
        validate_receipts(packs, (requests[0], duplicate), receipts)


def test_swapped_receipt_snapshots_cannot_preserve_custody_by_relabelling_ids():
    packs, requests, receipts = scenario()
    swapped = tuple(replace(receipts[i], capture=replace(receipts[1-i].capture, id=receipts[i].capture.id))
                    for i in range(2))
    assert {item.capture.id for item in swapped} == {item.capture.id for item in requests}
    with pytest.raises(ValueError, match="^pack_receipts_capture_mismatch$"):
        validate_receipts(packs, requests, swapped)


@pytest.mark.parametrize("change,code", [
    ({"owner": StepId("test.beta/parse")}, "pack_receipts_owner_mismatch"),
    ({"owner": StepId("test.alpha/missing")}, "pack_receipts_owner_mismatch"),
    ({"context": None}, "pack_receipts_context_mismatch"),
    ({"context": "sample:other"}, "pack_receipts_context_mismatch"),
    ({"registration_sha256": "0" * 64}, "pack_receipts_registration_mismatch"),
])
def test_owner_context_and_registration_are_checked_against_trusted_inputs(change, code):
    packs, requests, receipts = scenario()
    with pytest.raises(ValueError, match="^" + code + "$"):
        validate_receipts(packs, requests, (replace(receipts[0], **change), receipts[1]))


@pytest.mark.parametrize("reverse", [False, True])
def test_distinct_receipt_faults_refuse_in_capture_id_order(reverse):
    packs, requests, receipts = scenario()
    broken = (replace(receipts[0], owner=receipts[1].owner),
              replace(receipts[1], context="wrong-context"))
    if reverse:
        packs, requests, broken = tuple(reversed(packs)), tuple(reversed(requests)), tuple(reversed(broken))
    with pytest.raises(ValueError, match="^pack_receipts_owner_mismatch$"):
        validate_receipts(packs, requests, broken)


def changed_metadata(item, **changes):
    return replace(item, metadata=replace(item.resolved_metadata, **changes))


@pytest.mark.parametrize("change", [
    lambda c: replace(c, raw=b"other\n", lines=text_lines(b"other\n", c.codec)),
    lambda c: replace(c, source=k.EntityKey("node:synthetic:other")),
    lambda c: replace(c, operation="collect.beta"),
    lambda c: replace(c, rendered="show synthetic other"),
    lambda c: replace(c, codec="ascii"),
    lambda c: replace(c, integrity=k.IntegrityState.TRUNCATED),
    lambda c: replace(c, view=k.ViewConsistency.CACHED),
    lambda c: changed_metadata(c, scope=replace(c.scope, context="another-cli-context")),
    lambda c: changed_metadata(c, error=ErrorKind.TIMEOUT),
    lambda c: changed_metadata(c, collected_utc=TimeInterval(
        earliest=1, latest=2, clock="collector:synthetic", bound=BoundSource.COLLECTOR_RECORDED)),
    lambda c: replace(changed_metadata(c, read_scope_evidence=c.integrity_evidence), read_scope=k.ReadScope.LIMITED),
    lambda c: replace(c, lines=(replace(c.lines[0], text="different"),)),
    lambda c: replace(c, lines=(replace(c.lines[0], offsets=(1,) + c.lines[0].offsets[1:]),)),
])
def test_same_capture_id_cannot_hide_changed_bytes_or_interpretation(change):
    packs, requests, receipts = scenario()
    original = receipts[0].capture
    altered = change(original)  # A valid Capture constructor must reach the custody comparator.
    assert altered.id == original.id and altered != original
    assert validate_receipts(packs, requests, receipts) == receipts
    with pytest.raises(ValueError, match="^pack_receipts_capture_mismatch$"):
        validate_receipts(packs, requests, (replace(receipts[0], capture=altered), receipts[1]))


@pytest.mark.parametrize("operation", [None, "collect.unregistered"])
def test_unregistered_supplied_operation_refuses_even_with_a_matching_receipt(operation):
    packs, requests, receipts = scenario()
    item = replace(requests[0].capture, operation=operation)
    request, result = replace(requests[0], capture=item), replace(receipts[0], capture=item)
    with pytest.raises(ValueError, match="^pack_receipts_unregistered_operation$"):
        validate_receipts(packs, (request,), (result,))


def test_compiled_record_cannot_replace_trusted_declarations_or_forge_an_owner():
    packs, requests, receipts = scenario()
    compiled = compile_packs(packs)
    forged = replace(compiled, operations=(replace(compiled.operations[0], step=compiled.operations[1].step),
                                          compiled.operations[1]))
    assert forged.registration_bytes == compiled.registration_bytes
    assert forged.registration_sha256 == compiled.registration_sha256
    with pytest.raises(ValueError, match="^invalid_pack_declarations$"):
        validate_receipts(forged, requests, receipts)
    with pytest.raises(ValueError, match="^pack_receipts_owner_mismatch$"):
        validate_receipts(packs, requests, (replace(receipts[0], owner=forged.operations[0].step), receipts[1]))


def test_self_consistent_forged_registration_hash_is_not_authority():
    packs, requests, receipts = scenario()
    compiled = compile_packs(packs)
    body = json.loads(compiled.registration_bytes)
    body["operations"][0]["step"] = body["operations"][1]["step"]
    forged_digest = sha256(canonical(body)).hexdigest()
    assert forged_digest != compiled.registration_sha256
    forged = tuple(replace(item, registration_sha256=forged_digest) for item in receipts)
    assert tuple(item.owner for item in forged) == tuple(item.owner for item in receipts)
    assert validate_receipts(packs, requests, receipts) == receipts
    with pytest.raises(ValueError, match="^pack_receipts_registration_mismatch$"):
        validate_receipts(packs, requests, forged)


def test_changed_registration_requires_fresh_receipt_digest_even_without_new_captures():
    packs, requests, receipts = scenario()
    extended = packs + (declaration("gamma"),)
    digest = compile_packs(extended).registration_sha256
    refreshed = tuple(replace(item, registration_sha256=digest) for item in receipts)
    assert validate_receipts(extended, requests, refreshed) == refreshed
    with pytest.raises(ValueError, match="^pack_receipts_registration_mismatch$"):
        validate_receipts(extended, requests, receipts)


def test_extra_synthetic_pack_uses_the_same_helper_and_missing_operations_invent_nothing():
    packs, requests, receipts = scenario(("alpha", "beta", "gamma"))
    assert validate_receipts(packs, requests, receipts) == receipts
    # A registered operation without a supplied capture contributes no receipt or health claim.
    assert validate_receipts(packs, requests[:1], receipts[:1]) == receipts[:1]


@pytest.mark.parametrize("has_registration", [False, True])
def test_empty_custody_returns_only_an_empty_tuple_and_extra_receipts_still_refuse(has_registration):
    packs, _, receipts = scenario()
    declarations = packs if has_registration else ()
    assert validate_receipts(declarations, (), ()) == ()
    with pytest.raises(ValueError, match="^pack_receipts_coverage$"):
        validate_receipts(declarations, (), receipts[:1])


def test_invalid_declarations_are_not_hidden_by_empty_custody():
    pack = declaration("alpha")
    with pytest.raises(ValueError, match="^duplicate_pack$"):
        validate_receipts((pack, pack), (), ())


def test_empty_capture_and_partial_parse_retain_their_exact_states_without_health_promotion():
    packs, _, _ = scenario(("alpha",))
    digest = compile_packs(packs).registration_sha256
    for raw in (b"", b"unrecognised!\n"):
        request = CaptureRequest(capture=capture("alpha", raw), context=None)
        result = receipt(request, packs[0].steps[0].id, digest)
        actual, = validate_receipts(packs, (request,), (result,))
        assert actual is result and actual.capture is request.capture and actual.parse is result.parse
        assert actual.parse.quality == ("complete" if not raw else "partial")
        assert actual.capture.integrity is (k.IntegrityState.EMPTY if not raw else k.IntegrityState.COMPLETE)


def test_custody_does_not_authenticate_opaque_parse_payloads():
    packs, requests, receipts = scenario()
    opaque = ParseResult((), (), (), "complete")
    changed = replace(receipts[0], parse=opaque)
    actual = validate_receipts(packs, requests, (changed, receipts[1]))
    assert requests[0].capture.raw and opaque.records == opaque.lines == opaque.tokens == ()
    assert actual[0] is changed and actual[0].parse is opaque
    assert {field.name for field in fields(actual[0])} == {
        "capture", "owner", "context", "registration_sha256", "parse"}


@pytest.mark.parametrize("collection,value,code", [
    ("requests", [], "pack_receipts_requests"), ("requests", ("bad",), "pack_receipts_requests"),
    ("receipts", [], "pack_receipts_receipts"), ("receipts", ("bad",), "pack_receipts_receipts"),
])
def test_top_level_collections_are_exact_typed_tuples(collection, value, code):
    packs, requests, receipts = scenario()
    supplied = {"requests": requests, "receipts": receipts, collection: value}
    with pytest.raises(ValueError, match="^" + code + "$"):
        validate_receipts(packs, **supplied)


@pytest.mark.parametrize("field,value,code", [
    ("capture", "bad", "pack_receipts_capture"), ("context", "", "pack_receipts_context"),
    ("context", 1, "pack_receipts_context"), ("owner", "", "pack_receipts_owner"),
    ("owner", 1, "pack_receipts_owner"), ("registration_sha256", "bad", "invalid_digest"),
    ("parse", "complete", "pack_receipts_parse"),
])
def test_receipt_constructor_rejects_mistyped_or_unbound_fields(field, value, code):
    _, _, receipts = scenario()
    with pytest.raises(ValueError, match="^" + code + "$"):
        replace(receipts[0], **{field: value})


def test_request_constructor_and_both_records_are_closed_and_frozen():
    _, requests, receipts = scenario()
    for change, code in (({"capture": "bad"}, "pack_receipts_capture"), ({"context": ""}, "pack_receipts_context")):
        with pytest.raises(ValueError, match="^" + code + "$"):
            replace(requests[0], **change)
    for item in (requests[0], receipts[0]):
        with pytest.raises(FrozenInstanceError):
            item.context = "changed"


@pytest.mark.parametrize("offset", [False, 0.0], ids=["boolean", "float"])
def test_equal_offset_values_with_wrong_types_cannot_bypass_custody(offset):
    packs, requests, receipts = scenario()
    original = receipts[0].capture
    line = replace(original.lines[0], offsets=(offset,) + original.lines[0].offsets[1:])
    forged = replace(original, lines=(line,))
    assert forged == original
    assert original.lines[0].raw_span(0, 1) == k.ByteSpan(start=0, end=1)
    with pytest.raises(ValueError, match="^invalid_span$"):
        line.raw_span(0, 1)
    with pytest.raises(ValueError, match="^pack_receipts_capture_lines$"):
        validate_receipts(packs, requests, (replace(receipts[0], capture=forged), receipts[1]))
