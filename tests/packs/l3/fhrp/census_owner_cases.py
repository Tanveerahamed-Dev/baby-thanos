"""Actual census parser fixture and observation tripwires without an owner dependency."""
from dataclasses import replace
from hashlib import sha256

import pytest
from test_parse_hsrp_census_product import forged_success

from atlas_brain.kernel import states as k
from atlas_brain.model.store import FactWriter
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census
from atlas_brain.runner.pack_receipts import CaptureRequest

SCOPE = b"baby-thanos.hsrp-census/1 node=node:demo:b interface=BD10 af=ipv4 protocol=hsrp groups=all\n"


def _frame(body, count, *, valid=True):
    digest = sha256(body).hexdigest().encode("ascii") if valid else b"0" * 64
    return body + b"success rows=" + str(count).encode("ascii") + b" sha256=" + digest + b"\n"


def zero_frame(*, valid=True):
    return _frame(SCOPE, 0, valid=valid)


def group_three_frame():
    return _frame(SCOPE + b"group node=node:demo:b interface=BD10 id=3\n", 1)


INTAKE_CASES = [
    ("plan", None, "owner_plan"),
    ("request_value", None, "owner_plan"),
    ("interface", _frame(SCOPE.replace(b"BD10", b"Vl30"), 0), "plan_scopes"),
    ("uncollected", None, "plan_scopes"),
]


def observe_parser(monkeypatch):
    parse = census.parse_capture
    calls = []

    def parsing(capture, *, node, interface):
        value = parse(capture, node=node, interface=interface)
        calls.append((capture, node, interface, value))
        return value

    monkeypatch.setattr(census, "parse_capture", parsing)
    monkeypatch.setattr(FactWriter, "write", lambda *_a, **_k: pytest.fail("census owner wrote a fact"))
    return calls


class OpenCarrier:
    def __getattribute__(self, name):
        pytest.fail(f"read an open owner carrier: {name}")


def open_plan_carrier(plan):
    class OpenPlan(type(plan)):
        __slots__ = ()
        __getattribute__ = OpenCarrier.__getattribute__

    object.__setattr__(plan, "__class__", OpenPlan)


def plant_prepared_carrier(monkeypatch, requests, fault):
    prepare = requests.prepare_census_folder
    hits = []

    def preparing(root, budgets):
        plan = prepare(root, budgets)
        hits.append(plan)
        if fault == "plan":
            open_plan_carrier(plan)
        elif fault == "request_value":
            identity, request, _capture, value = plan.request_values[0]
            object.__setattr__(plan, "request_values", ((identity, request, OpenCarrier(), value),))
        elif fault == "interface":
            scope = plan.scopes[1]
            domain = plan.brief_bindings.indexed[plan.envelope.context, scope.source.node.key]
            assert scope.interface == "BD10" and any(interface == "Vl30" for interface, _ in domain.groups)
            assert scope.request.capture.raw == _frame(SCOPE.replace(b"BD10", b"Vl30"), 0)
            object.__setattr__(scope, "interface", "Vl30")
        else:
            assert len(plan.scopes) == 2 and plan.scopes[1].member is plan.scopes[1].request is None
            object.__setattr__(plan, "scopes", plan.scopes[:1])
        return plan

    monkeypatch.setattr(requests, "prepare_census_folder", preparing)
    return hits


def plant_late_plan_class(monkeypatch, custody, run):
    validate = custody.validate_plan
    hits = []

    def validating(*args):
        validate(*args)
        if not hits:
            hits.append(run.plan)
            open_plan_carrier(run.plan)

    monkeypatch.setattr(custody, "validate_plan", validating)
    return hits


def plant_copied_pair(monkeypatch, run, earlier, kind):
    parse = census.parse_capture

    def parsing(capture, *, node, interface):
        result = parse(capture, node=node, interface=interface)
        emission = run.emitted[earlier.request.capture.id]
        value, effective = emission.pair
        pair = (replace(value), effective) if kind == "value" else (value, replace(effective))
        coordinate = 0 if kind == "value" else 1
        assert pair == emission.pair and pair[coordinate] is not emission.pair[coordinate]
        object.__setattr__(emission, "pair", pair)
        return result

    monkeypatch.setattr(census, "parse_capture", parsing)


def plant_reentry(monkeypatch, run, request, dispatch, observations):
    parse = census.parse_capture

    def parsing(capture, *, node, interface):
        value = parse(capture, node=node, interface=interface)
        if len(observations) == 1:
            run.attempted.clear()
            with pytest.raises(ValueError, match="^hsrp_census_owner_reentry$"):
                dispatch(run, request)
        return value

    monkeypatch.setattr(census, "parse_capture", parsing)


def plant_input_graph(monkeypatch, cold, plant):
    if plant == "before":
        object.__setattr__(cold.member, "raw", b"replacement")
    else:
        real = census.parse_capture

        def parsing(capture, *, node, interface):
            value = real(capture, node=node, interface=interface)
            if plant == "member_after":
                object.__setattr__(cold.member, "raw", b"replacement")
            else:
                raw_copy = bytes(bytearray(capture.raw))
                assert raw_copy == capture.raw and raw_copy is not capture.raw
                object.__setattr__(capture, "raw", raw_copy)
            return value

        monkeypatch.setattr(census, "parse_capture", parsing)


def plant_earlier_negative(monkeypatch, earlier, accounting):
    real = census.parse_capture

    def parsing(capture, *, node, interface):
        value = real(capture, node=node, interface=interface)
        object.__setattr__(earlier, "detail", "changed")
        for line in accounting.lines:
            object.__setattr__(line, "reason", "changed")
        return value

    monkeypatch.setattr(census, "parse_capture", parsing)


def plant_forged_success(monkeypatch):
    parse = census.parse_capture

    def parsing(capture, *, node, interface):
        result = parse(capture, node=node, interface=interface)
        assert result.detail == "footer_hash"
        return forged_success(capture, result)

    monkeypatch.setattr(census, "parse_capture", parsing)


def plant_parser_failure(monkeypatch):
    original = census.parse_capture
    calls = []

    def failing(capture, *, node, interface):
        calls.append(original(capture, node=node, interface=interface))
        raise RuntimeError("parser_failed")

    monkeypatch.setattr(census, "parse_capture", failing)
    return calls


def assert_real_scope_products(run, calls, case, detail, second, dispatch, close):
    assert not calls and len(run.plan.scopes) == 2
    first, cold = run.plan.scopes
    first_result, effective = dispatch(run, first.request)
    assert first_result is calls[0][3] and first_result.parse is None
    assert first_result.census is None and first_result.reason is k.UnknownReason.PARSE_UNSUPPORTED_VARIANT
    assert first_result.detail == "capture_encoding"
    assert [(line.span.start, line.span.end) for line in effective.lines] == [(0, 3), (3, 6)]
    assert effective.quality == "partial" and not effective.records and not effective.tokens
    assert all((line.status, line.reason) == ("unrecognised", "capture_encoding") for line in effective.lines)
    assert calls[0][0] is first.request.capture and calls[0][1:3] == ("node:demo:a", "Vl10")
    if second is not None:
        with pytest.raises(ValueError, match="^hsrp_census_owner_emissions$"):
            close(run)
        observed, parsed = dispatch(run, CaptureRequest(capture=cold.request.capture, context=cold.request.context))
        assert observed is calls[1][3] and calls[1][0] is cold.request.capture
        assert calls[1][1:3] == ("node:demo:b", "BD10")
        assert observed.detail == detail
        if case == "valid_empty":
            assert observed.census.groups == () and parsed.quality == "complete"
            assert observed.census.scope_raw == SCOPE
        else:
            assert observed.census is None and parsed.quality == "partial"
        if case == "empty_bytes":
            assert observed.parse is None and parsed.lines == ()
        else:
            assert parsed is observed.parse
    else:
        assert cold.member is cold.request is None and len(calls) == 1
    closed = close(run)
    assert len(closed) == len(calls) and {id(pair[0]) for pair in closed} == {id(call[3]) for call in calls}
    assert next(parsed for result, parsed in closed if result is first_result) is effective


def plant_snapshot_capture_id(monkeypatch, context, capture):
    snapshot = context.request_values
    seen = []

    class OpenId(str):
        def __hash__(self):
            raise AssertionError("hashed a capture ID changed after its snapshot")

    def snapshotting(requests):
        values = snapshot(requests)
        object.__setattr__(capture, "id", OpenId(capture.id))
        seen.append(values)
        return values

    monkeypatch.setattr(context, "request_values", snapshotting)
    return seen
