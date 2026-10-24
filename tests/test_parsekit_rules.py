"""The two plan-row planted failures precede the rule engine."""
from enum import StrEnum

import pytest

from atlas_brain.evidence.parsekit.rules import Rule, TokenMap, run_rules
from atlas_brain.kernel.states import CaptureId, Unknown, UnknownReason

CITATION = ("https://github.com/Tanveerahamed-Dev/atlas-brain-staging/"
            "blob/67893ef01b3b228ae428e3e459782539e501b5ee/tests/test_parsekit_rules.py#L42")


class Duplex(StrEnum):
    HALF = "half"
    FULL = "full"


def table():
    return (Rule("duplex", "start", r"duplex (?P<duplex>\S++)", "record", "start", "", ("duplex",)),)


def test_planted_unrecognised_line_is_partial():
    result = run_rules(b"duplex full\nnew firmware line\n", CaptureId("cap-a"), table(), ())
    assert result.quality == "partial"
    assert [line.status for line in result.lines] == ["consumed", "unrecognised"]
    assert len(result.records) == 1


def test_planted_unmapped_token_is_unknown_with_raw_kept():
    maps = (("duplex", TokenMap.closed({"half": Duplex.HALF, "full": Duplex.FULL})),)
    result = run_rules(b"duplex a-half\n", CaptureId("cap-a"), table(), maps)
    field = result.records[0].fields[0][1]
    assert result.quality == "partial"
    assert field.raw == "a-half"
    assert isinstance(field.value, Unknown)
    assert field.value.reason is UnknownReason.PARSE_PARTIAL
    assert field.value.evidence[0].locator == field.span
    assert result.tokens == (("duplex", field),)


def test_ordered_states_and_cited_ignore():
    rules = (
        Rule("open", "start", "BEGIN", "enter_state", "body", "", ()),
        Rule("blank", "body", "", "ignore", "body", CITATION, ()),
        Rule("value", "body", r"(?P<value>\d++)", "record", "body", "", ("value",)),
        Rule("close", "body", "END", "leave_state", "start", "", ()),
    )
    result = run_rules(b"BEGIN\r\n\r\n42\nEND", CaptureId("cap-a"), rules, ())
    assert result.quality == "complete"
    assert [line.rule_id for line in result.lines] == ["open", "blank", "value", "close"]
    assert result.lines[1].status == "ignored"
    assert result.records[0].fields[0][1].raw == "42"


def test_first_rule_wins_and_lone_cr_is_not_a_line_break():
    rules = (Rule("first", "start", r"(?P<value>[\s\S]*+)", "record", "start", "", ("value",)),
             Rule("second", "start", r"(?P<value>.*+)", "record", "start", "", ("value",)))
    result = run_rules(b"a\rb\r\n", CaptureId("cap-a"), rules, ())
    assert len(result.lines) == 1
    assert result.records[0].rule_id == "first"
    assert result.records[0].fields[0][1].raw == "a\rb"


def test_invalid_ignore_and_undeclared_capture_are_refused():
    import pytest

    for rule in (Rule("bad", "start", "", "ignore", "start", "", ()),
                 Rule("bad", "start", r"(?P<x>.*+)", "record", "start", "", ())):
        with pytest.raises(ValueError):
            run_rules(b"\n", CaptureId("cap-a"), (rule,), ())


def test_empty_capture_does_not_invent_a_record():
    result = run_rules(b"", CaptureId("cap-a"), table(), ())
    assert result.lines == result.records == ()


def test_runtime_token_map_rejects_plain_string_values():
    from typing import cast

    import pytest

    with pytest.raises(ValueError):
        TokenMap.closed({"full": cast(StrEnum, "full")})


@pytest.mark.parametrize("pattern", [r".*+", r"[\s\S]*+", r".?+"])
def test_planted_broad_ignore_cannot_hide_unknown_evidence(pattern):
    rule = Rule("swallow", "start", pattern, "ignore", "start", CITATION, ())
    with pytest.raises(ValueError):
        run_rules(b"unrecognised evidence\n", CaptureId("cap-a"), (rule,), ())


@pytest.mark.parametrize("reason", ["x", "fixture:blank", "https://example.com/doc#L1"])
def test_ignore_requires_a_pinned_source_line_citation(reason):
    rule = Rule("blank", "start", "", "ignore", "start", reason, ())
    with pytest.raises(ValueError):
        run_rules(b"\n", CaptureId("cap-a"), (rule,), ())


def test_cited_whitespace_ignore_preserves_an_unrecognised_line():
    rule = Rule("blank", "start", r"[ \t]*+", "ignore", "start", CITATION, ())
    result = run_rules(b" \t\nnew token\n", CaptureId("cap-a"), (rule,), ())
    assert result.quality == "partial"
    assert [line.status for line in result.lines] == ["ignored", "unrecognised"]


@pytest.mark.parametrize("rows", [
    [["full", Duplex.FULL]],
    (["full", Duplex.FULL],),
])
def test_mutable_rows_cannot_change_a_frozen_token_map(rows):
    from typing import cast

    with pytest.raises(ValueError):
        TokenMap(cast(tuple[tuple[str, StrEnum], ...], rows))


def test_closed_map_snapshots_the_source_dictionary():
    rows = {"full": Duplex.FULL}
    mapping = TokenMap.closed(rows)
    rows["full"] = Duplex.HALF
    result = run_rules(b"duplex full\n", CaptureId("cap-a"), table(), (("duplex", mapping),))
    assert result.records[0].fields[0][1].value is Duplex.FULL


@pytest.mark.parametrize("kind", ["enter_state", "leave_state", "record"])
def test_planted_no_value_catchall_cannot_consume_unknown_evidence(kind):
    rule = Rule("swallow", "start", ".*+", kind, "start", "", ())
    with pytest.raises(ValueError):
        run_rules(b"unknown evidence\n", CaptureId("cap-a"), (rule,), ())


@pytest.mark.parametrize("pattern", ["", ".", r"[A-Z]++", r"\w++"])
def test_no_value_rules_require_nonempty_fixed_literal_markers(pattern):
    rule = Rule("swallow", "start", pattern, "record", "start", "", ())
    with pytest.raises(ValueError):
        run_rules(b"unknown evidence\n", CaptureId("cap-a"), (rule,), ())


def test_literal_state_marker_does_not_hide_a_following_unknown_line():
    rule = Rule("marker", "start", r"BEGIN\(body\)", "enter_state", "start", "", ())
    result = run_rules(b"BEGIN(body)\nnew evidence\n", CaptureId("cap-a"), (rule,), ())
    assert result.quality == "partial"
    assert [line.status for line in result.lines] == ["consumed", "unrecognised"]
