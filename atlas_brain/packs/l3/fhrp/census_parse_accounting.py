"""Physical LF accounting for an owned unresolved synthetic census parse."""
from atlas_brain.evidence.admission import BudgetExceeded
from atlas_brain.evidence.parsekit import rules
from atlas_brain.kernel import states as k
from atlas_brain.packs.l3.fhrp import parse_hsrp_census as census


def refused_parse_accounting(
    result: census.Result, original_raw: bytes, *, max_bytes: int, max_lines: int,
) -> rules.ParseResult:
    """Use the caller's retained parser result and raw bytes, without proving their origin.

    An existing partial parse remains the original record. The limits bound
    additional physical line accounting when the parser produced no record.
    """
    k.require(type(result) is census.Result and type(original_raw) is bytes, "hsrp_census_negative_accounting")
    k.require(type(max_bytes) is int and max_bytes >= 0 and type(max_lines) is int and max_lines >= 0,
              "hsrp_census_accounting_limits")
    detail = result.detail
    if result.census is not None or type(result.reason) is not k.UnknownReason or type(detail) is not str or not detail:
        raise ValueError("hsrp_census_negative_accounting")
    parsed = result.parse
    if parsed is not None:
        k.require(type(parsed) is rules.ParseResult and type(parsed.quality) is str and parsed.quality == "partial",
                  "hsrp_census_negative_accounting")
        return parsed

    length = len(original_raw)
    if length > max_bytes:
        raise BudgetExceeded("hsrp_census_negative_accounting")
    line_count = original_raw.count(b"\n") + int(length > 0 and not original_raw.endswith(b"\n"))
    if line_count > max_lines:
        raise BudgetExceeded("hsrp_census_negative_accounting")
    lines: list[rules.LineAccounting] = []
    start = 0
    while start < length:
        lf = original_raw.find(b"\n", start)
        end = length if lf < 0 else lf + 1
        lines.append(rules.LineAccounting(k.ByteSpan(start=start, end=end), "unrecognised", "", detail))
        start = end
    return rules.ParseResult((), tuple(lines), (), "partial")
