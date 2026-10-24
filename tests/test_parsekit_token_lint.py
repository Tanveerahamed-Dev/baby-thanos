"""Sealed token-map runtime refusals; full source-policy regressions follow in B."""
import pytest

from atlas_brain.evidence.parsekit.rules import TokenMap


def test_token_map_refuses_subclasses():
    with pytest.raises(TypeError):
        type("FallbackMap", (TokenMap,), {})


def test_rule_engine_rejects_a_foreign_fallback_resolver_before_calling_it():
    from typing import cast

    from atlas_brain.evidence.parsekit.rules import Rule, run_rules
    from atlas_brain.kernel.states import CaptureId

    class FallbackMap:
        def resolve(self, field, capture):
            raise AssertionError("foreign resolver was executed")

    rule = Rule("value", "start", r"duplex (?P<duplex>\S++)", "record", "start", "", ("duplex",))
    with pytest.raises(ValueError):
        run_rules(b"duplex a-half\n", CaptureId("cap-a"), (rule,),
                  (("duplex", cast(TokenMap, FallbackMap())),))
