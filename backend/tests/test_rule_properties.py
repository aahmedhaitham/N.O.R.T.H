from pathlib import Path

from hypothesis import given, settings, strategies as st

from detection_rules import RuleError, parse_catalog

SAMPLE = (Path(__file__).parents[1] / "rules.yaml").read_text(encoding="utf-8").split("\n- id:", 1)[0]


@settings(max_examples=100, derandomize=True)
@given(st.integers(min_value=0, max_value=len(SAMPLE)), st.text(max_size=16))
def test_rule_parser_rejects_or_compiles_arbitrary_edits(offset, replacement):
    candidate = SAMPLE[:offset] + replacement + SAMPLE[offset + 1:]
    try:
        rules = parse_catalog(candidate)
    except RuleError:
        return
    assert len(rules) == 1
    assert rules[0].id and callable(rules[0].predicate)
