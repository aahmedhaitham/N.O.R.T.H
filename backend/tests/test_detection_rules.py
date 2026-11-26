import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from detection_rules import RuleError, bundled_rules, condition_predicate, evaluate_rules, field_predicate, parse_catalog
from event_contract import event_contract
from main import demo_alerts, make_app
from north import Store, build_cases, normalize
from windows_sources import normalize_record


FIXTURES = Path(__file__).parents[1] / "fixtures"


def records(name):
    return [normalize_record(item["source"], item) if "event_id" in item else normalize(item)
            for item in json.loads((FIXTURES / name).read_text(encoding="utf-8"))]


@pytest.mark.parametrize("rule", bundled_rules(), ids=lambda rule: rule.id)
def test_bundled_rule_matches_positive_but_not_negative(rule):
    positive = [event_contract(event) for event in records(rule.fixtures["positive"])]
    negative = [event_contract(event) for event in records(rule.fixtures["negative"])]
    assert rule.evidence(positive)
    assert not rule.evidence(negative)


def test_yaml_correlations_preserve_legacy_evidence_groups():
    normalized = [normalize(item) for item in demo_alerts(include_linux=True)]
    cases = {case["title"]: tuple(event["id"] for event in case["evidence"]) for case in build_cases(normalized)}
    rules = [rule for rule in bundled_rules() if rule.correlation]
    events = [event_contract(item) for item in reversed(normalized)]
    assert len(rules) == 2
    for rule in rules:
        assert rule.evidence(events) == [cases[rule.title]]


def test_yaml_threshold_does_not_count_duplicate_evidence_or_unidentified_assets():
    rule = next(rule for rule in bundled_rules() if rule.id == "repeated-ssh-authentication-failures")
    first, second, third = [event_contract(item) for item in records(rule.fixtures["positive"])]
    assert evaluate_rules([rule], [first, second, second])["matches"] == []
    assert rule.evidence([first, second, {**third, "asset_id": ""}]) == []


@pytest.mark.parametrize(("modifier", "values", "passes"), [
    ("", "example.exe", True),
    ("|contains", ["missing", "ample"], True),
    ("|contains|all", ["ample", ".exe"], True),
    ("|contains|all", ["ample", "missing"], False),
    ("|startswith", "example", True),
    ("|endswith", ".dll", False),
    ("|re", r"^ex[a-z]+\.exe$", True),
])
def test_field_modifiers(modifier, values, passes):
    predicate = field_predicate("ProcessName" + modifier, values)
    assert predicate({"process": {"name": "Example.EXE"}}) is passes
    assert not predicate({"process": {}})


def test_boolean_precedence_and_grouping():
    predicates = {key: lambda event, name=key: event[name] for key in ("one", "two", "three")}
    event = {"one": True, "two": False, "three": True}
    assert condition_predicate("one or two and not three", predicates)(event)
    assert not condition_predicate("(one or two) and not three", predicates)(event)
    with pytest.raises(RuleError):
        condition_predicate("one and unknown", predicates)


@pytest.mark.parametrize("text", ["- &alias {a: 1}\n- *alias", "- {id: yes, id: no}", "[[[[[[[[[[[[[0]]]]]]]]]]]]]", "- {}"])
def test_rejects_untrusted_yaml_sections(text):
    with pytest.raises(RuleError):
        parse_catalog(text)


def test_timeout_under_negation_is_neither_negative_nor_positive(monkeypatch):
    class Pattern:
        def search(self, _value, *, timeout):
            assert timeout > 0
            raise TimeoutError

    monkeypatch.setattr("detection_rules.regex.compile", lambda *_args: Pattern())
    rule, = parse_catalog("""
- id: test-timeout
  title: Synthetic test
  severity: low
  tags: [attack.t1055]
  logsource: {source: sysmon}
  falsepositives: [Synthetic data]
  plain_summary: Synthetic summary
  what_to_do: Check the synthetic input
  requires: [sysmon]
  tests: {positive: positive.json, negative: negative.json}
  detection:
    excluded: {'ProcessName|re': example}
    condition: not excluded
""")
    assert evaluate_rules([rule], [{"id": "fixture", "source": "sysmon", "process": {"name": "test"}}]) == {
        "matches": [], "timed_out_rule_ids": [rule.id],
    }


def test_loopback_detections_return_only_stored_evidence_ids(tmp_path):
    store = Store(path=tmp_path / "detections.sqlite3")
    store.initialize()
    events = records("detections_positive.json")
    store.ingest_local_windows(events, checkpoint=("fixture", 5))
    store.ingest(demo_alerts(include_linux=True))
    with TestClient(make_app(store), base_url="http://localhost") as client:
        assert client.get("/api/local/detections").status_code == 401
        assert client.post("/api/local-session", headers={"X-North-Local-Session": "start"}).status_code == 200
        result = client.get("/api/local/detections").json()
        assert len(result["matches"]) == len(bundled_rules())
        assert {identity for item in result["matches"] for identity in item["evidence_ids"]} == {
            event["id"] for event in [*events, *store.events()]
        }
        assert not result["timed_out_rule_ids"]
