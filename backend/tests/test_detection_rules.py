import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from cloud_sync import build_snapshot

from detection_rules import (
    RuleError, bundled_rules, condition_predicate, consume_detection_queue, evaluate_rules, field_predicate, parse_catalog,
)
from event_contract import event_contract
from main import demo_alerts, make_app
from north import Store, build_cases, normalize
from windows_sources import normalize_record


FIXTURES = Path(__file__).parents[1] / "fixtures"


def records(name, rule_id=None):
    fixture = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    if isinstance(fixture, dict):
        fixture = fixture[rule_id] if rule_id else [item for group in fixture.values() for item in group]
    return [normalize_record(item["source"], item) if "event_id" in item else normalize(item) for item in fixture]


@pytest.mark.parametrize("rule", bundled_rules(), ids=lambda rule: rule.id)
def test_bundled_rule_matches_positive_but_not_negative(rule):
    positive = [event_contract(event) for event in records(rule.fixtures["positive"], rule.id)]
    negative = [event_contract(event) for event in records(rule.fixtures["negative"], rule.id)]
    assert rule.evidence(positive)
    assert not rule.evidence(negative)


def test_catalog_minimum():
    assert len(bundled_rules()) >= 40


def test_yaml_correlations_preserve_legacy_evidence_groups():
    normalized = [normalize(item) for item in demo_alerts(include_linux=True)]
    cases = {case["title"]: tuple(event["id"] for event in case["evidence"]) for case in build_cases(normalized)}
    rules = [rule for rule in bundled_rules() if rule.correlation and rule.correlation.kind in ("threshold", "sequence")]
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
        assert len(result["matches"]) == 7
        assert {identity for item in result["matches"] for identity in item["evidence_ids"]} == {
            event["id"] for event in [*events, *store.events()]
        }
        assert not result["timed_out_rule_ids"]


def test_persisted_findings_keep_reviews_and_link_stored_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("NORTH_AUTO_DETECTIONS", "0")
    path = tmp_path / "findings.sqlite3"
    store = Store(path=path)
    store.initialize()
    event = records("detections_positive.json")[0]
    store.ingest_local_windows([event], checkpoint=("fixture", 1))
    with TestClient(make_app(store), base_url="http://localhost") as client:
        assert client.post("/api/local/findings/evaluate").status_code == 401
        client.post("/api/local-session", headers={"X-North-Local-Session": "start"})
        assert client.get("/api/local/findings").json() == {"findings": []}
        assert client.post("/api/local/findings/evaluate").json()["matched_findings"] >= 1
        finding = next(item for item in client.get("/api/local/findings").json()["findings"]
                       if item["rule_id"] == "windows-service-installed")
        assert finding["status"] == "new"
        assert finding["evidence_ids"] == [event["id"]]
        assert finding["first_seen"] == finding["last_seen"] == event["timestamp"]
        evidence = client.get("/api/local/evidence/" + event["id"]).json()
        assert evidence["id"] == event["id"]
        review = "/api/local/findings/" + finding["id"] + "/review"
        assert client.post(review, json={"status": "deleted"}).status_code == 422
        assert client.post(review, json={"status": "benign"}).status_code == 200
        assert client.post("/api/local/findings/evaluate").status_code == 200
    reopened = Store(path=path)
    assert [item["status"] for item in reopened.detection_findings() if item["id"] == finding["id"]] == ["benign"]
    snapshot, _, _ = build_snapshot(reopened, {}, {}, "https://north.example")
    assert finding["id"].encode() not in snapshot
    assert event["id"].encode() not in snapshot


def test_detection_queue_survives_restart_and_uses_prior_context(tmp_path):
    path = tmp_path / "queue.sqlite3"
    store = Store(path=path)
    store.initialize()
    first, connection, write = demo_alerts()
    store.ingest([first, connection], enqueue=False)
    store.ingest([write, write])
    store = Store(path=path)
    rules = bundled_rules()
    assert consume_detection_queue(store, rules) == 1
    finding, = store.detection_findings()
    assert finding["evidence_ids"] == [normalize(raw)["id"] for raw in (first, connection, write)]
    store.set_finding_status(finding["id"], "reviewed")
    assert store.ingest([write]) == 0
    assert consume_detection_queue(store, rules) == 0
    assert store.detection_findings()[0]["status"] == "reviewed"


def test_detection_queue_ack_and_findings_share_a_transaction(tmp_path):
    store = Store(path=tmp_path / "rollback.sqlite3")
    store.initialize()
    store.ingest_local_windows(records("detections_positive.json")[:1], checkpoint=("fixture", 1))
    with store.connect() as db:
        db.execute("""CREATE TRIGGER synthetic_failure BEFORE DELETE ON local_detection_queue
                      BEGIN SELECT RAISE(ABORT, 'fixture'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        consume_detection_queue(store, bundled_rules())
    assert store.detection_findings() == []
    assert len(store.pending_detections()) == 1
    with store.connect() as db:
        db.execute("DROP TRIGGER synthetic_failure")
    assert consume_detection_queue(store, bundled_rules()) == 1
    assert not store.pending_detections()
    assert len(store.detection_findings()) == 1


def test_local_service_consumes_queue_on_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("NORTH_AUTO_DETECTIONS", "1")
    store = Store(path=tmp_path / "startup.sqlite3")
    store.initialize()
    event = records("detections_positive.json")[0]
    store.ingest_local_windows([event], checkpoint=("fixture", 1))
    with TestClient(make_app(store), base_url="http://localhost") as client:
        client.post("/api/local-session", headers={"X-North-Local-Session": "start"})
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            items = client.get("/api/local/findings").json()["findings"]
            if items:
                assert items[0]["evidence_ids"] == [event["id"]]
                break
            time.sleep(.05)
        else:
            pytest.fail("Background detection did not consume the startup queue")


def test_first_seen_baselines_learn_then_alert_once_and_stay_local(tmp_path):
    path = tmp_path / "baseline.sqlite3"
    store = Store(path=path)
    store.initialize()
    start = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    rules = bundled_rules()

    def record(identity, at, image, *, destination=None, outbound=True, host="WIN-SYNTHETIC"):
        fields = {"Image": image}
        if destination:
            fields.update(DestinationIp=destination, Initiated=str(outbound).lower())
        return normalize_record("sysmon", {
            "host": host, "event_id": 3 if destination else 1, "record_id": identity,
            "timestamp": (start + timedelta(hours=at)).isoformat(), "fields": fields,
        })

    def ingest(records, hours):
        store.ingest_local_windows(records, checkpoint=("fixture", max(int(event["source_event_id"]) for event in records)))
        assert consume_detection_queue(store, rules, now=start + timedelta(hours=hours), learning_hours=1) == len(records)

    ingest([record(1, 0, r"C:\Example\baseline.exe"),
            record(2, 0, r"C:\Example\baseline.exe", destination="192.0.2.42")], 0)
    assert store.detection_findings() == []
    store = Store(path=path)
    new_process = record(3, 1, r"C:\Example\new.exe")
    new_destination = record(4, 1, r"C:\Example\baseline.exe", destination="192.0.2.43")
    ingest([new_process, new_destination], 1)
    assert {finding["rule_id"]: finding["evidence_ids"] for finding in store.detection_findings()} == {
        "first-seen-process-path": [new_process["id"]],
        "first-seen-process-destination": [new_destination["id"]],
    }
    ingest([record(5, 2, r"c:\example\NEW.exe"),
            record(6, 2, r"C:\Example\baseline.exe", destination="192.0.2.43"),
            record(7, 0.5, r"C:\Example\old-import.exe"),
            record(8, 2, r"C:\Example\baseline.exe", destination="192.0.2.44", outbound=False),
            record(9, 2, r"C:\Example\other.exe", host="WIN-OTHER-SYNTHETIC")], 2)
    findings = store.detection_findings()
    assert len(findings) == 2
    payload, _, _ = build_snapshot(store, {}, {}, "https://north.example")
    assert all(finding["id"].encode() not in payload for finding in findings)

    ingest([record(i, 2.5, r"C:\Example\other.exe",
                   destination="192.0.2.50" if i == 29 else "192.0.2.51",
                   host="WIN-OTHER-SYNTHETIC") for i in range(10, 30)], 2.5)
    rare = record(30, 3.5, r"C:\Example\other.exe", destination="192.0.2.50", host="WIN-OTHER-SYNTHETIC")
    ingest([rare, record(31, 3.5, r"C:\Example\other.exe", destination="192.0.2.51",
                        host="WIN-OTHER-SYNTHETIC")], 3.5)
    ingest([record(32, 4, r"C:\Example\other.exe", destination="192.0.2.50",
                   host="WIN-OTHER-SYNTHETIC")], 4)
    frequency_findings = [item for item in store.detection_findings() if item["rule_id"] == "rare-process-destination"]
    assert [item["evidence_ids"] for item in frequency_findings] == [[rare["id"]]]
