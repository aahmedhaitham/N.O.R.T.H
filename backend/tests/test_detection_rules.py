import json
import random
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from cloud_sync import build_snapshot
from cloudtrail import normalize as normalize_cloudtrail

from detection_rules import (
    RuleError, active_rules, bundled_rules, condition_predicate, consume_detection_queue, evaluate_rules, field_predicate,
    parse_catalog, rule_workspace,
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
    return [normalize_record(item["source"], item) if "event_id" in item else normalize_cloudtrail(item) if "eventID" in item else normalize(item) for item in fixture]


@pytest.mark.parametrize("rule", bundled_rules(), ids=lambda rule: rule.id)
def test_bundled_rule_matches_positive_but_not_negative(rule):
    positive = [event_contract(event) for event in records(rule.fixtures["positive"], rule.id)]
    negative = [event_contract(event) for event in records(rule.fixtures["negative"], rule.id)]
    assert rule.evidence(positive)
    assert not rule.evidence(negative)


def test_catalog_minimum():
    assert len(bundled_rules()) >= 40


@pytest.mark.parametrize(("state", "problem", "kinds", "coverage"), [
    ("starting", None, [], "unchecked"),
    ("ready", None, [], "partly"),
    ("ready", None, [8], "covered"),
    ("unavailable", "channel_missing", [], "blind"),
    ("unavailable", "access_denied", [], "partly"),
    ("unavailable", "read_failed", [], "blind"),
])
def test_rule_catalog_uses_the_desktop_source_check(tmp_path, state, problem, kinds, coverage):
    store = Store(path=tmp_path / "coverage.sqlite3")
    store.initialize()
    response = rule_workspace(store, source_checks={"sysmon": {"state": state, "problem": problem, "kinds": kinds}})
    row = next(row for row in response["rules"] if row["id"] == "remote-thread-observed")
    assert row["coverage"] == coverage


def test_configured_rules_cover_observed_sources_and_preview_without_creating_findings(tmp_path):
    path = tmp_path / "rules.sqlite3"
    store = Store(path=path)
    store.initialize()
    now = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
    rule_id = "windows-service-installed"

    def entry(identity=rule_id):
        return next(item for item in rule_workspace(store, now=now)["rules"] if item["id"] == identity)

    assert entry()["coverage"] == "unchecked"
    store.save_source_health("system", "access_denied", now.isoformat())
    assert entry()["coverage"] == "partly"
    assert "needs admin" in entry()["requires"][0]["state"]
    store.save_source_health("system", "collecting", now.isoformat())
    assert entry()["coverage"] == "partly"
    event, = records("detections_positive.json", rule_id)[:1]
    assert event["kind"] == 7045
    store.ingest_local_windows([event])
    assert entry()["coverage"] == "covered"
    assert rule_workspace(store, now=now + timedelta(minutes=3))["techniques"]["attack.t1543.003"] == "unchecked"

    example = (Path(__file__).parents[1] / "rules.yaml").read_text(encoding="utf-8").split("\n- id:", 1)[0]
    with pytest.raises(RuleError, match="already exists"):
        rule_workspace(store, {"action": "import", "yaml": example})
    custom_id = "custom-service-observation"
    assert rule_workspace(store, {"action": "import", "yaml": example.replace(rule_id, custom_id)}) == {"imported": 1}
    assert not entry(custom_id)["enabled"]
    assert rule_workspace(store, {"action": "toggle", "id": rule_id, "enabled": False}) == {"enabled": False}
    store = Store(path=path)
    assert not entry()["enabled"]
    test = rule_workspace(store, {"action": "test", "id": rule_id})
    assert test["matches"][0]["evidence_ids"] == (event["id"],)
    assert test["trace"] == {"event_id": event["id"], "source_matches": True,
                             "selections": {"service_install": True}, "condition": True}
    assert store.detection_findings() == []
    assert consume_detection_queue(store, active_rules(store)) == 1
    assert store.detection_findings() == []


def test_yaml_correlations_preserve_legacy_evidence_groups():
    normalized = [normalize(item) for item in demo_alerts(include_linux=True)]
    cases = {case["title"]: tuple(event["id"] for event in case["evidence"]) for case in build_cases(normalized)}
    rules = [rule for rule in bundled_rules() if rule.id in ("powershell-script-write", "repeated-ssh-authentication-failures")]
    events = [event_contract(item) for item in reversed(normalized)]
    assert len(rules) == 2
    for rule in rules:
        assert rule.evidence(events) == [cases[rule.title]]


def test_yaml_threshold_does_not_count_duplicate_evidence_or_unidentified_assets():
    rule = next(rule for rule in bundled_rules() if rule.id == "repeated-ssh-authentication-failures")
    first, second, third = [event_contract(item) for item in records(rule.fixtures["positive"])]
    assert evaluate_rules([rule], [first, second, second])["matches"] == []
    assert rule.evidence([first, second, {**third, "asset_id": ""}]) == []


def test_yaml_threshold_includes_window_boundary_but_excludes_next_microsecond():
    rule = next(rule for rule in bundled_rules() if rule.id == "repeated-ssh-authentication-failures")
    first, second, third = [event_contract(item) for item in records(rule.fixtures["positive"])]
    start = datetime.fromisoformat(first["ts"])
    boundary = start + rule.correlation.window
    exact = {**third, "ts": boundary.isoformat(timespec="microseconds")}
    late = {**third, "ts": (boundary + timedelta(microseconds=1)).isoformat(timespec="microseconds")}
    assert rule.evidence([first, second, exact]) == [(first["id"], second["id"], third["id"])]
    assert rule.evidence([first, second, late]) == []


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


def test_seeded_mutations_of_rule_yaml_compile_or_fail_with_a_validation_error():
    sample = (Path(__file__).parents[1] / "rules.yaml").read_text(encoding="utf-8").split("\n- id:", 1)[0]
    rng = random.Random(1835)
    tokens = ["[", "}", ":", "?", "\x00", "\n", "[]", "{}", "'x'", "雪"]
    for _ in range(100):
        position = rng.randrange(len(sample))
        text = sample[:position] + rng.choice(tokens) + sample[position + rng.randrange(3):]
        try:
            rules = parse_catalog(text)
        except RuleError:
            continue
        assert len(rules) == 1 and rules[0].id


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
        assert client.get("/api/local/findings").json() == {
            "findings": [], "has_more": False, "summary": {"unreviewed": 0, "severe": 0},
        }
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
    assert all(item["rarity"] == "first seen" for item in store.detection_findings())
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

@pytest.mark.parametrize(
    "rule",
    [rule for rule in bundled_rules() if rule.fixtures["positive"] == "rule_catalog_positive.json"
     and rule.correlation is None],
    ids=lambda rule: rule.id,
)
def test_keyed_single_event_fixtures_match_individually(rule):
    positive = records(rule.fixtures["positive"], rule.id)
    negative = records(rule.fixtures["negative"], rule.id)
    assert len(positive) >= 3 and len(negative) >= 3
    assert all(rule.evidence([event_contract(event)]) for event in positive)
    assert not any(rule.evidence([event_contract(event)]) for event in negative)


def test_rule_replay_traces_selected_nonmatch_and_reports_sample_rate(tmp_path):
    store = Store(path=tmp_path / "rule-replay.sqlite3")
    store.initialize()
    matching = records("detections_positive.json", "windows-service-installed")[0]
    nonmatching = records("detections_negative.json", "windows-service-installed")[0]
    nonmatching["timestamp"] = "2026-01-15T12:00:00+00:00"
    store.ingest_local_windows([matching, nonmatching])
    result = rule_workspace(store, {"action": "test", "id": "windows-service-installed",
                                    "event_id": nonmatching["id"]})
    assert result["event_ids"] == [nonmatching["id"], matching["id"]]
    assert result["trace"] == {"event_id": nonmatching["id"], "source_matches": False,
                                "selections": {"service_install": False}, "condition": False}
    assert result["noise"] == {"alerts": 1, "hours": 2, "alerts_per_day": 12}
    assert store.detection_findings() == []


def test_discovery_uses_distinct_names_and_separates_parents():
    rule = next(rule for rule in bundled_rules() if rule.id == "discovery-utility-burst")
    good = [event_contract(event) for event in records(rule.fixtures["positive"], rule.id)]
    bad = [event_contract(event) for event in records(rule.fixtures["negative"], rule.id)]
    assert len(rule.evidence(list(reversed(good)))) == 3
    assert not rule.evidence(bad)
    replay = evaluate_rules([rule], good)
    from detection_rules import findings_from_matches
    findings = list(findings_from_matches(replay["matches"], good))
    assert len(findings) == 3
    assert all(item["confidence"] == "correlated" and item["rarity"] == "unknown" for item in findings)

@pytest.mark.parametrize("identity", ["powershell-script-write", "repeated-ssh-authentication-failures", "periodic-dns-query"])
def test_existing_correlations_replay_independent_positive_and_near_miss_scenarios(identity):
    rule = next(rule for rule in bundled_rules() if rule.id == identity)
    projected = [event_contract(event) for event in records(rule.fixtures["positive"], identity)]
    group = rule.evidence(projected)[0]
    by_id = {item["id"]: item for item in projected}
    examples = [by_id[event_id] for event_id in group]
    ordered = sorted(examples, key=lambda item: item["ts"])

    for minutes in (0, 6, 21):
        shifted = [
            {**event, "id": f"{event['id']}-{minutes}",
             "ts": (datetime.fromisoformat(event["ts"]) + timedelta(minutes=minutes)).isoformat()}
            for event in ordered
        ]
        assert len(rule.evidence(shifted)) == 1

    wrong_source = [{**event, "source": "synthetic-other"} for event in ordered]
    late = {**ordered[-1], "ts": (datetime.fromisoformat(ordered[0]["ts"])
                                  + rule.correlation.window + timedelta(seconds=1)).isoformat()}
    keyless = [{**event, "host": "", "asset_id": "", "process": {**event["process"], "guid": ""},
                "dns": {"query": ""}, "network": {**event["network"], "src": {"ip": ""}}} for event in ordered]
    assert not rule.evidence(wrong_source)
    assert not rule.evidence(keyless)
    if identity == "powershell-script-write":
        assert not rule.evidence([ordered[0], {**late, **{"file": {"path": "C:/Example/fixture.ps1"},
                                                       "raw": {"event_type": 11}}}])
    else:
        assert not rule.evidence([*ordered[:-1], late])

def test_rule_finding_uses_learned_process_baseline(tmp_path):
    store = Store(path=tmp_path / "scoring.sqlite3")
    store.initialize()
    start = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    rule = next(rule for rule in bundled_rules() if rule.id == "powershell-encoded-command")

    def ingest(number, at, folder, arguments):
        event = normalize_record("security", {
            "host": "WIN-SYNTHETIC", "event_id": 4688, "record_id": number, "timestamp": at.isoformat(),
            "fields": {"NewProcessName": fr"C:\Example\{folder}\powershell.exe", "CommandLine": arguments},
        })
        store.ingest_local_windows([event])
        consume_detection_queue(store, [rule], now=at, learning_hours=1)

    ingest(1, start, "known", "synthetic normal")
    ingest(2, start + timedelta(hours=2), "known", "synthetic -enc AAAA")
    ingest(3, start + timedelta(hours=3), "new", "synthetic -enc AAAA")
    findings = [item for item in store.detection_findings() if item["rule_id"] == rule.id]
    assert [item["rarity"] for item in findings] == ["first seen", "previously observed"]
    assert all(item["confidence"] == "single observation" for item in findings)

def test_recorded_sensor_check_requires_confirmation_and_does_not_write_findings(tmp_path):
    store = Store(path=tmp_path / "sensor-check.sqlite3")
    store.initialize()
    event = records("detections_positive.json", "windows-service-installed")[0]
    store.ingest_local_windows([event])
    command = {"action": "verify-sensors"}
    with pytest.raises(RuleError, match="Confirm"):
        rule_workspace(store, command)
    report = rule_workspace(store, {**command, "confirmed": True})
    by_id = {row["id"]: row for row in report["results"]}
    assert report["verified"] == 1
    assert by_id["windows-service-installed"]["evidence_ids"] == (event["id"],)
    assert by_id["scheduled-task-created"]["outcome"] == "source_unchecked"
    assert store.detection_findings() == []
    with store.connect() as db:
        persisted, = db.execute("SELECT payload FROM local_sensor_verification").fetchone()
    assert json.loads(persisted)["verified"] == 1
    assert rule_workspace(store)["sensor_report"]["verified"] == 1

@pytest.mark.parametrize(("source_state", "expected"), [
    ("not_installed", "source_missing"),
    ("access_denied", "access_denied"),
    ("misconfigured", "logging_disabled"),
    ("read_failed", "source_unavailable"),
    ("unknown", "source_unchecked"),
    ("collecting", "event_not_collected"),
])
def test_recorded_sensor_check_explains_missing_signal(source_state, expected):
    from detection_rules import recorded_sensor_check

    rule = next(candidate for candidate in bundled_rules() if candidate.id == "windows-service-installed")
    result, = recorded_sensor_check([rule], set(), [], {"system": source_state})
    assert result["outcome"] == expected
    result, = recorded_sensor_check([rule], {rule.id}, [], {"system": source_state})
    assert result["outcome"] == "rule_disabled"

def test_sensor_coverage_needs_fresh_source_and_independent_finding(tmp_path):
    store = Store(path=tmp_path / "verified.sqlite")
    store.initialize()
    event = records("detections_positive.json", "windows-service-installed")[0]
    now = datetime.fromisoformat(event["timestamp"])
    store.ingest_local_windows([event])
    store.save_source_health("system", "collecting", now.isoformat())

    def coverage(at):
        return rule_workspace(store, now=at)["techniques"]["attack.t1543.003"]

    rule_workspace(store, {"action": "verify-sensors", "confirmed": True}, now=now)
    assert coverage(now) == "covered"
    assert consume_detection_queue(store, bundled_rules(), now=now) == 1
    assert coverage(now) == "verified"
    assert coverage(now + timedelta(minutes=3)) != "verified"
    later = now + timedelta(days=1)
    store.save_source_health("system", "collecting", later.isoformat())
    assert coverage(later) == "covered"
    rule_workspace(store, {"action": "toggle", "id": "windows-service-installed", "enabled": False}, now=now)
    assert coverage(now) != "verified"

@pytest.mark.parametrize(
    "rule", [rule for rule in bundled_rules() if rule.logsource.get("source") == "cloudtrail"], ids=lambda rule: rule.id,
)
def test_cloudtrail_fixture_scenarios(rule):
    positives = [event_contract(item) for item in records(rule.fixtures["positive"], rule.id)]
    negatives = [event_contract(item) for item in records(rule.fixtures["negative"], rule.id)]
    assert len(negatives) >= 3
    assert len(rule.evidence(positives)) == 3
    assert not rule.evidence(negatives)
