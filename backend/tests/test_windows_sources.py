import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cloud_sync import build_snapshot
from device_watch import record_snapshot
from detection_rules import bundled_rules, consume_detection_queue
from main import demo_alerts, make_app
from north import Store
from windows_sources import collect_source, collect_tcp_sample


def sample():
    return {
        "host": "WIN-SYNTHETIC", "event_id": 4688, "record_id": 41,
        "timestamp": "2026-01-15T12:00:00+02:00",
        "fields": {
            "NewProcessName": r"C:\Example\test.exe", "NewProcessId": "0x20",
            "CommandLine": "synthetic-local-only-marker", "UnlistedField": "discard-this",
        },
    }


def test_rich_records_are_resumable_and_excluded_from_cloud(tmp_path, monkeypatch):
    store = Store(path=tmp_path / "windows.sqlite3")
    store.initialize()
    store.ingest(demo_alerts())
    args = []

    def run(command, **_kwargs):
        args.append(command)
        return SimpleNamespace(stdout=json.dumps({"state": "collecting", "position": 41, "events": [sample()]}))

    monkeypatch.setattr("windows_sources.subprocess.run", run)
    assert collect_source(store, "security") == ("collecting", 1)
    assert collect_source(store, "security") == ("collecting", 1)
    assert args[0][-4:] == ["-Source", "security", "-After", "0"]
    assert args[1][-4:] == ["-Source", "security", "-After", "41"]
    event, = store.local_windows_events()
    assert event["timestamp"] == "2026-01-15T10:00:00.000000+00:00"
    assert "UnlistedField" not in event["raw"]
    snapshot, _, pending = build_snapshot(store, {}, {}, "https://north.example")
    assert len(pending) == 3
    assert event["id"].encode() not in snapshot
    assert b"synthetic-local-only-marker" not in snapshot
    with TestClient(make_app(store), base_url="http://localhost") as client:
        assert client.get("/api/local/windows-events").status_code == 401
        assert client.post("/api/local-session", headers={"X-North-Local-Session": "start"}).status_code == 200
        item, = client.get("/api/local/windows-events?limit=1").json()["events"]
        assert item["id"] == event["id"]
        assert item["process"]["pid"] == 32
        assert item["process"]["cmdline"] == "synthetic-local-only-marker"


def test_invalid_windows_batch_does_not_advance_cursor(tmp_path, monkeypatch):
    store = Store(path=tmp_path / "invalid.sqlite3")
    store.initialize()
    batch = {"state": "collecting", "position": 42, "events": [sample()]}
    monkeypatch.setattr("windows_sources.subprocess.run",
                        lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps(batch)))
    with pytest.raises(ValueError, match="cursor ordering"):
        collect_source(store, "security")
    assert store.local_windows_events() == []
    assert store.collection_offset("local-windows:security") == 0
    batch.update(state="access_denied", position=99, events=[])
    assert collect_source(store, "security") == ("access_denied", 0)
    assert store.collection_offset("local-windows:security") == 0


def test_local_tcp_snapshot_and_neighbor_cite_stored_evidence(tmp_path, monkeypatch):
    store = Store(path=tmp_path / "network.sqlite3")
    store.initialize()
    rows = [{"state": "Listen", "pid": 12, "process": "synthetic",
             "local_address": "::", "local_port": 8123, "remote_address": "::", "remote_port": 0}]
    def run(_args, **_kwargs):
        return SimpleNamespace(stdout=json.dumps(
            {"state": "ready", "rows": rows, "limited": False, "listeners_limited": False}))

    monkeypatch.setattr("windows_sources.subprocess.run", run)
    assert collect_tcp_sample(store) == ("collecting", 1)
    assert collect_tcp_sample(store) == ("collecting", 1)
    assert store.tcp_snapshots()[0]["rows"] == rows
    local, = store.local_windows_events()
    assert local["source"] == "windows_tcp"
    assert local["raw"]["LocalPort"] == "8123"
    record_snapshot(store, [{"address": "192.0.2.1", "interface": "Test LAN", "mac": "02:00:00:00:00:01"}],
                    "2026-01-15T00:00:00.000000+00:00")
    record_snapshot(store, [{"address": "192.0.2.2", "interface": "Test LAN", "mac": "02:00:00:00:00:02"}],
                    "2026-01-15T00:01:00.000000+00:00")
    assert consume_detection_queue(store, bundled_rules()) == 2
    finding, = store.detection_findings()
    assert finding["rule_id"] == "new-lan-neighbor"
    evidence = store.local_evidence(finding["evidence_ids"][0])
    assert evidence["raw"]["addresses"] == ["192.0.2.2"]
    snapshot, _, pending = build_snapshot(store, {}, {}, "https://north.example")
    assert pending == []
    assert local["id"].encode() not in snapshot
    assert evidence["id"].encode() not in snapshot


def test_standalone_local_monitor_stops_at_parent_eof(tmp_path, monkeypatch):
    import asyncio
    import io
    from types import SimpleNamespace

    import run_collector

    started = []

    async def watch(store):
        started.append(store.path)
        await asyncio.Event().wait()

    database = tmp_path / "desktop.sqlite3"
    monkeypatch.setenv("NORTH_DB_PATH", str(database))
    monkeypatch.setattr(run_collector.sys, "stdin", SimpleNamespace(buffer=io.BytesIO()))
    monkeypatch.setattr(run_collector, "NeighborMonitor", lambda store, _: SimpleNamespace(run=lambda: watch(store)))
    monkeypatch.setattr(run_collector, "WindowsSources", lambda store, _: SimpleNamespace(run=lambda: watch(store)))
    monkeypatch.setattr(run_collector, "run_detection_monitor", watch)
    asyncio.run(asyncio.wait_for(run_collector.collect_local(), timeout=5))
    assert database.is_file()
    assert len(started) == 3

def test_sysmon_file_creation_is_collected_and_counts_toward_rule_coverage(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    from detection_rules import rule_workspace
    from event_contract import event_contract

    store = Store(path=tmp_path / "file-create.sqlite3")
    store.initialize()
    start = sample()
    start.update(event_id=1, fields={"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"})
    create = dict(start, event_id=11, record_id=42, fields={"TargetFilename": r"C:\Example\sample.ps1"})
    batch = {"state": "collecting", "position": 42, "events": [start, create]}
    monkeypatch.setattr("windows_sources.subprocess.run",
                        lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps(batch)))

    assert collect_source(store, "sysmon") == ("collecting", 2)
    event = next(event for event in store.local_windows_events() if event["kind"] == 11)
    assert event_contract(event)["file"]["path"] == create["fields"]["TargetFilename"]

    now = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    store.save_source_health("sysmon", "collecting", now.isoformat())
    catalog = rule_workspace(store, now=now)
    rule = next(row for row in catalog["rules"] if row["id"] == "powershell-script-write")
    assert rule["coverage"] == "covered"

def test_passive_source_health_tracks_quiet_failure_and_recovery(tmp_path):
    from datetime import datetime, timedelta, timezone
    from windows_sources import source_snapshot

    store = Store(path=tmp_path / "health.sqlite")
    store.initialize()
    now = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    initial = {"fix": "Check the Sysmon log."}

    waiting = source_snapshot(initial, "no_data", 0, None, now, expect_activity=True)
    assert waiting["health"] == "waiting"
    assert store.record_source_snapshot("sysmon", waiting) == waiting
    assert store.detection_findings() == []

    observed = source_snapshot(waiting, "collecting", 1, now.isoformat(), now, expect_activity=True)
    store.record_source_snapshot("sysmon", observed)
    quiet = source_snapshot(observed, "no_data", 0, None, now + timedelta(hours=1), expect_activity=True)
    assert quiet["health"] == "quiet"
    assert quiet["last_event_at"] == now.isoformat()
    store.record_source_snapshot("sysmon", quiet)
    store.record_source_snapshot("sysmon", quiet)
    assert len(store.detection_findings()) == 1

    denied = source_snapshot(quiet, "access_denied", 0, None, now + timedelta(hours=2), expect_activity=True)
    store.record_source_snapshot("sysmon", denied)
    assert store.source_snapshot("sysmon")["health"] == "unavailable"
    assert len(store.detection_findings()) == 2
    recovered_at = now + timedelta(hours=3)
    recovered = source_snapshot(denied, "collecting", 1, recovered_at.isoformat(), recovered_at, expect_activity=True)
    store.record_source_snapshot("sysmon", recovered)
    assert store.source_snapshot("sysmon")["health"] == "observed"
    assert len(store.detection_findings()) == 2
    assert source_snapshot(observed, "no_data", 0, None, recovered_at)["health"] == "observed"

def test_recorded_windows_audit_policy_change_links_evidence_once(tmp_path):
    store = Store(path=tmp_path / "audit-policy.sqlite3")
    store.initialize()
    record = sample()
    record.update(event_id=4719, fields={"AuditPolicyChanges": "synthetic change"})
    from windows_sources import normalize_record

    event = normalize_record("security", record)
    store.ingest_local_windows([event])
    assert consume_detection_queue(store, bundled_rules()) == 1
    finding, = store.detection_findings()
    assert finding["rule_id"] == "windows-audit-policy-change"
    assert finding["evidence_ids"] == [event["id"]]
    assert store.local_evidence(event["id"])["raw"]["AuditPolicyChanges"] == "synthetic change"
    assert consume_detection_queue(store, bundled_rules()) == 0
