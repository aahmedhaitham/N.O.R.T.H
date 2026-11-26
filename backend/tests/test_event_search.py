import json
import sqlite3

from north import Store


def test_iris_search_backfills_old_events_and_preserves_literal_matching(tmp_path):
    filename = tmp_path / "existing.sqlite3"
    timestamp = "2026-01-15T12:00:00.000000+00:00"
    with sqlite3.connect(filename) as connection:
        connection.execute("CREATE TABLE events(id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL)")
        items = [("first", "RARE-Test.exe"), ("second", "rare_test.exe")]
        connection.executemany("INSERT INTO events VALUES (?, ?, ?)", [
            (identifier, timestamp, json.dumps({"id": identifier, "timestamp": timestamp, "process": process}))
            for identifier, process in items
        ])
    store = Store(path=filename)
    store.initialize()
    assert [event["id"] for event in store.event_page(search="rare-test.exe")["events"]] == ["first"]
    assert [event["id"] for event in store.event_page(search="rare_test.exe")["events"]] == ["second"]
    assert len(store.event_page(search="RA")["events"]) == 2
    assert store.event_page(search="%")["events"] == []
    with store.connect() as connection:
        connection.execute("DELETE FROM events WHERE id = ?", ("first",))
    assert store.event_page(search="rare-test.exe")["events"] == []
