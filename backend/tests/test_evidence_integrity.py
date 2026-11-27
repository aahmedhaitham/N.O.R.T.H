import pytest

from north import Store


KEY = b"x" * 32


def seeded(tmp_path):
    path = tmp_path / "evidence.sqlite"
    legacy = Store(path=path)
    legacy.initialize()
    event = {"id": "existing", "timestamp": "2026-01-01T00:00:00Z", "source": "fixture", "kind": 1}
    legacy.ingest_local_windows([event])
    store = Store(path=path, integrity_key=KEY)
    store.initialize()
    store.ingest_local_windows([{**event, "id": identity} for identity in ("first", "second")])
    return store


def test_integrity_starts_at_migration_deduplicates_and_requires_the_key(tmp_path):
    store = seeded(tmp_path)
    assert store.verify_integrity()["records"] == 2
    event = store.local_evidence("first")
    assert store.ingest_local_windows([event]) == 0
    assert store.verify_integrity()["records"] == 2
    unkeyed = Store(path=store.path)
    assert unkeyed.verify_integrity()["state"] == "key_unavailable"
    with pytest.raises(ValueError, match="key"):
        unkeyed.ingest_local_windows([{**event, "id": "unprotected"}])
    assert store.local_evidence("unprotected") is None


@pytest.mark.parametrize(("statement", "sequence"), [
    ("UPDATE local_windows_events SET payload = '{}' WHERE id = 'first'", 1),
    ("UPDATE local_windows_events SET timestamp = 'later' WHERE id = 'second'", 2),
    ("DELETE FROM local_windows_events WHERE id = 'first'", 1),
    ("DELETE FROM local_integrity_entries WHERE sequence = 2", 2),
    ("UPDATE local_integrity_entries SET event_id = 'existing' WHERE sequence = 1", 1),
])
def test_integrity_points_to_first_broken_record(tmp_path, statement, sequence):
    store = seeded(tmp_path)
    with store.connect() as db:
        db.execute(statement)
    assert store.verify_integrity()["state"] == "broken"
    assert store.verify_integrity()["sequence"] == sequence


def test_integrity_head_rejects_metadata_tampering_and_wrong_key(tmp_path):
    store = seeded(tmp_path)
    assert Store(path=store.path, integrity_key=b"y" * 32).verify_integrity()["state"] == "head_invalid"
    with store.connect() as db:
        db.execute("UPDATE local_integrity_head SET sequence = 1")
    assert store.verify_integrity()["state"] == "head_invalid"

def test_missing_integrity_head_is_not_recreated_when_entries_exist(tmp_path):
    store = seeded(tmp_path)
    with store.connect() as db:
        db.execute("DELETE FROM local_integrity_head")
    store.initialize()
    assert store.verify_integrity()["state"] == "head_invalid"
    with pytest.raises(ValueError, match="checkpoint"):
        store.ingest_local_windows([{**store.local_evidence("first"), "id": "blocked"}])
