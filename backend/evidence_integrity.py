"""Authenticated append-order metadata for the local SQLite evidence store."""

import hmac
import json
from datetime import datetime, timezone
from secrets import token_hex


def mac(key, *fields):
    message = json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode()
    return hmac.digest(key, message, "sha256").hex()


def initialize(db, key):
    db.execute("""CREATE TABLE IF NOT EXISTS local_integrity_head (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1), start TEXT NOT NULL,
        genesis TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL, signature TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS local_integrity_entries (
        sequence INTEGER PRIMARY KEY, local INTEGER NOT NULL CHECK(local IN (0, 1)),
        event_id TEXT NOT NULL, digest TEXT NOT NULL, UNIQUE(local, event_id)
    )""")
    if key is not None and head(db) is None:
        if db.execute("SELECT 1 FROM local_integrity_entries LIMIT 1").fetchone():
            return
        start, genesis = datetime.now(timezone.utc).isoformat(), token_hex(32)
        digest = mac(key, "genesis", genesis)
        db.execute("INSERT OR IGNORE INTO local_integrity_head VALUES (1, ?, ?, 0, ?, ?)",
                   (start, genesis, digest, mac(key, "head", start, genesis, 0, digest)))


def head(db):
    return db.execute(
        "SELECT start, genesis, sequence, digest, signature FROM local_integrity_head WHERE singleton = 1"
    ).fetchone()


def authentic(key, checkpoint):
    start, genesis, sequence, digest, signature = checkpoint
    if type(sequence) is not int or sequence < 0 or not all(
        isinstance(value, str) and value.isascii() for value in (start, genesis, digest, signature)
    ):
        return False
    return hmac.compare_digest(signature, mac(key, "head", start, genesis, sequence, digest))


def append(db, key, checkpoint, local, identity, timestamp, payload):
    start, genesis, sequence, previous, signature = checkpoint
    sequence += 1
    digest = mac(key, "entry", genesis, sequence, previous, local, identity, timestamp, payload)
    db.execute("INSERT INTO local_integrity_entries VALUES (?, ?, ?, ?)", (sequence, local, identity, digest))
    return start, genesis, sequence, digest, mac(key, "head", start, genesis, sequence, digest)


def save_head(db, checkpoint):
    db.execute("UPDATE local_integrity_head SET sequence = ?, digest = ?, signature = ? WHERE singleton = 1",
               checkpoint[2:])


def verify(db, key):
    checkpoint = head(db)
    if checkpoint is None:
        if db.execute("SELECT 1 FROM local_integrity_entries LIMIT 1").fetchone():
            return {"state": "head_invalid"}
        return {"state": "unavailable" if key is not None else "not_enabled"}
    if key is None:
        return {"state": "key_unavailable"}
    if not authentic(key, checkpoint):
        return {"state": "head_invalid"}
    start, genesis, end, expected, _ = checkpoint
    previous = mac(key, "genesis", genesis)
    sequence = 0
    rows = db.execute("""
        SELECT e.sequence, e.local, e.event_id, e.digest, coalesce(w.timestamp, s.timestamp),
               coalesce(w.payload, s.payload)
        FROM local_integrity_entries e
        LEFT JOIN local_windows_events w ON e.local = 1 AND e.event_id = w.id
        LEFT JOIN events s ON e.local = 0 AND e.event_id = s.id
        ORDER BY e.sequence
    """)
    for position, local, identity, digest, timestamp, payload in rows:
        sequence += 1
        if position != sequence or position > end or not all(
            isinstance(value, str) for value in (identity, timestamp, payload, digest)
        ) or not digest.isascii():
            return {"state": "broken", "sequence": sequence, "event_id": identity if position == sequence else None}
        observed = mac(key, "entry", genesis, sequence, previous, local, identity, timestamp, payload)
        if not hmac.compare_digest(observed, digest):
            return {"state": "broken", "sequence": sequence, "event_id": identity}
        previous = digest
    if sequence != end or not hmac.compare_digest(previous, expected):
        return {"state": "broken", "sequence": sequence + 1, "event_id": None}
    return {"state": "verified", "start": start, "records": sequence, "checkpoint": {
        "format": 1, "start": start, "genesis": genesis, "records": sequence, "digest": expected,
        "signature": checkpoint[4],
    }}
