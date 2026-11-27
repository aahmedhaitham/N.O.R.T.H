from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from event_contract import event_contract


SSH_FAILURE = 1001
SUDO_COMMAND = 1002
SSH_SERVICES = {"sshd", "sshd-session", "sshd-auth"}
SSH_FAILURE_MESSAGE = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?:invalid user )?\S+ from (?P<address>\S+) port \d+(?:\s|$)"
)
SUDO_COMMAND_MESSAGE = re.compile(r"(?:^|;\s*)COMMAND=(?P<command>/\S+)(?:\s|$)")


def collector_tool(name):
    location = sys.executable if getattr(sys, "frozen", False) else __file__
    return Path(location).resolve().parents[1] / "tools" / name


def journal_activity(entry):
    service = entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER")
    message = entry.get("MESSAGE")
    if not isinstance(message, str):
        return None
    if service in SSH_SERVICES:
        match = SSH_FAILURE_MESSAGE.match(message)
        if match:
            return SSH_FAILURE, service, match["address"]
    if service == "sudo":
        match = SUDO_COMMAND_MESSAGE.search(message)
        if match:
            return SUDO_COMMAND, service, match["command"].rsplit("/", 1)[-1]
    return None


def normalize_journal(entry):
    if not isinstance(entry, dict):
        raise ValueError("Journal entry must be an object")
    activity = journal_activity(entry)
    if not activity:
        raise ValueError("Expected an OpenSSH failure or sudo command entry")
    kind, service, value = activity
    host, device, cursor = (entry.get(key) for key in ("_HOSTNAME", "_MACHINE_ID", "__CURSOR"))
    if not all(isinstance(value, str) and value.strip() for value in (host, device, cursor)):
        raise ValueError("Missing journal host, machine ID, or cursor")
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=int(entry["__REALTIME_TIMESTAMP"])
    )
    source = str(ip_address(value)) if kind == SSH_FAILURE else ""
    identity = json.dumps(["journalctl", device, cursor], separators=(",", ":"))
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "timestamp": timestamp.isoformat(timespec="microseconds"),
        "kind": kind,
        "host": host,
        "asset_id": "linux-" + hashlib.sha256(device.encode()).hexdigest()[:16],
        "process": service,
        "process_guid": "",
        "parent_guid": "",
        "destination": "",
        "source_ip": source,
        "target": value if kind == SUDO_COMMAND else "",
        "raw": {"MESSAGE": entry["MESSAGE"], "_HOSTNAME": host, "_COMM": service,
                "__REALTIME_TIMESTAMP": entry["__REALTIME_TIMESTAMP"]},
    }


def normalize(raw: dict) -> dict:
    """Normalize a Windows Sysmon alert or Linux journal entry."""
    if raw.get("source") == "journalctl":
        return normalize_journal(raw["entry"])
    data = raw.get("data", {}).get("win", {})
    system = data.get("system", {})
    fields = data.get("eventdata", {})
    agent = raw.get("agent", {})
    host = agent.get("name")
    device = agent.get("id")
    record = system.get("eventRecordID")
    if not all(isinstance(value, str) and value.strip() for value in (host, device, str(record or ""))):
        raise ValueError("Missing agent id, agent name, or Sysmon record ID")
    instant = datetime.fromisoformat(system.get("systemTime") or raw["timestamp"])
    if instant.tzinfo is None:
        raise ValueError("Event timestamp must include a time zone")
    timestamp = instant.astimezone(timezone.utc).isoformat(timespec="microseconds")
    kind = int(system["eventID"])
    if kind not in (1, 3, 11):
        raise ValueError("Supported Sysmon event types are 1, 3, and 11")
    if not isinstance(fields, dict):
        raise ValueError("Sysmon eventdata must be an object")
    for field in ("image", "processGuid", "parentProcessGuid", "destinationIp", "targetFilename"):
        if not isinstance(fields.get(field, ""), str):
            raise ValueError(f"Sysmon {field} must be a string")
    identity = json.dumps([device, str(record), kind, timestamp], separators=(",", ":"))
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "timestamp": timestamp,
        "kind": kind,
        "host": host,
        "asset_id": device,
        "process": fields.get("image", ""),
        "process_guid": fields.get("processGuid", ""),
        "parent_guid": fields.get("parentProcessGuid", ""),
        "destination": fields.get("destinationIp", ""),
        "target": fields.get("targetFilename", ""),
        "raw": raw,
    }


class Store:
    def __init__(self, url: str | None = None, path: str | Path = "north.sqlite3"):
        self.url = url
        self.path = path

    @contextmanager
    def connect(self):
        if self.url:
            import psycopg

            connection = psycopg.connect(self.url)
        else:
            connection = sqlite3.connect(self.path)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self):
        with self.connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL
                )
                """)
            db.execute("CREATE INDEX IF NOT EXISTS events_time ON events (timestamp, id)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS local_windows_events (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, payload TEXT NOT NULL
                )
                """)
            db.execute("CREATE INDEX IF NOT EXISTS local_windows_time ON local_windows_events (timestamp, id)")
            if not self.url:
                self._initialize_event_search(db)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_detection_findings (
                        id TEXT PRIMARY KEY, status TEXT NOT NULL, last_seen TEXT NOT NULL, payload TEXT NOT NULL
                    )
                    """)
                db.execute("CREATE INDEX IF NOT EXISTS local_findings_by_status ON local_detection_findings (status, last_seen)")
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_detection_queue (
                        sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                        local_windows INTEGER NOT NULL
                    )
                    """)
                db.execute("CREATE TABLE IF NOT EXISTS local_rule_disabled (id TEXT PRIMARY KEY)")
                db.execute("CREATE TABLE IF NOT EXISTS local_custom_rules (digest TEXT PRIMARY KEY, yaml TEXT NOT NULL)")
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_source_health (
                        source TEXT PRIMARY KEY, state TEXT NOT NULL, checked_at TEXT NOT NULL
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_sensor_verification (
                        id INTEGER PRIMARY KEY, payload TEXT NOT NULL
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_source_snapshots (
                        source TEXT PRIMARY KEY, payload TEXT NOT NULL
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_observed_event_types (
                        source TEXT NOT NULL, kind INTEGER NOT NULL, PRIMARY KEY (source, kind)
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_baseline_scopes (
                        scope TEXT PRIMARY KEY, learning_until TEXT NOT NULL
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_baseline_entities (
                        scope TEXT NOT NULL, entity TEXT NOT NULL, PRIMARY KEY (scope, entity)
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_destination_frequency (
                        scope TEXT NOT NULL, entity TEXT NOT NULL, samples INTEGER NOT NULL,
                        reported INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (scope, entity)
                    )
                    """)
                db.execute("""
                    CREATE TABLE IF NOT EXISTS local_tcp_snapshots (
                        sampled_at TEXT PRIMARY KEY, payload TEXT NOT NULL
                    )
                    """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS collection_offsets (
                    source TEXT PRIMARY KEY, position BIGINT NOT NULL
                )
                """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS neighbor_baseline (
                    scope TEXT PRIMARY KEY, started_at TEXT NOT NULL
                )
                """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS neighbor_devices (
                    id TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL, baseline INTEGER NOT NULL, reviewed_at TEXT
                )
                """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS neighbor_review ON neighbor_devices (baseline, reviewed_at, first_seen)
                """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS cloud_event_receipts (
                    target TEXT NOT NULL, event_id TEXT NOT NULL,
                    PRIMARY KEY (target, event_id)
                )
                """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS internet_checks (
                    scope TEXT NOT NULL, checked_at TEXT NOT NULL, payload TEXT NOT NULL,
                    PRIMARY KEY (scope, checked_at)
                )
                """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS router_traffic_state (
                    scope TEXT PRIMARY KEY, payload TEXT NOT NULL
                )
                """)

    def router_traffic(self, scope):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            row = db.execute(f"SELECT payload FROM router_traffic_state WHERE scope = {marker}", (scope,)).fetchone()
        return json.loads(row[0]) if row else None

    def record_router_traffic(self, scope, state):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            db.execute(
                f"INSERT INTO router_traffic_state (scope, payload) VALUES ({marker}, {marker}) "
                "ON CONFLICT (scope) DO UPDATE SET payload = excluded.payload",
                (scope, json.dumps(state)),
            )

    def internet_checks(self, scope):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            rows = db.execute(
                f"SELECT payload FROM internet_checks WHERE scope = {marker} ORDER BY checked_at DESC LIMIT 72",
                (scope,),
            ).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

    def record_internet_check(self, scope, sample):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            db.execute(
                f"INSERT INTO internet_checks (scope, checked_at, payload) VALUES ({marker}, {marker}, {marker}) "
                "ON CONFLICT (scope, checked_at) DO NOTHING",
                (scope, sample["checked_at"], json.dumps(sample)),
            )
            db.execute(
                f"DELETE FROM internet_checks WHERE scope = {marker} AND checked_at NOT IN "
                f"(SELECT checked_at FROM internet_checks WHERE scope = {marker} ORDER BY checked_at DESC LIMIT 72)",
                (scope, scope),
            )

    def collection_offset(self, source):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            row = db.execute(
                f"SELECT position FROM collection_offsets WHERE source = {marker}", (source,),
            ).fetchone()
        return row[0] if row else 0

    def ingest(self, alerts: list[dict], *, checkpoint: tuple[str, int] | None = None, enqueue=True) -> int:
        # Normalize the whole batch before opening the transaction.
        events = [normalize(alert) for alert in alerts]
        return self._store_events(events, checkpoint, local=False, enqueue=enqueue)

    def ingest_local_windows(self, events, *, checkpoint=None):
        if self.url:
            raise ValueError("Expanded Windows events require the local SQLite store")
        return self._store_events(events, checkpoint, local=True, enqueue=True)

    def record_tcp_snapshot(self, sampled_at, sample):
        if self.url:
            raise ValueError("TCP telemetry requires local SQLite")
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO local_tcp_snapshots VALUES (?, ?)", (sampled_at, json.dumps(sample)))
            db.execute("""DELETE FROM local_tcp_snapshots WHERE sampled_at NOT IN
                          (SELECT sampled_at FROM local_tcp_snapshots ORDER BY sampled_at DESC LIMIT 96)""")

    def tcp_snapshots(self):
        if self.url:
            raise ValueError("TCP telemetry requires local SQLite")
        with self.connect() as db:
            return [{"sampled_at": at, **json.loads(payload)} for at, payload in db.execute(
                "SELECT sampled_at, payload FROM local_tcp_snapshots ORDER BY sampled_at DESC LIMIT 12")]

    def _store_events(self, events, checkpoint, *, local, enqueue):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            inserted = self._insert_events(db, events, local=local, enqueue=enqueue)
            if checkpoint is not None:
                db.execute(
                    f"INSERT INTO collection_offsets (source, position) VALUES ({marker}, {marker}) "
                    "ON CONFLICT (source) DO UPDATE SET position = excluded.position",
                    checkpoint,
                )
            return inserted

    def _insert_events(self, db, events, *, local, enqueue):
        table = "local_windows_events" if local else "events"
        marker = "%s" if self.url else "?"
        values = ", ".join([marker] * 3)
        inserted = 0
        for event in events:
            added = db.execute(
                f"INSERT INTO {table} (id, timestamp, payload) VALUES ({values}) ON CONFLICT (id) DO NOTHING",
                (event["id"], event["timestamp"], json.dumps(event)),
            ).rowcount
            inserted += added
            if added and enqueue and not self.url:
                db.execute("INSERT OR IGNORE INTO local_detection_queue (event_id, local_windows) VALUES (?, ?)",
                           (event["id"], int(local)))
                if local and event.get("source"):
                    db.execute("INSERT OR IGNORE INTO local_observed_event_types VALUES (?, ?)",
                               (event["source"], event["kind"]))
        return inserted

    def save_source_health(self, source, state, checked_at):
        with self.connect() as db:
            db.execute("""
                INSERT INTO local_source_health VALUES (?, ?, ?)
                ON CONFLICT (source) DO UPDATE SET state = excluded.state, checked_at = excluded.checked_at
                """, (source, state, checked_at))

    def record_source_snapshot(self, source, snapshot):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM local_source_snapshots WHERE source = ?", (source,)).fetchone()
            previous = json.loads(row[0]) if row else {}
            snapshot = {**snapshot}
            for field in ("last_event_at", "last_collected_at"):
                snapshot[field] = max(filter(None, (snapshot.get(field), previous.get(field))), default=None)
            db.execute("""INSERT INTO local_source_snapshots VALUES (?, ?)
                          ON CONFLICT (source) DO UPDATE SET payload = excluded.payload""",
                       (source, json.dumps(snapshot)))
            db.execute("""INSERT INTO local_source_health VALUES (?, ?, ?)
                          ON CONFLICT (source) DO UPDATE SET state = excluded.state, checked_at = excluded.checked_at""",
                       (source, "collecting" if snapshot["state"] == "no_data" and snapshot["last_event_at"]
                        else snapshot["state"], snapshot["checked_at"]))
            changed = snapshot["health"] != previous.get("health") or snapshot["reason"] != previous.get("reason")
            if changed and snapshot["health"] in {"quiet", "unavailable"}:
                checked = snapshot["checked_at"]
                identity = hashlib.sha256(f"sensor-health:{source}:{checked}".encode()).hexdigest()[:24]
                self._write_findings(db, [{
                    "id": identity, "rule_id": "sensor-health", "title": f"Check the {source} source",
                    "severity": "low", "plain_summary": snapshot["reason"], "what_to_do": snapshot["fix"],
                    "first_seen": checked, "last_seen": checked, "evidence_ids": [],
                    "confidence": "single observation", "rarity": "unknown",
                }])
            return snapshot

    def source_snapshot(self, source):
        with self.connect() as db:
            row = db.execute("SELECT payload FROM local_source_snapshots WHERE source = ?", (source,)).fetchone()
        return json.loads(row[0]) if row else {}

    def local_windows_events(self, *, limit=100):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            rows = db.execute(
                f"SELECT payload FROM local_windows_events ORDER BY timestamp DESC, id DESC LIMIT {marker}",
                (min(max(1, limit), 500),),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def record_findings(self, findings):
        if self.url:
            raise ValueError("Detection findings require the local SQLite store")
        with self.connect() as db:
            self._write_findings(db, findings)

    @staticmethod
    def _write_findings(db, findings):
        db.executemany(
            """INSERT INTO local_detection_findings (id, status, last_seen, payload) VALUES (?, 'new', ?, ?)
               ON CONFLICT (id) DO UPDATE SET payload = excluded.payload, last_seen = excluded.last_seen
               WHERE excluded.last_seen >= local_detection_findings.last_seen""",
            [(item["id"], item["last_seen"], json.dumps(item)) for item in findings],
        )

    def pending_detections(self):
        with self.connect() as db:
            rows = db.execute("""
                SELECT q.event_id, coalesce(w.payload, e.payload) FROM local_detection_queue q
                LEFT JOIN local_windows_events w ON q.local_windows = 1 AND w.id = q.event_id
                LEFT JOIN events e ON q.local_windows = 0 AND e.id = q.event_id
                ORDER BY q.sequence LIMIT 100
                """).fetchall()
        return [(identity, json.loads(payload) if payload else None) for identity, payload in rows]

    def detection_context(self, since, until):
        with self.connect() as db:
            rows = db.execute("""
                SELECT payload FROM (
                    SELECT id, timestamp, payload FROM events WHERE timestamp BETWEEN ? AND ?
                    UNION ALL
                    SELECT id, timestamp, payload FROM local_windows_events WHERE timestamp BETWEEN ? AND ?
                ) ORDER BY timestamp DESC, id DESC LIMIT 501
                """, (since, until, since, until)).fetchall()
        return [json.loads(row[0]) for row in rows[:500]], len(rows) > 500

    def complete_detections(self, identities, findings, *, observations=(), now=None, learning_until=None):
        observations_by_id = {}
        with self.connect() as db:
            if observations:
                db.execute("BEGIN IMMEDIATE")
                for scope, entity, finding, rare in observations:
                    if not db.execute("SELECT 1 FROM local_detection_queue WHERE event_id = ?",
                                      (finding["evidence_ids"][0],)).fetchone():
                        continue
                    db.execute("INSERT OR IGNORE INTO local_baseline_scopes VALUES (?, ?)", (scope, learning_until))
                    deadline, = db.execute("SELECT learning_until FROM local_baseline_scopes WHERE scope = ?",
                                           (scope,)).fetchone()
                    added = db.execute("INSERT OR IGNORE INTO local_baseline_entities VALUES (?, ?)",
                                       (scope, entity)).rowcount
                    if now >= deadline and finding["first_seen"] >= deadline:
                        observations_by_id[finding["evidence_ids"][0]] = "first seen" if added else "previously observed"
                        if added:
                            self._write_findings(db, [finding])
                    if rare is not None:
                        self._observe_destination_frequency(db, scope, entity, rare, now, deadline)
            for finding in findings:
                comparisons = {observations_by_id.get(identity) for identity in finding["evidence_ids"]}
                if "first seen" in comparisons:
                    finding["rarity"] = "first seen"
                elif "previously observed" in comparisons:
                    finding["rarity"] = "previously observed"
            self._write_findings(db, findings)
            db.executemany("DELETE FROM local_detection_queue WHERE event_id = ?", [(identity,) for identity in identities])

    def _observe_destination_frequency(self, db, scope, entity, finding, now, deadline):
        if now < deadline and finding["first_seen"] < deadline:
            db.execute("""
                INSERT INTO local_destination_frequency (scope, entity, samples) VALUES (?, ?, 1)
                ON CONFLICT (scope, entity) DO UPDATE SET samples = samples + 1
                """, (scope, entity))
        elif now >= deadline and finding["first_seen"] >= deadline:
            changed = db.execute("""
                UPDATE local_destination_frequency SET reported = 1
                WHERE scope = ? AND entity = ? AND reported = 0
                  AND samples * 20 <= (
                    SELECT sum(samples) FROM local_destination_frequency WHERE scope = ?
                  )
                """, (scope, entity, scope))
            if changed.rowcount:
                self._write_findings(db, [finding])

    def detection_findings(self, limit=100, *, offset=0, lookahead=False):
        if self.url:
            raise ValueError("Detection findings require the local SQLite store")
        with self.connect() as db:
            rows = db.execute(
                """SELECT status, payload FROM local_detection_findings
                   ORDER BY CASE WHEN status = 'new' THEN 0 ELSE 1 END, last_seen DESC, id DESC LIMIT ? OFFSET ?""",
                (min(max(1, limit), 100) + int(lookahead), offset),
            ).fetchall()
        return [{**json.loads(payload), "status": status} for status, payload in rows]

    def unreviewed_summary(self):
        with self.connect() as db:
            total, severe = db.execute("""
                SELECT count(*), count(CASE WHEN json_extract(payload, '$.severity') IN ('high', 'critical') THEN 1 END)
                FROM local_detection_findings WHERE status = 'new'
                """).fetchone()
        return {"unreviewed": total, "severe": severe}

    def detection_baselines(self):
        with self.connect() as db:
            rows = db.execute("SELECT scope, learning_until FROM local_baseline_scopes ORDER BY scope LIMIT 100").fetchall()
        now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        return [{"signal": signal, "host": host, "learning_until": deadline,
                 "state": "learning" if now < deadline else "ready"}
                for scope, deadline in rows for signal, host in [json.loads(scope)]]

    def set_finding_status(self, identity, status):
        if self.url or status not in ("reviewed", "benign", "new"):
            raise ValueError("Invalid local finding review")
        with self.connect() as db:
            return bool(db.execute("UPDATE local_detection_findings SET status = ? WHERE id = ?",
                                   (status, identity)).rowcount)

    def local_evidence(self, identity):
        if self.url:
            raise ValueError("Local evidence lookup requires the local SQLite store")
        with self.connect() as db:
            row = db.execute(
                "SELECT payload FROM local_windows_events WHERE id = ? UNION ALL SELECT payload FROM events WHERE id = ?",
                (identity, identity),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def events(self) -> list[dict]:
        with self.connect() as db:
            return [
                json.loads(row[0])
                for row in db.execute("SELECT payload FROM events ORDER BY timestamp, id")
            ]

    @staticmethod
    def _initialize_event_search(db):
        if db.execute("SELECT 1 FROM sqlite_master WHERE name = 'events_search'").fetchone():
            return
        db.execute("SAVEPOINT event_search_setup")
        try:
            db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS events_search
                          USING fts5(payload, content='events', content_rowid='rowid', tokenize='trigram')""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS events_search_insert AFTER INSERT ON events BEGIN
                          INSERT INTO events_search(rowid, payload) VALUES (new.rowid, new.payload); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS events_search_delete AFTER DELETE ON events BEGIN
                          INSERT INTO events_search(events_search, rowid, payload)
                          VALUES ('delete', old.rowid, old.payload); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS events_search_update AFTER UPDATE OF payload ON events BEGIN
                          INSERT INTO events_search(events_search, rowid, payload)
                          VALUES ('delete', old.rowid, old.payload);
                          INSERT INTO events_search(rowid, payload) VALUES (new.rowid, new.payload); END""")
            db.execute("INSERT INTO events_search(events_search) VALUES ('rebuild')")
        except sqlite3.OperationalError as error:
            db.execute("ROLLBACK TO event_search_setup")
            if "no such module" not in str(error) and "no such tokenizer" not in str(error):
                raise
        finally:
            db.execute("RELEASE event_search_setup")

    def event_page(self, *, search="", kind=None, before=None, limit=50):
        marker = "%s" if self.url else "?"
        terms, params = [], []
        if search:
            escaped = search.lower().replace("!", "!!").replace("%", "!%").replace("_", "!_")
            terms.append(f"LOWER(payload) LIKE {marker} ESCAPE '!'")
            params.append(f"%{escaped}%")
        if kind is not None:
            field = "CAST(payload AS jsonb)->>'kind'" if self.url else "CAST(json_extract(payload, '$.kind') AS TEXT)"
            terms.append(f"({field}) = {marker}")
            params.append(str(kind))
        if before:
            timestamp, event_id = before
            terms.append(f"(timestamp < {marker} OR (timestamp = {marker} AND id < {marker}))")
            params.extend((timestamp, timestamp, event_id))
        with self.connect() as db:
            if (not self.url and re.fullmatch(r"[a-zA-Z0-9_.-]{3,200}", search)
                    and db.execute("SELECT 1 FROM sqlite_master WHERE name = 'events_search'").fetchone()):
                terms.append("rowid IN (SELECT rowid FROM events_search WHERE events_search MATCH ?)")
                params.append(f'"{search.lower()}"')
            where = " WHERE " + " AND ".join(terms) if terms else ""
            params.append(limit + 1)
            rows = db.execute(
                f"SELECT payload FROM events{where} ORDER BY timestamp DESC, id DESC LIMIT {marker}", params,
            ).fetchall()
        events = [json.loads(row[0]) for row in rows[:limit]]
        last = events[-1] if len(rows) > limit else None
        return {"events": events, "next": f"{last['timestamp']}|{last['id']}" if last else None}

    def pending_cloud_events(self, target, limit=100):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            rows = db.execute(
                "SELECT events.payload FROM events "
                "WHERE NOT EXISTS (SELECT 1 FROM cloud_event_receipts "
                f"WHERE target = {marker} AND event_id = events.id) "
                f"ORDER BY events.timestamp, events.id LIMIT {marker}",
                (target, limit),
            )
            return [json.loads(row[0]) for row in rows]

    def record_cloud_receipts(self, target, event_ids):
        marker = "%s" if self.url else "?"
        with self.connect() as db:
            for event_id in event_ids:
                db.execute(
                    f"INSERT INTO cloud_event_receipts (target, event_id) VALUES ({marker}, {marker}) "
                    "ON CONFLICT (target, event_id) DO NOTHING", (target, event_id),
                )


def threshold_groups(events, *, group_key, count, window, time_key="timestamp", distinct_key=None):
    pending_by_key = {}
    for event in sorted(events, key=lambda item: (item[time_key], item["id"])):
        key = group_key(event)
        pending = pending_by_key.setdefault(key, deque())
        instant = datetime.fromisoformat(event[time_key])
        while pending and instant - pending[0][0] > window:
            pending.popleft()
        pending.append((instant, event))
        candidates = [item for _, item in pending]
        if distinct_key:
            candidates = list({distinct_key(item): item for item in candidates}.values())
        if len(candidates) == count:
            yield key, candidates
            pending.clear()


def events_in_window(anchor, candidates, window, *, time_key="timestamp"):
    started = datetime.fromisoformat(anchor[time_key])
    return [candidate for candidate in candidates
            if timedelta(0) <= datetime.fromisoformat(candidate[time_key]) - started <= window]


def windows_cases(events: list[dict]) -> list[dict]:
    """Correlate process creation with a subsequent file write by the same process."""
    writes: dict[tuple[str, str], list[dict]] = {}
    connections: dict[tuple[str, str], list[dict]] = {}
    for event in events:
        key = (event["asset_id"], event["process_guid"])
        if event["kind"] == 11 and event["target"].lower().endswith(".ps1"):
            writes.setdefault(key, []).append(event)
        elif event["kind"] == 3:
            connections.setdefault(key, []).append(event)

    cases = []
    for event in events:
        if event["kind"] != 1 or not event["process_guid"]:
            continue
        image = event_contract(event)["process"]["name"].lower()
        if image not in ("powershell.exe", "pwsh.exe"):
            continue
        key = (event["asset_id"], event["process_guid"])
        window = timedelta(seconds=120)
        matching_writes = events_in_window(event, writes.get(key, ()), window)
        if not matching_writes:
            continue
        network = events_in_window(event, connections.get(key, ()), window)
        timeline = sorted([event, *matching_writes, *network], key=lambda item: (item["timestamp"], item["id"]))
        cases.append({
            "id": event["id"],
            "title": "PowerShell process wrote a script file",
            "host": event["host"],
            "asset_id": event["asset_id"],
            "summary": "A PowerShell process wrote a .ps1 file within 120 seconds of its creation. Review the file path and the process context before drawing a conclusion.",
            "evidence": timeline,
            "links": [
                {"destination": item["destination"], "evidence_id": item["id"]}
                for item in network if item["destination"]
            ],
        })
    return cases


def linux_cases(events: list[dict]) -> list[dict]:
    cases = []
    failures = (event for event in events if event["kind"] == SSH_FAILURE)
    for key, evidence in threshold_groups(failures, group_key=lambda event: (event["asset_id"], event["source_ip"]),
                                          count=3, window=timedelta(minutes=5)):
        first = evidence[0]
        cases.append({
            "id": first["id"],
            "title": "Repeated SSH authentication failures",
            "host": first["host"],
            "asset_id": first["asset_id"],
            "summary": "OpenSSH recorded three failed authentication attempts from one address within five minutes. These records do not establish whether a login later succeeded.",
            "evidence": evidence,
            "links": [{"destination": key[1], "evidence_id": first["id"], "direction": "inbound"}],
        })
    return cases


def build_cases(events: list[dict]) -> list[dict]:
    sudo = [
        {
            "id": event["id"], "title": "Sudo command observed", "host": event["host"],
            "asset_id": event["asset_id"],
            "summary": "The Linux journal recorded a sudo command. This is a local audit observation.",
            "evidence": [event], "links": [],
        }
        for event in events if event["kind"] == SUDO_COMMAND
    ]
    return [*windows_cases(events), *linux_cases(events), *sudo]


def report(case: dict) -> str:
    linux_labels = {SSH_FAILURE: "OpenSSH authentication failure", SUDO_COMMAND: "Sudo command"}
    evidence = [
        f"- {item['timestamp']} | "
        f"{linux_labels.get(item['kind'], 'Sysmon ' + str(item['kind']))}"
        f" | {item['id']} | "
        f"{item['target'] or item['destination'] or item.get('source_ip') or item['process']}"
        for item in case["evidence"]
    ]
    return "\n".join([
        "# NORTH investigation report", "", case["title"], "",
        f"Case ID: {case['id']}", f"Host: {case['host']}", "", case["summary"],
        "", "## ECHO evidence timeline", "", *evidence, "",
    ])


def configured_store() -> Store:
    return Store(os.getenv("DATABASE_URL"), os.getenv("NORTH_DB_PATH", "north.sqlite3"))
