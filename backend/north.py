from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path


SSH_FAILURE = 1001
SSH_SERVICES = {"sshd", "sshd-session", "sshd-auth"}
SSH_FAILURE_MESSAGE = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?:invalid user )?\S+ from (?P<address>\S+) port \d+(?:\s|$)"
)


def normalize_journal(entry):
    if not isinstance(entry, dict):
        raise ValueError("Journal entry must be an object")
    service = entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER")
    message = entry.get("MESSAGE")
    match = SSH_FAILURE_MESSAGE.match(message) if isinstance(message, str) else None
    if service not in SSH_SERVICES or not match:
        raise ValueError("Expected an OpenSSH failed authentication entry")
    host, device, cursor = (entry.get(key) for key in ("_HOSTNAME", "_MACHINE_ID", "__CURSOR"))
    if not all(isinstance(value, str) and value.strip() for value in (host, device, cursor)):
        raise ValueError("Missing journal host, machine ID, or cursor")
    timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=int(entry["__REALTIME_TIMESTAMP"])
    )
    source = str(ip_address(match["address"]))
    identity = json.dumps(["journalctl", device, cursor], separators=(",", ":"))
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "timestamp": timestamp.isoformat(timespec="microseconds"),
        "kind": SSH_FAILURE,
        "host": host,
        "asset_id": "linux-" + hashlib.sha256(device.encode()).hexdigest()[:16],
        "process": service,
        "process_guid": "",
        "parent_guid": "",
        "destination": "",
        "source_ip": source,
        "target": "",
        "raw": {"MESSAGE": message, "_HOSTNAME": host, "_COMM": service,
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

    def ingest(self, alerts: list[dict]) -> int:
        # Normalize the whole batch before opening the transaction.
        events = [normalize(alert) for alert in alerts]
        marker = "%s" if self.url else "?"
        values = ", ".join([marker] * 3)
        with self.connect() as db:
            return sum(
                db.execute(
                    f"INSERT INTO events (id, timestamp, payload) VALUES ({values}) "
                    "ON CONFLICT (id) DO NOTHING",
                    (event["id"], event["timestamp"], json.dumps(event)),
                ).rowcount
                for event in events
            )

    def events(self) -> list[dict]:
        with self.connect() as db:
            return [
                json.loads(row[0])
                for row in db.execute("SELECT payload FROM events ORDER BY timestamp, id")
            ]


def windows_cases(events: list[dict]) -> list[dict]:
    """Correlate process creation with a subsequent file write by the same process."""
    writes: dict[tuple[str, str], list[dict]] = {}
    connections: dict[tuple[str, str], list[dict]] = {}
    for event in events:
        key = (event["asset_id"], event["process_guid"])
        if event["kind"] == 11:
            writes.setdefault(key, []).append(event)
        elif event["kind"] == 3:
            connections.setdefault(key, []).append(event)

    cases = []
    for event in events:
        if event["kind"] != 1 or not event["process_guid"]:
            continue
        image = event["process"].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if image not in ("powershell.exe", "pwsh.exe"):
            continue
        key = (event["asset_id"], event["process_guid"])
        started = datetime.fromisoformat(event["timestamp"])

        def within_window(candidate):
            elapsed = datetime.fromisoformat(candidate["timestamp"]) - started
            return 0 <= elapsed.total_seconds() <= 120

        matching_writes = [
            item for item in writes.get(key, [])
            if within_window(item) and item["target"].lower().endswith(".ps1")
        ]
        if not matching_writes:
            continue
        network = [item for item in connections.get(key, []) if within_window(item)]
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
    windows = {}
    cases = []
    failures = sorted(
        (event for event in events if event["kind"] == SSH_FAILURE),
        key=lambda event: (event["timestamp"], event["id"]),
    )
    for event in failures:
        key = (event["asset_id"], event["source_ip"])
        pending = windows.setdefault(key, deque())
        instant = datetime.fromisoformat(event["timestamp"])
        while pending and instant - datetime.fromisoformat(pending[0]["timestamp"]) > timedelta(minutes=5):
            pending.popleft()
        pending.append(event)
        if len(pending) == 3:
            first = pending[0]
            cases.append({
                "id": first["id"],
                "title": "Repeated SSH authentication failures",
                "host": first["host"],
                "asset_id": first["asset_id"],
                "summary": "OpenSSH recorded three failed authentication attempts from one address within five minutes. These records do not establish whether a login later succeeded.",
                "evidence": list(pending),
                "links": [{"destination": key[1], "evidence_id": first["id"], "direction": "inbound"}],
            })
            pending.clear()
    return cases


def build_cases(events: list[dict]) -> list[dict]:
    return [*windows_cases(events), *linux_cases(events)]


def report(case: dict) -> str:
    evidence = [
        f"- {item['timestamp']} | "
        f"{'OpenSSH authentication failure' if item['kind'] == SSH_FAILURE else 'Sysmon ' + str(item['kind'])}"
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
