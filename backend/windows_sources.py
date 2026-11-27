"""Opt-in local Windows event channels, isolated from workspace snapshots."""

import asyncio
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from starlette.concurrency import run_in_threadpool

from north import collector_tool


SOURCE_EVENTS = {
    "sysmon": {1, 3, 7, 8, 10, 11, 13, 22},
    "security": {1102, 4624, 4625, 4688, 4698, 4720, 4732},
    "system": {104, 7045},
    "powershell": {4104},
    "defender": {1116, 1117, 1118, 1119, 5001, 5007},
}
FIXES = {
    "sysmon": "Check that Sysmon is installed and configured to record the required event types.",
    "security": "Check Windows audit policy and whether this account can read the Security log.",
    "system": "Check access to the Windows System event log.",
    "powershell": "Check whether PowerShell script block logging is enabled and readable.",
    "defender": "Check whether Windows Defender and its Operational event log are enabled and readable.",
}
STATES = {"collecting", "no_data", "not_installed", "access_denied", "misconfigured"}
FIELDS = frozenset((
    "Provider", "Image", "ImageLoaded", "ProcessGuid", "ProcessId", "CommandLine", "ParentProcessGuid",
    "ParentImage", "ParentProcessName", "GrantedAccess", "ParentCommandLine", "User", "TargetImage", "TargetFilename", "TargetObject", "QueryName", "SourceImage",
    "NewProcessName", "NewProcessId", "TargetUserName", "TargetDomainName", "TargetUserSid", "TargetSid", "MemberSid", "IpAddress", "IpPort",
    "TaskName", "ServiceName", "ImagePath", "ScriptBlockId", "Path", "Threat Name", "Detection ID",
    "Initiated", "DestinationIp", "DestinationPort", "Protocol", "LogonType",
))


def normalize_record(source, record):
    host, event_id, record_id = record["host"], record["event_id"], record["record_id"]
    if not isinstance(host, str) or not host.strip() or len(host) > 255:
        raise ValueError("Invalid Windows event host")
    if type(event_id) is not int or event_id not in SOURCE_EVENTS[source]:
        raise ValueError("Unexpected Windows event type")
    if type(record_id) is not int or not 0 < record_id < (1 << 63):
        raise ValueError("Invalid Windows event record ID")
    timestamp = datetime.fromisoformat(record["timestamp"])
    if timestamp.utcoffset() is None:
        raise ValueError("Windows event time requires a timezone")
    timestamp = timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    fields = {key: value[:1024] for key, value in record["fields"].items()
              if key in FIELDS and isinstance(value, str)}
    identity = json.dumps(["north-local-windows", source, host.casefold(), record_id, event_id, timestamp])
    return {
        "id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "timestamp": timestamp,
        "kind": event_id,
        "source": source,
        "source_event_id": str(record_id),
        "host": host,
        "raw": fields,
    }


def collect_source(store, source):
    state, count, _, _ = read_source_batch(store, source)
    return state, count


def read_source_batch(store, source):
    if source not in SOURCE_EVENTS:
        raise ValueError("Unsupported Windows event source")
    offset = "local-windows:" + source
    after = store.collection_offset(offset)
    shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [str(shell), "-NoProfile", "-NonInteractive", "-File", str(collector_tool("Read-NorthWindowsSource.ps1")),
         "-Source", source, "-After", str(after)],
        capture_output=True, check=True, encoding="utf-8", timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if len(result.stdout) > 4_000_000:
        raise ValueError("Windows event batch is too large")
    batch = json.loads(result.stdout)
    state, position, records = batch["state"], batch["position"], batch["events"]
    if state not in STATES or type(position) is not int or not 0 <= position < (1 << 63):
        raise ValueError("Invalid Windows source state or position")
    if not isinstance(records, list) or len(records) > 100 or bool(records) != (state == "collecting"):
        raise ValueError("Invalid Windows event batch")
    last_event_at = None
    if state in {"collecting", "no_data"}:
        events = [normalize_record(source, record) for record in records]
        positions = [int(event["source_event_id"]) for event in events]
        if positions and (sorted(set(positions)) != positions or positions[-1] != position):
            raise ValueError("Invalid Windows source cursor ordering")
        store.ingest_local_windows(events, checkpoint=(offset, position))
        last_event_at = max((event["timestamp"] for event in events), default=None)
    service_state = batch.get("service_state")
    return state, len(records), last_event_at, service_state if service_state in ("running", "stopped") else "unknown"


def collect_tcp_sample(store):
    shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [str(shell), "-NoProfile", "-NonInteractive", "-File", str(collector_tool("Read-NorthTcp.ps1"))],
        capture_output=True, check=True, encoding="utf-8", timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if len(result.stdout) > 400_000:
        raise ValueError("TCP snapshot is too large")
    sample = json.loads(result.stdout)
    state = sample["state"]
    if state != "ready":
        if state in {"access_denied", "unavailable", "read_failed"}:
            return ("not_installed" if state == "unavailable" else state), 0
        raise ValueError("Unknown TCP source state")
    if not isinstance(sample["rows"], list) or len(sample["rows"]) > 200:
        raise ValueError("Invalid TCP snapshot")
    rows = []
    for item in sample["rows"]:
        if item["state"] not in {"Listen", "Established", "SynSent", "SynReceived", "CloseWait"}:
            raise ValueError("Invalid TCP state")
        for key, limit in (("pid", 4294967295), ("local_port", 65535), ("remote_port", 65535)):
            if type(item[key]) is not int or not 0 <= item[key] <= limit:
                raise ValueError("Invalid TCP metadata")
        if not isinstance(item["process"], str):
            raise ValueError("Invalid TCP process")
        rows.append({**{key: item[key] for key in ("state", "pid", "local_port", "remote_port")},
                     "local_address": str(ip_address(item["local_address"])),
                     "remote_address": str(ip_address(item["remote_address"])), "process": item["process"][:256]})
    at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    store.record_tcp_snapshot(at, {"rows": rows, "limited": sample.get("limited") is True})
    if sample.get("listeners_limited", sample.get("limited")) is False:
        host = socket.gethostname()
        events = []
        for row in rows:
            if row["state"] != "Listen" or not row["local_port"]:
                continue
            identity = hashlib.sha256(json.dumps(["windows_tcp", host.casefold(), row["local_address"],
                                                 row["local_port"]]).encode()).hexdigest()[:24]
            events.append({"id": identity, "timestamp": at, "kind": 2001, "source": "windows_tcp",
                           "host": host, "source_event_id": identity,
                           "raw": {"LocalAddress": row["local_address"], "LocalPort": str(row["local_port"]),
                                   "ProcessId": str(row["pid"]), "Image": row["process"], "Protocol": "tcp"}})
        store.ingest_local_windows(events)
    return ("collecting" if rows else "no_data"), len(rows)


SOURCE_FAILURES = {
    "not_installed": "Windows could not find the event channel.",
    "access_denied": "Windows denied this account access to the source.",
    "misconfigured": "Windows reports that the event channel is disabled.",
    "read_failed": "The collector could not read the source.",
    "unavailable": "Windows did not provide a source snapshot.",
}


def source_snapshot(previous, state, count, last_event_at, now, *, expect_activity=False, service_state="unknown"):
    stamp = now.isoformat()
    last_event = max(filter(None, (last_event_at, previous.get("last_event_at"))), default=None)
    if state in SOURCE_FAILURES:
        health = "unavailable"
        reason = SOURCE_FAILURES[state]
    elif service_state == "stopped":
        health = "unavailable"
        reason = "Windows reports that the Sysmon service is stopped."
    elif expect_activity and last_event and now - datetime.fromisoformat(last_event) >= timedelta(hours=1):
        health = "quiet"
        reason = "No new Sysmon event has been observed for an hour. Activity or logging may have changed."
    else:
        health = "observed" if last_event or count else "waiting"
        reason = ""
    return {**previous, "state": state, "health": health, "reason": reason, "checked_at": stamp,
            "last_collected_at": stamp if count else previous.get("last_collected_at"),
            "last_event_at": last_event, "service_state": service_state}


class WindowsSources:
    def __init__(self, store, enabled):
        self.store = store
        self.current = {source: {"state": "starting" if enabled else "disabled",
                                 "last_collected_at": None, "fix": FIXES[source]} for source in SOURCE_EVENTS}
        self.current["tcp"] = {"state": "starting" if enabled else "disabled", "last_collected_at": None,
                               "fix": "Check whether this account can read the local Windows TCP/IP provider."}

    async def watch(self, source):
        try:
            previous = await run_in_threadpool(self.store.source_snapshot, source)
        except sqlite3.Error:
            previous = {}
        self.current[source] = {**self.current[source], **previous}
        while True:
            last_event_at = None
            service_state = "unknown"
            try:
                if source == "tcp":
                    state, count = await run_in_threadpool(collect_tcp_sample, self.store)
                else:
                    state, count, last_event_at, service_state = await run_in_threadpool(read_source_batch, self.store, source)
            except (OSError, TypeError, ValueError, KeyError, AttributeError, sqlite3.Error, subprocess.SubprocessError):
                state, count = "read_failed", 0
            previous = self.current[source]
            current = source_snapshot(previous, state, count, last_event_at, datetime.now(timezone.utc),
                                      expect_activity=source == "sysmon", service_state=service_state)
            self.current[source] = current
            try:
                await run_in_threadpool(self.store.record_source_snapshot, source, current)
            except sqlite3.Error:
                pass
            await asyncio.sleep(60 if source == "tcp" else 2 if count == 100 else 30)

    async def run(self):
        async with asyncio.TaskGroup() as tasks:
            for source in self.current:
                tasks.create_task(self.watch(source))
