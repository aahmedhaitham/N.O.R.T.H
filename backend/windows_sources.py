"""Opt-in local Windows event channels, isolated from workspace snapshots."""

import asyncio
import hashlib
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from starlette.concurrency import run_in_threadpool

from north import collector_tool


SOURCE_EVENTS = {
    "sysmon": {7, 8, 10, 13, 22},
    "security": {4624, 4625, 4688, 4698},
    "system": {7045},
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
    "Image", "ImageLoaded", "ProcessGuid", "ProcessId", "CommandLine", "ParentProcessGuid",
    "ParentImage", "ParentCommandLine", "User", "TargetImage", "TargetObject", "QueryName", "SourceImage",
    "NewProcessName", "NewProcessId", "TargetUserName", "TargetDomainName", "TargetUserSid", "IpAddress", "IpPort",
    "TaskName", "ServiceName", "ImagePath", "ScriptBlockId", "Path", "Threat Name", "Detection ID",
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
    if state in {"collecting", "no_data"}:
        events = [normalize_record(source, record) for record in records]
        positions = [int(event["source_event_id"]) for event in events]
        if positions and (sorted(set(positions)) != positions or positions[-1] != position):
            raise ValueError("Invalid Windows source cursor ordering")
        store.ingest_local_windows(events, checkpoint=(offset, position))
    return state, len(records)


class WindowsSources:
    def __init__(self, store, enabled):
        self.store = store
        self.current = {source: {"state": "starting" if enabled else "disabled",
                                 "last_collected_at": None, "fix": FIXES[source]} for source in SOURCE_EVENTS}

    async def watch(self, source):
        while True:
            try:
                state, count = await run_in_threadpool(collect_source, self.store, source)
            except (OSError, TypeError, ValueError, KeyError, AttributeError, sqlite3.Error, subprocess.SubprocessError):
                state, count = "read_failed", 0
            previous = self.current[source]
            if state == "no_data" and previous["last_collected_at"]:
                state = "collecting"
            self.current[source] = {**previous, "state": state,
                                    "last_collected_at": datetime.now(timezone.utc).isoformat() if count
                                    else previous["last_collected_at"]}
            await asyncio.sleep(2 if count == 100 else 30)

    async def run(self):
        async with asyncio.TaskGroup() as tasks:
            for source in SOURCE_EVENTS:
                tasks.create_task(self.watch(source))
