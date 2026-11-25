"""Collect recent OpenSSH failures and sudo records available to this Linux user."""

import asyncio
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone

from starlette.concurrency import run_in_threadpool

from north import SSH_SERVICES, normalize_journal


def collect(store):
    result = subprocess.run([
        "journalctl", "--system", "--no-pager", "--output=json",
        "--output-fields=MESSAGE,_HOSTNAME,_MACHINE_ID,_COMM,SYSLOG_IDENTIFIER", "--since=5 minutes ago", "-n", "500",
        *("_COMM=" + service for service in sorted(SSH_SERVICES | {"sudo"})),
    ], capture_output=True, check=True, encoding="utf-8", errors="replace", timeout=15,
        env={**os.environ, "LC_ALL": "C"})
    if not result.stdout.strip() and ("not seeing messages" in result.stderr.lower() or "permission" in result.stderr.lower()):
        raise PermissionError("System journal access is unavailable")
    if len(result.stdout) > 2_000_000:
        raise ValueError("Journal batch exceeded the collector limit")
    alerts = []
    for line in result.stdout.splitlines():
        if len(line) > 8192:
            continue
        try:
            entry = json.loads(line)
            normalize_journal(entry)
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
        alerts.append({"source": "journalctl", "entry": entry})
    return store.ingest(alerts) if alerts else 0


class JournalMonitor:
    def __init__(self, store):
        self.store = store
        self.current = {"state": "starting", "updated_at": None, "session_events": 0}

    async def run(self):
        while True:
            try:
                count = await run_in_threadpool(collect, self.store)
            except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
                self.current = {**self.current, "state": "unavailable"}
            else:
                self.current = {
                    "state": "ready", "updated_at": datetime.now(timezone.utc).isoformat(),
                    "session_events": self.current["session_events"] + count,
                }
            await asyncio.sleep(15)
